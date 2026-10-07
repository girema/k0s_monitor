package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/snapshot"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

// testCA makes a CA and a serving certificate it signs.
func testCA(t *testing.T, names []string, ips []net.IP) (caPEM []byte, cert tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "kubernetes"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(20 * 24 * time.Hour),
		DNSNames: names, IPAddresses: ips, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// apiServer answers like a k0s API server whose etcd check fails, and
// counts the requests that carried the token.
func apiServer(t *testing.T, cert tls.Certificate, withToken *atomic.Int32) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer secret-token" {
			withToken.Add(1)
		} else if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/healthz":
			w.Write([]byte("ok"))
		case "/readyz":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("[+]ping ok\n[+]log ok\n[-]etcd failed: reason withheld\n[+]poststarthook/start-kube-aggregator-informers ok\nreadyz check failed\n"))
		case "/livez":
			w.Write([]byte("[+]ping ok\nlivez check passed\n"))
		case "/version":
			w.Write([]byte(`{"gitVersion":"v1.36.4+k0s"}`))
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestAskController(t *testing.T) {
	caPEM, cert := testCA(t, []string{"kubernetes", "kubernetes.default.svc"}, []net.IP{net.ParseIP("127.0.0.1")})
	var tokens atomic.Int32
	srv := apiServer(t, cert, &tokens)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	rc := &rest.Config{Host: "https://api.shop.lan:6443", BearerToken: "secret-token", TLSClientConfig: rest.TLSClientConfig{CAData: caPEM}}
	s := NewSource(&cluster.Conn{Name: "c", Config: rc}, func() time.Time { return now })

	ctl := s.ask(context.Background(), rc, candidate{name: "ctrl-1", host: host, port: port, from: []string{"controlnode"}}, "api.shop.lan")
	if !ctl.Reached || ctl.Error != "" {
		t.Fatalf("not reached: %+v", ctl)
	}
	if len(ctl.Failing) != 1 || ctl.Failing[0].Name != "etcd" || ctl.Failing[0].Message != "reason withheld" || len(ctl.LiveFailing) != 0 || !ctl.EtcdFailing() {
		t.Errorf("checks: %+v / %+v", ctl.Failing, ctl.LiveFailing)
	}
	if ctl.Version != "v1.36.4+k0s" || ctl.Cert == nil || ctl.Cert.CoversServer || !strings.Contains(strings.Join(ctl.Cert.Names, ","), "kubernetes.default.svc") {
		t.Errorf("version %q, cert %+v", ctl.Version, ctl.Cert)
	}
	if d := time.Until(ctl.Cert.NotAfter); d < 19*24*time.Hour || d > 21*24*time.Hour {
		t.Errorf("not after %v", ctl.Cert.NotAfter)
	}
	if tokens.Load() == 0 {
		t.Error("the controller was asked with the cluster's credentials")
	}

	// A certificate of another CA gets no credentials.
	_, other := testCA(t, []string{"kubernetes.default.svc"}, []net.IP{net.ParseIP("127.0.0.1")})
	var stolen atomic.Int32
	evil := apiServer(t, other, &stolen)
	host, port, _ = net.SplitHostPort(strings.TrimPrefix(evil.URL, "https://"))
	ctl = s.ask(context.Background(), rc, candidate{host: host, port: port}, "api.shop.lan")
	if ctl.Reached || !strings.Contains(ctl.Error, "isn't signed by the cluster's certificate authority") || stolen.Load() != 0 {
		t.Errorf("another CA: reached %v, error %q, token sent %d times", ctl.Reached, ctl.Error, stolen.Load())
	}

	// A closed port says so in words.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closed, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	ctl = s.ask(context.Background(), rc, candidate{host: "127.0.0.1", port: closed}, "api.shop.lan")
	if ctl.Reached || !strings.Contains(ctl.Error, "can't reach 127.0.0.1:"+closed+" from this host: connection refused") {
		t.Errorf("closed: %+v", ctl)
	}
}

func TestDiscover(t *testing.T) {
	port := int32(6443)
	client := fake.NewClientset(&discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.12"}}, {Addresses: []string{"10.0.0.11"}}},
		Ports:       []discoveryv1.EndpointPort{{Port: &port}},
	})
	s := NewSource(cluster.NewForClient("c", "https://10.0.0.11:6443", client, nil), func() time.Time { return now })

	// The kubeconfig points at one of the controllers.
	cands := s.discover(context.Background(), "10.0.0.11", "6443")
	if len(cands) != 2 || cands[0].host != "10.0.0.11" || strings.Join(cands[0].from, ",") != "endpoints,kubeconfig" || cands[1].port != "6443" {
		t.Errorf("candidates = %+v", cands)
	}
	// Through a load balancer, the kubeconfig's address is not a controller.
	cands = s.discover(context.Background(), "api.shop.lan", "443")
	if len(cands) != 2 || cands[0].port != "6443" || strings.Contains(strings.Join(cands[0].from, ","), "kubeconfig") {
		t.Errorf("behind a load balancer: %+v", cands)
	}
	// A controller that runs a worker is named after its node.
	cands = s.discover(context.Background(), "10.0.0.11", "6443")
	nameByNode(cands, []*corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "ctrl-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.11"}}}}})
	if cands[0].name != "ctrl-a" || cands[1].name != "" {
		t.Errorf("named: %+v", cands)
	}
	// Nothing known but the kubeconfig: ask that.
	s = NewSource(cluster.NewForClient("c", "https://10.0.0.11:6443", fake.NewClientset(), nil), func() time.Time { return now })
	if cands = s.discover(context.Background(), "10.0.0.11", "6443"); len(cands) != 1 || cands[0].from[0] != "kubeconfig" {
		t.Errorf("only the kubeconfig: %+v", cands)
	}
}

func TestParseStorageMetrics(t *testing.T) {
	text := `# HELP apiserver_request_total x
apiserver_request_total{code="200"} 12
apiserver_resource_objects{group="apps",resource="replicasets"} 4200
apiserver_resource_objects{group="",resource="events"} 180000
apiserver_storage_objects{resource="secrets"} 900
# TYPE apiserver_storage_size_bytes gauge
apiserver_storage_size_bytes{storage_cluster_id="a"} 1.2e+09
apiserver_storage_size_bytes{storage_cluster_id="b"} 1.9327e+09
apiserver_watch_events_total{kind="Pod"} 5
etcd_request_duration_seconds_bucket{le="0.005"} 1
`
	db, objs := parseStorageMetrics(strings.NewReader(text))
	if db != 1.9327e9 {
		t.Errorf("db = %v", db)
	}
	if len(objs) != 3 || objs[0].Resource != "events" || objs[1].Resource != "replicasets.apps" || objs[2].Count != 900 {
		t.Errorf("objects = %+v", objs)
	}
	if db, objs := parseStorageMetrics(strings.NewReader("up 1\n")); snapshot.Known(db) || len(objs) != 0 {
		t.Errorf("nothing known: %v %v", db, objs)
	}
}

func TestFailingSince(t *testing.T) {
	clock := now
	s := NewSource(nil, func() time.Time { return clock })
	record := func(failing bool) *snapshot.Controller {
		c := &snapshot.Controller{Address: "10.0.0.12:6443", Reached: true}
		if failing {
			c.Failing = []snapshot.Check{{Name: "etcd"}}
		}
		s.remember(&snapshot.ControlPlane{At: clock, Controllers: []*snapshot.Controller{c}})
		return c
	}
	record(true)
	clock = now.Add(time.Minute)
	if c := record(true); !c.FailingSince.Equal(now) {
		t.Errorf("since %v", c.FailingSince)
	}
	record(false)
	clock = now.Add(2 * time.Minute)
	if c := record(true); !c.FailingSince.Equal(clock) {
		t.Errorf("a new failure starts again: %v", c.FailingSince)
	}
}
