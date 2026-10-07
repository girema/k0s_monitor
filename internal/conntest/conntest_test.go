package conntest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes/scheme"

	"k0s_monitor/internal/config"
)

// fakeAPI answers the calls the connection test makes.
func fakeAPI(t *testing.T, token string, canAdmin bool) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Unauthorized","code":401}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/version":
			io.WriteString(w, `{"gitVersion":"v1.36.4+k0s","major":"1","minor":"36"}`)
		case r.URL.Path == "/api":
			io.WriteString(w, `{"kind":"APIVersions","versions":["v1"]}`)
		case r.URL.Path == "/apis":
			io.WriteString(w, `{"kind":"APIGroupList","groups":[{"name":"helm.k0sproject.io","versions":[{"groupVersion":"helm.k0sproject.io/v1beta1","version":"v1beta1"}]}]}`)
		case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
			io.WriteString(w, `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","status":{"userInfo":{"username":"kubernetes-admin","groups":["system:masters","system:authenticated"]}}}`)
		case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
			// client-go sends built-in types as protobuf.
			body, _ := io.ReadAll(r.Body)
			obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, nil)
			req, ok := obj.(*authzv1.SelfSubjectAccessReview)
			if err != nil || !ok || req.Spec.ResourceAttributes == nil {
				t.Errorf("bad access review: %v", err)
				return
			}
			a := req.Spec.ResourceAttributes
			allowed := canAdmin || (a.Verb != "create" && a.Verb != "bind" && !(a.Resource == "secrets"))
			if a.Resource == "pods" && a.Subresource == "log" && !canAdmin {
				allowed = false
			}
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "status": map[string]any{"allowed": allowed}})
		case r.URL.Path == "/api/v1/nodes":
			io.WriteString(w, `{"kind":"NodeList","apiVersion":"v1","items":[{"metadata":{"name":"w1"}},{"metadata":{"name":"w2"}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
		}
	}))
	// The TLS probe hangs up after the handshake; don't log that.
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func caPEM(c *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func kubeconfig(server, ca, token string) []byte {
	return []byte(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "` + server + `", certificate-authority-data: ` + ca + `}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {token: ` + token + `}}]
`)
}

func run(t *testing.T, kc []byte, o Options) *Report {
	t.Helper()
	o.StepTimeout = 3 * time.Second
	return Run(context.Background(), config.Cluster{Name: "t", KubeconfigData: kc}, o)
}

func step(r *Report, name string) *Step {
	for i := range r.Steps {
		if r.Steps[i].Name == name {
			return &r.Steps[i]
		}
	}
	return nil
}

func TestHealthyAdmin(t *testing.T) {
	ts := fakeAPI(t, "good", true)
	r := run(t, kubeconfig(ts.URL, caPEM(ts.Certificate()), "good"), Options{ExpectedNodes: 3})
	if !r.OK {
		t.Fatalf("report = %+v", r)
	}
	if r.Identity != "kubernetes-admin (system:masters)" || !r.K0s || !r.CanCreateAccount || r.Nodes != 2 {
		t.Errorf("report = %+v", r)
	}
	if s := step(r, "Check the server certificate"); s == nil || s.Status != Pass {
		t.Errorf("tls step = %+v", s)
	}
	if s := step(r, "Compare with k0sctl.yaml"); s == nil || s.Status != Warn || !strings.Contains(s.Detail, "lists 3") {
		t.Errorf("layout step = %+v", s)
	}
}

func TestReadOnlyCredentials(t *testing.T) {
	ts := fakeAPI(t, "good", false)
	r := run(t, kubeconfig(ts.URL, caPEM(ts.Certificate()), "good"), Options{})
	if !r.OK || r.CanCreateAccount {
		t.Fatalf("read-only credentials pass, without the account option: %+v", r)
	}
	if s := step(r, "Check permissions"); s == nil || s.Status != Warn || !strings.Contains(s.Detail, "get pods/log") {
		t.Errorf("missing permissions are reported, not fatal: %+v", s)
	}
}

func TestAddressNotInCertificate(t *testing.T) {
	ts := fakeAPI(t, "good", true)
	// The test certificate is for 127.0.0.1 and example.com, not localhost.
	server := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	r := run(t, kubeconfig(server, caPEM(ts.Certificate()), "good"), Options{})
	s := step(r, "Check the server certificate")
	if r.OK || s == nil || s.Status != Fail || !strings.Contains(s.Detail, "localhost is not in") ||
		!strings.Contains(s.Hint, "127.0.0.1") || !strings.Contains(s.Hint, "spec.api.sans") {
		t.Errorf("step = %+v", s)
	}
}

func TestUnknownCA(t *testing.T) {
	ts := fakeAPI(t, "good", true)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	other, _ := x509.ParseCertificate(der)
	r := run(t, kubeconfig(ts.URL, caPEM(other), "good"), Options{})
	if s := step(r, "Check the server certificate"); r.OK || s == nil || !strings.Contains(s.Detail, "not signed") {
		t.Errorf("step = %+v", s)
	}
}

func TestRejectedCredentials(t *testing.T) {
	ts := fakeAPI(t, "good", true)
	r := run(t, kubeconfig(ts.URL, caPEM(ts.Certificate()), "stale"), Options{})
	if s := step(r, "Sign in"); r.OK || s == nil || s.Status != Fail || !strings.Contains(s.Hint, "k0s kubeconfig admin") {
		t.Errorf("step = %+v", s)
	}
}

func TestDNSAndRefused(t *testing.T) {
	ts := fakeAPI(t, "good", true)
	ca := caPEM(ts.Certificate())
	r := run(t, kubeconfig("https://k0sm-conntest.invalid:6443", ca, "good"), Options{})
	if s := step(r, "Find the address"); r.OK || s == nil || s.Status != Fail {
		t.Errorf("dns step = %+v", r.Steps)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	r = run(t, kubeconfig("https://"+addr, ca, "good"), Options{})
	if s := step(r, "Reach the API server"); r.OK || s == nil || s.Status != Fail || s.Hint == "" {
		t.Errorf("tcp step = %+v", r.Steps)
	}
}

func TestBadKubeconfig(t *testing.T) {
	r := run(t, []byte("not: a kubeconfig"), Options{})
	if r.OK || r.Steps[0].Status != Fail {
		t.Errorf("report = %+v", r)
	}
}
