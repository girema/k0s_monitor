package cluster

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k0s_monitor/internal/config"
)

// writeKubeconfig writes a kubeconfig for server. With trustCA the server's
// certificate is embedded as the certificate authority.
func writeKubeconfig(t *testing.T, server string, ts *httptest.Server, trustCA bool) string {
	t.Helper()
	ca := ""
	if trustCA && ts != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
		ca = "    certificate-authority-data: " + b64(pemCert) + "\n"
	}
	kc := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: %s
%scontexts:
- name: test
  context: {cluster: test, user: test}
current-context: test
users:
- name: test
  user: {token: abc}
`, server, ca)
	path := filepath.Join(t.TempDir(), "cluster.config")
	if err := os.WriteFile(path, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ping(t *testing.T, kubeconfig string, timeout time.Duration) error {
	t.Helper()
	conn, err := Connect(config.Cluster{Name: "test", Kubeconfig: kubeconfig}, timeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err = conn.Ping(ctx)
	return err
}

func kindOf(t *testing.T, err error) ErrorKind {
	t.Helper()
	var ce *ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a *ConnError, got %T: %v", err, err)
	}
	return ce.Kind
}

func apiServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func TestPingOK(t *testing.T) {
	ts := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" || r.Header.Get("Authorization") != "Bearer abc" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"major":"1","minor":"36","gitVersion":"v1.36.4+k0s"}`)
	})
	conn, err := Connect(config.Cluster{Name: "test", Kubeconfig: writeKubeconfig(t, ts.URL, ts, true)}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v, err := conn.Ping(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.GitVersion != "v1.36.4+k0s" {
		t.Errorf("version = %q", v.GitVersion)
	}
	if !strings.HasPrefix(conn.Config.UserAgent, "k0s-monitor/") {
		t.Errorf("user agent = %q", conn.Config.UserAgent)
	}
}

func TestPingUnauthorized(t *testing.T) {
	ts := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`)
	})
	err := ping(t, writeKubeconfig(t, ts.URL, ts, true), 5*time.Second)
	if k := kindOf(t, err); k != KindUnauthorized {
		t.Errorf("kind = %s (%v)", k, err)
	}
}

func TestPingUnknownCA(t *testing.T) {
	ts := apiServer(t, func(w http.ResponseWriter, r *http.Request) {})
	err := ping(t, writeKubeconfig(t, ts.URL, ts, false), 5*time.Second)
	if k := kindOf(t, err); k != KindUnknownCA {
		t.Errorf("kind = %s (%v)", k, err)
	}
}

func TestPingCertificateName(t *testing.T) {
	ts := apiServer(t, func(w http.ResponseWriter, r *http.Request) {})
	// The test certificate is valid for 127.0.0.1 and example.com, not "localhost".
	server := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	err := ping(t, writeKubeconfig(t, server, ts, true), 5*time.Second)
	if k := kindOf(t, err); k != KindCertName {
		t.Fatalf("kind = %s (%v)", k, err)
	}
	var ce *ConnError
	errors.As(err, &ce)
	if !strings.Contains(ce.Hint, "only works on the controller itself") {
		t.Errorf("a localhost address should get the loopback hint: %q", ce.Hint)
	}
}

func TestPingRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	err = ping(t, writeKubeconfig(t, "https://"+addr, nil, false), 5*time.Second)
	if k := kindOf(t, err); k != KindRefused {
		t.Errorf("kind = %s (%v)", k, err)
	}
}

func TestPingTimeout(t *testing.T) {
	// A listener that accepts connections but never answers the TLS handshake.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c) // keep it open and silent
			mu.Unlock()
		}
	}()
	err = ping(t, writeKubeconfig(t, "https://"+l.Addr().String(), nil, false), 300*time.Millisecond)
	if k := kindOf(t, err); k != KindTimeout {
		t.Errorf("kind = %s (%v)", k, err)
	}
}

func TestClassifyDNS(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Name: "k0s.invalid", Err: "no such host", IsNotFound: true}}
	ce := Classify(fmt.Errorf("Get \"https://k0s.invalid:6443/version\": %w", err), "https://k0s.invalid:6443", "")
	if ce.Kind != KindDNS || !strings.Contains(ce.Plain, "k0s.invalid") {
		t.Errorf("got %+v", ce)
	}
}

func TestConnectErrors(t *testing.T) {
	_, err := Connect(config.Cluster{Name: "x", Kubeconfig: filepath.Join(t.TempDir(), "missing")}, time.Second)
	if k := kindOf(t, err); k != KindConfig {
		t.Errorf("missing file: kind = %s", k)
	}
	path := filepath.Join(t.TempDir(), "broken")
	os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), 0o600)
	_, err = Connect(config.Cluster{Name: "x", Kubeconfig: path}, time.Second)
	if k := kindOf(t, err); k != KindConfig {
		t.Errorf("empty kubeconfig: kind = %s", k)
	}
}

func TestConnectProxy(t *testing.T) {
	kc := writeKubeconfig(t, "https://10.0.0.1:6443", nil, false)
	conn, err := Connect(config.Cluster{Name: "x", Kubeconfig: kc, Proxy: "socks5://127.0.0.1:1080"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.proxyURL(); got != "socks5://127.0.0.1:1080" {
		t.Errorf("proxy = %q", got)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// TestServerName checks how another controller is reached by its own
// address: its certificate must be valid for the name k0s-monitor asks for,
// or it gets no credentials.
func TestServerName(t *testing.T) {
	var mu sync.Mutex
	tokens := 0
	ts := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			mu.Lock()
			tokens++
			mu.Unlock()
		}
		w.Write([]byte(`{"gitVersion":"v1.36.4+k0s"}`))
	})
	kc := writeKubeconfig(t, "https://k0s.invalid:6443", ts, true)
	connect := func(name string) error {
		conn, err := Connect(config.Cluster{Name: "test", Kubeconfig: kc, Server: ts.URL, ServerName: name}, 2*time.Second)
		if err != nil {
			return err
		}
		_, err = conn.Ping(context.Background())
		return err
	}
	// httptest's certificate is valid for example.com, not for
	// kubernetes.default.svc.
	if err := connect(InClusterName); kindOf(t, err) != KindCertName || tokens != 0 {
		t.Errorf("a certificate without the name: %v, token sent %d times", err, tokens)
	}
	if err := connect("example.com"); err != nil || tokens != 1 {
		t.Errorf("a certificate with the name: %v, token sent %d times", err, tokens)
	}

	// Without a certificate authority to check against, no other address
	// gets the credentials.
	insecure := filepath.Join(t.TempDir(), "insecure.config")
	raw, _ := os.ReadFile(writeKubeconfig(t, "https://k0s.invalid:6443", nil, false))
	os.WriteFile(insecure, []byte(strings.Replace(string(raw), "    server:", "    insecure-skip-tls-verify: true\n    server:", 1)), 0o600)
	_, err := Connect(config.Cluster{Name: "test", Kubeconfig: insecure, Server: ts.URL, ServerName: InClusterName}, time.Second)
	if kindOf(t, err) != KindConfig {
		t.Errorf("insecure kubeconfig: %v", err)
	}

	if a := Address("https://10.0.0.5:6443"); a != "10.0.0.5:6443" {
		t.Errorf("Address = %q", a)
	}
	if a := Address("https://api.shop.lan"); a != "api.shop.lan:443" {
		t.Errorf("Address without a port = %q", a)
	}
}
