package tlsca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAAndServerCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ca, err := NewCA("jump-01", now, []string{"jump-01", "localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.10.5")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, CAKeyFile)); st.Mode().Perm() != 0o600 {
		t.Errorf("CA key mode = %v", st.Mode().Perm())
	}
	loaded, err := LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.IssueFiles(dir, []string{"jump-01", "localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.10.5")}, now); err != nil {
		t.Fatal(err)
	}
	if NeedsRenewal(filepath.Join(dir, CertFile), now) {
		t.Error("a fresh certificate does not need renewal")
	}
	if !NeedsRenewal(filepath.Join(dir, CertFile), now.Add(820*24*time.Hour)) {
		t.Error("a certificate close to expiry needs renewal")
	}

	// A client that trusts only ca.crt accepts the server certificate.
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "jump-01"}}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("a browser that trusts ca.crt must accept the UI: %v", err)
	}
	resp.Body.Close()
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "other-host"
	if _, err := client.Get(srv.URL); err == nil {
		t.Error("a name not in the certificate must be rejected")
	}
}

func TestHosts(t *testing.T) {
	names, ips := Hosts([]string{"monitor.example.lan", "10.9.8.7", ""})
	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	if !has("localhost") || !has("monitor.example.lan") || names[len(names)-1] != "localhost" {
		t.Errorf("names = %v", names)
	}
	found := false
	for _, ip := range ips {
		if ip.String() == "10.9.8.7" {
			found = true
		}
	}
	if !found {
		t.Errorf("ips = %v", ips)
	}
}

// A stolen CA key must not be usable for other sites.
func TestNameConstraints(t *testing.T) {
	now := time.Now()
	ca, err := NewCA("jump-01", now, []string{"jump-01"}, []net.IP{net.ParseIP("203.0.113.7")})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	verify := func(names []string, ips []net.IP) error {
		certPEM, _, err := ca.Issue(names, ips, now)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(certPEM)
		c, _ := x509.ParseCertificate(block.Bytes)
		_, err = c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now})
		return err
	}
	if err := verify([]string{"jump-01"}, []net.IP{net.ParseIP("192.168.1.9"), net.ParseIP("203.0.113.7")}); err != nil {
		t.Errorf("the host's own names and addresses must verify: %v", err)
	}
	if err := verify([]string{"www.bank.example"}, nil); err == nil {
		t.Error("a certificate for another site must not verify")
	}
	if err := verify([]string{"jump-01"}, []net.IP{net.ParseIP("8.8.8.8")}); err == nil {
		t.Error("a certificate for a public address that is not the host's must not verify")
	}
}

func TestSelfSigned(t *testing.T) {
	c, err := SelfSigned(time.Now())
	if err != nil || len(c.Certificate) == 0 {
		t.Fatalf("self-signed: %v", err)
	}
}
