package snapshot

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTLSCerts(t *testing.T) {
	s, err := FromYAMLFile("test", "../rules/testdata/tls.yaml", time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]TLSCert{}
	for _, c := range s.TLSCerts {
		byName[c.Secret] = c
	}
	if len(s.TLSCerts) != 6 {
		t.Fatalf("certs = %d, want the 6 TLS Secrets only", len(s.TLSCerts))
	}
	web := byName["web-tls"]
	if web.Subject != "CN=shop.example.com" || web.Issuer != "CN=shop.example.com" || !web.NotAfter.Equal(time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC)) || web.Error != "" {
		t.Errorf("web = %+v", web)
	}
	if byName["late-tls"].CertManager != "late" || byName["web-tls"].CertManager != "" {
		t.Error("cert-manager annotation")
	}
	wild := byName["wild-tls"]
	for host, want := range map[string]bool{"app.example.com": true, "example.com": true, "a.b.example.com": false, "example.org": false} {
		if wild.Covers(host) != want {
			t.Errorf("*.example.com covers %s: %v", host, !want)
		}
	}
}

func TestOnlyTLSCertDropsTheKey(t *testing.T) {
	in := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "shop", Labels: map[string]string{"a": "b"}, Annotations: map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": `{"data":{"tls.key":"S0VZ"}}`, CertManagerAnnotation: "x"}},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY"), "ca.crt": []byte("CA")},
	}
	out := OnlyTLSCert(in)
	if len(out.Data) != 1 || string(out.Data["tls.crt"]) != "CERT" || len(out.Annotations) != 1 || out.Annotations[CertManagerAnnotation] != "x" || out.Labels != nil {
		t.Errorf("kept %+v", out)
	}
	if c := TLSCertOf(out); c.Error != "tls.crt holds no PEM certificate" {
		t.Errorf("error = %q", c.Error)
	}
}
