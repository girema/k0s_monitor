package snapshot

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// KindTLSSecret is the TLS Secrets, read only when the account is allowed
// to: it is not in AllKinds, so clusters without the permission aren't
// partial.
const KindTLSSecret Kind = "secrets"

// CertManagerAnnotation names the cert-manager Certificate that renews a
// Secret.
const CertManagerAnnotation = "cert-manager.io/certificate-name"

// TLSCert is the certificate in a TLS Secret: public data only. The private
// key is never kept.
type TLSCert struct {
	Namespace string
	Secret    string
	Subject   string
	Issuer    string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	// CertManager names the cert-manager Certificate that renews it, if
	// any.
	CertManager string
	// Error says why tls.crt couldn't be read.
	Error string
}

// Names are the host names the certificate is for: its DNS names, else its
// subject's common name.
func (c TLSCert) Names() []string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames
	}
	if cn, ok := strings.CutPrefix(c.Subject, "CN="); ok && !strings.Contains(cn, ",") {
		return []string{cn}
	}
	return nil
}

// Covers reports whether the certificate is valid for a host name,
// wildcards included.
func (c TLSCert) Covers(host string) bool {
	host = strings.ToLower(host)
	for _, n := range c.Names() {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if i := strings.Index(host, "."); i > 0 && host[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// TLSCertOf reads the certificate of a TLS Secret: the first one in
// tls.crt, which is the server's own; the rest is its chain.
func TLSCertOf(s *corev1.Secret) TLSCert {
	c := TLSCert{Namespace: s.Namespace, Secret: s.Name, CertManager: s.Annotations[CertManagerAnnotation]}
	data := s.Data[corev1.TLSCertKey]
	if len(data) == 0 {
		c.Error = "tls.crt is empty"
		return c
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		c.Error = "tls.crt holds no PEM certificate"
		return c
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Error = "tls.crt can't be read: " + err.Error()
		return c
	}
	c.Subject, c.Issuer = cert.Subject.String(), cert.Issuer.String()
	c.DNSNames = cert.DNSNames
	c.NotBefore, c.NotAfter = cert.NotBefore, cert.NotAfter
	return c
}

// OnlyTLSCert keeps what TLSCertOf reads from a Secret: its name, the
// cert-manager annotation and tls.crt. The private key and every other
// annotation (kubectl's last-applied-configuration holds the whole Secret)
// are dropped.
func OnlyTLSCert(s *corev1.Secret) *corev1.Secret {
	out := &corev1.Secret{Type: s.Type}
	out.Name, out.Namespace, out.UID, out.ResourceVersion = s.Name, s.Namespace, s.UID, s.ResourceVersion
	if v := s.Annotations[CertManagerAnnotation]; v != "" {
		out.Annotations = map[string]string{CertManagerAnnotation: v}
	}
	if crt := s.Data[corev1.TLSCertKey]; crt != nil {
		out.Data = map[string][]byte{corev1.TLSCertKey: crt}
	}
	return out
}
