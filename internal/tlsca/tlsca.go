// Package tlsca creates the small local certificate authority that `init`
// sets up, and the web UI's server certificate signed by it. Importing
// ca.crt once into Windows lets Edge and Chrome open the UI without
// warnings (plan section 13).
package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// File names inside the configuration directory.
const (
	CACertFile  = "ca.crt"
	CAKeyFile   = "ca.key"
	CertFile    = "tls.crt"
	KeyFile     = "tls.key"
	caLifetime  = 10 * 365 * 24 * time.Hour
	crtLifetime = 825 * 24 * time.Hour
	// RenewBefore is when serve issues a new server certificate.
	RenewBefore = 30 * 24 * time.Hour
)

// CA is a certificate authority with its key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// privateRanges are the addresses a server certificate may carry besides
// the host's own: loopback and private networks.
var privateRanges = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

// NewCA creates a CA named after the host. If names or ips are given, the
// CA is name-constrained to them and to private addresses: even if its key
// were stolen, it could not be used to impersonate other websites to a PC
// that trusts it.
func NewCA(host string, now time.Time, names []string, ips []net.IP) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "k0s-monitor CA (" + host + ")", Organization: []string{"k0s-monitor"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if len(names) > 0 || len(ips) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = names
		seen := map[string]bool{}
		for _, r := range privateRanges {
			_, n, _ := net.ParseCIDR(r)
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
		}
		for _, ip := range ips {
			if isPrivate(ip) || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Issue creates a server certificate for the given DNS names and IP
// addresses. It returns the PEM certificate and key.
func (ca *CA) Issue(names []string, ips []net.IP, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cn := "k0s-monitor"
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"k0s-monitor"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(crtLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

// Save writes the CA certificate (world-readable, to be copied to the
// Windows PC) and its key (owner only).
func (ca *CA) Save(dir string) error {
	kb, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, CACertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CAKeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// LoadCA reads the CA from dir.
func LoadCA(dir string) (*CA, error) {
	cb, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the CA key is not an ECDSA key")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// IssueFiles issues a server certificate and writes tls.crt and tls.key.
func (ca *CA) IssueFiles(dir string, names []string, ips []net.IP, now time.Time) error {
	certPEM, keyPEM, err := ca.Issue(names, ips, now)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, KeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CertFile), certPEM, 0o644)
}

// NeedsRenewal reports whether the certificate file expires within
// RenewBefore, or can't be read.
func NeedsRenewal(certFile string, now time.Time) bool {
	c, err := ReadCert(certFile)
	return err != nil || now.Add(RenewBefore).After(c.NotAfter)
}

// ReadCert reads the first certificate of a PEM file.
func ReadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// Hosts returns the names and addresses a server certificate for this
// machine should cover: the host name, its fully qualified name, every
// non-loopback address, localhost, and the extra entries given.
func Hosts(extra []string) ([]string, []net.IP) {
	names := map[string]bool{"localhost": true}
	ipset := map[string]net.IP{"127.0.0.1": net.ParseIP("127.0.0.1"), "::1": net.ParseIP("::1")}
	if h, err := os.Hostname(); err == nil && h != "" {
		names[strings.ToLower(h)] = true
		if cname, err := net.LookupCNAME(h); err == nil {
			if n := strings.TrimSuffix(strings.ToLower(cname), "."); n != "" {
				names[n] = true
			}
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				ipset[ipn.IP.String()] = ipn.IP
			}
		}
	}
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			ipset[ip.String()] = ip
		} else {
			names[strings.ToLower(e)] = true
		}
	}
	var ns []string
	for n := range names {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool {
		// The host's own name first: it becomes the common name.
		if (ns[i] == "localhost") != (ns[j] == "localhost") {
			return ns[j] == "localhost"
		}
		return ns[i] < ns[j]
	})
	var ips []net.IP
	var keys []string
	for k := range ipset {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ips = append(ips, ipset[k])
	}
	return ns, ips
}

func isPrivate(ip net.IP) bool {
	for _, r := range privateRanges {
		if _, n, _ := net.ParseCIDR(r); n.Contains(ip) {
			return true
		}
	}
	return false
}

// SelfSigned returns an in-memory certificate for localhost, for laptop
// mode when init has not been run. Browsers warn about it.
func SelfSigned(now time.Time) (tls.Certificate, error) {
	names, ips := []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	ca, err := NewCA("localhost", now, names, ips)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, keyPEM, err := ca.Issue(names, ips, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
