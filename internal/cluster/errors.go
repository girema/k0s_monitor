package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrorKind classifies why a cluster could not be reached.
type ErrorKind string

const (
	KindConfig       ErrorKind = "config"
	KindDNS          ErrorKind = "dns"
	KindTimeout      ErrorKind = "timeout"
	KindRefused      ErrorKind = "refused"
	KindUnknownCA    ErrorKind = "unknown-ca"
	KindCertName     ErrorKind = "cert-name"
	KindCertExpired  ErrorKind = "cert-expired"
	KindTLS          ErrorKind = "tls"
	KindUnauthorized ErrorKind = "unauthorized"
	KindForbidden    ErrorKind = "forbidden"
	KindProxy        ErrorKind = "proxy"
	KindOther        ErrorKind = "other"
)

// ConnError explains a connection failure.
type ConnError struct {
	Kind   ErrorKind `json:"kind"`
	Server string    `json:"server,omitempty"`
	// Plain says what went wrong, in plain words.
	Plain string `json:"plain"`
	// Hint says what to do about it.
	Hint string `json:"hint,omitempty"`
	Err  error  `json:"-"`
}

func (e *ConnError) Error() string {
	if e.Err != nil {
		return e.Plain + " (" + e.Err.Error() + ")"
	}
	return e.Plain
}

func (e *ConnError) Unwrap() error { return e.Err }

// Detail returns the underlying error text.
func (e *ConnError) Detail() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Classify turns an error from talking to server into a ConnError.
func Classify(err error, server, proxy string) *ConnError {
	var ce *ConnError
	if errors.As(err, &ce) {
		return ce
	}
	host, port := hostPort(server)
	e := &ConnError{Kind: KindOther, Server: server, Err: err, Plain: "The cluster can't be reached: " + err.Error()}
	msg := err.Error()

	var dnsErr *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var opErr *net.OpError
	switch {
	case apierrors.IsUnauthorized(err):
		e.Kind = KindUnauthorized
		e.Plain = "The cluster doesn't accept the credentials in the kubeconfig."
		e.Hint = "They may have expired or been revoked. Upload a fresh kubeconfig."
	case apierrors.IsForbidden(err):
		e.Kind = KindForbidden
		e.Plain = "The credentials are valid, but they aren't allowed to read the cluster."
		e.Hint = "Use a kubeconfig whose account can read the cluster (the read-only account k0s-monitor creates is enough)."
	case strings.Contains(msg, "proxyconnect"):
		e.Kind = KindProxy
		e.Plain = fmt.Sprintf("The proxy %s can't be used to reach %s.", proxy, host)
		e.Hint = "Check the proxy address, or remove the proxy if the cluster can be reached directly."
	case errors.As(err, &dnsErr):
		e.Kind = KindDNS
		e.Plain = fmt.Sprintf("The name %s can't be found.", dnsErr.Name)
		e.Hint = "Check the server address in the kubeconfig and the DNS settings of this machine."
	case errors.As(err, &unknownCA) || strings.Contains(msg, "certificate signed by unknown authority"):
		e.Kind = KindUnknownCA
		e.Plain = "The cluster's certificate isn't signed by the authority in the kubeconfig."
		e.Hint = "The kubeconfig is probably from an older installation of this cluster. Upload a fresh one."
	case errors.As(err, &hostErr) || strings.Contains(msg, "certificate is valid for"):
		e.Kind = KindCertName
		e.Plain = fmt.Sprintf("The address %s isn't listed in the cluster's certificate.", host)
		e.Hint = "Use one of the addresses the certificate lists (see the details), or have this address added to spec.api.sans through a product update."
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired, strings.Contains(msg, "certificate has expired"):
		e.Kind = KindCertExpired
		e.Plain = "The cluster's certificate, or the one in the kubeconfig, has expired."
		e.Hint = "Upload a fresh kubeconfig. If the API server's own certificate expired, send the details to your support team."
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(msg, "connection refused"):
		e.Kind = KindRefused
		e.Plain = fmt.Sprintf("%s refused the connection on port %s.", host, port)
		e.Hint = "Nothing is listening there. The k0s controller may be stopped (on the controller: sudo k0s status), or the port is wrong."
	case isTimeout(err):
		e.Kind = KindTimeout
		e.Plain = fmt.Sprintf("No answer from %s on port %s.", host, port)
		e.Hint = fmt.Sprintf("Check that the controller is running and that the network or firewall allows this machine to reach port %s.", port)
	case errors.As(err, &opErr) && strings.Contains(msg, "tls"), strings.Contains(msg, "tls:"):
		e.Kind = KindTLS
		e.Plain = fmt.Sprintf("The secure connection to %s failed.", host)
		e.Hint = "Check that the address points at the k0s API server (port 6443)."
	}
	if isLoopback(host) && (e.Kind == KindRefused || e.Kind == KindTimeout || e.Kind == KindCertName) {
		e.Hint = "The kubeconfig points to " + host + ", which only works on the controller itself. Use the controller's address or load balancer instead. " + e.Hint
	}
	return e
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "Client.Timeout exceeded") ||
		strings.Contains(msg, "TLS handshake timeout") || strings.Contains(msg, "context deadline exceeded")
}

func hostPort(server string) (string, string) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return server, ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), port
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
