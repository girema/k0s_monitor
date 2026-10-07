// Package conntest runs the connection test of the Add cluster page (plan
// section 5.2): DNS, TCP, TLS (chain, expiry and whether the address is in
// the certificate), sign-in, k0s detection, permissions, and the layout
// compared with k0sctl.yaml. Every failure comes with its fix. Missing
// permissions never fail the test; they only disable what needs them.
package conntest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/metrics"
)

// Status of one step.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Step is one check.
type Step struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

// Report is the result of a test.
type Report struct {
	// Prometheus says whether metrics can be read.
	Prometheus *cluster.PrometheusStatus `json:"prometheus,omitempty"`
	OK         bool                      `json:"ok"`
	Steps      []Step                    `json:"steps"`
	Identity   string                    `json:"identity,omitempty"`
	// CanCreateAccount means the credentials may create k0s-monitor's own
	// read-only account.
	CanCreateAccount bool     `json:"canCreateAccount"`
	K0s              bool     `json:"k0s"`
	Version          string   `json:"version,omitempty"`
	Nodes            int      `json:"nodes"`
	CertNames        []string `json:"certNames,omitempty"`
	// Missing lists read permissions the credentials lack.
	Missing []string `json:"missingPermissions,omitempty"`
}

// Options tune a test.
type Options struct {
	// ExpectedNodes is the number of nodes k0sctl.yaml lists (0: unknown).
	ExpectedNodes int
	// StepTimeout bounds each network step.
	StepTimeout time.Duration
}

func (r *Report) add(s Step) { r.Steps = append(r.Steps, s) }

// Run tests the connection to a cluster.
func Run(ctx context.Context, c config.Cluster, o Options) *Report {
	if o.StepTimeout == 0 {
		o.StepTimeout = 10 * time.Second
	}
	r := &Report{}
	defer func() {
		r.OK = true
		for _, s := range r.Steps {
			if s.Status == Fail {
				r.OK = false
			}
		}
	}()

	rc, err := cluster.RESTConfig(c)
	if err != nil {
		ce := asConnError(err, "", c.Proxy)
		r.add(Step{Name: "Read the kubeconfig", Status: Fail, Detail: ce.Plain, Hint: ce.Hint})
		return r
	}
	r.add(Step{Name: "Read the kubeconfig", Status: Pass, Detail: "server " + rc.Host})
	u, err := url.Parse(rc.Host)
	if err != nil || u.Host == "" {
		r.add(Step{Name: "Find the address", Status: Fail, Detail: fmt.Sprintf("%q is not a valid server address", rc.Host)})
		return r
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	proxied := c.Proxy != "" || rc.Proxy != nil

	// DNS and TCP (a proxy does both itself).
	if proxied {
		r.add(Step{Name: "Find the address", Status: Skip, Detail: "through the proxy"})
		r.add(Step{Name: "Reach the API server", Status: Skip, Detail: "through the proxy"})
	} else {
		if net.ParseIP(host) != nil {
			r.add(Step{Name: "Find the address", Status: Pass, Detail: host + " is an IP address"})
		} else {
			dctx, cancel := context.WithTimeout(ctx, o.StepTimeout)
			addrs, err := net.DefaultResolver.LookupHost(dctx, host)
			cancel()
			if err != nil {
				ce := cluster.Classify(err, rc.Host, "")
				r.add(Step{Name: "Find the address", Status: Fail, Detail: ce.Plain, Hint: ce.Hint})
				return r
			}
			r.add(Step{Name: "Find the address", Status: Pass, Detail: host + " is " + strings.Join(addrs, ", ")})
		}
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: o.StepTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			ce := cluster.Classify(err, rc.Host, "")
			r.add(Step{Name: "Reach the API server", Status: Fail, Detail: ce.Plain, Hint: ce.Hint})
			return r
		}
		conn.Close()
		r.add(Step{Name: "Reach the API server", Status: Pass, Detail: fmt.Sprintf("port %s answers in %d ms", port, time.Since(start).Milliseconds())})
		if !r.tlsStep(ctx, rc, host, port, o) {
			return r
		}
	}

	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		r.add(Step{Name: "Sign in", Status: Fail, Detail: err.Error()})
		return r
	}
	if !r.authStep(ctx, cs, rc.Host, c.Proxy, o) {
		return r
	}
	r.k0sStep(cs)
	r.permissionStep(ctx, cs, o)
	r.layoutStep(ctx, cs, o)
	r.prometheusStep(ctx, cs, c.Prometheus, o)
	return r
}

// prometheusStep looks for the Prometheus that disk, volume and VM checks
// read. Not finding one is a warning: everything else works without it.
func (r *Report) prometheusStep(ctx context.Context, cs kubernetes.Interface, cfg *config.Prometheus, o Options) {
	const name = "Find Prometheus or VictoriaMetrics"
	sctx, cancel := context.WithTimeout(ctx, 3*o.StepTimeout)
	defer cancel()
	t, st := metrics.Find(sctx, cs, cfg)
	r.Prometheus = &st
	switch {
	case t != nil:
		r.add(Step{Name: name, Status: Pass, Detail: "found at " + t.String()})
	case st.State == "disabled":
		r.add(Step{Name: name, Status: Skip, Detail: st.Message})
	case st.State == "forbidden" && r.CanCreateAccount:
		r.add(Step{Name: name, Status: Pass, Detail: st.Target + ": the read-only account will be allowed to read it"})
	default:
		r.add(Step{Name: name, Status: Warn, Detail: st.Message, Hint: st.Hint})
	}
}

// tlsStep checks the server certificate: trusted chain, validity, and
// whether the address is one of its names. It returns false when the
// connection can't be trusted.
func (r *Report) tlsStep(ctx context.Context, rc *rest.Config, host, port string, o Options) bool {
	const name = "Check the server certificate"
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: o.StepTimeout}, Config: &tls.Config{InsecureSkipVerify: true, ServerName: host}} //nolint:gosec // verified below, to explain each failure
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.add(Step{Name: name, Status: Fail, Detail: "no TLS: " + err.Error(), Hint: "Check that the address is the Kubernetes API server (usually port 6443)."})
		return false
	}
	state := c.(*tls.Conn).ConnectionState()
	c.Close()
	if len(state.PeerCertificates) == 0 {
		r.add(Step{Name: name, Status: Fail, Detail: "the server sent no certificate"})
		return false
	}
	leaf := state.PeerCertificates[0]
	r.CertNames = append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...)
	sort.Strings(r.CertNames)
	if rc.Insecure {
		r.add(Step{Name: name, Status: Warn, Detail: "not verified: the kubeconfig turns the check off (insecure-skip-tls-verify)",
			Hint: "Prefer a kubeconfig with certificate-authority-data."})
		return true
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		r.add(Step{Name: name, Status: Fail, Detail: fmt.Sprintf("the API server certificate expired on %s", leaf.NotAfter.UTC().Format("2006-01-02")),
			Hint: "k0s renews its certificates when the controller restarts. Ask your support team if it does not."})
		return false
	}
	pool := x509.NewCertPool()
	if len(rc.TLSClientConfig.CAData) > 0 {
		pool.AppendCertsFromPEM(rc.TLSClientConfig.CAData)
	} else if sys, err := x509.SystemCertPool(); err == nil {
		pool = sys
	}
	inter := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now}); err != nil {
		r.add(Step{Name: name, Status: Fail, Detail: "the certificate is not signed by the certificate authority in the kubeconfig",
			Hint: "The kubeconfig may belong to another cluster, or the cluster was set up again. Create a fresh one on a controller: sudo k0s kubeconfig admin"})
		return false
	}
	if err := leaf.VerifyHostname(host); err != nil {
		r.add(Step{Name: name, Status: Fail, Detail: fmt.Sprintf("the address %s is not in the API server certificate", host),
			Hint: fmt.Sprintf("Use one of the addresses it has: %s. Or add %s to spec.api.sans in the k0s configuration, which on your product comes with an update or from your support team.",
				strings.Join(r.CertNames, ", "), host)})
		return false
	}
	detail := fmt.Sprintf("trusted, valid until %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	st := Pass
	if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
		st = Warn
		detail = fmt.Sprintf("trusted, but expires on %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	r.add(Step{Name: name, Status: st, Detail: detail})
	return true
}

func (r *Report) authStep(ctx context.Context, cs kubernetes.Interface, server, proxy string, o Options) bool {
	const name = "Sign in"
	sctx, cancel := context.WithTimeout(ctx, o.StepTimeout)
	defer cancel()
	res, err := cs.AuthenticationV1().SelfSubjectReviews().Create(sctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		ui := res.Status.UserInfo
		r.Identity = ui.Username
		var groups []string
		for _, g := range ui.Groups {
			if g != "system:authenticated" {
				groups = append(groups, g)
			}
		}
		if len(groups) > 0 {
			r.Identity += " (" + strings.Join(groups, ", ") + ")"
		}
		r.add(Step{Name: name, Status: Pass, Detail: "signed in as " + r.Identity})
		return true
	}
	if apierrors.IsUnauthorized(err) {
		r.add(Step{Name: name, Status: Fail, Detail: "the cluster rejected the credentials in the kubeconfig",
			Hint: "They may be revoked or belong to another cluster. Create a fresh kubeconfig on a controller: sudo k0s kubeconfig admin"})
		return false
	}
	if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) || apierrors.IsMethodNotSupported(err) {
		// Older API servers: any authorized answer proves the sign-in.
		_, lerr := cs.CoreV1().Namespaces().List(sctx, metav1.ListOptions{Limit: 1})
		if apierrors.IsUnauthorized(lerr) {
			r.add(Step{Name: name, Status: Fail, Detail: "the cluster rejected the credentials"})
			return false
		}
		r.add(Step{Name: name, Status: Pass, Detail: "signed in"})
		return true
	}
	ce := cluster.Classify(err, server, proxy)
	r.add(Step{Name: name, Status: Fail, Detail: ce.Plain, Hint: ce.Hint})
	return false
}

func (r *Report) k0sStep(cs kubernetes.Interface) {
	const name = "Detect k0s"
	v, err := cs.Discovery().ServerVersion()
	if err != nil {
		r.add(Step{Name: name, Status: Warn, Detail: "the version can't be read: " + err.Error()})
		return
	}
	r.Version = v.GitVersion
	r.K0s = strings.Contains(v.GitVersion, "+k0s")
	if !r.K0s {
		if groups, err := cs.Discovery().ServerGroups(); err == nil {
			for _, g := range groups.Groups {
				if strings.HasSuffix(g.Name, "k0sproject.io") {
					r.K0s = true
				}
			}
		}
	}
	if r.K0s {
		r.add(Step{Name: name, Status: Pass, Detail: "k0s, Kubernetes " + v.GitVersion})
	} else {
		r.add(Step{Name: name, Status: Warn, Detail: "Kubernetes " + v.GitVersion + ", not k0s",
			Hint: "It works as a generic Kubernetes monitor; k0s-specific checks are skipped."})
	}
}

// readChecks are the read permissions that matter most.
var readChecks = []authzv1.ResourceAttributes{
	{Verb: "list", Resource: "pods"},
	{Verb: "watch", Resource: "pods"},
	{Verb: "list", Resource: "nodes"},
	{Verb: "list", Resource: "events"},
	{Verb: "get", Resource: "pods", Subresource: "log"},
	{Verb: "list", Group: "apps", Resource: "deployments"},
	{Verb: "list", Resource: "persistentvolumeclaims"},
	{Verb: "list", Resource: "services"},
}

// accountChecks are what creating the read-only account needs.
var accountChecks = []authzv1.ResourceAttributes{
	{Verb: "create", Resource: "serviceaccounts", Namespace: "kube-system"},
	{Verb: "create", Resource: "secrets", Namespace: "kube-system"},
	{Verb: "get", Resource: "secrets", Namespace: "kube-system"},
	{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterroles"},
	{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"},
	{Verb: "bind", Group: "rbac.authorization.k8s.io", Resource: "clusterroles"},
}

func (r *Report) permissionStep(ctx context.Context, cs kubernetes.Interface, o Options) {
	const name = "Check permissions"
	can := func(a authzv1.ResourceAttributes) (bool, error) {
		sctx, cancel := context.WithTimeout(ctx, o.StepTimeout)
		defer cancel()
		res, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(sctx,
			&authzv1.SelfSubjectAccessReview{Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &a}}, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		return res.Status.Allowed, nil
	}
	for _, a := range readChecks {
		ok, err := can(a)
		if err != nil {
			r.add(Step{Name: name, Status: Warn, Detail: "permissions can't be checked: " + err.Error()})
			return
		}
		if !ok {
			what := a.Verb + " " + a.Resource
			if a.Subresource != "" {
				what += "/" + a.Subresource
			}
			r.Missing = append(r.Missing, what)
		}
	}
	r.CanCreateAccount = true
	for _, a := range accountChecks {
		if ok, err := can(a); err != nil || !ok {
			r.CanCreateAccount = false
			break
		}
	}
	switch {
	case len(r.Missing) > 0:
		r.add(Step{Name: name, Status: Warn, Detail: "can't " + strings.Join(r.Missing, ", "),
			Hint: "The checks that need these are skipped. Use credentials with read access to the whole cluster for full coverage."})
	case r.CanCreateAccount:
		r.add(Step{Name: name, Status: Pass, Detail: "can read everything k0s-monitor needs; can also create its read-only account"})
	default:
		r.add(Step{Name: name, Status: Pass, Detail: "can read everything k0s-monitor needs"})
	}
}

func (r *Report) layoutStep(ctx context.Context, cs kubernetes.Interface, o Options) {
	sctx, cancel := context.WithTimeout(ctx, o.StepTimeout)
	defer cancel()
	nodes, err := cs.CoreV1().Nodes().List(sctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	r.Nodes = len(nodes.Items)
	if o.ExpectedNodes == 0 {
		return
	}
	const name = "Compare with k0sctl.yaml"
	if r.Nodes < o.ExpectedNodes {
		r.add(Step{Name: name, Status: Warn, Detail: fmt.Sprintf("k0sctl.yaml lists %d nodes that run workloads, the cluster has %d", o.ExpectedNodes, r.Nodes),
			Hint: "A node may not have joined, or was removed. The Overview shows which nodes are there."})
		return
	}
	r.add(Step{Name: name, Status: Pass, Detail: fmt.Sprintf("%d nodes, as expected", r.Nodes)})
}

func asConnError(err error, server, proxy string) *cluster.ConnError {
	var ce *cluster.ConnError
	if errors.As(err, &ce) {
		return ce
	}
	return cluster.Classify(err, server, proxy)
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
