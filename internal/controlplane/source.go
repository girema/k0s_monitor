// Package controlplane asks each k0s controller directly how it is: its API
// server's readyz and livez checks, its serving certificate, and the etcd
// database size. Controllers are found from k0s's ControlNode objects, the
// kubernetes Service's endpoints and the kubeconfig's address; their leases
// come with the snapshot.
package controlplane

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/snapshot"
)

// metricsEvery is how often the etcd size is read: /metrics is large.
const metricsEvery = 5 * time.Minute

// askTimeout bounds the questions to one controller.
const askTimeout = 8 * time.Second

// Source keeps a cluster's control-plane view fresh.
type Source struct {
	conn *cluster.Conn
	now  func() time.Time

	mu        sync.Mutex
	latest    *snapshot.ControlPlane
	metricsAt time.Time
	dbBytes   float64
	objects   []snapshot.ObjectCount
	// failing is when each controller's checks started failing.
	failing map[string]time.Time
}

// NewSource asks the cluster behind conn.
func NewSource(conn *cluster.Conn, now func() time.Time) *Source {
	return &Source{conn: conn, now: now, dbBytes: snapshot.Missing, failing: map[string]time.Time{}}
}

// Latest returns the last view, or nil.
func (s *Source) Latest() *snapshot.ControlPlane {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

// candidate is a controller to ask.
type candidate struct {
	name, host, port string
	from             []string
	k0sVersion       string
	signal           *snapshot.UpdateSignal
}

// Update asks every controller once. The nodes name controllers that
// also run a worker, when k0s's ControlNodes don't.
func (s *Source) Update(ctx context.Context, nodes []*corev1.Node) {
	if s.conn == nil || s.conn.Config == nil {
		return // a client made for tests: nothing to dial
	}
	rc := s.conn.Config
	// While k0s-monitor uses another controller, the kubeconfig's server is
	// still the address clients use.
	server := rc.Host
	if s.conn.Fallback != nil {
		server = s.conn.Fallback.Server
	}
	u, err := url.Parse(server)
	if err != nil {
		return
	}
	serverHost, serverPort := u.Hostname(), u.Port()
	if serverPort == "" {
		serverPort = "443"
	}
	cp := &snapshot.ControlPlane{At: s.now(), Server: serverHost, EtcdDBBytes: snapshot.Missing, EtcdQuotaBytes: snapshot.DefaultEtcdQuota}
	cp.ClientCertNotAfter = clientCertExpiry(rc)

	cands := s.discover(ctx, serverHost, serverPort)
	nameByNode(cands, nodes)
	cp.Plans = s.plans(ctx)
	cp.Charts, cp.ChartsRead = s.charts(ctx)
	cp.Config = s.clusterConfig(ctx)
	out := make([]*snapshot.Controller, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			actx, cancel := context.WithTimeout(ctx, askTimeout)
			defer cancel()
			out[i] = s.ask(actx, rc, c, serverHost)
		}()
	}
	wg.Wait()
	cp.Controllers = out

	s.mu.Lock()
	due := s.now().Sub(s.metricsAt) >= metricsEvery
	s.mu.Unlock()
	if due {
		db, objs, err := s.storageMetrics(ctx)
		s.mu.Lock()
		s.metricsAt = s.now()
		if err == nil {
			s.dbBytes, s.objects = db, objs
		}
		s.mu.Unlock()
	}
	s.remember(cp)
}

// remember keeps a new view, with the last etcd size and when each
// controller started failing.
func (s *Source) remember(cp *snapshot.ControlPlane) {
	s.mu.Lock()
	cp.EtcdDBBytes, cp.Objects = s.dbBytes, s.objects
	seen := map[string]bool{}
	for _, c := range cp.Controllers {
		if len(c.Failing) == 0 && len(c.LiveFailing) == 0 {
			continue
		}
		seen[c.Address] = true
		if _, ok := s.failing[c.Address]; !ok {
			s.failing[c.Address] = cp.At
		}
		c.FailingSince = s.failing[c.Address]
	}
	for a := range s.failing {
		if !seen[a] {
			delete(s.failing, a)
		}
	}
	s.latest = cp
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Finding the controllers

type controlNodeList struct {
	Items []struct {
		Metadata metav1.ObjectMeta `json:"metadata"`
		Status   struct {
			Addresses []struct {
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"addresses"`
			K0sVersion string `json:"k0sVersion"`
		} `json:"status"`
	} `json:"items"`
}

// discover merges what names the controllers: k0s's ControlNodes (each
// controller's own address and k0s version), the kubernetes Service's
// endpoints (the API servers, unless k0s points them at a load balancer)
// and the kubeconfig's address.
func (s *Source) discover(ctx context.Context, serverHost, serverPort string) []candidate {
	var cands []candidate
	byHost := map[string]int{}
	add := func(c candidate) {
		if i, ok := byHost[c.host]; ok {
			for _, f := range c.from {
				if !contains(cands[i].from, f) {
					cands[i].from = append(cands[i].from, f)
				}
			}
			if cands[i].name == "" {
				cands[i].name = c.name
			}
			return
		}
		byHost[c.host] = len(cands)
		cands = append(cands, c)
	}

	// The API port: the endpoints know it; else the kubeconfig's.
	apiPort := ""
	var endpointHosts []string
	slices, err := s.conn.Client.DiscoveryV1().EndpointSlices("default").List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=kubernetes"})
	if err == nil {
		for _, sl := range slices.Items {
			for _, p := range sl.Ports {
				if p.Port != nil && apiPort == "" {
					apiPort = strconv.Itoa(int(*p.Port))
				}
			}
			for _, ep := range sl.Endpoints {
				endpointHosts = append(endpointHosts, ep.Addresses...)
			}
		}
	}
	if apiPort == "" {
		apiPort = serverPort
	}

	if rcl := s.conn.Client.Discovery().RESTClient(); rcl != nil {
		raw, err := rcl.Get().AbsPath("/apis/autopilot.k0sproject.io/v1beta2/controlnodes").Do(ctx).Raw()
		var list controlNodeList
		if err == nil && json.Unmarshal(raw, &list) == nil {
			for _, it := range list.Items {
				host := ""
				for _, want := range []string{"InternalIP", "ExternalIP", "Hostname"} {
					for _, a := range it.Status.Addresses {
						if a.Type == want && host == "" {
							host = a.Address
						}
					}
				}
				if host == "" {
					continue
				}
				c := candidate{name: it.Metadata.Name, host: host, port: apiPort, from: []string{"controlnode"}, k0sVersion: it.Status.K0sVersion}
				if sig, ok := snapshot.ParseUpdateSignal(it.Metadata.Annotations); ok {
					c.signal = &sig
				}
				add(c)
			}
		}
	}
	for _, h := range endpointHosts {
		add(candidate{host: h, port: apiPort, from: []string{"endpoints"}})
	}
	// The kubeconfig's address is a controller when it is one of these;
	// otherwise it is a load balancer or a name, and only asked when
	// nothing else is known.
	if i, ok := byHost[serverHost]; ok {
		cands[i].from = append(cands[i].from, "kubeconfig")
		cands[i].port = serverPort
	} else if len(cands) == 0 {
		add(candidate{host: serverHost, port: serverPort, from: []string{"kubeconfig"}})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].name != cands[j].name {
			return cands[i].name < cands[j].name
		}
		return cands[i].host < cands[j].host
	})
	return cands
}

// plans reads k0s's Autopilot plans; none when Autopilot isn't there.
func (s *Source) plans(ctx context.Context) []*snapshot.Plan {
	rcl := s.conn.Client.Discovery().RESTClient()
	if rcl == nil {
		return nil
	}
	raw, err := rcl.Get().AbsPath("/apis/autopilot.k0sproject.io/v1beta2/plans").Do(ctx).Raw()
	if err != nil {
		return nil
	}
	ps, err := snapshot.ParsePlans(raw)
	if err != nil {
		return nil
	}
	return ps
}

// charts reads the Helm add-ons k0s installs (Chart objects). ok is false
// when they can't be read.
func (s *Source) charts(ctx context.Context) (cs []snapshot.Chart, ok bool) {
	rcl := s.conn.Client.Discovery().RESTClient()
	if rcl == nil {
		return nil, false
	}
	raw, err := rcl.Get().AbsPath("/apis/helm.k0sproject.io/v1beta1/charts").Do(ctx).Raw()
	if err != nil {
		return nil, false
	}
	cs, err = snapshot.ParseCharts(raw)
	return cs, err == nil
}

// clusterConfig reads k0s's ClusterConfig object, which exists only when
// k0s runs with dynamic configuration (--enable-dynamic-config).
func (s *Source) clusterConfig(ctx context.Context) *snapshot.ClusterConfig {
	rcl := s.conn.Client.Discovery().RESTClient()
	if rcl == nil {
		return nil
	}
	raw, err := rcl.Get().AbsPath("/apis/k0s.k0sproject.io/v1beta1/namespaces/kube-system/clusterconfigs/k0s").Do(ctx).Raw()
	if err != nil {
		return nil
	}
	c, err := snapshot.ParseClusterConfig(raw, "the cluster (dynamic configuration)")
	if err != nil {
		return nil
	}
	return c
}

// nameByNode names the controllers known only by address after the node
// with that address: a controller that also runs a worker (--enable-worker
// or --single) is a node of the same name.
func nameByNode(cands []candidate, nodes []*corev1.Node) {
	for i := range cands {
		if cands[i].name != "" {
			continue
		}
		for _, n := range nodes {
			for _, a := range n.Status.Addresses {
				if a.Address == cands[i].host && cands[i].name == "" {
					cands[i].name = n.Name
				}
			}
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Asking one controller

// ask checks a controller's certificate first, without sending the
// cluster's credentials; only an API server certificate of the cluster's
// CA gets them.
func (s *Source) ask(ctx context.Context, rc *rest.Config, c candidate, serverHost string) *snapshot.Controller {
	addr := net.JoinHostPort(c.host, c.port)
	ctl := &snapshot.Controller{Name: c.name, Address: addr, From: c.from, K0sVersion: c.k0sVersion, UpdateSignal: c.signal}
	leaf, chainErr, err := certificate(ctx, rc, addr)
	if err != nil {
		ctl.Error = fmt.Sprintf("k0s-monitor can't reach %s from this host: %s", addr, shortErr(err))
		return ctl
	}
	ctl.Cert = &snapshot.Cert{NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Names: certNames(leaf),
		CoversServer: leaf.VerifyHostname(serverHost) == nil}
	if chainErr != nil && !rc.Insecure {
		ctl.Error = "its certificate isn't signed by the cluster's certificate authority, so k0s-monitor doesn't send it the cluster's credentials: " + shortErr(chainErr)
		return ctl
	}
	serverName := ""
	for _, n := range []string{serverHost, c.host, "kubernetes.default.svc", "kubernetes"} {
		if leaf.VerifyHostname(n) == nil {
			serverName = n
			break
		}
	}
	if serverName == "" && !rc.Insecure {
		ctl.Error = "its certificate is not an API server's (names: " + strings.Join(ctl.Cert.Names, ", ") + ")"
		return ctl
	}
	cfg := rest.CopyConfig(rc)
	cfg.Host = "https://" + addr
	cfg.TLSClientConfig.ServerName = serverName
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		ctl.Error = err.Error()
		return ctl
	}
	defer hc.CloseIdleConnections()

	failing, err := health(ctx, hc, cfg.Host+"/readyz?verbose")
	if err != nil {
		ctl.Error = err.Error()
		return ctl
	}
	ctl.Reached, ctl.Failing = true, failing
	if live, err := health(ctx, hc, cfg.Host+"/livez?verbose"); err == nil {
		ctl.LiveFailing = live
	}
	if v, err := get(ctx, hc, cfg.Host+"/version"); err == nil {
		var info struct {
			GitVersion string `json:"gitVersion"`
		}
		if json.Unmarshal(v, &info) == nil {
			ctl.Version = info.GitVersion
		}
	}
	return ctl
}

// certificate reads a server's certificate without trusting it yet, and
// says whether it chains to the cluster's CA. No credentials are sent.
func certificate(ctx context.Context, rc *rest.Config, addr string) (*x509.Certificate, error, error) {
	tr := &http.Transport{
		Proxy:               rc.Proxy,
		DialContext:         rc.Dial,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // verified below, before any credentials are sent
		TLSHandshakeTimeout: 5 * time.Second,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/healthz", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, nil, errors.New("no certificate")
	}
	leaf := resp.TLS.PeerCertificates[0]
	opts := x509.VerifyOptions{Intermediates: x509.NewCertPool()}
	for _, c := range resp.TLS.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}
	if tc, err := rest.TLSConfigFor(rc); err == nil && tc != nil {
		opts.Roots = tc.RootCAs
	}
	_, chainErr := leaf.Verify(opts)
	return leaf, chainErr, nil
}

func certNames(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// health reads a verbose readyz or livez answer and returns the failing
// checks. The answer is 200 when all pass and 500 when one fails, with the
// same list of lines:
//
//	[+]ping ok
//	[-]etcd failed: reason withheld
func health(ctx context.Context, hc *http.Client, u string) ([]snapshot.Check, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("it doesn't answer: %s", shortErr(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusInternalServerError:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("k0s-monitor's account may not read its health checks (HTTP %d)", resp.StatusCode)
	default:
		return nil, fmt.Errorf("it answers HTTP %d", resp.StatusCode)
	}
	var failing []snapshot.Check
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "[-]")
		if !ok {
			continue
		}
		name, msg, _ := strings.Cut(rest, " ")
		msg = strings.TrimPrefix(msg, "failed: ")
		if msg == "failed" {
			msg = ""
		}
		failing = append(failing, snapshot.Check{Name: name, Message: msg})
	}
	if resp.StatusCode == http.StatusInternalServerError && len(failing) == 0 {
		failing = append(failing, snapshot.Check{Name: "readyz", Message: strings.TrimSpace(string(body))})
	}
	return failing, nil
}

func get(ctx context.Context, hc *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// ---------------------------------------------------------------------------
// etcd size and objects

// storageMetrics reads the etcd database size and the object counts from
// the API server's metrics. The families come sorted by name, so reading
// stops after the apiserver_storage ones.
func (s *Source) storageMetrics(ctx context.Context) (float64, []snapshot.ObjectCount, error) {
	rcl := s.conn.Client.Discovery().RESTClient()
	if rcl == nil {
		return snapshot.Missing, nil, errors.New("no REST client")
	}
	mctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, err := rcl.Get().AbsPath("/metrics").Stream(mctx)
	if err != nil {
		return snapshot.Missing, nil, err
	}
	defer body.Close()
	db, objs := parseStorageMetrics(body)
	return db, objs, nil
}

// parseStorageMetrics finds the etcd database size (the largest reported)
// and the ten resources with the most objects.
func parseStorageMetrics(r io.Reader) (float64, []snapshot.ObjectCount) {
	db := snapshot.Missing
	counts := map[string]float64{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	seen := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, value, ok := splitSample(line)
		if !ok {
			continue
		}
		if seen && name > "apiserver_storage_~" {
			break
		}
		switch name {
		case "apiserver_storage_size_bytes", "apiserver_storage_db_total_size_in_bytes":
			seen = true
			if !snapshot.Known(db) || value > db {
				db = value
			}
		case "apiserver_storage_objects", "apiserver_resource_objects":
			seen = true
			res := label(labels, "resource")
			if g := label(labels, "group"); g != "" {
				res += "." + g
			}
			if res != "" && value > counts[res] {
				counts[res] = value
			}
		}
	}
	var objs []snapshot.ObjectCount
	for r, n := range counts {
		objs = append(objs, snapshot.ObjectCount{Resource: r, Count: n})
	}
	sort.Slice(objs, func(i, j int) bool {
		if objs[i].Count != objs[j].Count {
			return objs[i].Count > objs[j].Count
		}
		return objs[i].Resource < objs[j].Resource
	})
	if len(objs) > 10 {
		objs = objs[:10]
	}
	return db, objs
}

// splitSample splits `name{labels} value` into its parts.
func splitSample(line string) (name, labels string, value float64, ok bool) {
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		return "", "", 0, false
	}
	name = line[:i]
	rest := line[i:]
	if strings.HasPrefix(rest, "{") {
		j := strings.LastIndex(rest, "}")
		if j < 0 {
			return "", "", 0, false
		}
		labels, rest = rest[1:j], rest[j+1:]
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return "", "", 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return name, labels, v, err == nil
}

func label(labels, key string) string {
	for _, part := range strings.Split(labels, ",") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------

// clientCertExpiry is when the kubeconfig's client certificate expires,
// when it uses one.
func clientCertExpiry(rc *rest.Config) *time.Time {
	data := rc.TLSClientConfig.CertData
	if len(data) == 0 && rc.TLSClientConfig.CertFile != "" {
		b, err := os.ReadFile(rc.TLSClientConfig.CertFile)
		if err != nil {
			return nil
		}
		data = b
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return &c.NotAfter
}

// shortErr keeps the part of a network error people can act on.
func shortErr(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "no answer (timeout)"
	case strings.Contains(err.Error(), "connection refused"):
		return "connection refused"
	case strings.Contains(err.Error(), "no route to host"):
		return "no route to host"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}
