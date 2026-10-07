package snapshot

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KindControlPlane marks that each controller was asked directly: its API
// server's readyz and livez checks, its certificate, and the etcd size.
const KindControlPlane Kind = "controlplane"

// DefaultEtcdQuota is etcd's default database quota, which k0s keeps unless
// its configuration sets quota-backend-bytes.
const DefaultEtcdQuota = 2 << 30

// ControlPlane is what k0s-monitor learned by asking each controller.
type ControlPlane struct {
	At time.Time
	// Server is the host of the kubeconfig's address: what clients use.
	Server      string
	Controllers []*Controller
	// EtcdDBBytes is the size of the etcd database file the API server
	// reports, or Missing.
	EtcdDBBytes    float64
	EtcdQuotaBytes float64
	// Objects are the resources with the most stored objects, most first.
	Objects []ObjectCount
	// ClientCertNotAfter is when k0s-monitor's own client certificate
	// expires, when its kubeconfig uses one (a read-only account uses a
	// token instead).
	ClientCertNotAfter *time.Time
	// Plans are k0s's Autopilot plans: its updates, node by node.
	Plans []*Plan
	// Charts are the Helm add-ons k0s installs; ChartsRead says they could
	// be read (none may be configured).
	Charts     []Chart
	ChartsRead bool
	// Config is k0s's ClusterConfig object, which it keeps only with
	// dynamic configuration; else nil.
	Config *ClusterConfig
}

// Fallback says that k0s-monitor reads the cluster through another
// controller because the kubeconfig's server doesn't answer.
type Fallback struct {
	// Server is the kubeconfig's server (host:port), Error why it isn't
	// used.
	Server, Error string
	// Controller and Address name the controller used instead.
	Controller, Address string
	// ServerIsController says that Server is one controller's own address
	// rather than a shared one (a load balancer or a DNS name).
	ServerIsController bool
	Since              time.Time
}

// ObjectCount is how many objects of a resource etcd holds.
type ObjectCount struct {
	Resource string
	Count    float64
}

// Controller is one k0s controller as k0s-monitor sees it.
type Controller struct {
	// Name is the controller's host name, when k0s names it (ControlNode
	// or lease); controllers known only by address have none.
	Name    string
	Address string // host:port that was asked
	// From says where the controller was found: controlnode, lease,
	// endpoints (the kubernetes Service) or kubeconfig.
	From []string
	// Reached is true when its API server answered.
	Reached bool
	// Error says why it wasn't asked or didn't answer.
	Error string
	// Failing are the readyz checks that fail; LiveFailing the livez ones.
	Failing     []Check
	LiveFailing []Check
	// FailingSince is when its checks started failing, as far as
	// k0s-monitor saw; zero when unknown.
	FailingSince time.Time
	// Version is the API server's version, K0sVersion k0s's own.
	Version    string
	K0sVersion string
	Cert       *Cert
	// UpdateSignal is the controller's part of a k0s update (Autopilot),
	// from its ControlNode; nil when it has none.
	UpdateSignal *UpdateSignal
}

// Check is one failing health check of an API server.
type Check struct {
	Name    string
	Message string
}

// Cert is an API server's serving certificate.
type Cert struct {
	NotBefore, NotAfter time.Time
	// Names are its DNS names and IP addresses.
	Names []string
	// CoversServer says whether it is valid for the address clients use.
	CoversServer bool
}

// Label names a controller for people: its name, else its address.
func (c *Controller) Label() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Address
}

// Host is the controller's address without the port.
func (c *Controller) Host() string {
	if i := strings.LastIndex(c.Address, ":"); i > 0 && !strings.HasSuffix(c.Address, "]") {
		return strings.Trim(c.Address[:i], "[]")
	}
	return c.Address
}

// FailingNames lists the names of the failing readyz checks.
func (c *Controller) FailingNames() []string {
	var out []string
	for _, ch := range c.Failing {
		out = append(out, ch.Name)
	}
	return out
}

// EtcdFailing says whether one of the failing readyz checks is etcd's.
func (c *Controller) EtcdFailing() bool {
	for _, ch := range c.Failing {
		if strings.HasPrefix(ch.Name, "etcd") {
			return true
		}
	}
	return false
}

// ServerIsController says whether clients use one controller's own
// address rather than a shared one (a load balancer or a DNS name): then
// the other controllers never answer at that address.
func (cp *ControlPlane) ServerIsController() bool {
	if cp == nil {
		return false
	}
	for _, c := range cp.Controllers {
		if c.Host() == cp.Server {
			return true
		}
	}
	return false
}

// Controller returns a controller by name.
func (cp *ControlPlane) Controller(name string) *Controller {
	if cp == nil {
		return nil
	}
	for _, c := range cp.Controllers {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Controller leases

// ControllerLease is the lease a k0s controller keeps while it runs, when
// several controllers can run (k0s-ctrl-<node> in kube-node-lease). k0s
// releases it when the controller stops and never deletes it, so a removed
// controller's lease stays behind, not held.
type ControllerLease struct {
	Name    string
	Held    bool
	Renewed time.Time
	Alive   bool
}

// ControllerLeasePrefix starts the name of every controller lease.
const ControllerLeasePrefix = "k0s-ctrl-"

// ControllerLeases returns the controllers' leases, by name. A lease is
// alive when it is held and was renewed within its duration, as k0s itself
// counts controllers.
func (s *Snapshot) ControllerLeases() []ControllerLease {
	var out []ControllerLease
	for _, l := range s.Leases {
		if l.Namespace != "kube-node-lease" || !strings.HasPrefix(l.Name, ControllerLeasePrefix) {
			continue
		}
		cl := ControllerLease{Name: strings.TrimPrefix(l.Name, ControllerLeasePrefix)}
		cl.Held = l.Spec.HolderIdentity != nil && *l.Spec.HolderIdentity != ""
		if l.Spec.RenewTime != nil {
			cl.Renewed = l.Spec.RenewTime.Time
		} else if l.Spec.AcquireTime != nil {
			cl.Renewed = l.Spec.AcquireTime.Time
		}
		dur := 15 * time.Second
		if l.Spec.LeaseDurationSeconds != nil {
			dur = time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second
		}
		cl.Alive = cl.Held && !cl.Renewed.IsZero() && cl.Renewed.Add(dur).After(s.Now)
		out = append(out, cl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------------------------------------------------------------------
// Fixtures

// controlPlaneDoc is a ControlPlane fixture: what asking each controller
// would have answered.
//
//	apiVersion: k0s-monitor.io/v1
//	kind: ControlPlane
//	server: 10.0.0.1
//	etcdDB: 1.8Gi
//	controllers:
//	- {name: ctrl-1, address: "10.0.0.1:6443", failing: [etcd], certExpiresIn: 20d}
type controlPlaneDoc struct {
	Server      string          `json:"server"`
	EtcdDB      num             `json:"etcdDB"`
	EtcdQuota   num             `json:"etcdQuota"`
	Objects     map[string]num  `json:"objects"`
	ClientCert  string          `json:"clientCertExpiresIn"`
	Controllers []controllerDoc `json:"controllers"`
	// ExpectedK0s is the k0s version set for the cluster.
	ExpectedK0s *ExpectedK0s `json:"expectedK0s"`
	// Fallback: k0s-monitor connects to another controller, since this
	// long ("10m") ago.
	Fallback *struct {
		Server, Error, Controller, Address string
		ServerIsController                 bool   `json:"serverIsController"`
		Since                              string `json:"since"`
	} `json:"fallback"`
}

type controllerDoc struct {
	Name, Address, Error, Version string
	K0sVersion                    string   `json:"k0sVersion"`
	From                          []string `json:"from"`
	Unreached                     bool     `json:"unreached"`
	Failing                       []string `json:"failing"`
	LiveFailing                   []string `json:"liveFailing"`
	CertExpiresIn                 string   `json:"certExpiresIn"`
	CertNames                     []string `json:"certNames"`
	NotCoveringServer             bool     `json:"notCoveringServer"`
	// UpdateStatus is its signal status in an Autopilot update, like
	// FailedDownload; UpdateURL where it downloads from.
	UpdateStatus string `json:"updateStatus"`
	UpdateURL    string `json:"updateURL"`
}

// parseDays reads "20d", "36h" or a Go duration.
func parseDays(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		var n float64
		if _, err := fmt.Sscan(d, &n); err != nil {
			return 0, err
		}
		return time.Duration(n * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// parseControlPlaneDoc reads a ControlPlane fixture into s.
func parseControlPlaneDoc(js []byte, now time.Time, s *Snapshot) error {
	var doc controlPlaneDoc
	dec := json.NewDecoder(strings.NewReader(string(js)))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	delete(raw, "apiVersion")
	delete(raw, "kind")
	b, _ := json.Marshal(raw)
	strict := json.NewDecoder(strings.NewReader(string(b)))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&doc); err != nil {
		return err
	}
	var fb *Fallback
	if f := doc.Fallback; f != nil {
		ago, err := parseDays(f.Since)
		if err != nil {
			return fmt.Errorf("fallback.since: %w", err)
		}
		fb = &Fallback{Server: f.Server, Error: f.Error, Controller: f.Controller, Address: f.Address,
			ServerIsController: f.ServerIsController, Since: now.Add(-ago)}
	}
	cp := &ControlPlane{At: now, Server: doc.Server, EtcdDBBytes: Missing, EtcdQuotaBytes: DefaultEtcdQuota}
	if doc.EtcdDB.set {
		cp.EtcdDBBytes = doc.EtcdDB.v
	}
	if doc.EtcdQuota.set {
		cp.EtcdQuotaBytes = doc.EtcdQuota.v
	}
	for r, n := range doc.Objects {
		cp.Objects = append(cp.Objects, ObjectCount{Resource: r, Count: n.v})
	}
	sort.Slice(cp.Objects, func(i, j int) bool { return cp.Objects[i].Count > cp.Objects[j].Count })
	if doc.ClientCert != "" {
		d, err := parseDays(doc.ClientCert)
		if err != nil {
			return fmt.Errorf("clientCertExpiresIn: %w", err)
		}
		t := now.Add(d)
		cp.ClientCertNotAfter = &t
	}
	for _, c := range doc.Controllers {
		ctl := &Controller{Name: c.Name, Address: c.Address, From: c.From, Reached: !c.Unreached, Error: c.Error,
			Version: c.Version, K0sVersion: c.K0sVersion}
		if c.UpdateStatus != "" {
			ctl.UpdateSignal = &UpdateSignal{Status: c.UpdateStatus, URL: c.UpdateURL}
		}
		if ctl.Address == "" {
			ctl.Address = c.Name + ":6443"
		}
		if len(ctl.From) == 0 {
			ctl.From = []string{"controlnode"}
		}
		for _, f := range c.Failing {
			ctl.Failing = append(ctl.Failing, Check{Name: f, Message: "failed"})
		}
		for _, f := range c.LiveFailing {
			ctl.LiveFailing = append(ctl.LiveFailing, Check{Name: f, Message: "failed"})
		}
		if !c.Unreached {
			in := 300 * 24 * time.Hour
			if c.CertExpiresIn != "" {
				d, err := parseDays(c.CertExpiresIn)
				if err != nil {
					return fmt.Errorf("certExpiresIn of %s: %w", c.Name, err)
				}
				in = d
			}
			names := c.CertNames
			if len(names) == 0 {
				names = []string{"kubernetes", "kubernetes.default.svc", ctl.Host()}
			}
			ctl.Cert = &Cert{NotBefore: now.Add(in - 365*24*time.Hour), NotAfter: now.Add(in), Names: names, CoversServer: !c.NotCoveringServer}
		}
		cp.Controllers = append(cp.Controllers, ctl)
	}
	s.ControlPlane, s.Fallback, s.ExpectedK0s = cp, fb, doc.ExpectedK0s
	return nil
}
