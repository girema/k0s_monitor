// Package config loads the k0s-monitor configuration file.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// MaxClusters is the number of clusters one instance is sized for.
const MaxClusters = 5

// Config is the top-level configuration.
type Config struct {
	Clusters   []Cluster  `json:"clusters"`
	Thresholds Thresholds `json:"thresholds"`
	Scan       Scan       `json:"scan"`

	// The settings below are used by `k0s-monitor serve` only.

	// Listen is the address of the web UI, for example 0.0.0.0:8443.
	Listen string `json:"listen,omitempty"`
	TLS    TLS    `json:"tls,omitempty"`
	// AllowFrom limits which client addresses may open the UI. Entries are
	// IP addresses or CIDR ranges. Empty allows everyone.
	AllowFrom []string `json:"allowFrom,omitempty"`
	UI        UI       `json:"ui,omitempty"`
	Auth      Auth     `json:"auth,omitempty"`
	// MetricsTokenFile names a file holding a token that lets a Prometheus
	// read /metrics without signing in, sent as "Authorization: Bearer
	// <token>". Without it, /metrics needs a signed-in session.
	MetricsTokenFile string `json:"metricsTokenFile,omitempty"`
	// DataDir holds the database with history and uploaded clusters.
	DataDir string `json:"dataDir,omitempty"`
	// PacksDir holds product packs (*.yaml). The default is the packs
	// directory next to the configuration file.
	PacksDir string `json:"packsDir,omitempty"`
}

// TLS names the certificate the web UI uses.
type TLS struct {
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

// UI holds presentation defaults.
type UI struct {
	// DefaultMode is basic (the default) or full.
	DefaultMode string `json:"defaultMode,omitempty"`
	// Notify lists the priorities that notify: fix-now, fix-today,
	// plan-ahead, suggestions. The default is fix-now and fix-today.
	Notify []string `json:"notify,omitempty"`
}

// Auth configures sign-in.
type Auth struct {
	// SessionIdle ends a session after this long without activity.
	SessionIdle Duration `json:"sessionIdle,omitempty"`
	// SessionMax ends a session this long after sign-in, even while it is
	// used.
	SessionMax Duration `json:"sessionMax,omitempty"`
}

// Cluster describes how to reach one cluster.
type Cluster struct {
	// Name identifies the cluster in the UI and in findings.
	Name string `json:"name"`
	// Kubeconfig is the path of the kubeconfig file (for example the
	// product's cluster.config). Relative paths are resolved against the
	// directory of the config file.
	Kubeconfig string `json:"kubeconfig"`
	// Context selects a kubeconfig context. Empty means the current one.
	Context string `json:"context,omitempty"`
	// Proxy is an optional http://, https:// or socks5:// proxy URL. It
	// overrides proxy-url from the kubeconfig.
	Proxy string `json:"proxy,omitempty"`
	// Criticality raises (high) or lowers (low) the priority of every
	// finding in this cluster.
	Criticality string `json:"criticality,omitempty"`
	// Server replaces the API server address of the kubeconfig, for
	// example when the kubeconfig says https://localhost:6443.
	Server string `json:"server,omitempty"`
	// Prometheus overrides where metrics come from. By default k0s-monitor
	// finds Prometheus in the cluster and reads it through the API server.
	Prometheus *Prometheus `json:"prometheus,omitempty"`
	// K0sVersion is the k0s version the product ships for this cluster,
	// like v1.36.4+k0s.1: nodes that run another are reported. Empty
	// expects the version most controllers run.
	K0sVersion string `json:"k0sVersion,omitempty"`
	// K0sVersionFrom says where K0sVersion came from for a cluster added
	// in the UI: its k0sctl.yaml, or set in k0s-monitor.
	K0sVersionFrom string `json:"-"`
	// ReadTLSSecrets set to false keeps k0s-monitor from reading the
	// certificates in TLS Secrets, even when its account may. By default
	// it reads them when allowed.
	ReadTLSSecrets *bool `json:"readTLSSecrets,omitempty"`

	// ServerName is the name the API server's certificate must be valid
	// for, when not Server's host: k0s-monitor sets it to reach another
	// controller by its own address when the kubeconfig's server doesn't
	// answer. Never read from the configuration file.
	ServerName string `json:"-"`

	// KubeconfigData holds the kubeconfig of a cluster added in the UI. It
	// is never written to the configuration file.
	KubeconfigData []byte `json:"-"`
	// FromUI marks clusters added in the UI (as opposed to the file).
	FromUI bool `json:"-"`
}

// TLSSecretsOn reports whether the certificates in TLS Secrets are read
// when the account may.
func (c Cluster) TLSSecretsOn() bool { return c.ReadTLSSecrets == nil || *c.ReadTLSSecrets }

// Prometheus says where a cluster's metrics come from.
type Prometheus struct {
	// Disabled turns metrics off for the cluster.
	Disabled bool `json:"disabled,omitempty"`
	// Service is the Prometheus or VictoriaMetrics Service as
	// namespace/name:port, read through the API server's service proxy. A
	// path may follow, for example vm/vmselect-main:8481/select/0/prometheus.
	Service string `json:"service,omitempty"`
	// URL is a Prometheus outside the cluster, for example
	// https://prometheus.example.com. The other fields are its credentials.
	URL             string `json:"url,omitempty"`
	Username        string `json:"username,omitempty"`
	PasswordFile    string `json:"passwordFile,omitempty"`
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	CAFile          string `json:"caFile,omitempty"`
}

// ServiceParts splits Service into namespace, name and port.
func (p *Prometheus) ServiceParts() (ns, name, port string, ok bool) {
	nsName, rest, found := strings.Cut(p.Service, ":")
	port, _, _ = strings.Cut(rest, "/")
	ns, name, ok = strings.Cut(nsName, "/")
	if !found || !ok || ns == "" || name == "" || port == "" {
		return "", "", "", false
	}
	return ns, name, port, true
}

// ServicePath is the path after the port in Service, if any.
func (p *Prometheus) ServicePath() string {
	_, rest, _ := strings.Cut(p.Service, ":")
	_, path, _ := strings.Cut(rest, "/")
	return strings.Trim(path, "/")
}

// Thresholds tune when conditions become findings.
type Thresholds struct {
	PendingAfter               Duration `json:"pendingAfter"`
	PVCPendingAfter            Duration `json:"pvcPendingAfter"`
	CrashLoopRestarts          int32    `json:"crashLoopRestarts"`
	CrashLoopWindow            Duration `json:"crashLoopWindow"`
	OOMWindow                  Duration `json:"oomWindow"`
	DeploymentUnavailableAfter Duration `json:"deploymentUnavailableAfter"`
	ContainerCreatingAfter     Duration `json:"containerCreatingAfter"`
	TerminatingAfter           Duration `json:"terminatingAfter"`
	NotReadyAfter              Duration `json:"notReadyAfter"`
	CordonedAfter              Duration `json:"cordonedAfter"`
	LBPendingAfter             Duration `json:"lbPendingAfter"`
	NamespaceTerminatingAfter  Duration `json:"namespaceTerminatingAfter"`
	// UpdateStuckAfter is how long a node may take in a k0s update
	// (Autopilot) before it counts as stuck.
	UpdateStuckAfter Duration `json:"updateStuckAfter"`
	// FinishedPodsAfter is how long finished and evicted pods may stay
	// before they are suggested for removal.
	FinishedPodsAfter Duration `json:"finishedPodsAfter"`

	// Levels for metrics from Prometheus (plan section 9). Percentages
	// are 0 to 100.
	VolumeUsedPercent      Levels         `json:"volumeUsedPercent"`
	VolumeFullWithin       DurationLevels `json:"volumeFullWithin"`
	NodeDiskPercent        Levels         `json:"nodeDiskPercent"`
	HostDiskPercent        Levels         `json:"hostDiskPercent"`
	InodesPercent          Levels         `json:"inodesPercent"`
	NodeSaturationPercent  Levels         `json:"nodeSaturationPercent"`
	CPUStealPercent        Levels         `json:"cpuStealPercent"`
	IOWaitPercent          Levels         `json:"iowaitPercent"`
	DiskLatency            DurationLevels `json:"diskLatency"`
	ClockSkew              DurationLevels `json:"clockSkew"`
	ContainerMemoryPercent Levels         `json:"containerMemoryPercent"`
	CPUThrottledPercent    Levels         `json:"cpuThrottledPercent"`
	HPAMaxedAfter          Duration       `json:"hpaMaxedAfter"`

	// Control plane (plan section 7.6).
	CertExpiresWithin DurationLevels `json:"certExpiresWithin"`
	// AppCertExpiresWithin is for the certificates in apps' TLS Secrets.
	AppCertExpiresWithin DurationLevels `json:"appCertExpiresWithin"`
	EtcdQuotaPercent     Levels         `json:"etcdQuotaPercent"`
}

// Levels are thresholds that raise the severity step by step: warn is
// Medium, high is High and critical is Critical. Zero turns a level off.
type Levels struct {
	Warn     float64 `json:"warn,omitempty"`
	High     float64 `json:"high,omitempty"`
	Critical float64 `json:"critical,omitempty"`
}

// DurationLevels are Levels for durations. For "time left" thresholds
// (volumeFullWithin), shorter is worse.
type DurationLevels struct {
	Warn     Duration `json:"warn,omitempty"`
	High     Duration `json:"high,omitempty"`
	Critical Duration `json:"critical,omitempty"`
}

// Scan tunes connection and sync timeouts.
type Scan struct {
	ConnectTimeout Duration `json:"connectTimeout"`
	SyncTimeout    Duration `json:"syncTimeout"`
}

// DefaultThresholds follow section 9 of the plan.
func DefaultThresholds() Thresholds {
	return Thresholds{
		PendingAfter:               Duration(2 * time.Minute),
		PVCPendingAfter:            Duration(2 * time.Minute),
		CrashLoopRestarts:          3,
		CrashLoopWindow:            Duration(10 * time.Minute),
		OOMWindow:                  Duration(time.Hour),
		DeploymentUnavailableAfter: Duration(2 * time.Minute),
		ContainerCreatingAfter:     Duration(5 * time.Minute),
		TerminatingAfter:           Duration(5 * time.Minute),
		NotReadyAfter:              Duration(5 * time.Minute),
		CordonedAfter:              Duration(24 * time.Hour),
		LBPendingAfter:             Duration(10 * time.Minute),
		UpdateStuckAfter:           Duration(30 * time.Minute),
		FinishedPodsAfter:          Duration(7 * 24 * time.Hour),
		NamespaceTerminatingAfter:  Duration(10 * time.Minute),

		VolumeUsedPercent:      Levels{Warn: 80, High: 90, Critical: 95},
		VolumeFullWithin:       DurationLevels{High: Duration(24 * time.Hour), Critical: Duration(6 * time.Hour)},
		NodeDiskPercent:        Levels{Warn: 80, High: 85, Critical: 90},
		HostDiskPercent:        Levels{Warn: 80, High: 90},
		InodesPercent:          Levels{Warn: 85, High: 95},
		NodeSaturationPercent:  Levels{Warn: 85, High: 95},
		CPUStealPercent:        Levels{Warn: 10, High: 25},
		IOWaitPercent:          Levels{Warn: 20, High: 40},
		DiskLatency:            DurationLevels{Warn: Duration(100 * time.Millisecond), High: Duration(500 * time.Millisecond)},
		ClockSkew:              DurationLevels{Warn: Duration(time.Second), High: Duration(5 * time.Second)},
		ContainerMemoryPercent: Levels{Warn: 90},
		CPUThrottledPercent:    Levels{Warn: 25},
		HPAMaxedAfter:          Duration(30 * time.Minute),

		CertExpiresWithin:    DurationLevels{Warn: Duration(30 * 24 * time.Hour), Critical: Duration(7 * 24 * time.Hour)},
		AppCertExpiresWithin: DurationLevels{Warn: Duration(30 * 24 * time.Hour), Critical: Duration(7 * 24 * time.Hour)},
		EtcdQuotaPercent:     Levels{High: 70, Critical: 85},
	}
}

// DefaultScan returns the default timeouts.
func DefaultScan() Scan {
	return Scan{
		ConnectTimeout: Duration(10 * time.Second),
		SyncTimeout:    Duration(60 * time.Second),
	}
}

// Default returns a configuration with defaults and no clusters.
func Default() *Config {
	return &Config{Thresholds: DefaultThresholds(), Scan: DefaultScan()}
}

// Load reads a YAML (or JSON) configuration file and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	abs := func(p string) string {
		p = expandHome(p)
		if p != "" && !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		return p
	}
	for i := range cfg.Clusters {
		cfg.Clusters[i].Kubeconfig = abs(cfg.Clusters[i].Kubeconfig)
		if p := cfg.Clusters[i].Prometheus; p != nil {
			p.PasswordFile, p.BearerTokenFile, p.CAFile = abs(p.PasswordFile), abs(p.BearerTokenFile), abs(p.CAFile)
		}
	}
	cfg.TLS.CertFile = abs(cfg.TLS.CertFile)
	cfg.TLS.KeyFile = abs(cfg.TLS.KeyFile)
	cfg.MetricsTokenFile = abs(cfg.MetricsTokenFile)
	cfg.DataDir = abs(cfg.DataDir)
	if cfg.PacksDir == "" {
		cfg.PacksDir = "packs"
	}
	cfg.PacksDir = abs(cfg.PacksDir)
	return cfg, nil
}

// Parse decodes configuration data, applies defaults and validates it.
func Parse(data []byte) (*Config, error) {
	cfg := Default()
	if err := yaml.UnmarshalStrict(data, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	d := DefaultThresholds()
	t := &c.Thresholds
	if t.PendingAfter == 0 {
		t.PendingAfter = d.PendingAfter
	}
	if t.PVCPendingAfter == 0 {
		t.PVCPendingAfter = d.PVCPendingAfter
	}
	if t.CrashLoopRestarts == 0 {
		t.CrashLoopRestarts = d.CrashLoopRestarts
	}
	if t.CrashLoopWindow == 0 {
		t.CrashLoopWindow = d.CrashLoopWindow
	}
	if t.OOMWindow == 0 {
		t.OOMWindow = d.OOMWindow
	}
	for _, p := range []struct{ v, d *Duration }{
		{&t.DeploymentUnavailableAfter, &d.DeploymentUnavailableAfter},
		{&t.ContainerCreatingAfter, &d.ContainerCreatingAfter},
		{&t.TerminatingAfter, &d.TerminatingAfter},
		{&t.NotReadyAfter, &d.NotReadyAfter},
		{&t.CordonedAfter, &d.CordonedAfter},
		{&t.LBPendingAfter, &d.LBPendingAfter},
		{&t.UpdateStuckAfter, &d.UpdateStuckAfter},
		{&t.FinishedPodsAfter, &d.FinishedPodsAfter},
		{&t.NamespaceTerminatingAfter, &d.NamespaceTerminatingAfter},
		{&t.HPAMaxedAfter, &d.HPAMaxedAfter},
	} {
		if *p.v == 0 {
			*p.v = *p.d
		}
	}
	for _, p := range []struct{ v, d *Levels }{
		{&t.VolumeUsedPercent, &d.VolumeUsedPercent}, {&t.NodeDiskPercent, &d.NodeDiskPercent},
		{&t.HostDiskPercent, &d.HostDiskPercent}, {&t.InodesPercent, &d.InodesPercent},
		{&t.NodeSaturationPercent, &d.NodeSaturationPercent}, {&t.CPUStealPercent, &d.CPUStealPercent},
		{&t.IOWaitPercent, &d.IOWaitPercent}, {&t.ContainerMemoryPercent, &d.ContainerMemoryPercent},
		{&t.CPUThrottledPercent, &d.CPUThrottledPercent}, {&t.EtcdQuotaPercent, &d.EtcdQuotaPercent},
	} {
		if *p.v == (Levels{}) {
			*p.v = *p.d
		}
	}
	for _, p := range []struct{ v, d *DurationLevels }{
		{&t.VolumeFullWithin, &d.VolumeFullWithin}, {&t.DiskLatency, &d.DiskLatency}, {&t.ClockSkew, &d.ClockSkew},
		{&t.CertExpiresWithin, &d.CertExpiresWithin}, {&t.AppCertExpiresWithin, &d.AppCertExpiresWithin},
	} {
		if *p.v == (DurationLevels{}) {
			*p.v = *p.d
		}
	}
	ds := DefaultScan()
	if c.Scan.ConnectTimeout == 0 {
		c.Scan.ConnectTimeout = ds.ConnectTimeout
	}
	if c.Scan.SyncTimeout == 0 {
		c.Scan.SyncTimeout = ds.SyncTimeout
	}
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.UI.DefaultMode == "" {
		c.UI.DefaultMode = "basic"
	}
	if len(c.UI.Notify) == 0 {
		c.UI.Notify = []string{"fix-now", "fix-today"}
	}
	if c.Auth.SessionIdle == 0 {
		c.Auth.SessionIdle = Duration(12 * time.Hour)
	}
	if c.Auth.SessionMax == 0 {
		c.Auth.SessionMax = Duration(24 * time.Hour)
	}
}

// ApplyServeDefaults fills in the serve settings of a configuration that
// was not loaded from a file, and validates it.
func ApplyServeDefaults(c *Config) error {
	c.applyDefaults()
	return c.Validate()
}

// Defaults for `k0s-monitor serve` and `init`.
const (
	DefaultListen    = "0.0.0.0:8443"
	DefaultConfigDir = "/etc/k0s-monitor"
	DefaultDataDir   = "/var/lib/k0s-monitor"
)

var clusterNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$`)

// K0sVersionRE matches a k0s version: v1.36.4+k0s.1, or v1.36.4+k0s.
var K0sVersionRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(\+k0s(\.[0-9]+)?)?$`)

// Validate checks the configuration for mistakes a user can fix.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Clusters) > MaxClusters {
		errs = append(errs, fmt.Errorf("%d clusters configured; one instance is sized for up to %d", len(c.Clusters), MaxClusters))
	}
	seen := map[string]bool{}
	for i, cl := range c.Clusters {
		where := fmt.Sprintf("clusters[%d]", i)
		if cl.Name != "" && seen[cl.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name %q", where, cl.Name))
		}
		seen[cl.Name] = true
		if err := cl.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
		}
	}
	if c.Thresholds.CrashLoopRestarts < 1 {
		errs = append(errs, errors.New("thresholds.crashLoopRestarts must be at least 1"))
	}
	for _, a := range c.AllowFrom {
		if _, err := ParseAllow(a); err != nil {
			errs = append(errs, fmt.Errorf("allowFrom: %w", err))
		}
	}
	switch c.UI.DefaultMode {
	case "", "basic", "full":
	default:
		errs = append(errs, fmt.Errorf("ui.defaultMode must be basic or full, not %q", c.UI.DefaultMode))
	}
	for _, n := range c.UI.Notify {
		switch n {
		case "fix-now", "fix-today", "plan-ahead", "suggestions":
		default:
			errs = append(errs, fmt.Errorf("ui.notify: unknown level %q (use fix-now, fix-today, plan-ahead or suggestions)", n))
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls: set both certFile and keyFile, or neither"))
	}
	return errors.Join(errs...)
}

// Validate checks one cluster entry.
func (cl Cluster) Validate() error {
	var errs []error
	if cl.Name == "" {
		errs = append(errs, errors.New("name is required"))
	} else if !clusterNameRE.MatchString(cl.Name) {
		errs = append(errs, fmt.Errorf("name %q must be lowercase letters, digits, '.', '_' or '-', at most 63 characters", cl.Name))
	}
	if cl.Kubeconfig == "" && len(cl.KubeconfigData) == 0 {
		errs = append(errs, fmt.Errorf("%s: kubeconfig is required", cl.Name))
	}
	if cl.Proxy != "" {
		u, err := url.Parse(cl.Proxy)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			errs = append(errs, fmt.Errorf("%s: proxy must be an http://, https:// or socks5:// URL", cl.Name))
		}
	}
	if cl.Server != "" {
		u, err := url.Parse(cl.Server)
		if err != nil || u.Host == "" || u.Scheme != "https" {
			errs = append(errs, fmt.Errorf("%s: server must be an https:// URL", cl.Name))
		}
	}
	if cl.K0sVersion != "" && !K0sVersionRE.MatchString(cl.K0sVersion) {
		errs = append(errs, fmt.Errorf("%s: k0sVersion must look like v1.36.4+k0s.1", cl.Name))
	}
	switch strings.ToLower(cl.Criticality) {
	case "", "normal", "high", "low":
	default:
		errs = append(errs, fmt.Errorf("%s: criticality must be high, normal or low", cl.Name))
	}
	if p := cl.Prometheus; p != nil {
		if p.Service != "" && p.URL != "" {
			errs = append(errs, fmt.Errorf("%s: prometheus: set service or url, not both", cl.Name))
		}
		if _, _, _, ok := p.ServiceParts(); p.Service != "" && !ok {
			errs = append(errs, fmt.Errorf("%s: prometheus.service must be namespace/name:port", cl.Name))
		}
		if p.URL != "" {
			u, err := url.Parse(p.URL)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				errs = append(errs, fmt.Errorf("%s: prometheus.url must be an http:// or https:// URL", cl.Name))
			}
		}
	}
	return errors.Join(errs...)
}

// ParseAllow parses an allowFrom entry: an IP address or a CIDR range.
func ParseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR range", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Cluster returns the named cluster.
func (c *Config) Cluster(name string) (Cluster, bool) {
	for _, cl := range c.Clusters {
		if cl.Name == name {
			return cl, true
		}
	}
	return Cluster{}, false
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// Duration is a time.Duration that reads and writes strings like "2m".
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if v < 0 {
		return fmt.Errorf("duration %q must not be negative", s)
	}
	*d = Duration(v)
	return nil
}
