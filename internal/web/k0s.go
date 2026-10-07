package web

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// The k0s system page: the controllers as each answered, their leases,
// the etcd database, certificates, and k0s's own parts in kube-system.

type controllerRow struct {
	Name, Address string
	From          string
	// Health of its API server.
	Health, HealthPlain string
	Icon, Mark          string
	Failing             string
	// Lease: whether k0s counts it as running.
	Lease, LeasePlain   string
	LeaseIcon           string
	Version, K0sVersion string
	Cert, CertPlain     string
	CertIcon            string
	CertNote            string
	Error               string
	Top                 *findings.Finding
	// InUse marks the controller k0s-monitor connects to.
	InUse bool
}

type k0sData struct {
	State *engine.State
	// Addons are the Helm charts k0s installs; AddonsRead says they could
	// be read. Config is its configuration, explained.
	Addons     []addonView
	AddonsRead bool
	Config     configView
	// Asked is false until the controllers were asked; NotAsked says why.
	Asked    bool
	NotAsked string
	AskedAt  time.Time
	Server   string

	Controllers []controllerRow
	// Alive of Expected controllers run, by their leases; Single when k0s
	// keeps none (one controller that others can't join).
	Alive, Expected int
	Single          bool
	Reached, Ready  int

	EtcdKnown bool
	Etcd      usage
	EtcdText  string
	EtcdBad   int
	Objects   []snapshot.ObjectCount

	CertSoonest, CertSoonestPlain string
	CertIcon                      string
	ClientCert                    string

	System            []appRow
	SystemOK, Systems int
	Problems          []*findings.Finding

	// Versions: what every node runs, against what it should.
	WantVersion, WantFrom string
	WantPlain             string
	Versions              []versionGroup
	VersionsOK, Nodes     int
	// Updates are k0s's Autopilot plans.
	Updates []updateView
}

// versionGroup is the nodes that run one version.
type versionGroup struct {
	Version, Plain string
	OK             bool
	Nodes          []string
}

type updateView struct {
	Name, Version, State string
	// PlainVersion is the version for Basic mode: 1.36.4.
	PlainVersion string
	Icon, Mark   string
	Created      time.Time
	Running      bool
	Targets      []updateTarget
	Top          *findings.Finding
}

type updateTarget struct {
	Name, Role, State string
	Icon, Mark        string
	Updated           time.Time
}

var sourceNames = map[string]string{"controlnode": "ControlNode", "lease": "lease", "endpoints": "kubernetes Service", "kubeconfig": "kubeconfig"}

func k0sOf(st *engine.State, t config.Thresholds, now time.Time) k0sData {
	d := k0sData{State: st}
	d.Addons, d.AddonsRead = addonsOf(st)
	d.Config = configOf(st, nil)
	snap := st.Snapshot
	if snap == nil {
		d.NotAsked = "Waiting for the first check of the cluster."
		return d
	}
	// Control plane problems, most urgent first; they mark their
	// controller's row.
	top := map[string]*findings.Finding{}
	for _, f := range st.Findings {
		if f.IsSymptom() || f.Category != findings.ControlPlane {
			continue
		}
		d.Problems = append(d.Problems, f)
		if f.Resource.Kind == "Controller" && top[f.Resource.Name] == nil {
			top[f.Resource.Name] = f
		}
		if f.Resource.Kind == "Plan" && top["plan/"+f.Resource.Name] == nil {
			top["plan/"+f.Resource.Name] = f
		}
	}

	leases := map[string]snapshot.ControllerLease{}
	for _, l := range snap.ControllerLeases() {
		leases[l.Name] = l
		if l.Alive {
			d.Alive++
		}
		if l.Alive || now.Sub(l.Renewed) < 7*24*time.Hour {
			d.Expected++
		}
	}
	d.Single = len(leases) == 0

	cp := snap.ControlPlane
	if cp == nil {
		d.NotAsked = "The controllers haven't been asked yet: that happens within a minute of connecting."
	} else {
		d.Asked, d.AskedAt, d.Server = true, cp.At, cp.Server
	}
	seen := map[string]bool{}
	var soonest *snapshot.Controller
	inUse := ""
	if st.Info != nil && st.Status != engine.StatusUnreachable {
		inUse = cluster.Address(st.Info.Server)
	}
	if cp != nil {
		for _, c := range cp.Controllers {
			r := controllerRow{Name: c.Label(), Address: c.Address, Version: c.Version, K0sVersion: c.K0sVersion, Error: c.Error, Top: top[c.Label()],
				InUse: c.Address == inUse}
			var from []string
			for _, f := range c.From {
				from = append(from, sourceNames[f])
			}
			r.From = strings.Join(from, ", ")
			switch {
			case !c.Reached:
				r.Health, r.HealthPlain, r.Icon, r.Mark = "not asked", "can't be checked from here", "info", "i"
			case len(c.Failing) > 0 || len(c.LiveFailing) > 0:
				d.Reached++
				var names []string
				for _, ch := range append(append([]snapshot.Check{}, c.Failing...), c.LiveFailing...) {
					names = append(names, ch.Name)
				}
				r.Failing = strings.Join(names, ", ")
				r.Health, r.HealthPlain, r.Icon, r.Mark = "not ready", "not working", "crit", "✕"
				if c.EtcdFailing() {
					d.EtcdBad++
				}
			default:
				d.Reached++
				d.Ready++
				r.Health, r.HealthPlain, r.Icon, r.Mark = "ready", "working", "good", "✓"
			}
			if c.Cert != nil {
				left := c.Cert.NotAfter.Sub(now)
				r.Cert = c.Cert.NotAfter.UTC().Format("2006-01-02") + " (" + certLeft(left) + ")"
				r.CertPlain = certLeftPlain(left)
				r.CertIcon = certIcon(t, left)
				if !c.Cert.CoversServer && cp.Server != "" && !cp.ServerIsController() {
					r.CertNote = "doesn't include " + cp.Server
				}
				if soonest == nil || c.Cert.NotAfter.Before(soonest.Cert.NotAfter) {
					soonest = c
				}
			}
			if c.Name != "" {
				seen[c.Name] = true
				leaseState(&r, leases, c.Name, d.Single, now)
			}
			d.Controllers = append(d.Controllers, r)
		}
	}
	// Controllers known only by their lease: stopped or removed ones.
	var rest []string
	for name := range leases {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		r := controllerRow{Name: name, From: "lease", Health: "not asked", HealthPlain: "can't be checked", Icon: "info", Mark: "i", Top: top[name]}
		leaseState(&r, leases, name, false, now)
		d.Controllers = append(d.Controllers, r)
	}
	if soonest != nil {
		left := soonest.Cert.NotAfter.Sub(now)
		d.CertSoonest, d.CertSoonestPlain, d.CertIcon = certLeft(left), certLeftPlain(left), certIcon(t, left)
	}
	if cp != nil {
		if cp.ClientCertNotAfter != nil {
			d.ClientCert = "k0s-monitor signs in with a client certificate valid until " + cp.ClientCertNotAfter.UTC().Format("2006-01-02") + " (" + certLeft(cp.ClientCertNotAfter.Sub(now)) + ")."
		}
		if snapshot.Known(cp.EtcdDBBytes) && cp.EtcdQuotaBytes > 0 {
			d.EtcdKnown = true
			d.Etcd = levelUsage(cp.EtcdDBBytes/cp.EtcdQuotaBytes, config.Levels{High: t.EtcdQuotaPercent.High, Critical: t.EtcdQuotaPercent.Critical, Warn: t.EtcdQuotaPercent.Warn}, "")
			d.EtcdText = bytesIEC(cp.EtcdDBBytes) + " of " + bytesIEC(cp.EtcdQuotaBytes)
		}
		d.Objects = cp.Objects
	}

	versionsOf(&d, snap, top)

	// k0s's own parts: kube-system's workloads.
	apps := appsOf(st, appsQuery{System: true, Namespace: "kube-system"}, now)
	d.System = apps.Apps
	for _, a := range d.System {
		d.Systems++
		if a.Top == nil && a.Icon != "crit" && a.Icon != "warn" {
			d.SystemOK++
		}
	}
	return d
}

// versionsOf groups the nodes by the k0s version they run, expected first,
// and lists the Autopilot updates.
func versionsOf(d *k0sData, snap *snapshot.Snapshot, top map[string]*findings.Finding) {
	want, from, ok := snap.ExpectedVersion()
	all := snap.K0sVersions()
	if ok {
		d.WantVersion, d.WantFrom, d.WantPlain = want.Raw, from, strings.TrimPrefix(want.Kubernetes(), "v")
	}
	d.Nodes = len(all)
	var groups []*versionGroup
	var gv []snapshot.K0sVersion
	for _, nv := range all {
		var g *versionGroup
		for i, v := range gv {
			if v.Matches(nv.Version) {
				g = groups[i]
				if v.Build == "" && nv.Version.Build != "" {
					gv[i], g.Version = nv.Version, nv.Version.Raw
				}
				break
			}
		}
		if g == nil {
			g = &versionGroup{Version: nv.Version.Raw, Plain: strings.TrimPrefix(nv.Version.Kubernetes(), "v"), OK: !ok || nv.Version.Matches(want)}
			groups, gv = append(groups, g), append(gv, nv.Version)
		}
		g.Nodes = append(g.Nodes, nv.Name)
		if g.OK {
			d.VersionsOK++
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].OK && !groups[j].OK })
	for _, g := range groups {
		d.Versions = append(d.Versions, *g)
	}

	if snap.ControlPlane == nil {
		return
	}
	for _, p := range snap.ControlPlane.Plans {
		u := updateView{Name: p.Name, Version: p.Version(), State: snapshot.PlanStateText(p.State), Created: p.Created, Running: p.Running(), Top: top["plan/"+p.Name]}
		if v, ok := snapshot.ParseK0sVersion(u.Version); ok {
			u.PlainVersion = strings.TrimPrefix(v.Kubernetes(), "v")
		}
		switch {
		case p.State == snapshot.PlanCompleted:
			u.Icon, u.Mark = "good", "✓"
		case u.Running:
			u.Icon, u.Mark = "info", "⟳"
		default:
			u.Icon, u.Mark = "crit", "✕"
		}
		if u.Top != nil {
			u.Icon, u.Mark = "crit", "✕"
		}
		for _, t := range p.Targets() {
			ut := updateTarget{Name: t.Name, Role: "worker", State: snapshot.TargetStateText(t.State), Updated: t.Updated}
			if t.Controller {
				ut.Role = "controller"
			}
			if sig, ok := snap.UpdateSignalOf(t); ok && sig.Status != "" && t.State != snapshot.SignalCompleted {
				ut.State += ": " + snapshot.SignalStatusText(sig.Status)
			}
			switch t.State {
			case snapshot.SignalCompleted:
				ut.Icon, ut.Mark = "good", "✓"
			case snapshot.SignalPending, snapshot.SignalSent:
				ut.Icon, ut.Mark = "info", "⟳"
			default:
				ut.Icon, ut.Mark = "crit", "✕"
			}
			u.Targets = append(u.Targets, ut)
		}
		d.Updates = append(d.Updates, u)
	}
}

func leaseState(r *controllerRow, leases map[string]snapshot.ControllerLease, name string, single bool, now time.Time) {
	l, ok := leases[name]
	switch {
	case single:
		r.Lease, r.LeasePlain, r.LeaseIcon = "single controller", "the only one", "good"
	case !ok:
		r.Lease, r.LeasePlain, r.LeaseIcon = "no lease", "not counted", "info"
	case l.Alive:
		r.Lease, r.LeasePlain, r.LeaseIcon = "running", "running", "good"
	case l.Renewed.IsZero():
		r.Lease, r.LeasePlain, r.LeaseIcon = "stopped", "stopped", "crit"
	default:
		since := now.Sub(l.Renewed)
		r.Lease, r.LeasePlain, r.LeaseIcon = "stopped "+ago(since)+" ago", "stopped "+agoPlain(since), "crit"
		if since >= 7*24*time.Hour {
			r.LeaseIcon = "info"
			r.Lease += " (removed?)"
		}
	}
}

func certLeft(d time.Duration) string {
	if d <= 0 {
		return "expired " + ago(-d) + " ago"
	}
	return ago(d) + " left"
}

func certLeftPlain(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	return "valid for " + strings.TrimSuffix(agoPlain(d), " ago")
}

func certIcon(t config.Thresholds, left time.Duration) string {
	l := t.CertExpiresWithin
	switch {
	case left <= 0 || (l.Critical > 0 && left <= l.Critical.D()):
		return "crit"
	case l.High > 0 && left <= l.High.D():
		return "serious"
	case l.Warn > 0 && left <= l.Warn.D():
		return "warn"
	}
	return "good"
}

// controllersText is the Controllers tile's value.
func (d k0sData) ControllersText() string {
	if d.Single {
		return fmt.Sprint(len(d.Controllers))
	}
	return fmt.Sprintf("%d of %d", d.Alive, d.Expected)
}
