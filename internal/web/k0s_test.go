package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
)

func TestK0sPage(t *testing.T) {
	st := stateOf(t, "k0s-controllers.yaml")
	d := k0sOf(st, config.DefaultThresholds(), fixedNow)
	if !d.Asked || d.Single || d.ControllersText() != "2 of 3" || d.Reached != 2 || d.Ready != 1 || d.EtcdBad != 1 {
		t.Errorf("tiles: asked %v single %v controllers %q reached %d ready %d etcd bad %d", d.Asked, d.Single, d.ControllersText(), d.Reached, d.Ready, d.EtcdBad)
	}
	if !d.EtcdKnown || d.Etcd.Pct != 90 || d.EtcdText != "1.8 GiB of 2 GiB" || d.CertSoonest != "5 d left" || d.CertIcon != "crit" {
		t.Errorf("etcd %+v %q, cert %q %q", d.Etcd, d.EtcdText, d.CertSoonest, d.CertIcon)
	}
	rows := map[string]controllerRow{}
	for _, r := range d.Controllers {
		rows[r.Name] = r
	}
	if len(rows) != 4 {
		t.Fatalf("controllers: %+v", d.Controllers)
	}
	if r := rows["ctrl-1"]; r.Health != "ready" || r.Lease != "running" || r.CertIcon != "good" || r.From != "ControlNode, kubernetes Service" || r.Top != nil {
		t.Errorf("ctrl-1: %+v", r)
	}
	if r := rows["ctrl-2"]; r.Health != "not ready" || !strings.Contains(r.Failing, "etcd") || r.CertNote != "doesn't include api.shop.lan" || r.Top == nil {
		t.Errorf("ctrl-2: %+v", r)
	}
	if r := rows["ctrl-3"]; r.Health != "not asked" || r.Lease != "stopped 5 min ago" || !strings.Contains(r.Error, "connection refused") || r.Top == nil || r.Top.RuleID != "controllers.count" {
		t.Errorf("ctrl-3: %+v", r)
	}
	if r := rows["ctrl-old"]; r.From != "lease" || !strings.Contains(r.Lease, "(removed?)") || r.LeaseIcon != "info" {
		t.Errorf("ctrl-old: %+v", r)
	}
	if len(d.Problems) < 6 || !strings.Contains(d.ClientCert, "valid until") {
		t.Errorf("problems %d, client cert %q", len(d.Problems), d.ClientCert)
	}

	basic, full := renderPage(t, "k0s", d)
	for _, s := range []string{"Control plane servers", "stopped 5 minutes", "The cluster&#39;s database is 90% full", "k0s's own parts"} {
		if !strings.Contains(basic, s) {
			t.Errorf("Basic page lacks %q", s)
		}
	}
	for _, s := range []string{"API servers ready", "poststarthook/start-apiextensions-controllers, etcd", "doesn&#39;t include api.shop.lan", "clients use api.shop.lan", "events", "180000", "ControlNode, kubernetes Service"} {
		if !strings.Contains(full, s) {
			t.Errorf("Full page lacks %q", s)
		}
	}

	// The load balancer doesn't answer: k0s-monitor uses ctrl-1.
	st.Info = &cluster.Info{Server: "https://10.0.0.11:6443", Fallback: &cluster.Fallback{Server: "https://api.shop.lan:6443",
		Controller: "ctrl-1", Since: fixedNow.Add(-3 * time.Minute),
		Error: &cluster.ConnError{Kind: cluster.KindTimeout, Plain: "No answer from api.shop.lan on port 6443."}}}
	d = k0sOf(st, config.DefaultThresholds(), fixedNow)
	for _, r := range d.Controllers {
		if r.InUse != (r.Name == "ctrl-1") {
			t.Errorf("%s in use: %v", r.Name, r.InUse)
		}
	}
	basic, full = renderPage(t, "k0s", d)
	mustContain(t, basic, "watches this cluster through the server <b>ctrl-1</b>")
	mustContain(t, full, "Connected through controller <b>ctrl-1</b>", "doesn't answer (no answer from api.shop.lan on port 6443), since 2026-", ">in use</span>")

	// A single controller keeps no leases.
	one := stateOf(t, "crashloop.yaml")
	if d := k0sOf(one, config.DefaultThresholds(), fixedNow); !d.Single || d.Asked || d.NotAsked == "" {
		t.Errorf("without control plane data: %+v", d)
	}
}

func TestK0sRoute(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	resp := env.do("GET", "/c/edge-prod/k0s?mode=full", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("k0s page: %d", resp.StatusCode)
	}
	mustContain(t, readBody(t, resp), "<h1>k0s system</h1>", `href="/c/edge-prod/k0s" class="active"`, "haven&#39;t been asked yet")
}

func TestK0sVersionsAndUpdates(t *testing.T) {
	st := stateOf(t, "k0s-versions.yaml")
	d := k0sOf(st, config.DefaultThresholds(), fixedNow)
	if d.WantVersion != "v1.36.4+k0s.1" || d.WantFrom != "k0sctl.yaml" || d.Nodes != 5 || d.VersionsOK != 3 || len(d.Versions) != 3 {
		t.Fatalf("versions: %q %q %d/%d %+v", d.WantVersion, d.WantFrom, d.VersionsOK, d.Nodes, d.Versions)
	}
	if g := d.Versions[0]; !g.OK || g.Version != "v1.36.4+k0s.1" || strings.Join(g.Nodes, ",") != "ctrl-1,ctrl-2,worker-1" {
		t.Errorf("expected group: %+v", g)
	}
	if len(d.Updates) != 1 || d.Updates[0].Top == nil || d.Updates[0].Icon != "crit" || len(d.Updates[0].Targets) != 4 ||
		d.Updates[0].Targets[3].State != "failed: the download failed" {
		t.Errorf("updates: %+v", d.Updates)
	}
	basic, full := renderPage(t, "k0s", d)
	mustContain(t, basic, "2 of 5 servers run another version than 1.36.4.", "Update to 1.36.4: failed")
	mustContain(t, full, `expected <span class="mono">v1.36.4&#43;k0s.1</span> (k0sctl.yaml)`, "v1.35.9&#43;k0s", "worker-2", "failed: the download failed",
		"k0s update to v1.36.4&#43;k0s.1 failed on worker-2")

	d = k0sOf(stateOf(t, "k0s-update.yaml"), config.DefaultThresholds(), fixedNow)
	if len(d.Updates) != 2 || !d.Updates[0].Running || d.Updates[0].Targets[1].State != "updating: restarting k0s" {
		t.Errorf("running update: %+v", d.Updates)
	}
	_, full = renderPage(t, "k0s", d)
	mustContain(t, full, "Plan <span class=\"mono\">autopilot</span>", "running", "not started")

	// No plans, all on one version.
	d = k0sOf(stateOf(t, "k0s-controllers.yaml"), config.DefaultThresholds(), fixedNow)
	basic, _ = renderPage(t, "k0s", d)
	mustContain(t, basic, "All 2 servers run the same version (1.36.4).", "No update is running.")
}
