package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/snapshot"
)

// stateOf evaluates a rule fixture as the engine would.
func stateOf(t *testing.T, file string) *engine.State {
	t.Helper()
	snap, err := snapshot.FromYAMLFile("test", "../rules/testdata/"+file, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	fs, skipped := fleet.EvaluateSnapshot(snap, config.DefaultThresholds(), "")
	return &engine.State{Name: "test", Status: engine.StatusOK, Findings: fs, Skipped: skipped, Snapshot: snap}
}

// renderPage runs a page template in both modes and returns the output.
func renderPage(t *testing.T, name string, data any) (basic, full string) {
	t.Helper()
	s := &Server{now: func() time.Time { return fixedNow }}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"basic", "full"} {
		var buf bytes.Buffer
		p := &page{Title: name, Mode: mode, Basic: mode == "basic", Nav: name, Cluster: &navCluster{Name: "test"}, Data: data}
		if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
			t.Fatalf("%s in %s mode: %v", name, mode, err)
		}
		if mode == "basic" {
			basic = buf.String()
		} else {
			full = buf.String()
		}
	}
	return basic, full
}

func rowNamed(t *testing.T, rows []serverRow, name string) serverRow {
	t.Helper()
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no row for %s", name)
	return serverRow{}
}

func chipTexts(cs []chip) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Text+"/"+c.Icon)
	}
	return strings.Join(out, ", ")
}

func TestServersPage(t *testing.T) {
	d := serversOf(stateOf(t, "metrics-nodes.yaml"), config.DefaultThresholds(), "", fixedNow)
	if len(d.Rows) != 3 || d.NoUsage != "" || len(d.Down) != 0 {
		t.Fatalf("rows %d, no usage %q, down %d", len(d.Rows), d.NoUsage, len(d.Down))
	}
	w1 := rowNamed(t, d.Rows, "worker-1")
	if w1.Status != "DiskPressure" || w1.Disk.Pct != 91 || w1.Disk.Cls != "crit" || w1.CPU.Pct != 40 || w1.Mem.Pct != 50 {
		t.Errorf("worker-1: %+v", w1)
	}
	w2 := rowNamed(t, d.Rows, "worker-2")
	want := "steal 31%/crit, iowait 12%/, disk 200 ms/warn, skew -2.5s/warn, clock not synced/warn, swap 70%/warn, rebooted 2 h ago/"
	if got := chipTexts(w2.Signals); got != want {
		t.Errorf("worker-2 signals:\n got %s\nwant %s", got, want)
	}
	if w2.CPU.Pct != 93 || w2.CPU.Cls != "warn" {
		t.Errorf("worker-2 CPU: %+v", w2.CPU)
	}
	if got := chipTexts(rowNamed(t, d.Rows, "worker-3").Signals); got != "" {
		t.Errorf("worker-3 is a quiet VM, signals %s", got)
	}

	// The most urgent node is shown in detail, with its disk history.
	if d.Detail == nil || d.Detail.Row.Name != "worker-1" || !w1.Selected {
		t.Fatalf("detail = %+v", d.Detail)
	}
	det := d.Detail
	if det.Top == nil || det.Top.RuleID != "node.fs-high" || len(det.Problems) != 2 {
		t.Errorf("problems: top %v, %d", det.Top, len(det.Problems))
	}
	if det.Chart == nil || det.Chart.JSON == "" || !strings.Contains(det.Chart.JSON, `"label":"eviction (nodefs.available`) {
		t.Errorf("chart = %+v", det.Chart)
	}
	if n := len(det.Chart.Rows); n < 12 || det.Chart.Rows[n-1][1] != "91.0%" {
		t.Errorf("table view rows = %v", det.Chart.Rows)
	}
	if len(det.Filesystems) != 2 || det.Filesystems[1].Mountpoint != "/var/lib/k0s" || !det.Filesystems[1].Kubelet || det.Filesystems[0].Kubelet {
		t.Errorf("filesystems = %+v", det.Filesystems)
	}

	basic, full := renderPage(t, "servers", d)
	for _, s := range []string{"Servers", "Recommended", "Show me how", "worker-1 is running out of disk space", "If you can log in to it, find out what fills its disk."} {
		if !strings.Contains(basic, s) {
			t.Errorf("Basic page lacks %q", s)
		}
	}
	// Basic lists the steps written for it; the others are on the problem.
	if strings.Contains(basic, "On the node:") {
		t.Error("Basic page shows a technical step")
	}
	for _, s := range []string{"Nodes &amp; VMs", "steal 31%", "nodefs usage, last 24 h (/var/lib/k0s, 200 GiB)", "data-chart=", "Suggested fixes", "crictl"} {
		if !strings.Contains(full, s) {
			t.Errorf("Full page lacks %q", s)
		}
	}

	// Another node on request.
	d = serversOf(stateOf(t, "metrics-nodes.yaml"), config.DefaultThresholds(), "worker-3", fixedNow)
	if d.Detail == nil || d.Detail.Row.Name != "worker-3" || d.Detail.Top == nil {
		t.Errorf("selected worker-3: %+v", d.Detail)
	}
}

func TestServersPageWithoutMetrics(t *testing.T) {
	d := serversOf(stateOf(t, "node-condition.yaml"), config.DefaultThresholds(), "", fixedNow)
	if !strings.Contains(d.NoUsage, "need Prometheus") {
		t.Errorf("no usage = %q", d.NoUsage)
	}
	if len(d.Down) != 2 || d.Down[0].F.RuleID != "node.not-ready" {
		t.Fatalf("down = %+v", d.Down)
	}
	if !strings.Contains(d.Down[0].Copy, "What to do:") {
		t.Errorf("instructions to copy:\n%s", d.Down[0].Copy)
	}
	w2 := rowNamed(t, d.Rows, "worker-2")
	if w2.Status != "NotReady" || !strings.HasPrefix(w2.CPU.Text, "stale") {
		t.Errorf("worker-2: %+v", w2)
	}
	if w1 := rowNamed(t, d.Rows, "worker-1"); w1.CPU.Text != "—" || len(w1.Signals) != 0 {
		t.Errorf("without Prometheus there is no usage: %+v", w1)
	}
	// The detail prefers a node that still responds.
	if d.Detail == nil || d.Detail.Row.Name != "worker-1" {
		t.Errorf("detail = %+v", d.Detail)
	}
	basic, full := renderPage(t, "servers", d)
	if !strings.Contains(basic, "Copy instructions") || !strings.Contains(full, "Host checklist") {
		t.Errorf("the down servers need their instructions")
	}
}

func TestStoragePage(t *testing.T) {
	st := stateOf(t, "metrics-storage.yaml")
	d := storageOf(st, config.DefaultThresholds(), "", "", false, fixedNow)
	if d.Claims != 4 || d.Over80 != 2 || d.FullSoon != 1 || d.DefaultClass != "openebs-hostpath" {
		t.Errorf("tiles: claims %d, over 80 %d, full soon %d, default %q", d.Claims, d.Over80, d.FullSoon, d.DefaultClass)
	}
	if d.FullSoonText != "data-db · ~4 h" {
		t.Errorf("full soon text = %q", d.FullSoonText)
	}
	if len(d.Rows) == 0 || d.Rows[0].Name != "data-db" {
		t.Fatalf("the forecast comes first: %+v", d.Rows)
	}
	db := d.Rows[0]
	if db.Used.Pct != 93 || db.Used.Cls != "serious" || db.FullIn != "~4 h" || db.FullIcon != "crit" || db.Spark == "" || db.Owner != "db" {
		t.Errorf("data-db row: %+v", db)
	}
	if !strings.HasSuffix(db.Spark, ",93.0") {
		t.Errorf("sparkline ends at the current usage: %s", db.Spark)
	}
	for _, r := range d.Rows {
		switch r.Name {
		case "uploads":
			if r.FullIn != "stable" || r.Used.Cls != "warn" {
				t.Errorf("uploads: %+v", r)
			}
		case "reports":
			// A few bytes an hour is stable, not "full in 0 s".
			if r.FullIn != "stable" || r.Growing || r.FullIcon != "" {
				t.Errorf("reports: %+v", r)
			}
		case "journal":
			if r.Inodes.Pct != 91 || r.Inodes.Cls == "" {
				t.Errorf("journal inodes: %+v", r.Inodes)
			}
		}
	}
	det := d.Detail
	if det == nil || det.Row.Name != "data-db" {
		t.Fatalf("detail = %+v", det)
	}
	if det.GrowthNow != "+150 MiB/h" || det.Baseline != "+20 MiB/h" || det.Full != "≈ 18:46 UTC" {
		t.Errorf("detail facts: growth %q, baseline %q, full %q", det.GrowthNow, det.Baseline, det.Full)
	}
	if det.Chart == nil || !strings.Contains(det.Chart.JSON, `"projection":{`) {
		t.Errorf("the chart shows when it will be full: %+v", det.Chart)
	}

	basic, full := renderPage(t, "storage", d)
	for _, s := range []string{"The storage of db will be full in about 4 hours", "in about 4 hours", "Almost full"} {
		if !strings.Contains(basic, s) {
			t.Errorf("Basic page lacks %q", s)
		}
	}
	for _, s := range []string{"PVCs", "data-spark=", "Projected 100%", "du -xsh"} {
		if !strings.Contains(full, s) {
			t.Errorf("Full page lacks %q", s)
		}
	}

	// Filters change the rows, not the totals.
	d = storageOf(st, config.DefaultThresholds(), "logs", "", false, fixedNow)
	if len(d.Rows) != 1 || d.Rows[0].Name != "journal" || d.Claims != 4 {
		t.Errorf("namespace filter: %d rows, %d claims", len(d.Rows), d.Claims)
	}
	d = storageOf(st, config.DefaultThresholds(), "", "shop/uploads", true, fixedNow)
	for _, r := range d.Rows {
		if r.Top == nil {
			t.Errorf("only problems, but %s has none", r.Name)
		}
	}
	if d.Detail == nil || d.Detail.Row.Name != "uploads" {
		t.Errorf("selected uploads: %+v", d.Detail)
	}
}

func TestStoragePageWithoutMetrics(t *testing.T) {
	d := storageOf(stateOf(t, "pvc.yaml"), config.DefaultThresholds(), "", "", false, fixedNow)
	if !strings.Contains(d.NoUsage, "needs Prometheus") || d.Pending == 0 {
		t.Errorf("no usage %q, pending %d", d.NoUsage, d.Pending)
	}
	for _, r := range d.Rows {
		if r.Phase == "Pending" && !strings.HasPrefix(r.Note, "Pending") {
			t.Errorf("pending claim %s has no note", r.Name)
		}
	}
	renderPage(t, "storage", d)
}

func TestServersAndStorageRoutes(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	for path, want := range map[string]string{
		"/c/edge-prod/servers?mode=basic": "runs your apps",
		"/c/edge-prod/servers?mode=full":  "Nodes &amp; VMs",
		"/c/edge-prod/storage?mode=full":  "PersistentVolumeClaims",
		"/c/edge-prod/storage?mode=basic": "storage volume",
	} {
		resp := env.do("GET", path, nil, nil)
		body := readBody(t, resp)
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Errorf("%s: %d, want %q in the page", path, resp.StatusCode, want)
		}
		if !strings.Contains(body, `href="/c/edge-prod/storage"`) {
			t.Errorf("%s: the navigation lacks Storage", path)
		}
	}
	if resp := env.do("GET", "/c/nope/servers", nil, nil); resp.StatusCode != 404 {
		t.Errorf("unknown cluster: %d", resp.StatusCode)
	}
}

// Without node-exporter, CPU and memory come from the metrics API and the
// disk from the kubelets.
func TestServersPageFromFallbacks(t *testing.T) {
	st := stateOf(t, "metrics-nodes.yaml")
	fs := snapshot.NewNodeMetrics("")
	fs.Up = true
	fs.Filesystems = []snapshot.Filesystem{{Mountpoint: snapshot.K0sDataDir, Device: "nodefs", Size: 100, Avail: 30}}
	st.Snapshot.Metrics = &snapshot.Metrics{At: fixedNow, Have: map[string]bool{"kubelet-nodefs": true},
		Nodes:     map[string]*snapshot.NodeMetrics{"worker-1": fs},
		NodeUsage: map[string]snapshot.NodeUsage{"worker-1": {CPUCores: 1, MemoryBytes: 4 << 30}},
		Fallbacks: []string{"node CPU and memory from the metrics API", "node disk usage from the kubelets"}}
	d := serversOf(st, config.DefaultThresholds(), "", fixedNow)
	if d.NoUsage != "" || !strings.Contains(d.Source, "current values from the metrics API") || !strings.Contains(d.Source, "from the kubelets") {
		t.Errorf("source %q, no usage %q", d.Source, d.NoUsage)
	}
	w1 := rowNamed(t, d.Rows, "worker-1")
	if w1.CPU.Pct != 25 || w1.Mem.Pct != 25 || w1.Disk.Pct != 70 || len(w1.Signals) != 0 || !strings.Contains(w1.CPU.Title, "metrics API") {
		t.Errorf("worker-1: %+v", w1)
	}
	if w2 := rowNamed(t, d.Rows, "worker-2"); w2.CPU.Known || w2.CPU.Text != "—" {
		t.Errorf("worker-2 has no data: %+v", w2.CPU)
	}
	renderPage(t, "servers", d)
}

func TestServersPageWithNodeProblemDetector(t *testing.T) {
	d := serversOf(stateOf(t, "node-npd.yaml"), config.DefaultThresholds(), "worker-1", fixedNow)
	w1 := rowNamed(t, d.Rows, "worker-1")
	if w1.Status != "ReadonlyFilesystem, FrequentKubeletRestart" || w1.Plain != "A disk can't be written, App runner keeps restarting" {
		t.Errorf("worker-1: status %q, plain %q", w1.Status, w1.Plain)
	}
	if w2 := rowNamed(t, d.Rows, "worker-2"); w2.Status != "Ready" {
		t.Errorf("worker-2: %q", w2.Status)
	}
	icons := map[string]string{}
	for _, c := range d.Detail.Conditions {
		icons[c.Type] = c.Icon
	}
	if icons["ReadonlyFilesystem"] != "serious" || icons["KernelDeadlock"] != "good" || icons["Ready"] != "good" {
		t.Errorf("icons = %v", icons)
	}
	d = serversOf(stateOf(t, "node-npd.yaml"), config.DefaultThresholds(), "worker-2", fixedNow)
	for _, c := range d.Detail.Conditions {
		if c.Type == "GPUHealthy" && c.Icon != "info" {
			t.Errorf("another tool's condition is judged: %+v", c)
		}
	}
}
