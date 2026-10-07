package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes/fake"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/testutil"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

// evaluated runs an engine on the fixture until it has evaluated once.
func evaluated(t *testing.T) *engine.Engine {
	t.Helper()
	client := fake.NewClientset(testutil.Objects(t, "testdata/report.yaml")...)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fleet := engine.NewFleet(ctx, engine.Options{
		Now: func() time.Time { return now }, MinInterval: 20 * time.Millisecond, MaxInterval: 200 * time.Millisecond,
		Connect: func(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
			return cluster.NewForClient(c.Name, "https://192.168.10.5:6443", client, &version.Info{GitVersion: "v1.36.4+k0s"}), nil
		},
	})
	t.Cleanup(fleet.Stop)
	e, err := fleet.Add(config.Cluster{Name: "shop-prod", Kubeconfig: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for e.State().Evals == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no evaluation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return e
}

func build(t *testing.T, e *engine.Engine, o Options) *Report {
	t.Helper()
	return Build(context.Background(), Input{State: e.State(), Conn: e.Conn(), Tool: "v0.9.0", Host: "jump-01", Now: now, Options: o})
}

// all is every file of the report, concatenated.
func all(r *Report) string {
	var b strings.Builder
	for _, f := range r.Files {
		b.WriteString("=== " + f.Path + "\n")
		b.Write(f.Data)
	}
	return b.String()
}

func TestReportContents(t *testing.T) {
	e := evaluated(t)
	r := build(t, e, DefaultOptions)
	text := all(r)

	for _, p := range []string{"README.txt", "index.html", "problems.json", "cluster.json", "nodes.txt", "events.txt",
		"describe/pod/shop/payments-api-7c9f8d6b5-x2kqp.txt",
		"logs/shop/payments-api-7c9f8d6b5-x2kqp/api.log", "logs/shop/payments-api-7c9f8d6b5-a1b2c/api.previous.log"} {
		if r.File(p) == nil {
			t.Errorf("no %s; files: %v; missing: %v", p, paths(r), r.Missing)
		}
	}
	// The fake client has no REST configuration, which kubectl's
	// Deployment describer needs: the report says so.
	if len(r.Missing) != 1 || !strings.Contains(r.Missing[0], "describe/deployment/shop/payments-api.txt") {
		t.Errorf("missing: %v", r.Missing)
	}
	if r.Files[0].Path != "README.txt" || r.Files[1].Path != "index.html" {
		t.Errorf("order: %v", paths(r))
	}
	if r.Problems == 0 || r.Described == 0 || r.Logs == 0 {
		t.Errorf("counts: %+v", r)
	}
	// Secrets never get in: not the env values, not the password in the
	// URL or the termination message, not the event's token, and nothing
	// of the Secret and the ConfigMap.
	for _, leak := range []string{"hunter2", "Sup3rSecret", "abc123secret", "c2VjcmV0LWZyb20tc2VjcmV0", "secret-from-secret", "configmap-api-key-value", "payments-db"} {
		if strings.Contains(text, leak) {
			i := strings.Index(text, leak)
			t.Errorf("the report holds %q: …%s…", leak, text[max(0, i-200):min(len(text), i+50)])
		}
	}
	// Without the option, IP addresses stay.
	if !strings.Contains(text, "10.244.1.37") || !strings.Contains(text, "192.168.10.21") {
		t.Error("IP addresses missing")
	}
	sum := html.UnescapeString(string(r.File("index.html").Data))
	for _, want := range []string{"Report for support: shop-prod", "payments-api", "What to do", "describe/pod/shop/payments-api-7c9f8d6b5-x2kqp.txt",
		"logs/shop/payments-api-7c9f8d6b5-x2kqp/api.log", "v1.36.4+k0s", "jump-01"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	if strings.Contains(sum, "<script") {
		t.Error("the summary has a script")
	}
	var fs []map[string]any
	if err := json.Unmarshal(r.File("problems.json").Data, &fs); err != nil || len(fs) == 0 {
		t.Errorf("problems.json: %v, %d", err, len(fs))
	}
	if !strings.Contains(string(r.File("nodes.txt").Data), "worker-1") {
		t.Error("nodes.txt lacks the node")
	}
	if !strings.Contains(string(r.File("events.txt").Data), "BackOff") {
		t.Error("events.txt lacks the event")
	}
}

func TestReportMasksIPs(t *testing.T) {
	e := evaluated(t)
	r := build(t, e, Options{MaskIPs: true, Logs: true})
	text := all(r)
	for _, ip := range []string{"10.244.1.37", "10.244.1.38", "192.168.10.21", "192.168.10.5", "10.0.0.9"} {
		if strings.Contains(text, ip) {
			t.Errorf("%s not masked", ip)
		}
	}
	if r.MaskedIPs == 0 || !strings.Contains(text, "ip-1") {
		t.Errorf("no masked addresses: %d", r.MaskedIPs)
	}
	// The same address has the same name in every file.
	m := newIPMasker()
	a, b := m.mask("pod 10.244.1.37 on 192.168.10.21"), m.mask("again 10.244.1.37")
	if a != "pod ip-1 on ip-2" || b != "again ip-1" {
		t.Errorf("names: %q %q", a, b)
	}
}

func TestIPMasker(t *testing.T) {
	for in, want := range map[string]string{
		"dial tcp 10.0.0.9:5432: refused":   "dial tcp ip-1:5432: refused",
		"version 1.2.3.4.5 and v10.1.2.3":   "version 1.2.3.4.5 and v10.1.2.3",
		"at 12:34:56 mac aa:bb:cc:dd:ee:ff": "at 12:34:56 mac aa:bb:cc:dd:ee:ff",
		"[fe80::1]:8080 and 2001:db8::5":    "[ip6-1]:8080 and ip6-2",
		"listen 0.0.0.0 127.0.0.1 [::1]":    "listen 0.0.0.0 127.0.0.1 [::1]",
		"cidr 10.244.0.0/16":                "cidr ip-1/16",
	} {
		if got := newIPMasker().mask(in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReportOptions(t *testing.T) {
	e := evaluated(t)
	r := build(t, e, Options{})
	for _, f := range r.Files {
		if strings.HasPrefix(f.Path, "logs/") {
			t.Errorf("logs without the option: %s", f.Path)
		}
	}
	if r.Logs != 0 {
		t.Errorf("logs: %d", r.Logs)
	}
}

func TestReportUnreachable(t *testing.T) {
	e := evaluated(t)
	r := Build(context.Background(), Input{State: e.State(), Tool: "v0.9.0", Host: "jump-01", Now: now, Options: DefaultOptions})
	if r.Described != 0 || len(r.Missing) == 0 || !strings.Contains(r.Missing[0], "can't be reached") {
		t.Errorf("unreachable: %+v", r.Missing)
	}
	if r.File("index.html") == nil || r.File("problems.json") == nil {
		t.Error("summary missing")
	}
}

func TestZip(t *testing.T) {
	e := evaluated(t)
	r := build(t, e, DefaultOptions)
	var buf bytes.Buffer
	if err := r.Zip(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(r.Files) {
		t.Errorf("%d files in the zip, %d in the report", len(zr.File), len(r.Files))
	}
	if want := "k0s-monitor-report-shop-prod-20260927-1400/README.txt"; zr.File[0].Name != want {
		t.Errorf("first file %q, want %q", zr.File[0].Name, want)
	}
	f, _ := zr.File[1].Open()
	b, _ := io.ReadAll(f)
	if !strings.Contains(string(b), "<html") {
		t.Error("index.html isn't HTML")
	}
	if r.FileName() != "k0s-monitor-report-shop-prod-20260927-1400.zip" {
		t.Errorf("file name %q", r.FileName())
	}
}

func paths(r *Report) []string {
	var out []string
	for _, f := range r.Files {
		out = append(out, f.Path)
	}
	return out
}

// The alerts of the cluster's Prometheus go in alerts.json and the
// summary, with the problems they are about, and their texts redacted.
func TestReportAlerts(t *testing.T) {
	snap, err := snapshot.FromYAMLFile("shop-prod", "../rules/testdata/alerts.yaml", now)
	if err != nil {
		t.Fatal(err)
	}
	snap.Metrics.Alerts[len(snap.Metrics.Alerts)-1].Description = "Probe with password=hunter2 failed"
	fs, _ := fleet.EvaluateSnapshot(snap, config.DefaultThresholds(), "")
	st := &engine.State{Name: "shop-prod", Status: engine.StatusOK, Findings: fs, Snapshot: snap}
	r := Build(context.Background(), Input{State: st, Tool: "v0.9.0", Host: "jump-01", Now: now, Options: DefaultOptions})
	f := r.File("alerts.json")
	if f == nil {
		t.Fatalf("no alerts.json: %v", paths(r))
	}
	var as []struct {
		Name     string
		Problems []string
		About    struct{ Kind, Name string }
	}
	if err := json.Unmarshal(f.Data, &as); err != nil || len(as) != 4 {
		t.Fatalf("alerts.json: %v, %+v", err, as)
	}
	for _, a := range as {
		if a.Name == "KubePodCrashLooping" && (a.About.Kind != "Pod" || len(a.Problems) != 2) {
			t.Errorf("crash alert: %+v", a)
		}
	}
	text := all(r)
	if strings.Contains(text, "hunter2") {
		t.Error("the report holds the password from an alert")
	}
	sum := html.UnescapeString(string(r.File("index.html").Data))
	for _, want := range []string{"Alerts from Prometheus (4)", "KubePersistentVolumeFillingUp", "No problem found about this.", "Prometheus alerts</th>"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
}
