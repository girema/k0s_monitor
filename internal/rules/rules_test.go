package rules_test

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func load(t *testing.T, file string) *snapshot.Snapshot {
	t.Helper()
	s, err := snapshot.FromYAMLFile("test", filepath.Join("testdata", file), now)
	if err != nil {
		t.Fatalf("loading %s: %v", file, err)
	}
	return s
}

// scan runs rules, scoring and folding, exactly like a real scan.
func scan(t *testing.T, file string) []*findings.Finding {
	t.Helper()
	fs, skipped := fleet.EvaluateSnapshot(load(t, file), config.DefaultThresholds(), "")
	if len(skipped) > 0 {
		t.Fatalf("unexpected skipped rules: %+v", skipped)
	}
	return fs
}

func find(t *testing.T, fs []*findings.Finding, rule, resource string) *findings.Finding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && f.Resource.String() == resource {
			return f
		}
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.RuleID+" "+f.Resource.String())
	}
	t.Fatalf("no %s finding for %s; got %v", rule, resource, got)
	return nil
}

func absent(t *testing.T, fs []*findings.Finding, rule, resource string) {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && (resource == "" || f.Resource.String() == resource) {
			t.Errorf("unexpected %s finding for %s: %s", rule, f.Resource.String(), f.Title)
		}
	}
}

func fact(f *findings.Finding, label string) string {
	for _, e := range f.Evidence {
		if e.Label == label {
			return e.Value
		}
	}
	return ""
}

func hasCommand(f *findings.Finding, cmd string) bool {
	for _, s := range f.Remedy.Steps {
		if strings.Contains(s.Command, cmd) {
			return true
		}
	}
	return false
}

func expect(t *testing.T, f *findings.Finding, sev findings.Severity, score int, p findings.Priority) {
	t.Helper()
	if f.Severity != sev || f.Score != score || f.Priority != p {
		t.Errorf("%s %s: got severity %s, score %d, %s; want %s, %d, %s",
			f.RuleID, f.Resource.String(), f.Severity, f.Score, f.Priority, sev, score, p)
	}
}

func TestCrashLoopWithSymptoms(t *testing.T) {
	fs := scan(t, "crashloop.yaml")
	w01 := find(t, fs, "pod.crashloop", "shop/deployment/payments-api")
	// Critical (all replicas down) 60 + all down 20 + exposed through an Ingress 5.
	expect(t, w01, findings.Critical, 85, findings.P1)
	if !w01.Impact.AllReplicasDown || !w01.Impact.Exposed {
		t.Errorf("impact = %+v, want all replicas down and exposed", w01.Impact)
	}
	if got := fact(w01, "Exit code"); got != "1 (Error)" {
		t.Errorf("exit code fact = %q", got)
	}
	if got := fact(w01, "Restarts"); got != "23" {
		t.Errorf("restarts fact = %q", got)
	}
	if !strings.Contains(w01.Title, "3 of 3 pods") {
		t.Errorf("title = %q", w01.Title)
	}
	if w01.Plain.Title != "The app payments-api keeps crashing" {
		t.Errorf("plain title = %q", w01.Plain.Title)
	}
	if !hasCommand(w01, "kubectl -n shop logs payments-api-7c9f8d6b5-x2kqp -c api --previous") {
		t.Errorf("missing logs --previous step: %+v", w01.Remedy.Steps)
	}
	if !hasCommand(w01, "kubectl -n shop rollout undo deploy/payments-api") {
		t.Errorf("missing rollout undo step")
	}

	for _, sym := range []*findings.Finding{
		find(t, fs, "deploy.unavailable", "shop/deployment/payments-api"),
		find(t, fs, "svc.no-endpoints", "shop/service/payments-api"),
	} {
		if sym.ParentID != w01.ID {
			t.Errorf("%s should be folded under pod.crashloop, parent = %q", sym.RuleID, sym.ParentID)
		}
	}
	if fs[0] != w01 {
		t.Errorf("root cause should come first, got %s", fs[0].RuleID)
	}
}

func TestOOMKilled(t *testing.T) {
	fs := scan(t, "oom.yaml")
	w02 := find(t, fs, "pod.oomkilled", "batch/deployment/report-worker")
	// High 45 + half of the replicas down 12.
	expect(t, w02, findings.High, 57, findings.P2)
	if got := fact(w02, "Memory limit"); got != "512Mi" {
		t.Errorf("memory limit fact = %q", got)
	}
	if !hasCommand(w02, "set resources deploy/report-worker -c worker --limits=memory=768Mi") {
		t.Errorf("missing raise-limit step: %+v", w02.Remedy.Steps)
	}
	absent(t, fs, "pod.crashloop", "")
	w12 := find(t, fs, "deploy.unavailable", "batch/deployment/report-worker")
	if w12.ParentID != w02.ID {
		t.Errorf("deploy.unavailable should be folded under pod.oomkilled")
	}
}

func TestImagePull(t *testing.T) {
	fs := scan(t, "imagepull.yaml")
	f := find(t, fs, "pod.image-pull", "batch/cronjob/nightly-backup")
	expect(t, f, findings.High, 45, findings.P3)
	if fact(f, "Registry") != "registry.local" {
		t.Errorf("registry = %q", fact(f, "Registry"))
	}
	if !strings.Contains(fact(f, "Error"), "not found") {
		t.Errorf("error should come from the Failed event, got %q", fact(f, "Error"))
	}
	if !strings.Contains(f.Title, "does not exist") {
		t.Errorf("title = %q", f.Title)
	}
	if f.Plain.Title != "The scheduled job nightly-backup can't download its software" {
		t.Errorf("plain title = %q", f.Plain.Title)
	}
}

func TestUnschedulable(t *testing.T) {
	fs := scan(t, "unschedulable.yaml")
	f := find(t, fs, "pod.unschedulable", "ml/statefulset/trainer")
	// High 45 + all replicas down 20 = 65, raised to the 80 of the
	// StatefulSet outage folded under it.
	expect(t, f, findings.High, 80, findings.P1)
	sts := find(t, fs, "sts.unavailable", "ml/statefulset/trainer")
	if sts.ParentID != f.ID {
		t.Errorf("sts.unavailable should be folded under pod.unschedulable")
	}
	if got := fact(f, "Priority"); !strings.HasPrefix(got, "raised to P1 by sts.unavailable") {
		t.Errorf("priority fact = %q", got)
	}
	if !strings.Contains(f.Title, "not enough free memory") {
		t.Errorf("title = %q", f.Title)
	}
	if !strings.Contains(f.Plain.Why, "24Gi") || !strings.Contains(f.Plain.Why, "4Gi") {
		t.Errorf("plain why should compare request and free memory: %q", f.Plain.Why)
	}
	if fact(f, "Most free node") != "worker-1: cpu 2, memory 4Gi" {
		t.Errorf("most free node = %q", fact(f, "Most free node"))
	}
	absent(t, fs, "pod.unschedulable", "ml/pod/just-created")
}

func TestNodes(t *testing.T) {
	fs := scan(t, "nodes.yaml")
	n01 := find(t, fs, "node.not-ready", "node/worker-3")
	// Critical 60 + 2 pods on the node + system 10 = 72, raised to the 80 of
	// the checkout outage folded under it.
	expect(t, n01, findings.Critical, 80, findings.P1)
	if got := fact(n01, "Priority"); !strings.HasPrefix(got, "raised to P1 by deploy.unavailable") {
		t.Errorf("priority fact = %q", got)
	}
	if fact(n01, "Lease renewed") != "12 min ago" {
		t.Errorf("lease fact = %q", fact(n01, "Lease renewed"))
	}
	if !hasCommand(n01, "ping -c 3 10.0.12.23") || !hasCommand(n01, "journalctl -u k0sworker") {
		t.Errorf("missing host steps: %+v", n01.Remedy.Steps)
	}
	w12 := find(t, fs, "deploy.unavailable", "shop/deployment/checkout")
	if w12.ParentID != n01.ID {
		t.Errorf("checkout outage should be folded under the NotReady node")
	}

	fresh := find(t, fs, "node.not-ready", "node/worker-4")
	if !strings.Contains(fresh.Plain.WhatHappened, "never reported") {
		t.Errorf("plain text for a node without status = %q", fresh.Plain.WhatHappened)
	}

	n02 := find(t, fs, "node.pressure", "node/worker-2")
	// High 45 + 2 evicted pods + system 10.
	expect(t, n02, findings.High, 57, findings.P2)
	if n02.Title != "DiskPressure (2 pods evicted)" {
		t.Errorf("title = %q", n02.Title)
	}
	if n02.Plain.Title != "The server worker-2 is running low on disk space" {
		t.Errorf("plain title = %q", n02.Plain.Title)
	}
}

func TestPVCPending(t *testing.T) {
	fs := scan(t, "pvc.yaml")
	db := find(t, fs, "pvc.pending", "shop/persistentvolumeclaim/data-db")
	// High 45 + blocks a workload 12.
	expect(t, db, findings.High, 57, findings.P2)
	if !strings.Contains(db.Title, "no default StorageClass") {
		t.Errorf("title = %q", db.Title)
	}
	s06 := find(t, fs, "sc.no-default", "storageclass/(default)")
	// Medium 30 + blocks a workload 12 + system 10 = 52, raised to the 57
	// of the claim.
	expect(t, s06, findings.Medium, 57, findings.P2)
	if !strings.HasPrefix(s06.Title, "No default StorageClass: 1 claim") {
		t.Errorf("title = %q", s06.Title)
	}
	if !hasCommand(s06, "kubectl patch storageclass openebs-hostpath") {
		t.Errorf("missing patch step: %+v", s06.Remedy.Steps)
	}
	// The claim waits for a default class; the pod waits for the claim.
	for _, sym := range []*findings.Finding{db, find(t, fs, "pod.unschedulable", "shop/statefulset/db")} {
		if sym.ParentID != s06.ID {
			t.Errorf("%s should end up under sc.no-default, parent = %q", sym.RuleID, sym.ParentID)
		}
	}
	missing := find(t, fs, "pvc.pending", "shop/persistentvolumeclaim/data-missing")
	expect(t, missing, findings.Medium, 30, findings.P3)
	absent(t, fs, "pvc.pending", "shop/persistentvolumeclaim/data-wait")
}

func TestServiceNoEndpoints(t *testing.T) {
	fs := scan(t, "services.yaml")
	absent(t, fs, "svc.no-endpoints", "shop/service/orphan")
	f := find(t, fs, "svc.selector-mismatch", "shop/service/orphan")
	// Medium 30 + exposed 5.
	expect(t, f, findings.Medium, 35, findings.P3)
	if !strings.Contains(f.Title, "matches no pods or workloads") {
		t.Errorf("title = %q", f.Title)
	}
	if fact(f, "Closest match") != "shop/pod/payments-api-0 has app=payments-api, not paymnts" {
		t.Errorf("closest match = %q", fact(f, "Closest match"))
	}
	for _, name := range []string{"fresh", "healthy", "external"} {
		absent(t, fs, "svc.no-endpoints", "shop/service/"+name)
	}
}

func TestDNS(t *testing.T) {
	fs := scan(t, "dns-down.yaml")
	down := find(t, fs, "dns.unhealthy", "kube-system/deployment/coredns")
	// Critical 60 + cluster-wide 25 + kube-system 10.
	expect(t, down, findings.Critical, 95, findings.P1)
	if down.Title != "CoreDNS is scaled to 0 replicas" {
		t.Errorf("title = %q", down.Title)
	}
	svc := find(t, fs, "svc.no-endpoints", "kube-system/service/kube-dns")
	if svc.ParentID != down.ID {
		t.Errorf("kube-dns has no endpoints because CoreDNS is scaled to 0; parent = %q", svc.ParentID)
	}
	if svc.Title != "No endpoints: deployment coredns is scaled to 0" || !hasCommand(svc, "scale deploy/coredns") {
		t.Errorf("title = %q, steps = %+v", svc.Title, svc.Remedy.Steps)
	}

	degraded := find(t, scan(t, "dns-degraded.yaml"), "dns.unhealthy", "kube-system/deployment/coredns")
	expect(t, degraded, findings.Medium, 40, findings.P3)
}

func TestHealthyClusterHasNoFindings(t *testing.T) {
	s := load(t, "services.yaml")
	s.Services = s.Services[2:3] // only "healthy"
	s = snapshot.New(s)
	fs, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if len(fs) != 0 {
		t.Errorf("expected no findings, got %d", len(fs))
	}
}

func TestRulesAreSkippedWithoutData(t *testing.T) {
	s := load(t, "crashloop.yaml")
	s.Available = map[snapshot.Kind]bool{snapshot.KindPod: true}
	_, skipped := rules.Evaluate(s, config.DefaultThresholds())
	byID := map[string]string{}
	for _, sk := range skipped {
		byID[sk.RuleID] = sk.Reason
	}
	if byID["node.not-ready"] != "cannot read nodes" {
		t.Errorf("node.not-ready skip reason = %q", byID["node.not-ready"])
	}
	if _, ok := byID["pod.crashloop"]; ok {
		t.Errorf("pod.crashloop only needs pods and should run")
	}
}

func TestFingerprintsAreStable(t *testing.T) {
	a := scan(t, "crashloop.yaml")
	b := scan(t, "crashloop.yaml")
	if len(a) != len(b) {
		t.Fatalf("different number of findings")
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("finding %d: ID changed from %s to %s", i, a[i].ID, b[i].ID)
		}
	}
}

// fixtures lists every fixture, for the tests that cover all rules.
var fixtures = []string{
	"crashloop.yaml", "oom.yaml", "imagepull.yaml", "unschedulable.yaml", "nodes.yaml", "node-condition.yaml",
	"pvc.yaml", "services.yaml", "dns-down.yaml", "dns-degraded.yaml", "config.yaml", "probes.yaml", "stuck.yaml",
	"addons.yaml", "volumes.yaml", "jobs.yaml", "network.yaml", "controlplane.yaml",
	"metrics-storage.yaml", "metrics-nodes.yaml", "metrics-workloads.yaml", "k0s-controllers.yaml", "k0s-versions.yaml", "k0s-update.yaml",
	"crashlog.yaml", "hygiene.yaml", "node-npd.yaml", "tls.yaml", "hpa-request.yaml", "k0s-monitoring.yaml", "k0s-addons.yaml", "alerts.yaml", "service-down.yaml", "kernel.yaml",
}

func TestControlPlaneHealth(t *testing.T) {
	fs := scan(t, "k0s-controllers.yaml")
	ready := find(t, fs, "apiserver.readyz", "controller/ctrl-2")
	if ready.Severity != findings.High || ready.Title != "API server on ctrl-2 not ready: poststarthook/start-apiextensions-controllers" {
		t.Errorf("readyz: %s %q", ready.Severity, ready.Title)
	}
	if !strings.Contains(ready.Remedy.LikelyCause, "hasn't finished starting") || fact(ready, "Controllers answering") != "1 of 2 are ready" {
		t.Errorf("readyz cause %q, facts %+v", ready.Remedy.LikelyCause, ready.Evidence)
	}
	for _, st := range ready.Remedy.Steps {
		if st.Host != "ctrl-2" {
			t.Errorf("the steps run on ctrl-2: %+v", st)
		}
	}
	absent(t, fs, "apiserver.readyz", "controller/ctrl-1")
	absent(t, fs, "apiserver.readyz", "controller/ctrl-3")

	if e := find(t, fs, "etcd.health", "controller/ctrl-2"); e.Severity != findings.High {
		t.Errorf("etcd on ctrl-2: %s", e.Severity)
	}
	db := find(t, fs, "etcd.health", "etcd/database")
	if db.Severity != findings.Critical || db.Title != "etcd database 90% of its quota (1.8 GiB of 2 GiB)" || fact(db, "Most objects") != "events 180000, replicasets.apps 4200, secrets 900" {
		t.Errorf("etcd size: %s %q %+v", db.Severity, db.Title, db.Evidence)
	}

	down := find(t, fs, "controllers.count", "controller/ctrl-3")
	if down.Severity != findings.High || down.Title != "Controller ctrl-3 not running (2 of 3 controllers run)" {
		t.Errorf("ctrl-3: %s %q", down.Severity, down.Title)
	}
	if fact(down, "Asking it directly") == "" {
		t.Errorf("the direct check is shown: %+v", down.Evidence)
	}
	old := find(t, fs, "controllers.count", "controller/ctrl-old")
	if old.Severity != findings.Low || !hasCommand(old, "kubectl -n kube-node-lease delete lease k0s-ctrl-ctrl-old") {
		t.Errorf("ctrl-old: %s %+v", old.Severity, old.Remedy.Steps)
	}
	absent(t, fs, "controllers.count", "controller/worker-1")

	cert := find(t, fs, "cert.expiry", "controller/ctrl-2")
	if cert.Severity != findings.Critical || cert.Title != "API server certificate on ctrl-2 expires in 5 days" || !hasCommand(cert, "sudo systemctl restart k0scontroller") {
		t.Errorf("cert: %s %q", cert.Severity, cert.Title)
	}
	if kc := find(t, fs, "cert.expiry", "kubeconfig/k0s-monitor"); kc.Severity != findings.Medium {
		t.Errorf("client cert: %s", kc.Severity)
	}
	absent(t, fs, "cert.expiry", "controller/ctrl-1")

	san := find(t, fs, "endpoint.tls-name", "controller/ctrl-2")
	if san.Title != "Certificate on ctrl-2 doesn't include api.shop.lan" || fact(san, "Names in its certificate") != "10.0.0.12, kubernetes, kubernetes.default.svc" {
		t.Errorf("tls name: %q %+v", san.Title, san.Evidence)
	}
	absent(t, fs, "endpoint.tls-name", "controller/ctrl-1")

	// The load balancer doesn't answer: everyone using it is cut off.
	lb := find(t, fs, "endpoint.fallback", "endpoint/api.shop.lan:6443")
	if lb.Severity != findings.High || lb.Title != "Cluster address api.shop.lan:6443 doesn't answer; the controllers do" ||
		!strings.Contains(lb.Summary, "doesn't answer: No answer from api.shop.lan on port 6443. The controllers run: k0s-monitor reads the cluster through ctrl-1 (10.0.0.11:6443).") {
		t.Errorf("fallback: %s %q %q", lb.Severity, lb.Title, lb.Summary)
	}
	if lb.Since == nil || now.Sub(*lb.Since) != 3*time.Minute || lb.Plain.Title != "The cluster's address doesn't answer" {
		t.Errorf("fallback since %v, plain %q", lb.Since, lb.Plain.Title)
	}

	// Clients that use ctrl-1's own address never reach ctrl-2 through it.
	s := load(t, "k0s-controllers.yaml")
	s.ControlPlane.Server = "10.0.0.11"
	s.Fallback = nil
	direct, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	absent(t, direct, "endpoint.tls-name", "controller/ctrl-2")
	absent(t, direct, "endpoint.fallback", "endpoint/api.shop.lan:6443")

	// A controller's own address that doesn't answer is only a note: the
	// controller's own problem says what is wrong.
	s.ControlPlane.Server = "10.0.0.13"
	s.Fallback = &snapshot.Fallback{Server: "10.0.0.13:6443", Error: "10.0.0.13 refused the connection on port 6443.",
		Controller: "ctrl-1", Address: "10.0.0.11:6443", Since: now.Add(-time.Minute)}
	own, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	ctl := find(t, own, "endpoint.fallback", "endpoint/10.0.0.13:6443")
	if ctl.Severity != findings.Low || ctl.Title != "Kubeconfig's controller 10.0.0.13:6443 doesn't answer; k0s-monitor uses ctrl-1" || ctl.Remedy.Steps[0].Host != "10.0.0.13" {
		t.Errorf("own address: %s %q %+v", ctl.Severity, ctl.Title, ctl.Remedy.Steps)
	}
}

func TestK0sVersions(t *testing.T) {
	fs := scan(t, "k0s-versions.yaml")
	drift := find(t, fs, "k0s.version-drift", "k0s/version")
	if drift.Severity != findings.Medium || drift.Title != "2 of 5 nodes run another k0s version than v1.36.4+k0s.1" {
		t.Errorf("drift: %s %q", drift.Severity, drift.Title)
	}
	if fact(drift, "Expected") != "v1.36.4+k0s.1 (k0sctl.yaml)" || fact(drift, "Runs v1.35.9+k0s") != "worker-2" || fact(drift, "Runs v1.36.3+k0s.0") != "ctrl-3" ||
		fact(drift, "On the expected version") != "3 of 5" || strings.Join(drift.Links.Nodes, ",") != "ctrl-3,worker-2" {
		t.Errorf("drift facts: %+v, nodes %v", drift.Evidence, drift.Links.Nodes)
	}
	if drift.Plain.Title != "2 servers run another version of the cluster software" || drift.Remedy.Steps[1].Host != "ctrl-3" {
		t.Errorf("drift plain %q, steps %+v", drift.Plain.Title, drift.Remedy.Steps)
	}
	failed := find(t, fs, "k0s.update-stuck", "plan/autopilot")
	if failed.Severity != findings.High || failed.Title != "k0s update to v1.36.4+k0s.1 failed on worker-2" ||
		fact(failed, "Nodes") != "3 updated, 1 failed" || fact(failed, "Plan") != "autopilot (failed)" {
		t.Errorf("failed: %s %q %+v", failed.Severity, failed.Title, failed.Evidence)
	}
	if fact(failed, "worker-2") != "the download failed" || failed.Remedy.LikelyCause != "worker-2 couldn't download the new k0s from https://updates.example.invalid/k0s-v1.36.4+k0s.1-amd64. Every node must reach that address." ||
		!hasCommand(failed, "curl -sSI --max-time 10 'https://updates.example.invalid/k0s-v1.36.4+k0s.1-amd64' | head -n 1") {
		t.Errorf("failed download: %+v, cause %q", failed.Evidence, failed.Remedy.LikelyCause)
	}
	if !hasCommand(failed, "sudo journalctl -u k0sworker -n 200 --no-pager | grep -iE 'autopilot|update|error'") || failed.Plain.Title != "An update of the cluster software didn't finish" {
		t.Errorf("failed steps %+v, plain %q", failed.Remedy.Steps, failed.Plain.Title)
	}

	// Without a version set, the one most controllers run is expected.
	s := load(t, "k0s-versions.yaml")
	s.ExpectedK0s = nil
	s.ControlPlane.Plans = nil
	fs, _ = fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if d := find(t, fs, "k0s.version-drift", "k0s/version"); fact(d, "Expected") != "v1.36.4+k0s.1 (the version most controllers run)" {
		t.Errorf("majority: %+v", d.Evidence)
	}
	absent(t, fs, "k0s.update-stuck", "plan/autopilot")

	// The whole cluster on another version than set.
	s = load(t, "k0s-versions.yaml")
	s.ExpectedK0s = &snapshot.ExpectedK0s{Version: "v1.37.0+k0s.0", From: "the configuration file"}
	s.Nodes, s.ControlPlane.Controllers, s.ControlPlane.Plans = s.Nodes[1:2], s.ControlPlane.Controllers[:2], nil
	fs, _ = fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if d := find(t, fs, "k0s.version-drift", "k0s/version"); d.Title != "Cluster runs k0s v1.36.4+k0s.1, not v1.37.0+k0s.0" || fact(d, "Runs v1.36.4+k0s.1") != "ctrl-1, ctrl-2, worker-1" ||
		d.Plain.WhatHappened != "Every server runs version 1.36.4, but 1.37.0 is expected." {
		t.Errorf("whole cluster: %q %+v %q", d.Title, d.Evidence, d.Plain.WhatHappened)
	}

	// A plan that couldn't start, or names nodes that are gone.
	s = load(t, "k0s-versions.yaml")
	s.ControlPlane.Plans[0].State = snapshot.PlanWarning
	s.ControlPlane.Plans[0].Commands[0].Description = "version skew too large"
	fs, _ = fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if w := find(t, fs, "k0s.update-stuck", "plan/autopilot"); w.Title != "k0s update to v1.36.4+k0s.1 refused: version skew too large" {
		t.Errorf("refused: %q", w.Title)
	}
	s.ControlPlane.Plans[0].State = snapshot.PlanIncompleteTargets
	s.ControlPlane.Plans[0].Commands[0].Targets[3].State = snapshot.SignalMissingNode
	fs, _ = fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if m := find(t, fs, "k0s.update-stuck", "plan/autopilot"); m.Title != "k0s update to v1.36.4+k0s.1 can't finish: worker-2 missing" {
		t.Errorf("missing: %q", m.Title)
	}
	// A completed plan is quiet.
	s.ControlPlane.Plans[0].State = snapshot.PlanCompleted
	fs, _ = fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	absent(t, fs, "k0s.update-stuck", "plan/autopilot")
}

func TestK0sUpdateRunning(t *testing.T) {
	fs := scan(t, "k0s-update.yaml")
	// Nodes differ while the update runs.
	absent(t, fs, "k0s.version-drift", "k0s/version")
	stuck := find(t, fs, "k0s.update-stuck", "plan/autopilot")
	if stuck.Title != "k0s update to v1.36.4+k0s.1 stuck on ctrl-2 for 45 min" || stuck.Since == nil || !stuck.Since.Equal(now.Add(-45*time.Minute)) ||
		fact(stuck, "Nodes") != "1 updated, 1 updating, 1 waiting" || stuck.Plain.Title != "An update of the cluster software is stuck" {
		t.Errorf("stuck: %q since %v %+v %q", stuck.Title, stuck.Since, stuck.Evidence, stuck.Plain.Title)
	}
	if !hasCommand(stuck, "sudo journalctl -u k0scontroller -n 200 --no-pager | grep -iE 'autopilot|update|error'") || fact(stuck, "ctrl-2") != "restarting k0s" {
		t.Errorf("stuck steps: %+v", stuck.Remedy.Steps)
	}
	if ns := find(t, fs, "k0s.update-stuck", "plan/product-hotfix"); ns.Title != "k0s update to v1.36.4+k0s.1 hasn't started in 2 h" {
		t.Errorf("not started: %q", ns.Title)
	}
	// Within the time a node may take, nothing is stuck yet.
	s := load(t, "k0s-update.yaml")
	th := config.DefaultThresholds()
	th.UpdateStuckAfter = config.Duration(3 * time.Hour)
	fs, _ = fleet.EvaluateSnapshot(s, th, "")
	absent(t, fs, "k0s.update-stuck", "plan/autopilot")
	absent(t, fs, "k0s.update-stuck", "plan/product-hotfix")
}

func TestEveryRuleIsCovered(t *testing.T) {
	seen := map[string]bool{}
	for _, file := range fixtures {
		for _, f := range scan(t, file) {
			seen[f.RuleID] = true
		}
	}
	for _, r := range rules.All() {
		if !seen[r.ID] {
			t.Errorf("rule %s (%s) has no finding in any fixture", r.ID, r.Code)
		}
	}
}

func TestEveryRuleHasBothTexts(t *testing.T) {
	for _, file := range fixtures {
		for _, f := range scan(t, file) {
			if f.Title == "" || f.Summary == "" {
				t.Errorf("%s %s: missing Full-mode title or summary", f.RuleID, f.Resource.String())
			}
			if f.Plain.Title == "" || f.Plain.WhatHappened == "" || f.Plain.WhatToDo == "" {
				t.Errorf("%s %s: missing Basic-mode text: %+v", f.RuleID, f.Resource.String(), f.Plain)
			}
			if len(f.Remedy.Steps) == 0 {
				t.Errorf("%s %s: no fix steps", f.RuleID, f.Resource.String())
			}
			for _, st := range f.Remedy.Steps {
				if findings.K0sKubectl(st.Command) != st.Command {
					t.Errorf("%s %s: a command calls kubectl without k0s: %s", f.RuleID, f.Resource.String(), st.Command)
				}
			}
		}
	}
}

func TestPodsWaitingForSickNodes(t *testing.T) {
	fs := scan(t, "node-condition.yaml")
	disk := find(t, fs, "node.pressure", "node/worker-1")
	down := find(t, fs, "node.not-ready", "node/worker-2")

	web := find(t, fs, "pod.unschedulable", "shop/deployment/web")
	if web.ParentID != disk.ID {
		t.Errorf("web waits only for worker-1's disk: parent = %q, want %q", web.ParentID, disk.ID)
	}
	if web.Title != "Unschedulable for 20 min: waiting for node worker-1 to recover (1 of 1 pods)" {
		t.Errorf("title = %q", web.Title)
	}
	if got := fact(web, "Waiting for"); got != "worker-1 (node.kubernetes.io/disk-pressure)" {
		t.Errorf("waiting-for fact = %q", got)
	}
	if web.Plain.Why != "The servers that could run it are low on disk space." {
		t.Errorf("plain why = %q", web.Plain.Why)
	}
	if w12 := find(t, fs, "deploy.unavailable", "shop/deployment/web"); w12.ParentID != disk.ID {
		t.Errorf("web's outage should end up under the disk problem, parent = %q", w12.ParentID)
	}

	never := find(t, fs, "node.not-ready", "node/worker-4")
	agent := find(t, fs, "pod.unschedulable", "kube-system/daemonset/agent")
	if agent.ParentID != down.ID && agent.ParentID != never.ID {
		t.Errorf("the DaemonSet pods wait for worker-2 and worker-4: parent = %q", agent.ParentID)
	}
	if got := fact(agent, "Waiting for"); got != "worker-2, worker-4 (node.kubernetes.io/unreachable)" {
		t.Errorf("waiting-for fact = %q", got)
	}
	if !strings.Contains(agent.Title, "waiting for 2 nodes to recover") || agent.Plain.Why != "The servers that could run it are not working." {
		t.Errorf("agent title %q, plain why %q", agent.Title, agent.Plain.Why)
	}

	big := find(t, fs, "pod.unschedulable", "ml/pod/big")
	if big.ParentID != "" || len(big.Links.BlockedBy) != 0 {
		t.Errorf("big waits for CPU on the healthy worker-3 and must stay a root cause: parent %q, blocked by %v", big.ParentID, big.Links.BlockedBy)
	}
	if !strings.Contains(big.Title, "not enough free cpu") {
		t.Errorf("big title = %q", big.Title)
	}
}

func TestConfigErrors(t *testing.T) {
	fs := scan(t, "config.yaml")
	web := find(t, fs, "pod.config-error", "shop/deployment/web")
	// Critical (all replicas down) 60 + all down 20.
	expect(t, web, findings.Critical, 80, findings.P1)
	if web.Title != `CreateContainerConfigError: key "DB_PASSWORD" is missing in Secret web-secrets (2 of 2 pods)` {
		t.Errorf("title = %q", web.Title)
	}
	if !hasCommand(web, "kubectl -n shop describe secret web-secrets") {
		t.Errorf("the step must list the Secret's keys without values: %+v", web.Remedy.Steps)
	}
	if w12 := find(t, fs, "deploy.unavailable", "shop/deployment/web"); w12.ParentID != web.ID {
		t.Errorf("the outage should fold under the config error")
	}
	worker := find(t, fs, "pod.config-error", "billing/statefulset/worker")
	if worker.Title != "CreateContainerConfigError: ConfigMap worker-config not found (1 pod)" || worker.Plain.Title != "The app worker can't start: its settings are missing" {
		t.Errorf("title %q, plain %q", worker.Title, worker.Plain.Title)
	}

	gw := find(t, fs, "pod.run-error", "edge/deployment/sensor-gw")
	if !strings.HasPrefix(gw.Title, "exec format error: image registry.local/sensor-gw:3.1 is not built for arm64") {
		t.Errorf("title = %q", gw.Title)
	}
	if fact(gw, "Node") != "edge-1 (arm64)" {
		t.Errorf("node fact = %q", fact(gw, "Node"))
	}
	absent(t, fs, "pod.crashloop", "")
}

func TestProbes(t *testing.T) {
	fs := scan(t, "probes.yaml")
	cart := find(t, fs, "pod.not-ready", "shop/deployment/cart")
	// High (no replica ready) 45 + all down 20 = 65, raised to the 80 of the
	// Deployment outage folded under it.
	expect(t, cart, findings.High, 80, findings.P1)
	if !strings.Contains(cart.Title, "Readiness probe failed: HTTP probe failed with statuscode: 503") {
		t.Errorf("title = %q", cart.Title)
	}
	if fact(cart, "Readiness probe") != "HTTP GET /healthz on port 8080, initial delay 0s, every 10s, timeout 1s, 3 failures" {
		t.Errorf("probe fact = %q", fact(cart, "Readiness probe"))
	}

	search := find(t, fs, "pod.probe-kills", "shop/statefulset/search")
	expect(t, search, findings.High, 45, findings.P3)
	if fact(search, "Startup probe") != "none" || !strings.HasPrefix(search.Title, "Restarted by its liveness probe") {
		t.Errorf("title %q, facts %+v", search.Title, search.Evidence)
	}
	absent(t, fs, "pod.crashloop", "")
	absent(t, fs, "pod.not-ready", "shop/statefulset/search")
}

func TestStuckPods(t *testing.T) {
	fs := scan(t, "stuck.yaml")
	creating := find(t, fs, "pod.stuck-creating", "shop/pod/report-gen")
	if creating.Severity != findings.Medium || creating.Links.Cause != "unknown" {
		t.Errorf("severity %s, cause %q", creating.Severity, creating.Links.Cause)
	}
	fin := find(t, fs, "pod.stuck-terminating", "shop/pod/old-web")
	if fin.Title != "Terminating for 40 min: waiting for finalizer example.com/cleanup (1 pod)" || fin.ParentID != "" {
		t.Errorf("title %q, parent %q", fin.Title, fin.ParentID)
	}
	gone := find(t, fs, "pod.stuck-terminating", "shop/deployment/api")
	node := find(t, fs, "node.not-ready", "node/worker-3")
	if gone.ParentID != node.ID || !hasCommand(gone, "--grace-period=0 --force") {
		t.Errorf("a pod on a dead node folds under it and may be force-deleted: parent %q, steps %+v", gone.ParentID, gone.Remedy.Steps)
	}
}

func TestAddons(t *testing.T) {
	fs := scan(t, "addons.yaml")
	loop := find(t, fs, "pod.crashloop", "kube-system/daemonset/kube-router")
	cni := find(t, fs, "cni.unhealthy", "kube-system/daemonset/kube-router")
	// Critical 60 + kube-system 10.
	expect(t, cni, findings.Critical, 70, findings.P2)
	if cni.ParentID != loop.ID || loop.Score != 70 {
		t.Errorf("the network plugin is down because its pod crashes: parent %q, root score %d", cni.ParentID, loop.Score)
	}
	if cni.Title != "kube-router not working on node worker-2 (CrashLoopBackOff)" {
		t.Errorf("title = %q", cni.Title)
	}
	for _, sym := range []*findings.Finding{
		find(t, fs, "pod.stuck-creating", "shop/pod/web-4b5c6d7e8f-n1"),
		find(t, fs, "node.network-unavailable", "node/worker-2"),
	} {
		if sym.ParentID != loop.ID {
			t.Errorf("%s should end up under the network plugin's problem, parent = %q", sym.RuleID, sym.ParentID)
		}
	}
	if fact(cni, "Network error") == "" {
		t.Errorf("the sandbox error should be evidence")
	}

	konn := find(t, fs, "konnectivity.agent-down", "kube-system/daemonset/konnectivity-agent")
	expect(t, konn, findings.High, 55, findings.P2)
	if !strings.HasPrefix(fact(konn, "Nodes"), "1 of 3: worker-3: no pod") || !hasCommand(konn, "nc -vz <controller address> 8132") {
		t.Errorf("nodes fact %q, steps %+v", fact(konn, "Nodes"), konn.Remedy.Steps)
	}
	proxy := find(t, fs, "kube-proxy.unhealthy", "kube-system/daemonset/kube-proxy")
	if proxy.Links.Nodes[0] != "worker-1" {
		t.Errorf("kube-proxy nodes = %v", proxy.Links.Nodes)
	}

	cordon := find(t, fs, "node.cordoned-long", "node/worker-3")
	// Low 15 + system 10.
	expect(t, cordon, findings.Low, 25, findings.P3)
	if cordon.Title != "Cordoned for 3 days" || !hasCommand(cordon, "kubectl uncordon worker-3") {
		t.Errorf("title %q", cordon.Title)
	}
}

func TestVolumesAndSets(t *testing.T) {
	fs := scan(t, "volumes.yaml")
	s05 := find(t, fs, "volume.mount-failure", "shop/persistentvolumeclaim/data-db-1")
	// High 45 + blocks a workload 12.
	expect(t, s05, findings.High, 57, findings.P2)
	if s05.Title != "Multi-Attach error: the volume is still attached to another node" || fact(s05, "Volume") != "pvc-5b1d" {
		t.Errorf("title %q, volume %q", s05.Title, fact(s05, "Volume"))
	}
	sts := find(t, fs, "sts.unavailable", "shop/statefulset/db")
	if sts.Title != "1 of 3 replicas ready, db-2 waits for db-1" {
		t.Errorf("title = %q", sts.Title)
	}
	for _, sym := range []*findings.Finding{sts, find(t, fs, "pod.stuck-creating", "shop/statefulset/db")} {
		if sym.ParentID != s05.ID {
			t.Errorf("%s should end up under the volume problem, parent = %q", sym.RuleID, sym.ParentID)
		}
	}
	ds := find(t, fs, "ds.unavailable", "logging/daemonset/fluent-bit")
	w09 := find(t, fs, "pod.not-ready", "logging/daemonset/fluent-bit")
	if ds.ParentID != w09.ID || ds.Title != "1 of 2 nodes without a ready pod" {
		t.Errorf("parent %q, title %q", ds.ParentID, ds.Title)
	}
}

func TestJobs(t *testing.T) {
	fs := scan(t, "jobs.yaml")
	job := find(t, fs, "job.failed", "ops/job/migrate-v3")
	expect(t, job, findings.Medium, 30, findings.P3)
	if !strings.Contains(job.Title, "container migrate exited with code 2") {
		t.Errorf("title = %q", job.Title)
	}
	failing := find(t, fs, "cronjob.failing", "ops/cronjob/nightly-report")
	if fact(failing, "Failed runs in a row") != "2 (of the runs Kubernetes keeps)" || fact(failing, "Last success") != "2 days ago" {
		t.Errorf("facts = %+v", failing.Evidence)
	}
	if !hasCommand(failing, "kubectl -n ops logs nightly-report-29311560-q8") {
		t.Errorf("missing log step: %+v", failing.Remedy.Steps)
	}
	missed := find(t, fs, "cronjob.missed", "ops/cronjob/sync-hourly")
	if missed.Title != "Missed its schedule: expected a run 2 h ago, last run 3 h ago" || !strings.Contains(missed.Remedy.LikelyCause, "concurrencyPolicy Forbid") {
		t.Errorf("title %q, cause %q", missed.Title, missed.Remedy.LikelyCause)
	}
	absent(t, fs, "cronjob.missed", "ops/cronjob/nightly-report")
	absent(t, fs, "cronjob.failing", "ops/cronjob/sync-hourly")
}

func TestIngressAndLoadBalancer(t *testing.T) {
	fs := scan(t, "network.yaml")
	ing := find(t, fs, "ingress.backend-missing", "shop/ingress/storefront")
	// Medium 30 + exposed 5.
	expect(t, ing, findings.Medium, 35, findings.P3)
	want := "Service api-gw does not exist; Service images has no port http (it has 80/TCP)"
	if fact(ing, "Problems") != want {
		t.Errorf("problems = %q", fact(ing, "Problems"))
	}
	lb := find(t, fs, "lb.pending", "shop/service/public-lb")
	if fact(lb, "Reachable meanwhile") != "node port 31443 on any node" {
		t.Errorf("facts = %+v", lb.Evidence)
	}
	absent(t, fs, "lb.pending", "shop/service/new-lb")
	absent(t, fs, "svc.no-endpoints", "")
}

func TestControlPlane(t *testing.T) {
	fs := scan(t, "controlplane.yaml")
	loop := find(t, fs, "pod.crashloop", "policy/deployment/policy-webhook")
	hook := find(t, fs, "webhook.blocking", "validatingwebhookconfiguration/policy-guard")
	// Critical 60 + blocks deployments cluster-wide 25 + system 10.
	expect(t, hook, findings.Critical, 95, findings.P1)
	if hook.ParentID != loop.ID || loop.Score != 95 {
		t.Errorf("the webhook is down because its app crashes: parent %q, root score %d", hook.ParentID, loop.Score)
	}
	if got := fact(loop, "Priority"); !strings.HasPrefix(got, "raised to P1 by webhook.blocking") {
		t.Errorf("priority fact = %q", got)
	}
	if svc := find(t, fs, "svc.no-endpoints", "policy/service/policy-webhook"); svc.ParentID != loop.ID {
		t.Errorf("the webhook Service should end up under the crash loop")
	}
	absent(t, fs, "webhook.blocking", "mutatingwebhookconfiguration/soft-defaults")

	api := find(t, fs, "apiservice.unavailable", "apiservice/v1beta1.metrics.k8s.io")
	expect(t, api, findings.High, 55, findings.P2)
	if !strings.Contains(api.Plain.WhatHappened, "metrics-server") {
		t.Errorf("plain = %q", api.Plain.WhatHappened)
	}
	ns := find(t, fs, "ns.stuck-terminating", "namespace/old-project")
	if ns.ParentID != api.ID || ns.Title != "Terminating for 3 h: an aggregated API is unavailable" {
		t.Errorf("parent %q, title %q", ns.ParentID, ns.Title)
	}
	if svc := find(t, fs, "svc.no-endpoints", "kube-system/service/metrics-server"); svc.ParentID != api.ID {
		t.Errorf("the metrics Service should fold under the API problem")
	}
	absent(t, fs, "apiservice.unavailable", "apiservice/v1.apps")
}

func TestVolumeForecast(t *testing.T) {
	fs := scan(t, "metrics-storage.yaml")
	db := find(t, fs, "pvc.fill-forecast", "shop/persistentvolumeclaim/data-db")
	// Critical 60 + blocks its pod 12 + full within 6 h 10.
	expect(t, db, findings.Critical, 82, findings.P1)
	if db.Impact.BreachIn < 4*time.Hour || db.Impact.BreachIn > 5*time.Hour {
		t.Errorf("breach in %s, want 0.7 GiB at 150 MiB/h, about 4.8 h", db.Impact.BreachIn)
	}
	if db.Title != "Full in about 4 h at 150 MiB per hour (now 93%)" {
		t.Errorf("title = %q", db.Title)
	}
	if db.Plain.Title != "The storage of db will be full in about 4 hours" {
		t.Errorf("plain title = %q", db.Plain.Title)
	}
	if got := fact(db, "Change"); got != "growing 8× faster than its 7-day average" {
		t.Errorf("the jump against the baseline should be shown, got %q", got)
	}
	if !hasCommand(db, "kubectl -n shop exec db-0 -- du -xsh /var/lib/postgresql/data/*") {
		t.Errorf("missing the step that finds what grows: %+v", db.Remedy.Steps)
	}
	if u := find(t, fs, "pvc.usage", "shop/persistentvolumeclaim/data-db"); u.ParentID != db.ID {
		t.Errorf("the usage finding should fold under the forecast, parent = %q", u.ParentID)
	}

	uploads := find(t, fs, "pvc.usage", "shop/persistentvolumeclaim/uploads")
	expect(t, uploads, findings.Medium, 30, findings.P3)
	if uploads.Title != "82% full: 8.2 GiB of 10 GiB used" || uploads.ParentID != "" {
		t.Errorf("title %q, parent %q", uploads.Title, uploads.ParentID)
	}
	absent(t, fs, "pvc.fill-forecast", "shop/persistentvolumeclaim/uploads")

	journal := find(t, fs, "pvc.usage", "logs/persistentvolumeclaim/journal")
	if journal.Severity != findings.High || journal.Title != "91% of its inodes used (20% of the space)" {
		t.Errorf("inodes: severity %s, title %q", journal.Severity, journal.Title)
	}
	absent(t, fs, "pvc.usage", "shop/persistentvolumeclaim/reports")
	// A few bytes an hour, steadily: no forecast (it once read "full in 0 s").
	absent(t, fs, "pvc.fill-forecast", "shop/persistentvolumeclaim/reports")

	released := find(t, fs, "pv.released", "persistentvolume/pvc-old-1")
	expect(t, released, findings.Low, 15, findings.P4)
	if !hasCommand(released, "kubectl delete pv pvc-old-1") {
		t.Errorf("missing delete step: %+v", released.Remedy.Steps)
	}
	resize := find(t, fs, "pvc.resize-stuck", "shop/persistentvolumeclaim/reports")
	if !hasCommand(resize, "kubectl -n shop delete pod report-0") {
		t.Errorf("the resize finishes when the pod restarts: %+v", resize.Remedy.Steps)
	}
}

func TestNodeAndVMHealth(t *testing.T) {
	fs := scan(t, "metrics-nodes.yaml")
	disk := find(t, fs, "node.fs-high", "node/worker-1")
	// Critical 60 + a node 10.
	expect(t, disk, findings.Critical, 70, findings.P2)
	if disk.Title != "Disk 91% full on /var/lib/k0s: 18 GiB free" {
		t.Errorf("the kubelet's disk is the one holding /var/lib/k0s, title = %q", disk.Title)
	}
	if !hasCommand(disk, "crictl --runtime-endpoint unix:///run/k0s/containerd.sock rmi --prune") {
		t.Errorf("missing image prune step: %+v", disk.Remedy.Steps)
	}
	if p := find(t, fs, "node.pressure", "node/worker-1"); p.ParentID != disk.ID {
		t.Errorf("DiskPressure should fold under the full disk, parent = %q", p.ParentID)
	}
	host := find(t, fs, "vm.host-fs", "node/worker-1")
	if host.Title != "Host disk / 85% full: 6 GiB free" {
		t.Errorf("host title = %q", host.Title)
	}

	steal := find(t, fs, "vm.cpu-steal", "node/worker-2")
	expect(t, steal, findings.High, 55, findings.P2)
	if got := fact(steal, "CPU steal (5 min)"); got != "31%" {
		t.Errorf("steal fact = %q", got)
	}
	for rule, title := range map[string]string{
		"vm.iowait":       "Slow disk: 200 ms per operation on sda",
		"vm.clock-skew":   "Clock 2.5 s off and not synchronized",
		"vm.memory":       "Swap 70% used",
		"vm.reboot":       "Rebooted 2 h ago",
		"node.saturation": "CPU 93% busy for 15 min",
	} {
		if f := find(t, fs, rule, "node/worker-2"); f.Title != title {
			t.Errorf("%s title = %q, want %q", rule, f.Title, title)
		}
	}
	for rule, title := range map[string]string{
		"node.inodes-high":   "Inodes 92% used on /",
		"node.overcommit":    "memory requests 100% of allocatable",
		"node.pods-near-max": "4 of 4 pods: the node is almost at its pod limit",
	} {
		if f := find(t, fs, rule, "node/worker-3"); f.Title != title {
			t.Errorf("%s title = %q, want %q", rule, f.Title, title)
		}
	}
	// worker-1 and worker-3 are healthy VMs.
	absent(t, fs, "vm.cpu-steal", "node/worker-1")
	absent(t, fs, "vm.cpu-steal", "node/worker-3")
	absent(t, fs, "node.fs-high", "node/worker-3")
}

func TestCapacityRules(t *testing.T) {
	fs := scan(t, "metrics-workloads.yaml")
	api := find(t, fs, "apiservice.unavailable", "apiservice/v1beta1.metrics.k8s.io")
	if f := find(t, fs, "hpa.no-metrics", "shop/horizontalpodautoscaler/api"); f.ParentID != api.ID {
		t.Errorf("the autoscaler can't read metrics because the metrics API is down, parent = %q", f.ParentID)
	}

	if f := find(t, fs, "hpa.no-metrics", "shop/horizontalpodautoscaler/api"); !strings.Contains(f.Remedy.LikelyCause, "metrics-server") || !hasCommand(f, "get apiservice") {
		t.Errorf("metrics API down: cause %q", f.Remedy.LikelyCause)
	}

	maxed := find(t, fs, "hpa.maxed", "shop/horizontalpodautoscaler/web")
	if maxed.Title != "At its maximum of 10 replicas for 1 h" || !hasCommand(maxed, `"maxReplicas":16`) {
		t.Errorf("title %q, steps %+v", maxed.Title, maxed.Remedy.Steps)
	}

	quota := find(t, fs, "quota.exhausted", "shop/resourcequota/shop-quota")
	expect(t, quota, findings.High, 45, findings.P3)
	if !strings.Contains(fact(quota, "Refused"), "exceeded quota: shop-quota") {
		t.Errorf("the refused create should be shown, got %q", fact(quota, "Refused"))
	}

	cache := find(t, fs, "container.near-limit", "shop/deployment/cache")
	if !hasCommand(cache, "kubectl -n shop set resources deploy/cache -c redis --limits=memory=768Mi,cpu=750m") {
		t.Errorf("missing raise-limits step: %+v", cache.Remedy.Steps)
	}

	spike := find(t, fs, "events.warning-spike", "cluster/test")
	if spike.Title != "Warning events jumped: 37 in the last 10 min, usually 1" {
		t.Errorf("title = %q", spike.Title)
	}
	if got := fact(spike, "Top reasons"); got != "Unhealthy 24, BackOff 12, FailedCreate 1" {
		t.Errorf("top reasons = %q", got)
	}
}

// With Prometheus history, the OOM finding suggests a limit from the
// highest use seen instead of a flat 1.5 times the limit, and the
// near-limit warning for the same app folds under it.
func TestOOMKilledWithPeakMemory(t *testing.T) {
	s := load(t, "oom.yaml")
	s.Metrics = &snapshot.Metrics{Source: "test", At: now, Have: map[string]bool{"cadvisor": true},
		Containers: map[string]*snapshot.ContainerMetrics{
			"batch/report-worker-5d8f-aaaaa/worker": {WorkingSet: 500 << 20, PeakWorkingSet7d: 700 << 20, Throttled: snapshot.Missing},
		}}
	fs, skipped := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if len(skipped) > 0 {
		t.Fatalf("unexpected skipped rules: %+v", skipped)
	}
	w02 := find(t, fs, "pod.oomkilled", "batch/deployment/report-worker")
	if got := fact(w02, "Peak memory (7 days)"); got != "700 MiB" {
		t.Errorf("peak fact = %q", got)
	}
	// 1.5 × 700 MiB, rounded up to 64 MiB.
	if !hasCommand(w02, "set resources deploy/report-worker -c worker --limits=memory=1088Mi") {
		t.Errorf("the suggestion should come from the peak: %+v", w02.Remedy.Steps)
	}
	if near := find(t, fs, "container.near-limit", "batch/deployment/report-worker"); near.ParentID != w02.ID {
		t.Errorf("near-limit should fold under the OOM kills, parent = %q", near.ParentID)
	}
}

func TestMetricRulesNeedMetrics(t *testing.T) {
	s := load(t, "metrics-storage.yaml")
	delete(s.Available, snapshot.KindMetrics)
	fs, skipped := rules.Evaluate(s, config.DefaultThresholds())
	reasons := map[string]string{}
	for _, sk := range skipped {
		reasons[sk.RuleID] = sk.Reason
	}
	for _, id := range []string{"pvc.usage", "pvc.fill-forecast", "node.fs-high", "vm.cpu-steal"} {
		if reasons[id] != "needs metrics from Prometheus, which are not available" {
			t.Errorf("%s skip reason = %q", id, reasons[id])
		}
	}
	// Rules that read only the API still run.
	if _, ok := reasons["pv.released"]; ok {
		t.Errorf("pv.released needs no metrics")
	}
	find(t, fs, "pv.released", "persistentvolume/pvc-old-1")

	// A cluster without Prometheus data has no metric findings at all.
	for _, f := range scan(t, "crashloop.yaml") {
		if strings.HasPrefix(f.RuleID, "vm.") || f.RuleID == "pvc.usage" || f.RuleID == "node.fs-high" {
			t.Errorf("unexpected %s without metrics", f.RuleID)
		}
	}
}

func TestCrashExplainedByItsLog(t *testing.T) {
	fs := scan(t, "crashlog.yaml")
	db := find(t, fs, "pod.crashloop", "shop/statefulset/postgres")
	if !strings.HasSuffix(db.Title, ": Permission denied: /var/lib/postgresql/data") {
		t.Errorf("postgres title = %q", db.Title)
	}
	if !strings.Contains(db.Remedy.LikelyCause, "runAsUser or fsGroup") || db.Plain.Why != "The app isn't allowed to open /var/lib/postgresql/data." {
		t.Errorf("postgres cause = %q, plain why = %q", db.Remedy.LikelyCause, db.Plain.Why)
	}
	if !strings.Contains(db.Remedy.Steps[0].Text, "fsGroup") {
		t.Errorf("first step = %+v", db.Remedy.Steps[0])
	}
	if got := fact(db, "Log says"); !strings.Contains(got, "has wrong ownership") {
		t.Errorf("log fact = %q", got)
	}
	if db.Rollout != nil {
		t.Errorf("a StatefulSet has no rollout: %+v", db.Rollout)
	}

	// orders can't reach postgres, which crashes itself: postgres is the
	// cause of both.
	orders := find(t, fs, "pod.crashloop", "shop/deployment/orders")
	if !strings.HasSuffix(orders.Title, ": Connection refused by 10.96.14.2:5432") {
		t.Errorf("orders title = %q", orders.Title)
	}
	if got := fact(orders, "Depends on"); got != "Service shop/postgres" {
		t.Errorf("depends on = %q", got)
	}
	if got := fact(orders, "Log says"); !strings.Contains(got, "(2 such lines)") {
		t.Errorf("log fact = %q", got)
	}
	if !hasCommand(orders, "kubectl -n shop get endpointslices -l kubernetes.io/service-name=postgres") {
		t.Errorf("steps = %+v", orders.Remedy.Steps)
	}
	if orders.Rollout != nil {
		t.Errorf("an update 17 days ago is blamed: %+v", orders.Rollout)
	}
	for _, sym := range []*findings.Finding{orders, find(t, fs, "svc.no-endpoints", "shop/service/postgres")} {
		if sym.ParentID != db.ID {
			t.Errorf("%s %s: parent %q, want postgres's crash", sym.RuleID, sym.Resource.String(), sym.ParentID)
		}
	}

	// mailer: a name that doesn't resolve, with CoreDNS fine.
	mailer := find(t, fs, "pod.crashloop", "shop/deployment/mailer")
	if !strings.HasSuffix(mailer.Title, ": Name not found: smtp-relay") || mailer.ParentID != "" {
		t.Errorf("mailer title = %q, parent %q", mailer.Title, mailer.ParentID)
	}
	if got := fact(mailer, "Also in the log"); got != "Go panic: no mail relay" {
		t.Errorf("also = %q", got)
	}
	if !hasCommand(mailer, "kubectl -n shop get services") || mailer.Rollout != nil {
		t.Errorf("mailer steps = %+v, rollout %+v", mailer.Remedy.Steps, mailer.Rollout)
	}
}

func TestCrashAfterAnUpdate(t *testing.T) {
	fs := scan(t, "crashlog.yaml")
	web := find(t, fs, "pod.crashloop", "shop/deployment/web")
	if !strings.HasSuffix(web.Title, ": Setting DATABASE_URL is missing") {
		t.Errorf("title = %q", web.Title)
	}
	r := web.Rollout
	if r == nil || r.Revision != 5 || r.Previous != 4 || !r.At.Equal(now.Add(-20*time.Minute)) {
		t.Fatalf("rollout = %+v", r)
	}
	var changes []string
	for _, c := range r.Changes {
		changes = append(changes, c.String())
	}
	want := []string{
		"web: image shop/web:1.4.0 → shop/web:1.5.0",
		"web: env API_KEY changed (value hidden)",
		"web: env DATABASE_URL removed (was postgres://web@postgres:5432/web)",
	}
	if strings.Join(changes, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n%s", strings.Join(changes, "\n"))
	}
	if got := fact(web, "Started with"); got != "the update to revision 5, 20 min ago" {
		t.Errorf("started with = %q", got)
	}
	if !strings.Contains(web.Remedy.LikelyCause, "DATABASE_URL") || !strings.Contains(web.Remedy.LikelyCause, "Every failing pod comes from the update 20 min ago (revision 5)") {
		t.Errorf("likely cause = %q", web.Remedy.LikelyCause)
	}
	first := web.Remedy.Steps[0]
	if first.Command != "k0s kubectl -n shop rollout undo deploy/web --to-revision=4" || !strings.Contains(first.Text, "Helm") {
		t.Errorf("first step = %+v", first)
	}
	if hasCommand(web, "rollout history") {
		t.Errorf("the generic undo step stays: %+v", web.Remedy.Steps)
	}
	if !strings.HasPrefix(web.Plain.WhatToDo, "Undo that update first (step 1)") || !strings.Contains(web.Plain.WhatToDo, "must add the setting DATABASE_URL") ||
		!strings.Contains(web.Plain.Why, "updated 20 minutes ago") || !strings.Contains(first.Plain, "Helm or Argo CD") {
		t.Errorf("plain = %+v", web.Plain)
	}
	for _, s := range append(changes, web.Remedy.LikelyCause, fact(web, "Log says")) {
		if strings.Contains(s, "sk-") || strings.Contains(s, "hunter22") {
			t.Errorf("a secret shows: %s", s)
		}
	}
}

func TestHygiene(t *testing.T) {
	fs := scan(t, "hygiene.yaml")
	for _, c := range []struct{ rule, title, fact, want string }{
		{"hygiene.no-limits", "1 workload in shop runs containers without a memory limit or requests", "Workloads", "deploy/api (api: no memory limit, no requests)"},
		{"hygiene.no-probes", "1 workload in shop has containers without health checks (probes)", "Workloads", "deploy/api (api, behind Service api)"},
		{"hygiene.latest-tag", "2 workloads in shop use images without a fixed version (latest)", "Workloads", "deploy/api (api: registry.local/shop/api); ds/agent (setup: busybox:latest)"},
		{"hygiene.pdb-blocks-drain", "1 disruption budget in shop allows no pod to be stopped", "Disruption budgets", "pdb/api (minAvailable 1 with 1 pod, deploy/api)"},
		{"hygiene.privileged", "1 workload in shop runs privileged containers", "Workloads", "ds/agent (agent)"},
		{"hygiene.finished-pods", "1 pod in shop finished more than 7 days ago", "Pods", "web-6c7d8e9f0-old11 (Evicted, 10 days ago)"},
	} {
		f := find(t, fs, c.rule, "namespace/shop")
		if f.Title != c.title {
			t.Errorf("%s: title %q", c.rule, f.Title)
		}
		if got := fact(f, c.fact); got != c.want {
			t.Errorf("%s: %s = %q, want %q", c.rule, c.fact, got, c.want)
		}
		if f.Category != findings.Hygiene || f.Priority != findings.P4 || f.ParentID != "" {
			t.Errorf("%s: category %s, priority %s, parent %q", c.rule, f.Category, f.Priority, f.ParentID)
		}
	}
	// k0s's own CoreDNS is left out, and nothing is reported about it.
	for _, f := range fs {
		if f.IsHygiene() && f.Resource.Name == "kube-system" {
			t.Errorf("%s about kube-system: %s", f.RuleID, fact(f, "Workloads"))
		}
	}
	del := find(t, fs, "hygiene.finished-pods", "namespace/shop")
	if !hasCommand(del, "k0s kubectl -n shop delete pod web-6c7d8e9f0-old11") || hasCommand(del, "migrate-once") || hasCommand(del, "report-") {
		t.Errorf("delete step: %+v", del.Remedy.Steps)
	}
	if f := find(t, fs, "hygiene.no-limits", "namespace/shop"); f.Plain.WhatHappened != "1 app may use as much memory as it wants." {
		t.Errorf("plain: %q", f.Plain.WhatHappened)
	}
}

func TestHygieneStaysASuggestion(t *testing.T) {
	// A critical cluster and kube-system's +10 don't lift good practices
	// out of the suggestions.
	s := load(t, "hygiene.yaml")
	fs, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "high")
	for _, f := range fs {
		if f.IsHygiene() && (f.Priority != findings.P4 || f.Score > 24) {
			t.Errorf("%s: %s %d", f.RuleID, f.Priority, f.Score)
		}
	}
}

func TestNodeProblemDetector(t *testing.T) {
	fs := scan(t, "node-npd.yaml")
	f := find(t, fs, "node.npd-condition", "node/worker-1")
	if f.Title != "worker-1: FrequentKubeletRestart, ReadonlyFilesystem" || f.Severity != findings.High {
		t.Errorf("title %q, severity %s", f.Title, f.Severity)
	}
	if got := fact(f, "ReadonlyFilesystem"); got != "FilesystemIsReadOnly, since 40 min ago: Filesystem is read-only" {
		t.Errorf("fact = %q", got)
	}
	if !strings.Contains(f.Summary, "the kubelet keeps restarting, and a filesystem was remounted read-only") {
		t.Errorf("summary = %q", f.Summary)
	}
	if !hasCommand(f, "sudo journalctl -u k0sworker") || !hasCommand(f, "findmnt") || !hasCommand(f, "k0s kubectl drain worker-1") {
		t.Errorf("steps = %+v", f.Remedy.Steps)
	}
	if f.Plain.WhatHappened != "On this server, the part that runs the apps keeps restarting, and one of its disks has errors and can no longer be written to." {
		t.Errorf("plain = %q", f.Plain.WhatHappened)
	}
	absent(t, fs, "node.npd-condition", "node/worker-2")
	absent(t, fs, "node.not-ready", "")
}

func TestAppCertificates(t *testing.T) {
	fs := scan(t, "tls.yaml")
	web := find(t, fs, "tls.cert-expiry", "shop/secret/web-tls")
	if web.Severity != findings.High || web.Title != "Certificate for shop.example.com expires in 5 days (Secret shop/web-tls)" || !web.Impact.Exposed {
		t.Errorf("web: %s %q exposed=%v", web.Severity, web.Title, web.Impact.Exposed)
	}
	for label, want := range map[string]string{
		"Valid until": "2026-10-02 14:00 UTC", "Names": "shop.example.com", "Issuer": "CN=shop.example.com",
		"Used by": "Ingress web", "Hosts not in it": "www.example.com", "Renewed by": "nothing in the cluster: renewed by hand",
	} {
		if got := fact(web, label); got != want {
			t.Errorf("web %s = %q, want %q", label, got, want)
		}
	}
	if !hasCommand(web, "k0s kubectl -n shop create secret tls web-tls --cert=renewed.crt --key=renewed.key --dry-run=client -o yaml | k0s kubectl apply -f -") {
		t.Errorf("web steps: %+v", web.Remedy.Steps)
	}
	if web.Plain.Title != "The security certificate for shop.example.com expires in 5 days" ||
		web.Plain.WhatToDo != "Whoever manages the certificate for shop.example.com should renew it before 2 October 2026." {
		t.Errorf("web plain: %+v", web.Plain)
	}

	api := find(t, fs, "tls.cert-expiry", "shop/secret/api-tls")
	if api.Severity != findings.Critical || api.Title != "Certificate for api.shop.internal expired 2 days ago (Secret shop/api-tls)" {
		t.Errorf("api: %s %q", api.Severity, api.Title)
	}
	if fact(api, "Used by") != "deploy/api" || !hasCommand(api, "k0s kubectl -n shop rollout restart deploy/api") || api.Plain.Title != "The security certificate for api.shop.internal has expired" {
		t.Errorf("api: used by %q, steps %+v, plain %q", fact(api, "Used by"), api.Remedy.Steps, api.Plain.Title)
	}

	late := find(t, fs, "tls.cert-expiry", "shop/secret/late-tls")
	if late.Severity != findings.Medium || fact(late, "Renewed by") != "cert-manager Certificate late" || !hasCommand(late, "k0s kubectl -n shop describe certificate late") ||
		!strings.Contains(late.Remedy.LikelyCause, "cert-manager should have renewed it") {
		t.Errorf("late: %s %q", late.Severity, late.Remedy.LikelyCause)
	}
	// Renewal isn't late yet, nothing uses it, or it is valid for long.
	absent(t, fs, "tls.cert-expiry", "shop/secret/le-tls")
	absent(t, fs, "tls.cert-expiry", "shop/secret/old-tls")
	absent(t, fs, "tls.cert-expiry", "shop/secret/wild-tls")
	for _, f := range fs {
		for _, e := range f.Evidence {
			if strings.Contains(e.Value, "secret-key") || strings.Contains(e.Value, "hunter22") {
				t.Errorf("%s shows secret data: %s", f.RuleID, e.Value)
			}
		}
	}
}

func TestAppCertificatesNeedThePermission(t *testing.T) {
	s := load(t, "tls.yaml")
	delete(s.Available, snapshot.KindTLSSecret)
	fs, skipped := rules.Evaluate(s, config.DefaultThresholds())
	absent(t, fs, "tls.cert-expiry", "")
	var reason string
	for _, sk := range skipped {
		if sk.RuleID == "tls.cert-expiry" {
			reason = sk.Reason
		}
	}
	if reason != "needs to read TLS Secrets, which the account may not or is turned off" {
		t.Errorf("skipped: %q", reason)
	}
}

func TestHPAMissingRequest(t *testing.T) {
	fs := scan(t, "hpa-request.yaml")
	f := find(t, fs, "hpa.no-metrics", "accounts/horizontalpodautoscaler/session-cache")
	if f.Title != "Can't scale: container session-cache has no CPU request" {
		t.Errorf("title %q", f.Title)
	}
	if f.Links.Cause != "" || f.ParentID != "" {
		t.Errorf("not a metrics API problem: cause %q, parent %q", f.Links.Cause, f.ParentID)
	}
	if !strings.Contains(f.Remedy.LikelyCause, "every container of the pod, sidecars included") || !strings.Contains(f.Remedy.LikelyCause, "The metrics API works") {
		t.Errorf("cause %q", f.Remedy.LikelyCause)
	}
	if fact(f, "No CPU request") != "container session-cache" || fact(f, "With a CPU request") != "login (250m)" {
		t.Errorf("facts %+v", f.Evidence)
	}
	for _, want := range []string{
		`get deploy/login -o jsonpath=`,
		"top pod login-5c7d9f6b48-k2x9m --containers",
		"set resources deploy/login -c session-cache --requests=cpu=100m",
		"get hpa session-cache",
		"container: login",
		"averageUtilization: 80",
	} {
		if !hasCommand(f, want) {
			t.Errorf("no step with %q: %+v", want, f.Remedy.Steps)
		}
	}
	helm := false
	for _, st := range f.Remedy.Steps {
		helm = helm || strings.Contains(st.Text, "for a Helm chart, in its values")
		if strings.Contains(st.Command, "apiservice") {
			t.Errorf("no metrics API steps: %+v", st)
		}
	}
	if !helm {
		t.Error("login is deployed by Helm: the request belongs in its values")
	}
	if !strings.Contains(f.Plain.Why, "the part session-cache reserves none") || !strings.Contains(f.Plain.WhatToDo, "give session-cache a CPU reservation") {
		t.Errorf("plain %+v", f.Plain)
	}
}

func TestK0sControlPlaneTargets(t *testing.T) {
	fs := scan(t, "k0s-monitoring.yaml")
	f := find(t, fs, "hygiene.k0s-control-plane-targets", "namespace/kube-system")
	if f.Title != "Monitoring looks for etcd, kube-controller-manager, kube-scheduler pods, which k0s doesn't have (3 Services in kube-system)" {
		t.Errorf("title %q", f.Title)
	}
	if f.Priority != findings.P4 || fact(f, "Made by") != "Helm release vmstack" || !strings.Contains(fact(f, "Services"), "svc/vmstack-victoria-metrics-k8s-stack-kube-etcd (component=etcd)") {
		t.Errorf("priority %s, facts %+v", f.Priority, f.Evidence)
	}
	for _, want := range []string{"kubeControllerManager: {enabled: false}", "kubeScheduler: {enabled: false}", "kubeEtcd: {enabled: false}",
		"helm -n monitoring get values vmstack", "helm -n monitoring upgrade vmstack <chart>", "k0s-system get svc"} {
		if !hasCommand(f, want) {
			t.Errorf("no step with %q: %+v", want, f.Remedy.Steps)
		}
	}
	if strings.Contains(fact(f, "Services"), "core-dns") {
		t.Error("the CoreDNS Service matches its pods")
	}
	// Not broken Services, then.
	for _, name := range []string{"kube-controller-manager", "kube-scheduler", "kube-etcd", "core-dns"} {
		absent(t, fs, "svc.selector-mismatch", "kube-system/service/vmstack-victoria-metrics-k8s-stack-"+name)
	}

	// A real typo still is, with its closest match; an app that isn't
	// installed has none, rather than any pod that lacks the label.
	web := find(t, fs, "svc.selector-mismatch", "shop/service/web")
	if fact(web, "Closest match") != "shop/deployment/web has app=web, not web-frontend" {
		t.Errorf("closest match %q", fact(web, "Closest match"))
	}
	if old := find(t, fs, "svc.selector-mismatch", "shop/service/old"); fact(old, "Closest match") != "" {
		t.Errorf("no closest match for a one-label selector nothing has: %q", fact(old, "Closest match"))
	}

	// Elsewhere than k0s, such Services are broken ones.
	snap := load(t, "k0s-monitoring.yaml")
	for _, n := range snap.Nodes {
		n.Status.NodeInfo.KubeletVersion = "v1.36.4"
	}
	fs, _ = fleet.EvaluateSnapshot(snap, config.DefaultThresholds(), "")
	absent(t, fs, "hygiene.k0s-control-plane-targets", "")
	find(t, fs, "svc.selector-mismatch", "kube-system/service/vmstack-victoria-metrics-k8s-stack-kube-scheduler")
}

func TestChartFailed(t *testing.T) {
	fs := scan(t, "k0s-addons.yaml")
	broken := find(t, fs, "k0s.chart-failed", "kube-system/chart/k0s-addon-chart-broken")
	if broken.Severity != findings.High || broken.Title != "Add-on broken: its chart repository can't be reached" {
		t.Errorf("broken: %s %q", broken.Severity, broken.Title)
	}
	if !strings.Contains(broken.Remedy.LikelyCause, "https://charts.example.invalid") || fact(broken, "Installed") != "no" || fact(broken, "Last attempt") != "5 min ago" {
		t.Errorf("broken: cause %q, facts %+v", broken.Remedy.LikelyCause, broken.Evidence)
	}
	if !hasCommand(broken, "curl -sSI https://charts.example.invalid/index.yaml") || !hasCommand(broken, "get chart k0s-addon-chart-broken -o jsonpath='{.status}") {
		t.Errorf("broken steps %+v", broken.Remedy.Steps)
	}
	if !strings.Contains(broken.Plain.WhatToDo, "can reach charts.example.invalid") || strings.Contains(broken.Plain.WhatToDo, "%!") {
		t.Errorf("broken plain %+v", broken.Plain)
	}

	ingress := find(t, fs, "k0s.chart-failed", "kube-system/chart/k0s-addon-chart-ingress")
	if ingress.Severity != findings.Medium || ingress.Title != "Add-on ingress: a previous install or update of it is stuck" || fact(ingress, "Installed") != "4.10.0 (revision 3)" {
		t.Errorf("ingress: %s %q %+v", ingress.Severity, ingress.Title, ingress.Evidence)
	}
	if !hasCommand(ingress, "helm -n ingress-nginx rollback ingress") || !strings.Contains(ingress.Plain.Why, "previous version keeps running") {
		t.Errorf("ingress: %+v %+v", ingress.Remedy.Steps, ingress.Plain)
	}

	mon := find(t, fs, "k0s.chart-failed", "kube-system/chart/k0s-addon-chart-monitoring")
	if mon.Title != "Add-on monitoring: it didn't become ready in time" || !hasCommand(mon, "kubectl -n monitoring get pods") {
		t.Errorf("monitoring: %q %+v", mon.Title, mon.Remedy.Steps)
	}
	absent(t, fs, "k0s.chart-failed", "kube-system/chart/k0s-addon-chart-metrics")

	for _, f := range []*findings.Finding{broken, ingress, mon} {
		all := f.Summary + f.Remedy.LikelyCause + f.Plain.WhatHappened + f.Plain.WhatToDo
		for _, st := range f.Remedy.Steps {
			all += st.Text + st.Plain + st.Command
		}
		for _, e := range f.Evidence {
			all += e.Value
		}
		if strings.Contains(all, "%!") || strings.Contains(all, "hunter2") || strings.Contains(all, "Sup3rSecret") {
			t.Errorf("%s: formatting noise or a secret in %q", f.Resource, all)
		}
	}
}

// basicJargon are words Basic mode doesn't use where it explains a problem
// or says what to do: its texts and the steps written for it. Technical
// steps are folded for whoever manages the cluster, so they may.
var basicJargon = regexp.MustCompile(`\b(pods?|containers?|ConfigMaps?|StorageClass(es)?|PVCs?|PersistentVolume(Claim)?s?|ReplicaSets?|kubelet|env|replicas?|tolerat\w+|kubectl|CrashLoopBackOff|OOMKilled|readiness|liveness|probes?|endpoints?|selectors?)\b`)

func TestBasicTextsAvoidJargon(t *testing.T) {
	for _, file := range fixtures {
		for _, f := range scan(t, file) {
			if f.IsHygiene() {
				continue
			}
			texts := map[string]string{"title": f.Plain.Title, "what happened": f.Plain.WhatHappened, "why": f.Plain.Why, "what to do": f.Plain.WhatToDo}
			for i, st := range f.Remedy.Steps {
				texts[fmt.Sprintf("step %d", i+1)] = st.Plain
			}
			for where, s := range texts {
				if m := basicJargon.FindAllString(s, -1); m != nil {
					t.Errorf("%s %s, %s: Basic text uses %v: %q", f.RuleID, f.Resource.String(), where, m, s)
				}
			}
		}
	}
}

func TestServiceDown(t *testing.T) {
	fs := scan(t, "service-down.yaml")
	w3 := find(t, fs, "vm.service-down", "node/worker-3")
	if w3.Severity != findings.Critical || w3.Title != "k0sworker.service is failed on worker-3" ||
		w3.Plain.Title != "k0s has stopped on server worker-3" || w3.IsSymptom() {
		t.Errorf("worker-3: %s %q %q parent %q", w3.Severity, w3.Title, w3.Plain.Title, w3.ParentID)
	}
	if len(w3.Remedy.Steps) != 3 || w3.Remedy.Steps[0].Host != "worker-3" || !strings.Contains(w3.Remedy.Steps[0].Command, "journalctl -u k0sworker") ||
		!strings.Contains(w3.Remedy.Steps[2].Command, "systemctl enable --now k0sworker") {
		t.Errorf("worker-3 steps: %+v", w3.Remedy.Steps)
	}
	// The node stopped responding because k0s stopped: it folds under it,
	// and so does what folded under the node.
	if nr := find(t, fs, "node.not-ready", "node/worker-3"); nr.ParentID != w3.ID {
		t.Errorf("node.not-ready's parent is %q, want %s", nr.ParentID, w3.ID)
	}
	if down := find(t, fs, "deploy.unavailable", "shop/deployment/checkout"); down.ParentID != w3.ID {
		t.Errorf("checkout's parent is %q, want %s", down.ParentID, w3.ID)
	}
	// A controller that is no node, by its address; restarting, not down.
	ctl := find(t, fs, "vm.service-down", "controller/ctrl-1")
	if ctl.Severity != findings.High || ctl.Title != "k0scontroller.service restarted 4 times in 15 min on ctrl-1" ||
		ctl.Plain.Title != "k0s keeps restarting on control plane server ctrl-1" || !ctl.Impact.ClusterWide || ctl.Category != findings.ControlPlane {
		t.Errorf("ctrl-1: %s %q %q", ctl.Severity, ctl.Title, ctl.Plain.Title)
	}
	// A host k0s-monitor doesn't know, by its address.
	if h := find(t, fs, "vm.service-down", "host/10.0.0.99"); !strings.Contains(h.Remedy.LikelyCause, "isn't enabled") {
		t.Errorf("unknown host: %q", h.Remedy.LikelyCause)
	}
	// One restart is no problem.
	absent(t, fs, "vm.service-down", "node/worker-2")
}

func TestKernelErrors(t *testing.T) {
	fs := scan(t, "kernel.yaml")
	w1 := find(t, fs, "vm.kernel-errors", "node/worker-1")
	if w1.Severity != findings.High || w1.Title != "Kernel errors on worker-1: disk I/O errors (12), tasks hung for minutes (2)" ||
		w1.Plain.Title != "The server worker-1 reports disk errors" || w1.Links.Cause != "disk" {
		t.Errorf("worker-1: %s %q %q %q", w1.Severity, w1.Title, w1.Plain.Title, w1.Links.Cause)
	}
	if v := fact(w1, "Disk I/O errors"); !strings.Contains(v, "12 in the last hour, from node-problem-detector; for example: Buffer I/O error on dev sdb1") {
		t.Errorf("evidence: %q", v)
	}
	if len(w1.Remedy.Steps) == 0 || !strings.Contains(w1.Remedy.Steps[0].Command, "journalctl -k") || w1.Remedy.Steps[0].Host != "worker-1" {
		t.Errorf("steps: %+v", w1.Remedy.Steps)
	}
	// A disk alert about worker-1 joins it.
	if len(w1.Alerts) != 1 || w1.Alerts[0].Name != "NodeDiskIOSaturation" {
		t.Errorf("alerts: %+v", w1.Alerts)
	}
	// worker-2: two OOM kills that weren't a container at its limit, and
	// eth0's link; the pods' interfaces don't count.
	w2 := find(t, fs, "vm.kernel-errors", "node/worker-2")
	if w2.Severity != findings.Medium || !strings.Contains(w2.Title, "processes killed for lack of memory (2)") ||
		!strings.Contains(w2.Title, "network link of eth0 going down and up (4)") || strings.Contains(w2.Title, "veth") || strings.Contains(w2.Title, "cali") {
		t.Errorf("worker-2: %s %q", w2.Severity, w2.Title)
	}
	// Not node-problem-detector's: no finding.
	absent(t, fs, "vm.kernel-errors", "node/worker-3")
}
