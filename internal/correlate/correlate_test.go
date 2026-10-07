package correlate

import (
	"testing"

	"k0s_monitor/internal/findings"
)

func mk(id, rule string, score int, res findings.ObjectRef) *findings.Finding {
	return &findings.Finding{ID: id, RuleID: rule, Score: score, Resource: res}
}

func TestChainsResolveToTheRoot(t *testing.T) {
	deploy := findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "checkout"}
	node := mk("node", "node.not-ready", 80, findings.ObjectRef{Kind: "Node", Name: "worker-3"})
	crash := mk("crash", "pod.crashloop", 70, deploy)
	crash.Links.Nodes = []string{"worker-3"}
	crash.Links.Workloads = []findings.ObjectRef{deploy}
	unavail := mk("unavail", "deploy.unavailable", 75, deploy)
	unavail.Links.Nodes = []string{"worker-3"}
	svc := mk("svc", "svc.no-endpoints", 50, findings.ObjectRef{Kind: "Service", Namespace: "shop", Name: "checkout"})
	svc.Links.Workloads = []findings.ObjectRef{deploy}

	out := Fold([]*findings.Finding{svc, unavail, crash, node})
	for _, f := range []*findings.Finding{crash, unavail, svc} {
		if f.ParentID != "node" {
			t.Errorf("%s: parent %q, want the node", f.ID, f.ParentID)
		}
	}
	if out[0] != node {
		t.Errorf("the root should come first, got %s", out[0].ID)
	}
	if len(out) != 4 {
		t.Errorf("no finding may be lost, got %d", len(out))
	}
}

func TestPartialNodeOutageIsNotFolded(t *testing.T) {
	deploy := findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	node := mk("node", "node.not-ready", 80, findings.ObjectRef{Kind: "Node", Name: "worker-3"})
	crash := mk("crash", "pod.crashloop", 70, deploy)
	crash.Links.Nodes = []string{"worker-3", "worker-1"} // also fails on a healthy node
	Fold([]*findings.Finding{node, crash})
	if crash.ParentID != "" {
		t.Errorf("a problem that also happens on healthy nodes is its own root cause")
	}
}

func TestCyclesAreBroken(t *testing.T) {
	a := &findings.Finding{ID: "a", ParentID: "b"}
	b := &findings.Finding{ID: "b", ParentID: "a"}
	resolveRoots([]*findings.Finding{a, b})
	roots := 0
	for _, f := range []*findings.Finding{a, b} {
		if f.ParentID == "" {
			roots++
		}
	}
	if roots != 1 {
		t.Errorf("exactly one of a cycle becomes the root, got %d", roots)
	}
}

// A full disk keeps CoreDNS from being scheduled: one incident, as urgent
// as the DNS outage it causes.
func TestDiskPressureTakingDownDNS(t *testing.T) {
	coredns := findings.ObjectRef{Kind: "Deployment", Namespace: "kube-system", Name: "coredns"}
	disk := mk("disk", "node.pressure", 57, findings.ObjectRef{Kind: "Node", Name: "worker-1"})
	disk.Priority = findings.P2
	pending := mk("pending", "pod.unschedulable", 67, coredns)
	pending.Links.BlockedBy = []string{"worker-1"}
	dns := mk("dns", "dns.unhealthy", 95, coredns)
	dns.Title = "CoreDNS is down (0 of 2 pods ready)"

	out := Fold([]*findings.Finding{dns, pending, disk})
	if pending.ParentID != "disk" || dns.ParentID != "disk" {
		t.Fatalf("parents: pending %q, dns %q; want both under the disk problem", pending.ParentID, dns.ParentID)
	}
	if disk.Score != 95 || disk.Priority != findings.P1 {
		t.Errorf("the root should take its worst symptom's score: %d %s", disk.Score, disk.Priority)
	}
	if len(disk.Evidence) != 1 || disk.Evidence[0].Value != "raised to P1 by dns.unhealthy: CoreDNS is down (0 of 2 pods ready)" {
		t.Errorf("evidence = %+v", disk.Evidence)
	}
	if out[0] != disk || out[1] != dns || out[2] != pending {
		t.Errorf("order = %s, %s, %s", out[0].ID, out[1].ID, out[2].ID)
	}
}

func TestPodsBlockedByAHealthyNodeAreNotFolded(t *testing.T) {
	disk := mk("disk", "node.pressure", 57, findings.ObjectRef{Kind: "Node", Name: "worker-1"})
	pending := mk("pending", "pod.unschedulable", 45, findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "web"})
	pending.Links.BlockedBy = []string{"worker-1", "worker-2"} // worker-2 has no problem found
	Fold([]*findings.Finding{disk, pending})
	if pending.ParentID != "" {
		t.Errorf("only fold when every blocking node has a problem of its own")
	}
	if disk.Score != 57 {
		t.Errorf("a root without symptoms keeps its score, got %d", disk.Score)
	}
}

// DiskPressure alone is what a full kubelet disk leads to; with memory
// pressure too, it is a problem of its own.
func TestDiskPressureFoldsUnderFullDisk(t *testing.T) {
	node := findings.ObjectRef{Kind: "Node", Name: "worker-1"}
	full := mk("full", "node.fs-high", 70, node)
	disk := mk("disk", "node.pressure", 55, node)
	disk.Links.Cause = "disk"
	Fold([]*findings.Finding{disk, full})
	if disk.ParentID != "full" {
		t.Errorf("DiskPressure should fold under the full disk, parent = %q", disk.ParentID)
	}

	both := mk("both", "node.pressure", 55, node)
	Fold([]*findings.Finding{both, mk("full", "node.fs-high", 70, node)})
	if both.ParentID != "" {
		t.Errorf("memory and disk pressure must stay a root cause, parent = %q", both.ParentID)
	}
	other := mk("other", "node.pressure", 55, findings.ObjectRef{Kind: "Node", Name: "worker-2"})
	other.Links.Cause = "disk"
	Fold([]*findings.Finding{other, mk("full", "node.fs-high", 70, node)})
	if other.ParentID != "" {
		t.Errorf("another node's full disk is not the cause, parent = %q", other.ParentID)
	}
}

func TestCrashFoldsUnderTheServiceItNeeds(t *testing.T) {
	api := findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}
	db := findings.ObjectRef{Kind: "StatefulSet", Namespace: "shop", Name: "postgres"}
	dbSvc := findings.ObjectRef{Kind: "Service", Namespace: "shop", Name: "postgres"}
	apiCrash := mk("api", "pod.crashloop", 85, api)
	apiCrash.Links.Cause = "dependency"
	apiCrash.Links.Services = []findings.ObjectRef{dbSvc}
	apiCrash.Links.DependsOn = []findings.ObjectRef{db}
	dbCrash := mk("db", "pod.crashloop", 70, db)
	noEndpoints := mk("svc", "svc.no-endpoints", 50, dbSvc)
	noEndpoints.Links.Workloads = []findings.ObjectRef{db}

	out := Fold([]*findings.Finding{apiCrash, dbCrash, noEndpoints})
	if apiCrash.ParentID != "db" || noEndpoints.ParentID != "db" {
		t.Errorf("parents: api %q, service %q; want both under the database's crash", apiCrash.ParentID, noEndpoints.ParentID)
	}
	if out[0] != dbCrash || dbCrash.Score != 85 {
		t.Errorf("the database's crash should lead with the api's score, got %s %d", out[0].ID, dbCrash.Score)
	}

	// Without a problem of its own, the service isn't blamed.
	apiCrash.ParentID = ""
	if Fold([]*findings.Finding{apiCrash}); apiCrash.ParentID != "" {
		t.Errorf("folded under %q", apiCrash.ParentID)
	}
}

func TestCrashFoldsUnderDNS(t *testing.T) {
	app := findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "worker"}
	crash := mk("crash", "pod.crashloop", 70, app)
	crash.Links.Cause = "dns"
	dns := mk("dns", "dns.unhealthy", 90, findings.ObjectRef{Kind: "Deployment", Namespace: "kube-system", Name: "coredns"})
	Fold([]*findings.Finding{crash, dns})
	if crash.ParentID != "dns" {
		t.Errorf("parent %q, want the DNS problem", crash.ParentID)
	}
}
