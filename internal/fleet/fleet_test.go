package fleet_test

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes/fake"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/testutil"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

// TestScanIsolatesClusters scans a fake cluster with a crash-looping app
// next to one that cannot be reached: each gets its own result.
func TestScanIsolatesClusters(t *testing.T) {
	client := fake.NewClientset(testutil.Objects(t, "../rules/testdata/crashloop.yaml")...)
	cfg := config.Default()
	cfg.Clusters = []config.Cluster{
		{Name: "good", Kubeconfig: "unused"},
		{Name: "dead", Kubeconfig: "unused"},
	}
	m := &fleet.Manager{
		Config: cfg,
		Now:    func() time.Time { return now },
		Connect: func(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
			if c.Name == "dead" {
				return nil, &cluster.ConnError{Kind: cluster.KindRefused, Server: "https://10.0.0.9:6443",
					Plain: "10.0.0.9 refused the connection on port 6443.", Hint: "The k0s controller may be stopped."}
			}
			return cluster.NewForClient(c.Name, "https://fake:6443", client, &version.Info{GitVersion: "v1.36.4+k0s"}), nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	results, err := m.Scan(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Name != "good" || results[1].Name != "dead" {
		t.Fatalf("results should keep configuration order: %+v", results)
	}

	good := results[0]
	if good.Status != fleet.StatusOK {
		t.Errorf("good cluster status = %s, warnings %v", good.Status, good.Warnings)
	}
	if !good.Info.K0s || good.Info.Pods != 3 || good.Info.Nodes != 1 {
		t.Errorf("info = %+v", good.Info)
	}
	if len(good.Findings) == 0 || good.Findings[0].RuleID != "pod.crashloop" {
		t.Fatalf("expected pod.crashloop first, got %+v", good.Findings)
	}
	if good.Counts[findings.P1] != 1 || good.Symptoms != 2 {
		t.Errorf("counts = %v, symptoms = %d", good.Counts, good.Symptoms)
	}

	dead := results[1]
	if dead.Status != fleet.StatusUnreachable || dead.Error == nil || dead.Error.Kind != cluster.KindRefused {
		t.Fatalf("dead cluster = %+v", dead)
	}
	if len(dead.Findings) != 1 || dead.Findings[0].RuleID != fleet.UnreachableRuleID || dead.Findings[0].Priority != findings.P1 {
		t.Errorf("dead cluster findings = %+v", dead.Findings)
	}
	if got := fleet.Worst(results); got != findings.P1 {
		t.Errorf("worst = %s", got)
	}
	if totals := fleet.Totals(results); totals[findings.P1] != 2 {
		t.Errorf("totals = %v", totals)
	}
}

func TestScanUnknownCluster(t *testing.T) {
	m := fleet.NewManager(config.Default())
	if _, err := m.Scan(context.Background(), []string{"nope"}); err == nil {
		t.Error("expected an error for an unknown cluster name")
	}
}
