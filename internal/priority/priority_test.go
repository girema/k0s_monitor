package priority

import (
	"testing"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

func TestBucket(t *testing.T) {
	cases := map[int]findings.Priority{100: findings.P1, 75: findings.P1, 74: findings.P2, 50: findings.P2, 49: findings.P3, 25: findings.P3, 24: findings.P4, 0: findings.P4}
	for score, want := range cases {
		if got := Bucket(score); got != want {
			t.Errorf("Bucket(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestScore(t *testing.T) {
	ref := findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}
	cases := []struct {
		name string
		f    findings.Finding
		want int
	}{
		{"all replicas down and exposed", findings.Finding{Severity: findings.Critical, Resource: ref, Impact: findings.Impact{AllReplicasDown: true, Exposed: true}}, 85},
		{"half down", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{FractionDown: 0.5}}, 57},
		{"one of many", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{FractionDown: 0.2}}, 49},
		{"cluster-wide system", findings.Finding{Severity: findings.Critical, System: true, Impact: findings.Impact{ClusterWide: true}}, 95},
		{"node with 30 pods caps at 25", findings.Finding{Severity: findings.Critical, Category: findings.Nodes, System: true, Impact: findings.Impact{AffectedPods: 30}}, 95},
		{"impact never exceeds 25", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{AllReplicasDown: true, Exposed: true, BlocksWorkload: true}}, 70},
		{"full within the hour", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{BreachIn: 30 * time.Minute}}, 60},
		{"full within 6 hours", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{BreachIn: 6 * time.Hour}}, 55},
		{"full within a day", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{BreachIn: 20 * time.Hour}}, 50},
		{"full in two days", findings.Finding{Severity: findings.High, Resource: ref, Impact: findings.Impact{BreachIn: 48 * time.Hour}}, 45},
	}
	for _, c := range cases {
		if got := Score(&c.f, nil, ""); got != c.want {
			t.Errorf("%s: score %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCriticalityAnnotations(t *testing.T) {
	s, err := snapshot.FromYAML("c", []byte(`
apiVersion: v1
kind: Namespace
metadata: {name: shop, annotations: {k0s-monitor.io/criticality: high}}
---
apiVersion: v1
kind: Namespace
metadata: {name: lab, annotations: {k0s-monitor.io/criticality: low}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: lab, annotations: {k0s-monitor.io/criticality: high}}
spec: {selector: {matchLabels: {a: b}}, template: {metadata: {labels: {a: b}}, spec: {containers: [{name: c, image: i}]}}}
`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(ns, name string) *findings.Finding {
		return &findings.Finding{Severity: findings.High, Resource: findings.ObjectRef{Kind: "Deployment", Namespace: ns, Name: name}}
	}
	if got := Score(mk("shop", "web"), s, ""); got != 55 {
		t.Errorf("high namespace: %d, want 55", got)
	}
	if got := Score(mk("lab", "other"), s, ""); got != 35 {
		t.Errorf("low namespace: %d, want 35", got)
	}
	if got := Score(mk("lab", "api"), s, ""); got != 55 {
		t.Errorf("the workload's annotation wins over its namespace: %d, want 55", got)
	}
	if got := Score(mk("shop", "web"), s, "low"); got != 45 {
		t.Errorf("low cluster: %d, want 45", got)
	}
}
