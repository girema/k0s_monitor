// Package priority turns a finding's severity, impact and criticality into
// a 0–100 score and a P1–P4 bucket (plan section 8.3).
package priority

import (
	"strings"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// CriticalityAnnotation raises ("high") or lowers ("low") the priority of
// findings about a namespace or workload.
const CriticalityAnnotation = "k0s-monitor.io/criticality"

var base = map[findings.Severity]int{
	findings.Critical: 60,
	findings.High:     45,
	findings.Medium:   30,
	findings.Low:      15,
	findings.Info:     5,
}

// Score computes the score of one finding. s may be nil (for findings about
// clusters that could not be reached). clusterCriticality is the cluster's
// setting from the config: "high", "low" or empty.
func Score(f *findings.Finding, s *snapshot.Snapshot, clusterCriticality string) int {
	score := base[f.Severity] + impactPoints(f) + criticalityPoints(f, s) + urgencyPoints(f)
	switch strings.ToLower(clusterCriticality) {
	case "high":
		score += 5
	case "low":
		score -= 10
	}
	if f.IsHygiene() {
		// Good practices are suggestions (P4), however critical the place.
		return clamp(score, 0, 24)
	}
	return clamp(score, 0, 100)
}

func impactPoints(f *findings.Finding) int {
	im := f.Impact
	pts := 0
	switch {
	case im.ClusterWide:
		pts = 25
	case im.AllReplicasDown:
		pts = 20
	case im.FractionDown >= 0.5:
		pts = 12
	case im.FractionDown > 0:
		pts = 4
	}
	if im.BlocksWorkload && pts < 12 {
		pts = 12
	}
	if f.Category == findings.Nodes && im.AffectedPods > pts {
		// A node problem weighs one point per pod on the node.
		pts = im.AffectedPods
	}
	if im.Exposed {
		pts += 5
	}
	return min(pts, 25)
}

// urgencyPoints rewards a forecast that runs out soon: within 1 h +15,
// 6 h +10, 24 h +5 (plan section 8.3).
func urgencyPoints(f *findings.Finding) int {
	switch b := f.Impact.BreachIn; {
	case b <= 0:
		return 0
	case b <= time.Hour:
		return 15
	case b <= 6*time.Hour:
		return 10
	case b <= 24*time.Hour:
		return 5
	}
	return 0
}

func criticalityPoints(f *findings.Finding, s *snapshot.Snapshot) int {
	pts := 0
	if f.System || f.Resource.Namespace == "kube-system" {
		pts += 10
	}
	if s == nil {
		return pts
	}
	// The workload's own annotation wins over its namespace's.
	level := ""
	if ns := s.Namespace(f.Resource.Namespace); ns != nil {
		level = ns.Annotations[CriticalityAnnotation]
	}
	if m := s.WorkloadMeta(snapshot.Workload{Kind: f.Resource.Kind, Namespace: f.Resource.Namespace, Name: f.Resource.Name}); m != nil {
		if v, ok := m.Annotations[CriticalityAnnotation]; ok {
			level = v
		}
	}
	switch strings.ToLower(level) {
	case "high":
		pts += 10
	case "low":
		pts -= 10
	}
	return pts
}

// Bucket maps a score to a priority.
func Bucket(score int) findings.Priority {
	switch {
	case score >= 75:
		return findings.P1
	case score >= 50:
		return findings.P2
	case score >= 25:
		return findings.P3
	}
	return findings.P4
}

// Apply scores every finding in place.
func Apply(fs []*findings.Finding, s *snapshot.Snapshot, clusterCriticality string) {
	for _, f := range fs {
		f.Score = Score(f, s, clusterCriticality)
		f.Priority = Bucket(f.Score)
	}
}

func clamp(v, lo, hi int) int {
	return max(lo, min(v, hi))
}
