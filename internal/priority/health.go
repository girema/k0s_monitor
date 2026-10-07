package priority

import "k0s_monitor/internal/findings"

// CategoryHealth is the score of one area of a cluster.
type CategoryHealth struct {
	Category findings.Category `json:"category"`
	Score    int               `json:"score"`
	Label    string            `json:"label"`
	Weight   int               `json:"weight"`
	// Roots counts the root causes in this category by priority.
	Roots map[findings.Priority]int `json:"roots"`
	// Symptoms counts folded symptoms in this category.
	Symptoms int `json:"symptoms"`
}

// Health is the health score of a cluster (plan section 8.4).
type Health struct {
	Score      int              `json:"score"`
	Label      string           `json:"label"`
	Categories []CategoryHealth `json:"categories"`
}

// healthAreas are the scored categories with their weight in percent.
var healthAreas = []struct {
	c      findings.Category
	weight int
}{
	{findings.Nodes, 25},
	{findings.Workloads, 25},
	{findings.Storage, 20},
	{findings.Network, 15},
	{findings.ControlPlane, 15},
}

var penalty = map[findings.Priority]int{findings.P1: 30, findings.P2: 12, findings.P3: 4, findings.P4: 1}

// HealthOf scores the unresolved findings of one cluster. Each category
// starts at 100 and loses points per root cause by priority, and 2 per
// folded symptom that belongs to it. A cluster with a P1 is labeled
// Warning at best. Fleet findings (the cluster can't be
// reached) are not scored: the caller shows the last known score instead.
func HealthOf(fs []*findings.Finding) Health {
	cats := map[findings.Category]*CategoryHealth{}
	for _, a := range healthAreas {
		cats[a.c] = &CategoryHealth{Category: a.c, Score: 100, Weight: a.weight,
			Roots: map[findings.Priority]int{findings.P1: 0, findings.P2: 0, findings.P3: 0, findings.P4: 0}}
	}
	for _, f := range fs {
		c := cats[f.Category]
		if c == nil || f.State == findings.StateResolved {
			continue
		}
		if f.IsSymptom() {
			c.Symptoms++
			c.Score -= 2
		} else {
			c.Roots[f.Priority]++
			c.Score -= penalty[f.Priority]
		}
	}
	var h Health
	total, fixNow := 0, false
	for _, c := range cats {
		fixNow = fixNow || c.Roots[findings.P1] > 0
	}
	for _, a := range healthAreas {
		c := cats[a.c]
		c.Score = max(c.Score, 0)
		c.Label = HealthLabel(c.Score)
		total += c.Score * a.weight
		h.Categories = append(h.Categories, *c)
	}
	h.Score = (total + 50) / 100
	h.Label = HealthLabel(h.Score)
	// Something to fix now is never healthy, however small its part of
	// the score.
	if fixNow && h.Score >= 90 {
		h.Label = HealthLabel(89)
	}
	return h
}

// HealthLabel names a score: Healthy, Warning, Degraded or Critical.
func HealthLabel(score int) string {
	switch {
	case score >= 90:
		return "Healthy"
	case score >= 70:
		return "Warning"
	case score >= 50:
		return "Degraded"
	}
	return "Critical"
}
