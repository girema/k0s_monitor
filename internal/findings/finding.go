// Package findings defines the problem reports that rules produce and that
// every output (CLI, API, UI) renders.
package findings

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"k0s_monitor/internal/remedy"
)

// Severity is how bad a problem is on its own, before impact and urgency
// are taken into account by the priority package.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for i, n := range severityNames {
		if n == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", name)
}

// Category groups findings for the health score and the UI.
type Category string

const (
	Nodes        Category = "nodes"
	Workloads    Category = "workloads"
	Storage      Category = "storage"
	Network      Category = "network"
	ControlPlane Category = "controlplane"
	Fleet        Category = "fleet"
	// Hygiene findings are good practices: nothing is broken. They are
	// not counted as problems, don't lower the health score and are left
	// out of Basic mode.
	Hygiene Category = "hygiene"
)

// Priority is the bucket derived from the score: P1 (fix now) to P4 (hygiene).
type Priority string

const (
	P1 Priority = "P1"
	P2 Priority = "P2"
	P3 Priority = "P3"
	P4 Priority = "P4"
)

// Rank orders priorities; lower is more urgent. Unknown values sort last.
func (p Priority) Rank() int {
	switch p {
	case P1:
		return 1
	case P2:
		return 2
	case P3:
		return 3
	case P4:
		return 4
	}
	return 5
}

// PlainLabel is the Basic-mode wording of a priority.
func (p Priority) PlainLabel() string {
	switch p {
	case P1:
		return "Fix now"
	case P2:
		return "Fix today"
	case P3:
		return "Plan ahead"
	case P4:
		return "Suggestion"
	}
	return string(p)
}

// ParsePriority accepts P1..P4 in any case.
func ParsePriority(s string) (Priority, error) {
	switch p := Priority(strings.ToUpper(strings.TrimSpace(s))); p {
	case P1, P2, P3, P4:
		return p, nil
	}
	return "", fmt.Errorf("unknown priority %q (want P1, P2, P3 or P4)", s)
}

// ObjectRef points at a Kubernetes object. Namespace is empty for
// cluster-scoped objects.
type ObjectRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (r ObjectRef) String() string {
	if r.Namespace == "" {
		return strings.ToLower(r.Kind) + "/" + r.Name
	}
	return r.Namespace + "/" + strings.ToLower(r.Kind) + "/" + r.Name
}

// IsZero reports whether the reference is empty.
func (r ObjectRef) IsZero() bool { return r.Kind == "" && r.Name == "" }

// Alert is an alert that fires in the cluster's Prometheus, about one of a
// problem's objects.
type Alert struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Severity string     `json:"severity,omitempty"`
	Summary  string     `json:"summary,omitempty"`
	Runbook  string     `json:"runbookUrl,omitempty"`
	Since    *time.Time `json:"since,omitempty"`
	// About is the object the alert's labels name.
	About ObjectRef `json:"about"`
}

// Fact is one piece of evidence, shown as "Label: Value".
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Step is one step of a fix guide. Command is copyable; Host marks commands
// that must run on a machine rather than through kubectl.
type Step struct {
	Text    string `json:"text"`
	Plain   string `json:"plain,omitempty"`
	Command string `json:"command,omitempty"`
	Host    string `json:"host,omitempty"`
	// Pack names the product pack the step comes from, if any.
	Pack string `json:"pack,omitempty"`
}

// Doc is a link to documentation, from a product pack.
type Doc struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Pack  string `json:"pack,omitempty"`
}

// Remedy is the fix guide. k0s-monitor never runs these commands itself.
type Remedy struct {
	LikelyCause string `json:"likelyCause,omitempty"`
	Steps       []Step `json:"steps,omitempty"`
}

// PlainText is the Basic-mode wording of a finding.
type PlainText struct {
	Title        string `json:"title"`
	WhatHappened string `json:"whatHappened"`
	Why          string `json:"why,omitempty"`
	WhatToDo     string `json:"whatToDo"`
}

// Impact describes how far a problem reaches. The priority package turns it
// into points.
type Impact struct {
	AllReplicasDown bool    `json:"allReplicasDown,omitempty"`
	FractionDown    float64 `json:"fractionDown,omitempty"`
	ClusterWide     bool    `json:"clusterWide,omitempty"`
	AffectedPods    int     `json:"affectedPods,omitempty"`
	Exposed         bool    `json:"exposed,omitempty"`
	BlocksWorkload  bool    `json:"blocksWorkload,omitempty"`
	// BreachIn is how soon a forecast says something runs out, for
	// example a volume filling up. Zero means no forecast.
	BreachIn time.Duration `json:"breachIn,omitempty"`
}

// Links are relations used by the correlator. They are not part of the
// public output.
type Links struct {
	Workloads []ObjectRef
	Nodes     []string
	Claims    []ObjectRef
	// BlockedBy lists the nodes that keep pending pods from being scheduled
	// only through the taints of their conditions (not ready, disk
	// pressure, ...). The pods start once those nodes recover.
	BlockedBy []string
	// WaitsForPod marks a pending claim that is only waiting for its pod
	// to be scheduled, so the pod's problem is the root cause.
	WaitsForPod bool
	// Services lists the Services the problem depends on, for example the
	// Service behind a webhook.
	Services []ObjectRef
	// Cause is a short machine-readable cause that correlation matches on,
	// for example "network" or "no-default-class".
	Cause string
	// DependsOn lists the workloads behind the Services in Services, for
	// a crash caused by one of them.
	DependsOn []ObjectRef
}

// Rollout is a recent update of a Deployment that the problem started
// with: every failing pod comes from it.
type Rollout struct {
	Workload ObjectRef `json:"workload"`
	// Revision is the update's; Previous the one before, which the update
	// can be undone to.
	Revision int64     `json:"revision"`
	Previous int64     `json:"previous"`
	At       time.Time `json:"at"`
	// Changes are what the update changed in the pods, secrets masked.
	Changes []remedy.Change `json:"changes,omitempty"`
}

// Finding is one problem in one cluster.
type Finding struct {
	ID       string      `json:"id"`
	Cluster  string      `json:"cluster"`
	RuleID   string      `json:"ruleId"`
	Category Category    `json:"category"`
	Severity Severity    `json:"severity"`
	Score    int         `json:"score"`
	Priority Priority    `json:"priority"`
	Title    string      `json:"title"`
	Summary  string      `json:"summary"`
	Plain    PlainText   `json:"plain"`
	Resource ObjectRef   `json:"resource"`
	Affected []ObjectRef `json:"affected,omitempty"`
	Evidence []Fact      `json:"evidence,omitempty"`
	Remedy   Remedy      `json:"remedy"`
	Since    *time.Time  `json:"since,omitempty"`
	ParentID string      `json:"parentId,omitempty"`
	Impact   Impact      `json:"impact"`
	// Rollout is set when the problem started with an update.
	Rollout *Rollout `json:"rollout,omitempty"`
	// App is the friendly name a product pack gives the problem's app,
	// and Docs the links to documentation it adds.
	App  string `json:"app,omitempty"`
	Docs []Doc  `json:"docs,omitempty"`
	// Alerts are the alerts of the cluster's Prometheus about this
	// problem's objects.
	Alerts []Alert `json:"alerts,omitempty"`

	// Lifecycle, set by the monitoring engine (plan section 8.5). A one-off
	// scan leaves these empty.
	FirstSeen    *time.Time `json:"firstSeen,omitempty"`
	LastSeen     *time.Time `json:"lastSeen,omitempty"`
	State        State      `json:"state,omitempty"`
	SnoozedUntil *time.Time `json:"snoozedUntil,omitempty"`
	// StateBy is the user who acknowledged or snoozed it.
	StateBy string `json:"stateBy,omitempty"`
	// Stale is true while the cluster can't be reached: the finding is
	// what was last seen, not current.
	Stale bool `json:"stale,omitempty"`

	// System marks findings about the cluster's own machinery (nodes,
	// kube-system). The priority package gives them extra weight.
	System bool  `json:"-"`
	Links  Links `json:"-"`
}

// State is where a finding is in its lifecycle.
type State string

const (
	StateOpen         State = "open"
	StateAcknowledged State = "acknowledged"
	StateSnoozed      State = "snoozed"
	StateResolved     State = "resolved"
)

// Quiet reports whether a person has seen the finding (acknowledged or
// snoozed), so it does not notify.
func (f *Finding) Quiet() bool {
	return f.State == StateAcknowledged || f.State == StateSnoozed
}

// Clone returns a copy that can be changed without affecting f. Evidence is
// copied; the other slices are never changed after a rule creates them and
// are shared.
func (f *Finding) Clone() *Finding {
	c := *f
	c.Evidence = append([]Fact(nil), f.Evidence...)
	c.Alerts = append([]Alert(nil), f.Alerts...)
	return &c
}

// New creates a finding with a stable ID derived from cluster, rule and
// resource, so acknowledgements survive pod churn.
func New(cluster, ruleID string, category Category, severity Severity, resource ObjectRef) *Finding {
	f := &Finding{
		Cluster:  cluster,
		RuleID:   ruleID,
		Category: category,
		Severity: severity,
		Resource: resource,
	}
	f.ID = Fingerprint(cluster, ruleID, resource)
	return f
}

// Fingerprint returns the stable ID for a finding.
func Fingerprint(cluster, ruleID string, resource ObjectRef) string {
	sum := sha1.Sum([]byte(cluster + "\x00" + ruleID + "\x00" + resource.Kind + "\x00" + resource.Namespace + "\x00" + resource.Name))
	return hex.EncodeToString(sum[:])[:12]
}

// AddFact appends a piece of evidence, skipping empty values.
func (f *Finding) AddFact(label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	f.Evidence = append(f.Evidence, Fact{Label: label, Value: value})
}

// AddStep appends a fix step.
// SetFact replaces the fact with this label, or adds it.
func (f *Finding) SetFact(label, value string) {
	out := make([]Fact, 0, len(f.Evidence)+1)
	for _, e := range f.Evidence {
		if e.Label != label {
			out = append(out, e)
		}
	}
	f.Evidence = append(out, Fact{Label: label, Value: value})
}

func (f *Finding) AddStep(s Step) { f.Remedy.Steps = append(f.Remedy.Steps, s) }

// IsSymptom reports whether the finding was folded under a root cause.
func (f *Finding) IsSymptom() bool { return f.ParentID != "" }

// IsHygiene reports whether the finding is a good-practice suggestion
// rather than a problem.
func (f *Finding) IsHygiene() bool { return f.Category == Hygiene }
