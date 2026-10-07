package web

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/store"
)

// notifier turns engine events into in-UI notifications (plan section
// 11.2): a new "Fix now" or "Fix today" problem, a problem that got worse,
// a cluster that can't be reached, and a "Fix now" problem that was
// resolved. Acknowledged or snoozed problems stay quiet.
type notifier struct {
	st     *store.Store
	hub    *hub
	levels map[findings.Priority]bool

	mu      sync.Mutex
	initial map[string][]*findings.Finding // cluster -> new findings of its first evaluation
	timers  map[string]*time.Timer
	delay   time.Duration
}

var notifyLevels = map[string]findings.Priority{
	"fix-now": findings.P1, "fix-today": findings.P2, "plan-ahead": findings.P3, "suggestions": findings.P4,
}

func newNotifier(st *store.Store, h *hub, levels []string) *notifier {
	n := &notifier{st: st, hub: h, levels: map[findings.Priority]bool{},
		initial: map[string][]*findings.Finding{}, timers: map[string]*time.Timer{}, delay: 2 * time.Second}
	for _, l := range levels {
		if p, ok := notifyLevels[l]; ok {
			n.levels[p] = true
		}
	}
	return n
}

// handle is called for every engine event.
func (n *notifier) handle(ev engine.Event) {
	f := ev.Finding
	if f == nil || f.IsSymptom() || f.Stale {
		return
	}
	switch ev.Type {
	case engine.FindingOpened:
		if f.Quiet() || f.IsHygiene() {
			return
		}
		if f.RuleID == cluster.UnreachableRuleID {
			n.add(store.Notification{Cluster: ev.Cluster, FindingID: f.ID, Kind: "unreachable", Priority: f.Priority,
				Title:      fmt.Sprintf("%s can't be reached: %s", ev.Cluster, f.Title),
				PlainTitle: fmt.Sprintf("%s can't be reached", ev.Cluster)})
			return
		}
		if !n.levels[f.Priority] {
			return
		}
		if ev.Initial {
			// A cluster that was just added reports everything at once:
			// one summary instead of a burst.
			n.collectInitial(ev.Cluster, f)
			return
		}
		n.add(store.Notification{Cluster: ev.Cluster, FindingID: f.ID, Kind: "opened", Priority: f.Priority,
			Title: ev.Cluster + ": " + f.Title, PlainTitle: ev.Cluster + ": " + lowerFirst(f.Plain.Title)})
	case engine.FindingUpdated:
		if f.Quiet() || !n.levels[f.Priority] || ev.Previous == "" || f.Priority.Rank() >= ev.Previous.Rank() {
			return
		}
		n.add(store.Notification{Cluster: ev.Cluster, FindingID: f.ID, Kind: "worse", Priority: f.Priority,
			Title:      fmt.Sprintf("%s: %s (was %s)", ev.Cluster, f.Title, ev.Previous),
			PlainTitle: fmt.Sprintf("%s: %s (got worse, was \"%s\")", ev.Cluster, lowerFirst(f.Plain.Title), ev.Previous.PlainLabel())})
	case engine.FindingResolved:
		if f.Priority != findings.P1 && f.RuleID != cluster.UnreachableRuleID {
			return
		}
		title := ev.Cluster + ": resolved: " + f.Title
		plain := ev.Cluster + ": " + resolvedPlain(f)
		if f.RuleID == cluster.UnreachableRuleID {
			title = ev.Cluster + " is reachable again"
			plain = ev.Cluster + " can be reached again"
		}
		n.add(store.Notification{Cluster: ev.Cluster, FindingID: f.ID, Kind: "resolved", Priority: f.Priority,
			Title: title, PlainTitle: plain})
	}
}

// setDelay changes how long the first evaluation's findings are collected
// before the summary is sent (tests use a short one).
func (n *notifier) setDelay(d time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.delay = d
}

func (n *notifier) collectInitial(clusterName string, f *findings.Finding) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.initial[clusterName] = append(n.initial[clusterName], f)
	if n.timers[clusterName] == nil {
		n.timers[clusterName] = time.AfterFunc(n.delay, func() { n.flushInitial(clusterName) })
	}
}

func (n *notifier) flushInitial(clusterName string) {
	n.mu.Lock()
	fs := n.initial[clusterName]
	delete(n.initial, clusterName)
	delete(n.timers, clusterName)
	n.mu.Unlock()
	if len(fs) == 0 {
		return
	}
	if len(fs) == 1 {
		f := fs[0]
		n.add(store.Notification{Cluster: clusterName, FindingID: f.ID, Kind: "opened", Priority: f.Priority,
			Title: clusterName + ": " + f.Title, PlainTitle: clusterName + ": " + lowerFirst(f.Plain.Title)})
		return
	}
	counts := map[findings.Priority]int{}
	worst := findings.P4
	for _, f := range fs {
		counts[f.Priority]++
		if f.Priority.Rank() < worst.Rank() {
			worst = f.Priority
		}
	}
	var full, plain []string
	for _, p := range []findings.Priority{findings.P1, findings.P2, findings.P3, findings.P4} {
		if c := counts[p]; c > 0 {
			full = append(full, fmt.Sprintf("%d %s", c, p))
			plain = append(plain, fmt.Sprintf("%d %s", c, strings.ToLower(p.PlainLabel())))
		}
	}
	n.add(store.Notification{Cluster: clusterName, Kind: "summary", Priority: worst,
		Title:      fmt.Sprintf("%s: %d problems found (%s)", clusterName, len(fs), strings.Join(full, ", ")),
		PlainTitle: fmt.Sprintf("%s: %d problems found (%s)", clusterName, len(fs), strings.Join(plain, ", "))})
}

func (n *notifier) add(nt store.Notification) {
	saved, err := n.st.AddNotification(nt)
	if err != nil {
		return
	}
	n.hub.publish("notification", saved.Cluster, saved)
}

func resolvedPlain(f *findings.Finding) string {
	t := f.Plain.Title
	if t == "" {
		t = f.Title
	}
	return "fixed: " + lowerFirst(t)
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
