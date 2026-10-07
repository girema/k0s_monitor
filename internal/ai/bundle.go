package ai

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/report"
	"k0s_monitor/internal/snapshot"
)

// Input is what a problem's explanation is asked from.
type Input struct {
	Cluster string
	// Kubernetes and K0s are the cluster's versions, when known.
	Kubernetes, K0s string
	Nodes           int
	Finding         *findings.Finding
	// Children are the problems folded under it.
	Children []*findings.Finding
	Snapshot *snapshot.Snapshot
	// Basic asks for plain language, for someone who isn't a Kubernetes
	// expert; otherwise the answer is for an administrator.
	Basic bool
	Now   time.Time
}

// Limits on what is sent.
const (
	maxEvents   = 10
	maxLogLines = 30
	maxBundle   = 24 << 10
)

// Messages are what is sent for a problem: the instructions, and the
// problem as k0s-monitor sees it. Every text from the cluster goes through
// the same redaction as the report for support: values of secret-looking
// names, tokens, keys and passwords in URLs are replaced; with MaskIPs,
// IP addresses become ip-1, ip-2, …. No Secret value is ever in it:
// k0s-monitor reads none for this.
func Messages(in Input, cfg Config) []Message {
	return []Message{{Role: "system", Content: instructions(in, cfg)}, {Role: "user", Content: describe(in, cfg)}}
}

func instructions(in Input, cfg Config) string {
	var b strings.Builder
	b.WriteString("You help people run k0s Kubernetes clusters. k0s-monitor, a read-only diagnostics tool, found the problem described below. ")
	b.WriteString("Explain what most likely causes it and how to fix it, from the facts given. Where the facts don't settle it, say what to check, and how. ")
	b.WriteString("Don't invent facts, object names or settings that aren't in the description. ")
	b.WriteString("Commands are run by people, not by k0s-monitor: use `k0s kubectl` (the kubectl that ships with k0s), say on which machine a command runs, and warn before anything that deletes data or restarts the cluster's own parts. ")
	if in.Basic {
		b.WriteString("The reader is not a Kubernetes expert: use plain, short sentences, explain any technical word the first time, and say who should do each step (the reader, whoever manages the servers, or the support team). ")
	} else {
		b.WriteString("The reader administers the cluster: be precise and technical, and give the commands. ")
	}
	b.WriteString("Keep it short: a few sentences on the cause, then numbered steps. Use simple Markdown (headings, lists, `code`). ")
	fmt.Fprintf(&b, "Answer in %s.", cfg.AnswerLanguage())
	return b.String()
}

func describe(in Input, cfg Config) string {
	var mask func(string) string
	if cfg.MaskIPs {
		m := report.NewIPMasker()
		mask = func(s string) string { return m.Mask(remedy.RedactText(s)) }
	} else {
		mask = remedy.RedactText
	}
	f := in.Finding
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	cluster := "Cluster: " + in.Cluster
	var about []string
	if in.Kubernetes != "" {
		about = append(about, "Kubernetes "+in.Kubernetes)
	}
	if in.K0s != "" {
		about = append(about, "k0s "+in.K0s)
	}
	if in.Nodes > 0 {
		about = append(about, plural(in.Nodes, "node"))
	}
	if len(about) > 0 {
		cluster += " (" + strings.Join(about, ", ") + ")"
	}
	line("%s", mask(cluster))
	line("")
	line("## Problem")
	line("%s", mask(f.Title))
	line("Rule: %s · priority %s (%s) · object: %s", f.RuleID, f.Priority, f.Priority.PlainLabel(), mask(f.Resource.String()))
	if f.Since != nil && !in.Now.IsZero() {
		line("Since: %s ago", roughly(in.Now.Sub(*f.Since)))
	}
	if f.Summary != "" {
		line("%s", mask(f.Summary))
	}
	if len(f.Evidence) > 0 {
		line("")
		line("## Evidence")
		for _, e := range f.Evidence {
			line("- %s: %s", e.Label, mask(strings.ReplaceAll(e.Value, "\n", "; ")))
		}
	}
	if len(f.Affected) > 0 {
		var refs []string
		for _, r := range f.Affected {
			refs = append(refs, r.String())
		}
		line("")
		line("Affected: %s", mask(strings.Join(refs, ", ")))
	}
	if r := f.Rollout; r != nil {
		line("")
		line("## It started with an update")
		line("%s was updated to revision %d (from %d).", mask(r.Workload.String()), r.Revision, r.Previous)
		for _, ch := range r.Changes {
			what := ch.What
			if ch.Container != "" {
				what = ch.Container + ": " + what
			}
			if ch.Old != "" && ch.Old == ch.New {
				line("- %s changed (value hidden)", what)
				continue
			}
			line("- %s: %s → %s", what, mask(orDash(ch.Old)), mask(orDash(ch.New)))
		}
	}
	if f.Remedy.LikelyCause != "" {
		line("")
		line("k0s-monitor's likely cause: %s", mask(f.Remedy.LikelyCause))
	}
	if len(f.Remedy.Steps) > 0 {
		line("")
		line("## Steps k0s-monitor suggests")
		for i, s := range f.Remedy.Steps {
			where := ""
			if s.Host != "" {
				where = " (on " + s.Host + ")"
			}
			line("%d. %s%s", i+1, mask(s.Text), mask(where))
			if s.Command != "" {
				line("   `%s`", mask(strings.ReplaceAll(s.Command, "\n", " ; ")))
			}
		}
	}
	if len(in.Children) > 0 {
		line("")
		line("## Caused by this problem too")
		for _, c := range in.Children {
			line("- %s (%s)", mask(c.Title), mask(c.Resource.String()))
		}
	}
	alerts := map[string]findings.Alert{}
	for _, x := range append([]*findings.Finding{f}, in.Children...) {
		for _, a := range x.Alerts {
			alerts[a.ID] = a
		}
	}
	if len(alerts) > 0 {
		line("")
		line("## Alerts from the cluster's Prometheus")
		for _, id := range sortedIDs(alerts) {
			a := alerts[id]
			line("- %s (%s): %s", a.Name, orDash(a.Severity), mask(a.Summary))
		}
	}
	if s := in.Snapshot; s != nil {
		if evs := events(s, f); len(evs) > 0 {
			line("")
			line("## Recent warning events")
			for _, e := range evs {
				line("- %s", mask(e))
			}
		}
		if !cfg.NoLogs {
			if logs := logLines(s, f); len(logs) > 0 {
				line("")
				line("## Log lines from the last crash")
				for _, l := range logs {
					line("    %s", mask(l))
				}
			}
		}
	}
	out := b.String()
	if len(out) > maxBundle {
		out = out[:maxBundle] + "\n[cut: the description is longer than k0s-monitor sends]\n"
	}
	return out
}

// events are the newest warning events about the problem's objects.
func events(s *snapshot.Snapshot, f *findings.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append([]findings.ObjectRef{f.Resource}, f.Affected...) {
		for _, e := range s.EventsFor("", r.Kind, r.Namespace, r.Name) {
			key := e.Reason + "|" + e.Message
			if seen[key] {
				continue
			}
			seen[key] = true
			text := fmt.Sprintf("%s %s/%s: %s: %s", strings.ToLower(e.InvolvedObject.Kind), e.InvolvedObject.Namespace, e.InvolvedObject.Name, e.Reason, strings.TrimSpace(e.Message))
			if e.Count > 1 {
				text += fmt.Sprintf(" (%d times)", e.Count)
			}
			out = append(out, text)
			if len(out) == maxEvents {
				return out
			}
		}
	}
	return out
}

// logLines are the lines that look like errors in the last crash of the
// problem's pods, as k0s-monitor read them (secrets masked already).
func logLines(s *snapshot.Snapshot, f *findings.Finding) []string {
	var out []string
	for _, r := range f.Affected {
		if r.Kind != "Pod" {
			continue
		}
		var keys []string
		for k, cl := range s.CrashLogs {
			if cl != nil && cl.Namespace == r.Namespace && cl.Pod == r.Name {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			cl := s.CrashLogs[k]
			for _, l := range cl.Lines {
				out = append(out, cl.Container+": "+l)
				if len(out) == maxLogLines {
					return out
				}
			}
		}
		if len(out) > 0 {
			return out // one pod's crash tells the story
		}
	}
	return out
}

func sortedIDs(m map[string]findings.Alert) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func roughly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
