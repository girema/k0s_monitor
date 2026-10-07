package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/rules"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiOrange = "\033[38;5;208m"
)

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (p painter) prio(pr findings.Priority, s string) string {
	switch pr {
	case findings.P1:
		return p.c(ansiBold+ansiRed, s)
	case findings.P2:
		return p.c(ansiOrange, s)
	case findings.P3:
		return p.c(ansiYellow, s)
	}
	return p.c(ansiDim, s)
}

func renderTable(w io.Writer, results []*fleet.ClusterResult, o Options) error {
	p := painter{on: o.Color}
	fmt.Fprintf(w, "%s · %s · %s\n\n", p.c(ansiBold, "k0s-monitor scan"), o.Now.UTC().Format("2006-01-02 15:04 UTC"), plural(len(results), "cluster", "clusters"))
	for _, r := range results {
		renderClusterTable(w, r, o, p)
	}
	totals := fleet.Totals(results)
	if len(results) > 1 {
		fmt.Fprintf(w, "%s %s in %s: %s\n", p.c(ansiBold, "Total:"), plural(total(totals), "problem", "problems"), plural(len(results), "cluster", "clusters"), countsText(totals, o.Mode))
	}
	if !o.Verbose && total(totals) > 0 {
		fmt.Fprintln(w, p.c(ansiDim, "Run with -v to see the evidence and the steps to fix each problem."))
	}
	return nil
}

func renderClusterTable(w io.Writer, r *fleet.ClusterResult, o Options, p painter) {
	mark := p.c(ansiGreen, "●")
	switch {
	case r.Status == fleet.StatusUnreachable:
		mark = p.c(ansiRed, "✕")
	case r.Counts[findings.P1] > 0:
		mark = p.c(ansiRed, "●")
	case r.Counts[findings.P2] > 0:
		mark = p.c(ansiOrange, "●")
	case r.Status == fleet.StatusPartial:
		mark = p.c(ansiYellow, "●")
	}
	server := ""
	if r.Info != nil {
		server = r.Info.Server
	} else if r.Error != nil {
		server = r.Error.Server
	}
	fmt.Fprintf(w, "%s %s  %s\n", mark, p.c(ansiBold, r.Name), p.c(ansiDim, strings.TrimSpace(server+"  "+clusterLine(r))))
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  %s %s\n", p.c(ansiYellow, "!"), warn)
	}
	if r.Info != nil && len(r.Info.Unreadable) > 0 {
		var kinds []string
		for k, why := range r.Info.Unreadable {
			kinds = append(kinds, k+" ("+why+")")
		}
		sort.Strings(kinds)
		fmt.Fprintf(w, "  %s cannot read: %s\n", p.c(ansiYellow, "!"), strings.Join(kinds, ", "))
	}
	shown := visible(r.Findings, o.Mode)
	if len(shown) == 0 {
		msg := "No problems found."
		if o.Mode == Basic {
			msg = "Everything we checked is working."
		}
		fmt.Fprintf(w, "  %s %s\n\n", p.c(ansiGreen, "✓"), msg)
		return
	}
	if o.Mode == Basic {
		renderBasic(w, shown, o, p)
	} else {
		renderFull(w, r, o, p)
	}
	roots := total(r.Counts)
	extra := ""
	if r.Symptoms > 0 {
		extra = fmt.Sprintf(" (+%s folded under them)", plural(r.Symptoms, "symptom", "symptoms"))
	}
	if r.Suggestions > 0 && o.Mode != Basic {
		extra += fmt.Sprintf(", %s", plural(r.Suggestions, "good-practice suggestion", "good-practice suggestions"))
	}
	fmt.Fprintf(w, "  %s: %s%s\n", plural(roots, "problem", "problems"), countsText(r.Counts, o.Mode), extra)
	if len(r.Skipped) > 0 {
		fmt.Fprintf(w, "  %s %s\n", p.c(ansiDim, "Skipped checks:"), p.c(ansiDim, skippedText(r.Skipped)))
	}
	fmt.Fprintln(w)
}

func renderFull(w io.Writer, r *fleet.ClusterResult, o Options, p painter) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  PRI\tSCORE\tRULE\tRESOURCE\tPROBLEM")
	for _, f := range r.Findings {
		if f.IsSymptom() {
			fmt.Fprintf(tw, "  \t\t%s\t%s\t%s\n", p.c(ansiDim, "↳ "+f.RuleID), p.c(ansiDim, f.Resource.String()), p.c(ansiDim, f.Title))
			continue
		}
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\n", p.prio(f.Priority, string(f.Priority)), f.Score, f.RuleID, f.Resource.String(), f.Title)
	}
	tw.Flush()
	if o.Verbose {
		fmt.Fprintln(w)
		for _, f := range r.Findings {
			renderDetailsFull(w, f, p)
		}
	}
}

func renderDetailsFull(w io.Writer, f *findings.Finding, p painter) {
	head := fmt.Sprintf("%s %d  %s  %s", f.Priority, f.Score, f.RuleID, f.Resource.String())
	if f.IsSymptom() {
		head = "↳ symptom  " + f.RuleID + "  " + f.Resource.String()
	}
	fmt.Fprintf(w, "  %s\n", p.prio(f.Priority, head))
	fmt.Fprintf(w, "    %s\n", f.Summary)
	for _, e := range f.Evidence {
		fmt.Fprintf(w, "    %s %s\n", p.c(ansiDim, e.Label+":"), e.Value)
	}
	if f.Remedy.LikelyCause != "" {
		fmt.Fprintf(w, "    %s %s\n", p.c(ansiBold, "Likely cause:"), f.Remedy.LikelyCause)
	}
	renderSteps(w, f.Remedy.Steps, false, p)
	fmt.Fprintln(w)
}

func renderSteps(w io.Writer, steps []findings.Step, plain bool, p painter) {
	for i, s := range steps {
		text := s.Text
		if plain && s.Plain != "" {
			text = s.Plain
		}
		where := ""
		if s.Host != "" {
			where = p.c(ansiDim, " (run on "+s.Host+")")
		}
		fmt.Fprintf(w, "    %d. %s%s\n", i+1, text, where)
		for _, line := range strings.Split(s.Command, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Fprintf(w, "       %s\n", p.c(ansiDim, "$ ")+line)
			}
		}
	}
}

func renderBasic(w io.Writer, fs []*findings.Finding, o Options, p painter) {
	children := map[string][]*findings.Finding{}
	for _, f := range fs {
		if f.IsSymptom() {
			children[f.ParentID] = append(children[f.ParentID], f)
		}
	}
	for _, f := range fs {
		if f.IsSymptom() {
			continue
		}
		label := fmt.Sprintf("%-10s", f.Priority.PlainLabel())
		fmt.Fprintf(w, "  %s %s\n", p.prio(f.Priority, label), p.c(ansiBold, f.Plain.Title))
		fmt.Fprintf(w, "  %10s %s\n", "", f.Plain.WhatHappened)
		if kids := children[f.ID]; len(kids) > 0 {
			var also []string
			for _, k := range kids {
				also = append(also, lowerFirst(k.Plain.Title))
			}
			fmt.Fprintf(w, "  %10s %s %s\n", "", p.c(ansiDim, "Also affected:"), strings.Join(also, "; "))
		}
		if o.Verbose {
			if f.Plain.Why != "" {
				fmt.Fprintf(w, "  %10s %s %s\n", "", p.c(ansiBold, "Why:"), f.Plain.Why)
			}
			fmt.Fprintf(w, "  %10s %s %s\n", "", p.c(ansiBold, "What to do:"), f.Plain.WhatToDo)
			renderSteps(w, f.Remedy.Steps, true, p)
		}
		fmt.Fprintln(w)
	}
}

// lowerFirst lowercases the first letter, for titles used mid-sentence.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// skippedText groups skipped rules by reason, so a cluster without
// Prometheus reads as one line rather than a list of every metric check.
func skippedText(skipped []rules.Skipped) string {
	var reasons []string
	byReason := map[string][]string{}
	for _, s := range skipped {
		if _, ok := byReason[s.Reason]; !ok {
			reasons = append(reasons, s.Reason)
		}
		byReason[s.Reason] = append(byReason[s.Reason], s.RuleID)
	}
	var parts []string
	for _, reason := range reasons {
		ids := byReason[reason]
		if len(ids) > 3 {
			parts = append(parts, fmt.Sprintf("%d checks (%s)", len(ids), reason))
		} else {
			parts = append(parts, strings.Join(ids, ", ")+" ("+reason+")")
		}
	}
	return strings.Join(parts, "; ")
}
