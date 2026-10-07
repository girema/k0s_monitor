package output

import (
	"fmt"
	"io"
	"strings"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
)

func renderMarkdown(w io.Writer, results []*fleet.ClusterResult, o Options) error {
	fmt.Fprintf(w, "# k0s-monitor scan\n\n%s · %s\n\n", o.Now.UTC().Format("2006-01-02 15:04 UTC"), plural(len(results), "cluster", "clusters"))
	totals := fleet.Totals(results)
	fmt.Fprintf(w, "**Total:** %s — %s\n\n", plural(total(totals), "problem", "problems"), countsText(totals, o.Mode))
	for _, r := range results {
		fmt.Fprintf(w, "## %s\n\n", r.Name)
		if r.Error != nil {
			fmt.Fprintf(w, "**Unreachable.** %s\n\n", mdEscape(r.Error.Plain))
		} else {
			fmt.Fprintf(w, "%s\n\n", clusterLine(r))
		}
		shown := visible(r.Findings, o.Mode)
		if len(shown) == 0 {
			fmt.Fprintf(w, "No problems found.\n\n")
			continue
		}
		if o.Mode == Basic {
			fmt.Fprintf(w, "| Urgency | Problem | What happened |\n|---|---|---|\n")
		} else {
			fmt.Fprintf(w, "| Priority | Score | Rule | Resource | Problem |\n|---|---|---|---|---|\n")
		}
		for _, f := range shown {
			if f.IsSymptom() {
				continue
			}
			if o.Mode == Basic {
				fmt.Fprintf(w, "| %s | %s | %s |\n", f.Priority.PlainLabel(), mdEscape(f.Plain.Title), mdEscape(f.Plain.WhatHappened))
			} else {
				fmt.Fprintf(w, "| %s | %d | `%s` | `%s` | %s |\n", f.Priority, f.Score, f.RuleID, f.Resource.String(), mdEscape(f.Title))
			}
		}
		fmt.Fprintln(w)
		for _, f := range shown {
			writeMarkdownDetails(w, f, o.Mode)
		}
	}
	return nil
}

func writeMarkdownDetails(w io.Writer, f *findings.Finding, mode Mode) {
	title := f.Title
	if mode == Basic {
		title = f.Plain.Title
	}
	prefix := string(f.Priority)
	if mode == Basic {
		prefix = f.Priority.PlainLabel()
	}
	if f.IsSymptom() {
		prefix = "Symptom"
	}
	fmt.Fprintf(w, "### %s: %s\n\n", prefix, mdEscape(title))
	if mode == Basic {
		fmt.Fprintf(w, "%s\n\n", f.Plain.WhatHappened)
		if f.Plain.Why != "" {
			fmt.Fprintf(w, "**Why:** %s\n\n", f.Plain.Why)
		}
		fmt.Fprintf(w, "**What to do:** %s\n\n", f.Plain.WhatToDo)
	} else {
		fmt.Fprintf(w, "`%s` on `%s` (score %d)\n\n%s\n\n", f.RuleID, f.Resource.String(), f.Score, f.Summary)
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "- **%s:** %s\n", e.Label, mdEscape(e.Value))
		}
		if len(f.Evidence) > 0 {
			fmt.Fprintln(w)
		}
		if f.Remedy.LikelyCause != "" {
			fmt.Fprintf(w, "**Likely cause:** %s\n\n", f.Remedy.LikelyCause)
		}
	}
	for i, s := range f.Remedy.Steps {
		text := s.Text
		if mode == Basic && s.Plain != "" {
			text = s.Plain
		}
		if s.Host != "" {
			text += " _(run on " + s.Host + ")_"
		}
		fmt.Fprintf(w, "%d. %s\n", i+1, text)
		if s.Command != "" {
			fmt.Fprintf(w, "\n   ```sh\n")
			for _, line := range strings.Split(s.Command, "\n") {
				fmt.Fprintf(w, "   %s\n", line)
			}
			fmt.Fprintf(w, "   ```\n\n")
		}
	}
	fmt.Fprintln(w)
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}
