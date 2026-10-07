// Package output renders scan results as a terminal table, JSON or Markdown.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/version"
)

// Format selects the renderer.
type Format string

const (
	Table    Format = "table"
	JSON     Format = "json"
	Markdown Format = "markdown"
)

// ParseFormat accepts table, json and markdown (or md).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "table", "":
		return Table, nil
	case "json":
		return JSON, nil
	case "markdown", "md":
		return Markdown, nil
	}
	return "", fmt.Errorf("unknown output format %q (want table, json or markdown)", s)
}

// Mode selects the wording: plain language (basic) or technical (full).
type Mode string

const (
	Basic Mode = "basic"
	Full  Mode = "full"
)

// ParseMode accepts basic and full.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "full", "":
		return Full, nil
	case "basic":
		return Basic, nil
	}
	return "", fmt.Errorf("unknown mode %q (want basic or full)", s)
}

// Options control rendering.
type Options struct {
	Format  Format
	Mode    Mode
	Verbose bool
	Color   bool
	Now     time.Time
}

// Report is the JSON document.
type Report struct {
	Tool        string                    `json:"tool"`
	Version     string                    `json:"version"`
	GeneratedAt time.Time                 `json:"generatedAt"`
	Clusters    []*fleet.ClusterResult    `json:"clusters"`
	Totals      map[findings.Priority]int `json:"totals"`
}

// Render writes the results.
func Render(w io.Writer, results []*fleet.ClusterResult, o Options) error {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	switch o.Format {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(Report{
			Tool:        "k0s-monitor",
			Version:     version.Version,
			GeneratedAt: o.Now.UTC(),
			Clusters:    results,
			Totals:      fleet.Totals(results),
		})
	case Markdown:
		return renderMarkdown(w, results, o)
	default:
		return renderTable(w, results, o)
	}
}

// visible returns the findings a mode shows: Basic mode leaves out good
// practices.
func visible(fs []*findings.Finding, mode Mode) []*findings.Finding {
	if mode != Basic {
		return fs
	}
	var out []*findings.Finding
	for _, f := range fs {
		if !f.IsHygiene() {
			out = append(out, f)
		}
	}
	return out
}

func countsText(c map[findings.Priority]int, mode Mode) string {
	if mode == Basic {
		var parts []string
		for _, p := range []findings.Priority{findings.P1, findings.P2, findings.P3, findings.P4} {
			if c[p] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", c[p], strings.ToLower(p.PlainLabel())))
			}
		}
		if len(parts) == 0 {
			return "nothing to fix"
		}
		return strings.Join(parts, " · ")
	}
	return fmt.Sprintf("P1 %d · P2 %d · P3 %d · P4 %d", c[findings.P1], c[findings.P2], c[findings.P3], c[findings.P4])
}

func total(c map[findings.Priority]int) int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

func clusterLine(r *fleet.ClusterResult) string {
	if r.Info == nil {
		return "unreachable"
	}
	parts := []string{}
	if r.Info.Version != "" {
		parts = append(parts, r.Info.Version)
	}
	if !r.Info.K0s && r.Info.Version != "" {
		parts = append(parts, "not k0s")
	}
	parts = append(parts, plural(r.Info.Nodes, "node", "nodes"), plural(r.Info.Pods, "pod", "pods"))
	return strings.Join(parts, " · ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
