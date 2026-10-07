package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/priority"
	"k0s_monitor/internal/rules"
)

//go:embed summary.html
var summaryHTML string

var summaryTmpl = template.Must(template.New("summary").Funcs(template.FuncMap{
	"prio": func(p findings.Priority) string { return strings.ToLower(string(p)) },
	"size": func(n int) string {
		if n < 1024 {
			return fmt.Sprintf("%d B", n)
		}
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	},
	"utc": func(t *time.Time) string {
		if t == nil || t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"lines": func(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") },
	"plural": func(n int, word string) string {
		if n == 1 {
			return "1 " + word
		}
		return fmt.Sprintf("%d %ss", n, word)
	},
}).Parse(summaryHTML))

type sumFinding struct {
	*findings.Finding
	Symptoms []*findings.Finding
	Files    []string
}

type countRow struct {
	Priority findings.Priority
	Label    string
	N        int
}

type keyValue struct{ Key, Value string }

type sumData struct {
	Cluster, Created, Tool, Host string
	Support                      string
	Packs                        []string
	Options                      Options
	MaskIPs                      bool
	Status                       string
	Problem                      string
	Server, Kubernetes, K0s      string
	Nodes, Pods                  int
	Health                       *priority.Health
	HealthAt                     string
	Counts                       []countRow
	Problems                     []sumFinding
	Suggestions                  []sumFinding
	// Alerts fire in the cluster's Prometheus; AlertsRead says they could
	// be read.
	Alerts     []reportAlert
	AlertsRead bool
	Metrics    string
	Unreadable []keyValue
	// Skipped are the rules that couldn't run, by reason.
	Skipped  []keyValue
	Warnings []string
	Missing  []string
	Files    []File
}

func (b *builder) summary(ips *ipMasker) []byte {
	st := b.in.State
	d := sumData{Cluster: st.Name, Created: b.r.Created.Format("2006-01-02 15:04 UTC"), Tool: b.in.Tool, Host: b.in.Host,
		Support: b.in.Support, Packs: b.in.Packs, Options: b.in.Options, MaskIPs: ips != nil, Missing: b.r.Missing, Skipped: skippedByReason(st.Skipped), Warnings: st.Warnings}
	switch st.Status {
	case engine.StatusOK:
		d.Status = "connected"
	case engine.StatusPartial:
		d.Status = "connected, but some kinds of objects can't be read"
	case engine.StatusUnreachable:
		d.Status = "can't be reached"
		if st.UnreachableSince != nil {
			d.Status += " since " + st.UnreachableSince.UTC().Format("2006-01-02 15:04 UTC") + "; the problems are as last seen"
		}
	default:
		d.Status = string(st.Status)
	}
	if st.Error != nil {
		d.Problem = st.Error.Error()
	}
	if i := st.Info; i != nil {
		d.Server, d.Kubernetes, d.Nodes, d.Pods = i.Server, i.Version, i.Nodes, i.Pods
		for _, k := range sortedKeys(i.Unreadable) {
			d.Unreadable = append(d.Unreadable, keyValue{k, i.Unreadable[k]})
		}
		if p := i.Prometheus; p != nil {
			d.Metrics = p.State
			if p.Target != "" {
				d.Metrics += ": " + p.Target
			}
			if p.Message != "" {
				d.Metrics += " (" + p.Message + ")"
			}
		}
		if i.TLSSecrets != "" && i.TLSSecrets != "ok" {
			d.Unreadable = append(d.Unreadable, keyValue{"TLS certificates", i.TLSSecrets})
		}
	}
	if b.snap != nil {
		if v, from, ok := b.snap.ExpectedVersion(); ok {
			d.K0s = v.Raw + " (" + from + ")"
		}
	}
	d.Health = st.Health
	d.Alerts = b.alerts()
	d.AlertsRead = d.Alerts != nil
	if st.HealthAt != nil && st.Status == engine.StatusUnreachable {
		d.HealthAt = st.HealthAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	for _, p := range []findings.Priority{findings.P1, findings.P2, findings.P3} {
		d.Counts = append(d.Counts, countRow{p, p.PlainLabel(), st.Counts[p]})
	}
	masked := map[string]*findings.Finding{}
	for _, f := range b.masked(b.all) {
		masked[f.ID] = f
	}
	sf := func(f *findings.Finding) sumFinding {
		s := sumFinding{Finding: masked[f.ID]}
		for _, sym := range b.symptoms[f.ID] {
			s.Symptoms = append(s.Symptoms, masked[sym.ID])
		}
		for _, ref := range b.related[f.ID] {
			if _, ok := b.files[describePath(ref)]; ok {
				s.Files = append(s.Files, describePath(ref))
			}
			s.Files = append(s.Files, b.byRef[ref]...)
		}
		return s
	}
	for _, f := range b.roots {
		d.Problems = append(d.Problems, sf(f))
	}
	for _, f := range b.suggestions {
		d.Suggestions = append(d.Suggestions, sf(f))
	}
	for _, f := range b.files {
		d.Files = append(d.Files, File{Path: f.Path, About: f.About, Size: len(f.Data)})
	}
	sort.Slice(d.Files, func(i, j int) bool { return d.Files[i].Path < d.Files[j].Path })
	var out bytes.Buffer
	if err := summaryTmpl.Execute(&out, d); err != nil {
		return []byte("The summary couldn't be made: " + template.HTMLEscapeString(err.Error()))
	}
	return out.Bytes()
}

// skippedByReason lists the skipped rules once per reason.
func skippedByReason(sk []rules.Skipped) []keyValue {
	var out []keyValue
	at := map[string]int{}
	for _, r := range sk {
		i, ok := at[r.Reason]
		if !ok {
			i = len(out)
			at[r.Reason] = i
			out = append(out, keyValue{Value: r.Reason})
		}
		if out[i].Key != "" {
			out[i].Key += ", "
		}
		out[i].Key += r.RuleID
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
