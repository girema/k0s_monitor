// Package report makes the report for support (plan section 10.6): a zip
// file with an HTML summary, the open problems with their evidence,
// `kubectl describe` output and log excerpts of the affected objects, the
// cluster's nodes, warning events and k0s control plane, and what
// k0s-monitor could and couldn't read.
//
// Secrets are never included: k0s-monitor doesn't read Secret values for
// it, environment values of secret-looking names are masked, and so are
// tokens, keys and passwords in logs, events and describe output. IP
// addresses can be replaced too.
package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/alerts"
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
)

// Options choose what goes into a report.
type Options struct {
	// MaskIPs replaces IP addresses with names that stay the same across
	// the report (ip-1, ip-2, …).
	MaskIPs bool `json:"maskIPs"`
	// Logs adds log excerpts of the affected containers.
	Logs bool `json:"logs"`
	// Suggestions adds the good-practice findings.
	Suggestions bool `json:"suggestions"`
}

// DefaultOptions are what the report page starts with.
var DefaultOptions = Options{Logs: true}

// Input is what a report is made from.
type Input struct {
	State *engine.State
	// Conn is nil when the cluster can't be reached: then the report has
	// no describe output and no logs.
	Conn *cluster.Conn
	// Tool is k0s-monitor's version, Host the machine it runs on.
	Tool, Host string
	Now        time.Time
	Options    Options
	// Support is who helps with the product, and Packs the product packs
	// in use ("shop 2.3.0"), when packs say so.
	Support string
	Packs   []string
}

// File is one file of the report.
type File struct {
	Path  string `json:"path"`
	About string `json:"about"`
	Size  int    `json:"size"`
	Data  []byte `json:"-"`
}

// Report is a report for support, ready to be written as a zip file.
type Report struct {
	Cluster string    `json:"cluster"`
	Created time.Time `json:"created"`
	Options Options   `json:"options"`
	Files   []File    `json:"files"`
	// Missing says what couldn't be gathered, and why.
	Missing []string `json:"missing,omitempty"`
	// What it holds, for the preview.
	Problems    int `json:"problems"`
	Suggestions int `json:"suggestions"`
	Described   int `json:"described"`
	Logs        int `json:"logs"`
	// MaskedIPs is how many different IP addresses were replaced.
	MaskedIPs int `json:"maskedIPs"`
}

// Limits keep a report small enough to send by email.
const (
	maxObjects     = 40
	maxLogPods     = 20
	maxContainers  = 4
	podsPerApp     = 2
	logTail        = 200
	maxLogBytes    = 128 << 10
	maxEvents      = 300
	callTimeout    = 20 * time.Second
	gatherParallel = 4
)

// Size is the report's size before compression.
func (r *Report) Size() int {
	n := 0
	for _, f := range r.Files {
		n += len(f.Data)
	}
	return n
}

// File returns the file at a path, or nil.
func (r *Report) File(p string) *File {
	for i := range r.Files {
		if r.Files[i].Path == p {
			return &r.Files[i]
		}
	}
	return nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// FileName is the zip file's name: k0s-monitor-report-prod-20261005-0712.zip.
func (r *Report) FileName() string {
	return fmt.Sprintf("k0s-monitor-report-%s-%s.zip", unsafeName.ReplaceAllString(r.Cluster, "_"), r.Created.Format("20060102-1504"))
}

// Zip writes the report as a zip file. Its files sit in one folder named
// like the zip file, so unpacking it doesn't scatter them.
func (r *Report) Zip(w io.Writer) error {
	zw := zip.NewWriter(w)
	dir := strings.TrimSuffix(r.FileName(), ".zip")
	for _, f := range r.Files {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: dir + "/" + f.Path, Method: zip.Deflate, Modified: r.Created})
		if err != nil {
			return err
		}
		if _, err := fw.Write(f.Data); err != nil {
			return err
		}
	}
	return zw.Close()
}

// builder gathers one report.
type builder struct {
	in   Input
	r    *Report
	snap *snapshot.Snapshot

	roots       []*findings.Finding
	symptoms    map[string][]*findings.Finding
	suggestions []*findings.Finding
	all         []*findings.Finding

	objects []findings.ObjectRef
	logPods []findings.ObjectRef
	seen    map[findings.ObjectRef]bool
	// related lists, per finding ID, the objects the report has files
	// about; byRef the log files of each pod.
	related map[string][]findings.ObjectRef
	byRef   map[findings.ObjectRef][]string

	mu    sync.Mutex
	files map[string]File
}

// Build gathers a report. It asks the cluster for describe output and logs
// when it can be reached; the rest comes from what k0s-monitor already
// knows.
func Build(ctx context.Context, in Input) *Report {
	st := in.State
	b := &builder{in: in, snap: st.Snapshot,
		r:        &Report{Cluster: st.Name, Created: in.Now.UTC(), Options: in.Options},
		symptoms: map[string][]*findings.Finding{}, seen: map[findings.ObjectRef]bool{},
		related: map[string][]findings.ObjectRef{}, byRef: map[findings.ObjectRef][]string{}, files: map[string]File{}}
	b.pickFindings()
	b.pickObjects()
	if in.Conn != nil {
		b.gather(ctx)
	} else if len(b.objects) > 0 {
		b.missing("The cluster can't be reached, so the report has no describe output and no logs: the problems are as k0s-monitor last saw them.")
	}
	b.add("problems.json", "The problems as JSON, as k0s-monitor's API returns them", b.problemsJSON())
	b.add("cluster.json", "The cluster's connection, versions, health and what k0s-monitor can read, as JSON", b.clusterJSON())
	if as := b.alerts(); as != nil {
		out, _ := json.MarshalIndent(as, "", "  ")
		b.add("alerts.json", "The alerts firing in the cluster's Prometheus, and the problems they are about, as JSON", append(out, '\n'))
	}
	if b.snap != nil {
		b.add("nodes.txt", "The servers (nodes): state, versions, capacity, conditions and taints", []byte(nodesText(b.snap)))
		if ev := eventsText(b.snap); ev != "" {
			b.add("events.txt", "Warning events, newest first", []byte(ev))
		}
		if cp := b.snap.ControlPlane; cp != nil || b.snap.IsK0s() {
			b.add("k0s.txt", "The k0s control plane: controllers, versions, etcd, updates and add-ons", []byte(k0sText(b.snap)))
		}
		if cfg := k0sConfigYAML(b.snap); cfg != nil {
			b.add("k0s-config.yaml", "k0s's cluster configuration (ClusterConfig), secret-looking values hidden", cfg)
		}
	}
	b.finish()
	return b.r
}

func (b *builder) missing(msg string) {
	b.mu.Lock()
	b.r.Missing = append(b.r.Missing, msg)
	b.mu.Unlock()
}

func (b *builder) add(p, about string, data []byte) {
	b.mu.Lock()
	b.files[p] = File{Path: p, About: about, Data: data}
	b.mu.Unlock()
}

// pickFindings takes the open problems, roots with their symptoms, and the
// suggestions when asked for.
func (b *builder) pickFindings() {
	for _, f := range b.in.State.Findings {
		switch {
		case f.IsHygiene():
			if b.in.Options.Suggestions {
				b.suggestions = append(b.suggestions, f)
				b.all = append(b.all, f)
			}
		case f.IsSymptom():
			b.symptoms[f.ParentID] = append(b.symptoms[f.ParentID], f)
			b.all = append(b.all, f)
		default:
			b.roots = append(b.roots, f)
			b.all = append(b.all, f)
		}
	}
	sort.SliceStable(b.roots, func(i, j int) bool {
		if a, c := b.roots[i].Priority.Rank(), b.roots[j].Priority.Rank(); a != c {
			return a < c
		}
		return b.roots[i].Score > b.roots[j].Score
	})
	b.r.Problems = len(b.roots)
	b.r.Suggestions = len(b.suggestions)
}

// describable are the kinds whose describe output goes into the report.
// Secrets, ConfigMaps and service accounts never do.
var describable = map[string]string{
	"Pod": "", "Node": "", "Service": "", "PersistentVolumeClaim": "", "PersistentVolume": "",
	"Deployment": "apps", "StatefulSet": "apps", "DaemonSet": "apps", "ReplicaSet": "apps",
	"Job": "batch", "CronJob": "batch", "Ingress": "networking.k8s.io",
	"HorizontalPodAutoscaler": "autoscaling", "PodDisruptionBudget": "policy", "StorageClass": "storage.k8s.io",
}

var workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true, "Job": true, "CronJob": true}

// pickObjects chooses the objects to describe and the pods whose logs to
// read: those of the most urgent problems first.
func (b *builder) pickObjects() {
	order := append([]*findings.Finding{}, b.roots...)
	for _, r := range b.roots {
		order = append(order, b.symptoms[r.ID]...)
	}
	order = append(order, b.suggestions...)
	for _, f := range order {
		b.pick(f, f.Resource)
		for _, a := range f.Affected {
			b.pick(f, a)
		}
	}
}

func (b *builder) pick(f *findings.Finding, ref findings.ObjectRef) {
	if _, ok := describable[ref.Kind]; !ok {
		return
	}
	b.object(f, ref)
	switch {
	case ref.Kind == "Pod":
		b.logPod(ref)
	case workloadKinds[ref.Kind] && b.snap != nil:
		for _, p := range worstPods(b.snap, ref) {
			pr := findings.ObjectRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}
			b.object(f, pr)
			b.logPod(pr)
		}
	}
}

func (b *builder) object(f *findings.Finding, ref findings.ObjectRef) {
	if !b.seen[ref] {
		if len(b.objects) >= maxObjects {
			return
		}
		b.seen[ref] = true
		b.objects = append(b.objects, ref)
	}
	for _, r := range b.related[f.ID] {
		if r == ref {
			return
		}
	}
	b.related[f.ID] = append(b.related[f.ID], ref)
}

func (b *builder) logPod(ref findings.ObjectRef) {
	if !b.in.Options.Logs || !b.seen[ref] || len(b.logPods) >= maxLogPods {
		return
	}
	for _, p := range b.logPods {
		if p == ref {
			return
		}
	}
	b.logPods = append(b.logPods, ref)
}

// worstPods picks the pods of an app that show its problem best: not
// ready first, then the most restarted.
func worstPods(s *snapshot.Snapshot, ref findings.ObjectRef) []*corev1.Pod {
	pods := append([]*corev1.Pod{}, s.PodsOf(snapshot.Workload{Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name})...)
	sort.SliceStable(pods, func(i, j int) bool {
		if a, c := podReady(pods[i]), podReady(pods[j]); a != c {
			return !a
		}
		return restarts(pods[i]) > restarts(pods[j])
	})
	if len(pods) > podsPerApp {
		pods = pods[:podsPerApp]
	}
	return pods
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func restarts(p *corev1.Pod) int32 {
	var n int32
	for _, c := range p.Status.ContainerStatuses {
		n += c.RestartCount
	}
	return n
}

func describePath(ref findings.ObjectRef) string {
	kind := strings.ToLower(ref.Kind)
	if ref.Namespace == "" {
		return path.Join("describe", kind, safe(ref.Name)+".txt")
	}
	return path.Join("describe", kind, safe(ref.Namespace), safe(ref.Name)+".txt")
}

func logPath(ref findings.ObjectRef, container string, previous bool) string {
	name := safe(container)
	if previous {
		name += ".previous"
	}
	return path.Join("logs", safe(ref.Namespace), safe(ref.Name), name+".log")
}

func safe(s string) string {
	s = unsafeName.ReplaceAllString(s, "_")
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	return s
}

// gather asks the cluster for describe output and logs, a few at a time.
func (b *builder) gather(ctx context.Context) {
	type job struct {
		run func(context.Context)
	}
	var jobs []job
	for _, ref := range b.objects {
		jobs = append(jobs, job{func(ctx context.Context) { b.describe(ctx, ref) }})
	}
	for _, ref := range b.logPods {
		jobs = append(jobs, job{func(ctx context.Context) { b.logs(ctx, ref) }})
	}
	sem := make(chan struct{}, gatherParallel)
	var wg sync.WaitGroup
	for _, j := range jobs {
		if ctx.Err() != nil {
			b.missing("Gathering took too long, so some describe output and logs are missing.")
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			j.run(cctx)
		}()
	}
	wg.Wait()
}

func (b *builder) describe(ctx context.Context, ref findings.ObjectRef) {
	out, err := describeObject(ctx, b.in.Conn, ref, describable[ref.Kind])
	p := describePath(ref)
	if err != nil {
		b.missing(fmt.Sprintf("%s: %s", p, oneLine(err.Error())))
		return
	}
	b.add(p, fmt.Sprintf("kubectl describe %s", kubectlRef(ref)), []byte(out))
	b.mu.Lock()
	b.r.Described++
	b.mu.Unlock()
}

func (b *builder) logs(ctx context.Context, ref findings.ObjectRef) {
	var pod *corev1.Pod
	if b.snap != nil {
		for _, p := range b.snap.Pods {
			if p.Namespace == ref.Namespace && p.Name == ref.Name {
				pod = p
				break
			}
		}
	}
	if pod == nil {
		return
	}
	statuses := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	n := 0
	for _, s := range statuses {
		if n == maxContainers {
			break
		}
		// A container that waits after a crash has its crashed run as the
		// current log; one that never started has none. While it runs
		// again, the crashed run is the previous one.
		if s.State.Waiting != nil && s.RestartCount == 0 {
			continue
		}
		n++
		b.readLog(ctx, ref, s.Name, false)
		if s.State.Running != nil && s.RestartCount > 0 {
			b.readLog(ctx, ref, s.Name, true)
		}
	}
}

func (b *builder) readLog(ctx context.Context, ref findings.ObjectRef, container string, previous bool) {
	p := logPath(ref, container, previous)
	text, err := readLog(ctx, b.in.Conn, ref, container, previous)
	if err != nil {
		b.missing(fmt.Sprintf("%s: %s", p, oneLine(err.Error())))
		return
	}
	if strings.TrimSpace(text) == "" {
		return
	}
	about := fmt.Sprintf("The last %d lines of the log of container %s in pod %s/%s", logTail, container, ref.Namespace, ref.Name)
	if previous {
		about = fmt.Sprintf("The last %d lines of the log of container %s in pod %s/%s, from before its last restart", logTail, container, ref.Namespace, ref.Name)
	}
	b.add(p, about, []byte(remedy.RedactText(text)))
	b.mu.Lock()
	b.r.Logs++
	b.byRef[ref] = append(b.byRef[ref], p)
	b.mu.Unlock()
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func kubectlRef(ref findings.ObjectRef) string {
	if ref.Namespace == "" {
		return strings.ToLower(ref.Kind) + " " + ref.Name
	}
	return fmt.Sprintf("-n %s %s %s", ref.Namespace, strings.ToLower(ref.Kind), ref.Name)
}

// maskedFindings are copies of the findings with secrets in their evidence
// masked (rules mask what they take from the cluster already; this also
// catches what a log line or an event message carries).
func (b *builder) masked(fs []*findings.Finding) []*findings.Finding {
	out := make([]*findings.Finding, 0, len(fs))
	for _, f := range fs {
		c := f.Clone()
		for i := range c.Evidence {
			c.Evidence[i].Value = remedy.RedactText(c.Evidence[i].Value)
		}
		for i := range c.Alerts {
			c.Alerts[i].Summary = remedy.RedactText(c.Alerts[i].Summary)
		}
		out = append(out, c)
	}
	return out
}

func (b *builder) problemsJSON() []byte {
	out, _ := json.MarshalIndent(b.masked(b.all), "", "  ")
	return append(out, '\n')
}

func (b *builder) clusterJSON() []byte {
	st := b.in.State
	v := map[string]any{
		"name": st.Name, "status": st.Status, "info": st.Info, "error": st.Error, "warnings": st.Warnings,
		"lastSync": st.LastSync, "unreachableSince": st.UnreachableSince, "health": st.Health, "healthAt": st.HealthAt,
		"counts": st.Counts, "foldedSymptoms": st.Symptoms, "suggestions": st.Suggestions, "skippedRules": st.Skipped,
		"evaluations": st.Evals, "k0sMonitor": map[string]string{"version": b.in.Tool, "host": b.in.Host},
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return append(out, '\n')
}

// finish adds the summary and the read-me, masks IP addresses, and orders
// the files.
func (b *builder) finish() {
	var ips *ipMasker
	if b.in.Options.MaskIPs {
		ips = newIPMasker()
		for p, f := range b.files {
			f.Data = []byte(ips.mask(string(f.Data)))
			b.files[p] = f
		}
	}
	b.add("index.html", "The summary: open it in a browser", b.summary(ips))
	b.add("README.txt", "What this report is and how secrets were hidden", []byte(b.readme(ips)))
	if ips != nil {
		for _, p := range []string{"index.html", "README.txt"} {
			f := b.files[p]
			f.Data = []byte(ips.mask(string(f.Data)))
			b.files[p] = f
		}
		b.r.MaskedIPs = ips.count()
	}
	first := map[string]int{"README.txt": 0, "index.html": 1, "problems.json": 2, "cluster.json": 3, "nodes.txt": 4, "events.txt": 5, "k0s.txt": 6, "k0s-config.yaml": 7}
	for _, f := range b.files {
		f.Size = len(f.Data)
		b.r.Files = append(b.r.Files, f)
	}
	sort.Slice(b.r.Files, func(i, j int) bool {
		a, okA := first[b.r.Files[i].Path]
		c, okC := first[b.r.Files[j].Path]
		switch {
		case okA && okC:
			return a < c
		case okA != okC:
			return okA
		}
		return b.r.Files[i].Path < b.r.Files[j].Path
	})
	sort.Strings(b.r.Missing)
}

func (b *builder) readme(ips *ipMasker) string {
	var w bytes.Buffer
	fmt.Fprintf(&w, "Report for support: cluster %s\n", b.r.Cluster)
	fmt.Fprintf(&w, "Made by k0s-monitor %s on %s at %s UTC.\n", b.in.Tool, b.in.Host, b.r.Created.Format("2006-01-02 15:04"))
	if len(b.in.Packs) > 0 {
		fmt.Fprintf(&w, "Product packs: %s.\n", strings.Join(b.in.Packs, ", "))
	}
	if b.in.Support != "" {
		fmt.Fprintf(&w, "Support: %s.\n", b.in.Support)
	}
	w.WriteString("\n")
	w.WriteString("Unpack the zip file, then open index.html in a browser: it summarizes the\n")
	w.WriteString("problems and links to the other files.\n\n")
	w.WriteString("How secrets were kept out\n")
	w.WriteString("- No Secret values were read for this report.\n")
	w.WriteString("- Environment values whose names look secret (password, token, key, ...) are\n")
	w.WriteString("  replaced by " + remedy.Mask + ", and so are passwords in URLs.\n")
	w.WriteString("- In logs and events, values of secret-looking names, bearer tokens, JSON web\n")
	w.WriteString("  tokens, private keys and cloud access keys are replaced too.\n")
	if ips != nil {
		fmt.Fprintf(&w, "- IP addresses are replaced by names: the same address has the same name\n  (ip-1, ip-2, ..., ip6-1 for IPv6) in every file. %d addresses were replaced.\n", ips.count())
	} else {
		w.WriteString("- IP addresses are shown as they are.\n")
	}
	w.WriteString("\nFiles\n")
	paths := make([]string, 0, len(b.files)+2)
	for p := range b.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(&w, "- %s: %s\n", p, b.files[p].About)
	}
	if len(b.r.Missing) > 0 {
		w.WriteString("\nWhat couldn't be gathered\n")
		for _, m := range b.r.Missing {
			fmt.Fprintf(&w, "- %s\n", m)
		}
	}
	return w.String()
}

// reportAlert is a firing alert as the report lists it.
type reportAlert struct {
	Name        string             `json:"name"`
	Severity    string             `json:"severity,omitempty"`
	Labels      map[string]string  `json:"labels"`
	Summary     string             `json:"summary,omitempty"`
	Description string             `json:"description,omitempty"`
	Runbook     string             `json:"runbookUrl,omitempty"`
	Since       *time.Time         `json:"since,omitempty"`
	About       findings.ObjectRef `json:"about"`
	// Problems are the titles of the problems it is about.
	Problems []string `json:"problems,omitempty"`
}

// alerts are the alerts that fire in the cluster's Prometheus, with their
// texts redacted; nil when they can't be read.
func (b *builder) alerts() []reportAlert {
	if b.snap == nil || b.snap.Metrics == nil || !b.snap.Metrics.AlertsRead {
		return nil
	}
	titles := map[string][]string{}
	for _, f := range b.in.State.Findings {
		for _, a := range f.Alerts {
			titles[a.ID] = append(titles[a.ID], f.Title)
		}
	}
	out := []reportAlert{}
	for _, a := range b.snap.Metrics.Alerts {
		r := reportAlert{Name: a.Name, Severity: a.Severity, Labels: a.Labels, Summary: remedy.RedactText(a.Summary),
			Description: remedy.RedactText(a.Description), Runbook: a.Runbook, Problems: titles[a.ID()]}
		if !a.Since.IsZero() {
			t := a.Since.UTC()
			r.Since = &t
		}
		if objs := alerts.Objects(a, b.snap); len(objs) > 0 {
			r.About = objs[0]
		}
		out = append(out, r)
	}
	return out
}
