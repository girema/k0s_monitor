package web

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

// The Servers (Nodes & VMs) and Storage pages (plan sections 11.3 and
// 11.4): what Kubernetes and Prometheus say about each node and volume.

// usage is a percentage cell: a meter, or a short text when the value is
// not known.
type usage struct {
	Known bool
	Pct   int
	Cls   string // meter color: "" (normal), warn, serious or crit
	Text  string
	Title string
}

// levelUsage colors a share (0..1) by percentage levels.
func levelUsage(frac float64, l config.Levels, title string) usage {
	if !snapshot.Known(frac) {
		return usage{Text: "—", Title: "no data"}
	}
	u := usage{Known: true, Pct: int(math.Round(frac * 100)), Title: title}
	p := frac * 100
	switch {
	case l.Critical > 0 && p >= l.Critical:
		u.Cls = "crit"
	case l.High > 0 && p >= l.High:
		u.Cls = "serious"
	case l.Warn > 0 && p >= l.Warn:
		u.Cls = "warn"
	}
	return u
}

// chip is a small labeled signal, such as "steal 18%".
type chip struct {
	Text  string
	Icon  string // warn, crit or empty
	Mark  string
	Title string
}

// chart is a line chart drawn by charts.js from JSON, with a table for
// readers without it.
type chart struct {
	JSON  string
	Aria  string
	Rows  [][2]string // time, value
	Empty string
}

type chartDoc struct {
	Aria       string       `json:"aria"`
	Series     [][2]float64 `json:"series"` // unix seconds, percent
	Start      int64        `json:"start"`
	End        int64        `json:"end"`
	Now        int64        `json:"now"`
	Thresholds []chartLine  `json:"thresholds,omitempty"`
	Projection *chartPoint  `json:"projection,omitempty"`
}

type chartLine struct {
	V     float64 `json:"v"`
	Label string  `json:"label"`
	Kind  string  `json:"kind"` // crit or muted
	Below bool    `json:"below,omitempty"`
}

type chartPoint struct {
	T     int64   `json:"t"`
	V     float64 `json:"v"`
	Label string  `json:"label"`
}

// newChart makes a chart of percentages over the last 24 hours, and a
// projection when one is given.
func newChart(aria string, pts []snapshot.Point, scale float64, now time.Time, lines []chartLine, proj *chartPoint) *chart {
	c := &chart{Aria: aria}
	if len(pts) < 2 {
		c.Empty = "No history yet."
		return c
	}
	d := chartDoc{Aria: aria, Start: now.Add(-24 * time.Hour).Unix(), End: now.Unix(), Now: now.Unix(), Thresholds: lines, Projection: proj}
	for _, p := range pts {
		if !snapshot.Known(p.V) {
			continue
		}
		v := math.Round(p.V*scale*1000) / 10
		d.Series = append(d.Series, [2]float64{float64(p.T.Unix()), v})
	}
	if len(d.Series) < 2 {
		c.Empty = "No history yet."
		return c
	}
	if first := int64(d.Series[0][0]); first < d.Start {
		d.Start = first
	}
	if proj != nil && proj.T > d.End {
		d.End = proj.T
	}
	js, _ := json.Marshal(d)
	c.JSON = string(js)
	// Every 2 hours for the table.
	next := time.Time{}
	for i, p := range d.Series {
		t := time.Unix(int64(p[0]), 0).UTC()
		if i == len(d.Series)-1 || !t.Before(next) {
			c.Rows = append(c.Rows, [2]string{t.Format("15:04"), strconv.FormatFloat(p[1], 'f', 1, 64) + "%"})
			next = t.Add(2 * time.Hour)
		}
	}
	return c
}

// spark is a sparkline of percentages: at most one value per hour.
func spark(pts []snapshot.Point, scale float64) (values, label string) {
	var vs []string
	var first, last float64
	next := time.Time{}
	for i, p := range pts {
		if !snapshot.Known(p.V) {
			continue
		}
		if i != len(pts)-1 && p.T.Before(next) {
			continue
		}
		next = p.T.Add(time.Hour)
		v := math.Round(p.V*scale*1000) / 10
		if len(vs) == 0 {
			first = v
		}
		last = v
		vs = append(vs, strconv.FormatFloat(v, 'f', 1, 64))
	}
	if len(vs) < 2 {
		return "", ""
	}
	return strings.Join(vs, ","), fmt.Sprintf("last 24 h: %.0f%% to %.0f%%", first, last)
}

// rootFindings maps a resource to its most urgent root finding, and lists
// every root finding about it.
func rootFindings(st *engine.State, match func(*findings.Finding) (string, bool)) (map[string]*findings.Finding, map[string][]*findings.Finding) {
	top, all := map[string]*findings.Finding{}, map[string][]*findings.Finding{}
	for _, f := range st.Findings { // already in priority order
		if f.IsSymptom() {
			continue
		}
		if key, ok := match(f); ok {
			if top[key] == nil {
				top[key] = f
			}
			all[key] = append(all[key], f)
		}
	}
	return top, all
}

// ---------------------------------------------------------------------------
// Servers

type serverRow struct {
	Name, Role, IP     string
	Status, Icon, Mark string
	Plain              string // the status in Basic mode
	CPU, Mem, Disk     usage
	Pods, MaxPods      int
	Signals            []chip
	Version, Kernel    string
	Link               string
	Selected           bool
	Top                *findings.Finding
}

type condRow struct {
	Type, Status, Since string
	Icon, Mark          string
}

type fsRow struct {
	Mountpoint, Device, FSType string
	Size, Free                 string
	Used                       usage
	Inodes                     string
	Kubelet, ReadOnly          bool
}

type fact struct{ Label, Value string }

type serverDetail struct {
	Row         serverRow
	Conditions  []condRow
	Host        []fact
	HostNote    string
	Filesystems []fsRow
	Chart       *chart
	ChartTitle  string
	Problems    []*findings.Finding
	Top         *findings.Finding
}

// downServer is a node that stopped responding, with instructions to
// send to whoever manages the machine.
type downServer struct {
	F    *findings.Finding
	Copy string
}

// instructions are a finding's plain text and steps, to copy and send.
func instructions(f *findings.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n%s\n", f.Plain.Title, f.Plain.WhatHappened)
	if f.Plain.WhatToDo != "" {
		fmt.Fprintf(&b, "\nWhat to do: %s\n", f.Plain.WhatToDo)
	}
	for i, st := range f.Remedy.Steps {
		text := st.Text
		if st.Plain != "" {
			text = st.Plain
		}
		fmt.Fprintf(&b, "\n%d. %s\n", i+1, text)
		if st.Command != "" {
			where := ""
			if st.Host != "" {
				where = " (on " + st.Host + ")"
			}
			fmt.Fprintf(&b, "   Run%s:\n   %s\n", where, strings.ReplaceAll(st.Command, "\n", "\n   "))
		}
	}
	return b.String()
}

type serversData struct {
	State   *engine.State
	Down    []downServer // nodes that stopped responding
	Rows    []serverRow
	Detail  *serverDetail
	Source  string // where usage comes from
	NoUsage string // why usage is missing
}

func serversOf(st *engine.State, t config.Thresholds, selected string, now time.Time) serversData {
	d := serversData{State: st}
	snap := st.Snapshot
	if snap == nil {
		return d
	}
	m := snap.Metrics
	top, all := rootFindings(st, func(f *findings.Finding) (string, bool) {
		if f.Resource.Kind == "Node" {
			return f.Resource.Name, true
		}
		return "", false
	})
	for _, f := range st.Findings {
		if f.RuleID == "node.not-ready" && !f.IsSymptom() {
			d.Down = append(d.Down, downServer{F: f, Copy: instructions(f)})
		}
	}
	exporter := m != nil && m.Have["node-exporter"]
	switch {
	case exporter:
		d.Source = "Usage from node-exporter, averaged over 15 minutes."
		if len(m.NodeUsage) > 0 {
			d.Source += " Nodes without node-exporter show current values from the metrics API."
		}
	case m != nil && (len(m.NodeUsage) > 0 || m.Have["kubelet-nodefs"]):
		var from []string
		if len(m.NodeUsage) > 0 {
			from = append(from, "CPU and memory are current values from the metrics API")
		}
		if m.Have["kubelet-nodefs"] {
			from = append(from, "disk usage comes from the kubelets")
		}
		d.Source = "No node-exporter data: " + strings.Join(from, ", ") + ". VM signals need Prometheus or VictoriaMetrics with node-exporter."
	case m != nil:
		d.NoUsage = "The metrics have no node-exporter data, so server usage and VM signals are not known."
	default:
		d.NoUsage = "Server usage and VM signals need Prometheus or VictoriaMetrics with node-exporter."
	}
	for _, n := range snap.Nodes {
		r := serverRow{Name: n.Name, Role: "worker", Pods: len(snap.PodsOnNode(n.Name)), Link: "?node=" + n.Name,
			Version: n.Status.NodeInfo.KubeletVersion, Kernel: n.Status.NodeInfo.KernelVersion, Top: top[n.Name]}
		if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
			r.Role = "controller + worker"
		}
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				r.IP = a.Address
				break
			}
		}
		if q, ok := n.Status.Allocatable[corev1.ResourcePods]; ok {
			r.MaxPods = int(q.Value())
		}
		r.Status, r.Icon, r.Mark = nodeStatus(n)
		r.Plain = plainStatus(r.Status)
		var nm *snapshot.NodeMetrics
		var nu snapshot.NodeUsage
		hasUsage := false
		if m != nil {
			nm = m.Nodes[n.Name]
			nu, hasUsage = m.NodeUsage[n.Name]
		}
		fromExporter := nm != nil && nm.Instance != "" && nm.Up
		if !snapshot.IsNodeReady(n) && !fromExporter {
			text, title := "stale", "the node stopped responding"
			if since, ok := notReadySince(n); ok {
				text = "stale " + ago(now.Sub(since))
			}
			r.CPU, r.Mem, r.Disk = usage{Text: text, Title: title}, usage{Text: text, Title: title}, usage{Text: text, Title: title}
			d.Rows = append(d.Rows, r)
			continue
		}
		sat := t.NodeSaturationPercent
		cpu, mem := snapshot.Missing, snapshot.Missing
		cpuTitle, memTitle := "CPU busy, average over 15 min", "memory in use, average over 15 min"
		if fromExporter {
			cpu = nm.CPUBusy15m
			if snapshot.Known(nm.MemTotal) && nm.MemTotal > 0 && snapshot.Known(nm.MemAvailable15m) {
				mem = 1 - nm.MemAvailable15m/nm.MemTotal
			}
			r.Signals = vmSignals(nm, t, now)
		} else if exporter {
			r.Signals = []chip{{Text: "no metrics", Icon: "crit", Mark: "✕", Title: "the metrics have no node-exporter data from this node"}}
		}
		if hasUsage {
			if q, ok := n.Status.Allocatable[corev1.ResourceCPU]; !snapshot.Known(cpu) && ok && q.MilliValue() > 0 && snapshot.Known(nu.CPUCores) {
				cpu, cpuTitle = nu.CPUCores/q.AsApproximateFloat64(), "CPU in use now, of the allocatable CPU (metrics API)"
			}
			if q, ok := n.Status.Allocatable[corev1.ResourceMemory]; !snapshot.Known(mem) && ok && q.Value() > 0 && snapshot.Known(nu.MemoryBytes) {
				mem, memTitle = nu.MemoryBytes/q.AsApproximateFloat64(), "memory in use now, of the allocatable memory (metrics API)"
			}
		}
		r.CPU, r.Mem = levelUsage(cpu, sat, cpuTitle), levelUsage(mem, sat, memTitle)
		r.Disk = usage{Text: "—"}
		if nm != nil {
			if fs, ok := nm.KubeletFilesystem(); ok {
				title := "the disk holding " + snapshot.K0sDataDir + " (" + fs.Mountpoint + ")"
				if !fromExporter {
					title = "the kubelet's disk (nodefs), from the kubelet"
				}
				r.Disk = levelUsage(fs.UsedFraction(), t.NodeDiskPercent, title)
			}
		}
		for _, u := range []*usage{&r.CPU, &r.Mem, &r.Disk} {
			if !u.Known {
				u.Title = orText(d.NoUsage, "not known for this node")
			}
		}
		d.Rows = append(d.Rows, r)
	}

	// The node shown in detail: the one asked for, else the first with a
	// problem that is still responding, else the first with any problem.
	pick := -1
	for i, r := range d.Rows {
		if r.Name == selected {
			pick = i
		}
	}
	if pick < 0 && selected == "" {
		best := findings.Priority("")
		for i, r := range d.Rows {
			if r.Top == nil || r.Top.RuleID == "node.not-ready" {
				continue
			}
			if pick < 0 || r.Top.Priority.Rank() < best.Rank() {
				pick, best = i, r.Top.Priority
			}
		}
		for i, r := range d.Rows {
			if pick < 0 && r.Top != nil {
				pick = i
			}
		}
	}
	if pick >= 0 {
		d.Rows[pick].Selected = true
		d.Detail = serverDetailOf(snap, d.Rows[pick], all[d.Rows[pick].Name], t, now)
	}
	return d
}

func nodeStatus(n *corev1.Node) (text, icon, mark string) {
	if !snapshot.IsNodeReady(n) {
		return "NotReady", "crit", "✕"
	}
	var bad []string
	for _, c := range n.Status.Conditions {
		if c.Type != corev1.NodeReady && c.Status == corev1.ConditionTrue && problemCondition(string(c.Type)) {
			bad = append(bad, string(c.Type))
		}
	}
	switch {
	case len(bad) > 0:
		return strings.Join(bad, ", "), "serious", "▲"
	case n.Spec.Unschedulable:
		return "Cordoned", "warn", "▲"
	}
	return "Ready", "good", "✓"
}

var plainConditions = map[string]string{
	"NotReady": "Not responding", "Ready": "Working", "Cordoned": "Takes no new apps",
	"DiskPressure": "Low on disk space", "MemoryPressure": "Low on memory", "PIDPressure": "Too many processes",
	"NetworkUnavailable": "Network not set up",
}

// problemCondition reports whether a node condition means trouble while it
// is True: the kubelet's pressure and network conditions, and those of
// node-problem-detector. Other tools' conditions may mean the opposite.
func problemCondition(t string) bool {
	if strings.HasSuffix(t, "Pressure") || t == string(corev1.NodeNetworkUnavailable) {
		return true
	}
	_, ok := rules.NodeProblemCondition(t)
	return ok
}

// plainStatus words a node status for Basic mode.
func plainStatus(status string) string {
	var out []string
	for _, p := range strings.Split(status, ", ") {
		if w, ok := plainConditions[p]; ok {
			out = append(out, w)
		} else if w, ok := rules.NodeProblemCondition(p); ok {
			out = append(out, w)
		} else {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

func notReadySince(n *corev1.Node) (time.Time, bool) {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && !c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

// vmSignals are what Kubernetes can't see: CPU steal, iowait, clock,
// reboots, swap and slow disks. Quiet values are left out.
func vmSignals(m *snapshot.NodeMetrics, t config.Thresholds, now time.Time) []chip {
	var out []chip
	add := func(text string, level int, title string) {
		c := chip{Text: text, Title: title}
		switch level {
		case 2:
			c.Icon, c.Mark = "crit", "!"
		case 1:
			c.Icon, c.Mark = "warn", "▲"
		}
		out = append(out, c)
	}
	lvl := func(v float64, l config.Levels) int {
		switch {
		case l.High > 0 && v >= l.High:
			return 2
		case l.Warn > 0 && v >= l.Warn:
			return 1
		}
		return 0
	}
	if v := m.CPUSteal * 100; snapshot.Known(v) && v >= 2 {
		add(fmt.Sprintf("steal %.0f%%", v), lvl(v, t.CPUStealPercent), "CPU time the hypervisor withheld, over 5 min")
	}
	if v := m.CPUIOWait * 100; snapshot.Known(v) && v >= 2 {
		add(fmt.Sprintf("iowait %.0f%%", v), lvl(v, t.IOWaitPercent), "CPU time waiting for disks, over 5 min")
	}
	if lat := max(m.DiskWriteLatency, m.DiskReadLatency); snapshot.Known(lat) && t.DiskLatency.Warn > 0 && lat >= t.DiskLatency.Warn.D().Seconds() {
		level := 1
		if t.DiskLatency.High > 0 && lat >= t.DiskLatency.High.D().Seconds() {
			level = 2
		}
		add(fmt.Sprintf("disk %.0f ms", lat*1000), level, "time per disk operation on "+m.DiskDevice)
	}
	if off := m.ClockOffset; snapshot.Known(off) && math.Abs(off) >= 0.5 {
		level := 0
		if t.ClockSkew.Warn > 0 && math.Abs(off) >= t.ClockSkew.Warn.D().Seconds() {
			level = 1
		}
		if t.ClockSkew.High > 0 && math.Abs(off) >= t.ClockSkew.High.D().Seconds() {
			level = 2
		}
		add(fmt.Sprintf("skew %+.1fs", off), level, "clock offset")
	}
	if m.ClockSynced == 0 {
		add("clock not synced", 1, "the clock is not synchronized with NTP")
	}
	if snapshot.Known(m.SwapTotal) && m.SwapTotal > 0 && snapshot.Known(m.SwapFree) {
		if used := (m.SwapTotal - m.SwapFree) / m.SwapTotal; used >= 0.5 {
			add(fmt.Sprintf("swap %.0f%%", used*100), 1, "swap in use")
		}
	}
	if !m.BootTime.IsZero() && now.Sub(m.BootTime) < 24*time.Hour {
		add("rebooted "+ago(now.Sub(m.BootTime))+" ago", 0, "booted at "+stamp(m.BootTime))
	}
	for _, f := range m.Filesystems {
		if f.ReadOnly {
			add("read-only "+f.Mountpoint, 2, "the filesystem turned read-only")
		}
	}
	return out
}

func serverDetailOf(snap *snapshot.Snapshot, row serverRow, problems []*findings.Finding, t config.Thresholds, now time.Time) *serverDetail {
	d := &serverDetail{Row: row, Problems: problems}
	if len(problems) > 0 {
		d.Top = problems[0]
	}
	n := snap.Node(row.Name)
	if n == nil {
		return d
	}
	for _, c := range n.Status.Conditions {
		cr := condRow{Type: string(c.Type), Status: string(c.Status)}
		if !c.LastTransitionTime.IsZero() {
			cr.Since = ago(now.Sub(c.LastTransitionTime.Time))
		}
		good := c.Status == corev1.ConditionFalse
		if c.Type == corev1.NodeReady {
			good = c.Status == corev1.ConditionTrue
		}
		switch {
		case c.Type != corev1.NodeReady && !problemCondition(string(c.Type)):
			// Another tool's condition: its meaning isn't known.
			cr.Icon, cr.Mark = "info", "•"
		case good:
			cr.Icon, cr.Mark = "good", "✓"
		default:
			cr.Icon, cr.Mark = "serious", "▲"
			if c.Type == corev1.NodeReady {
				cr.Icon, cr.Mark = "crit", "✕"
			}
		}
		d.Conditions = append(d.Conditions, cr)
	}
	info := n.Status.NodeInfo
	var nm *snapshot.NodeMetrics
	if snap.Metrics != nil {
		nm = snap.Metrics.Nodes[row.Name]
	}
	if nm == nil {
		d.HostNote = "No node-exporter data for this node."
	} else {
		if !nm.BootTime.IsZero() {
			d.Host = append(d.Host, fact{"Uptime", ago(now.Sub(nm.BootTime))})
		}
		if snapshot.Known(nm.CPUs) {
			d.Host = append(d.Host, fact{"CPUs", strconv.Itoa(int(nm.CPUs))})
		}
		if snapshot.Known(nm.MemTotal) {
			d.Host = append(d.Host, fact{"Memory", bytesIEC(nm.MemTotal)})
		}
		if snapshot.Known(nm.ClockOffset) {
			v := fmt.Sprintf("%+.3f s", nm.ClockOffset)
			if nm.ClockSynced == 0 {
				v += ", not synchronized"
			}
			d.Host = append(d.Host, fact{"Clock offset", v})
		}
		if snapshot.Known(nm.CPUSteal) || snapshot.Known(nm.CPUIOWait) {
			d.Host = append(d.Host, fact{"CPU steal · iowait", pctOr(nm.CPUSteal) + " · " + pctOr(nm.CPUIOWait)})
		}
		if lat := max(nm.DiskReadLatency, nm.DiskWriteLatency); snapshot.Known(lat) {
			v := fmt.Sprintf("%.0f ms", lat*1000)
			if nm.DiskDevice != "" {
				v += " (" + nm.DiskDevice + ")"
			}
			d.Host = append(d.Host, fact{"Disk latency", v})
		}
		if snapshot.Known(nm.SwapTotal) && nm.SwapTotal > 0 && snapshot.Known(nm.SwapFree) {
			d.Host = append(d.Host, fact{"Swap used", bytesIEC(nm.SwapTotal-nm.SwapFree) + " of " + bytesIEC(nm.SwapTotal)})
		}
		var ro []string
		for _, f := range nm.Filesystems {
			if f.ReadOnly {
				ro = append(ro, f.Mountpoint)
			}
		}
		d.Host = append(d.Host, fact{"Read-only filesystems", orText(strings.Join(ro, ", "), "none")})
		kfs, hasK := nm.KubeletFilesystem()
		for _, f := range nm.Filesystems {
			r := fsRow{Mountpoint: f.Mountpoint, Device: f.Device, FSType: f.FSType, Size: bytesIEC(f.Size), Free: bytesIEC(f.Avail),
				ReadOnly: f.ReadOnly, Kubelet: hasK && f.Mountpoint == kfs.Mountpoint}
			l := t.HostDiskPercent
			if r.Kubelet {
				l = t.NodeDiskPercent
			}
			r.Used = levelUsage(f.UsedFraction(), l, "")
			if in := f.InodesUsedFraction(); snapshot.Known(in) {
				r.Inodes = fmt.Sprintf("%.0f%%", in*100)
			}
			d.Filesystems = append(d.Filesystems, r)
		}
		if hasK {
			d.ChartTitle = fmt.Sprintf("nodefs usage, last 24 h (%s, %s)", kfs.Mountpoint, bytesIEC(kfs.Size))
			lines := []chartLine{{V: 90, Label: "eviction (nodefs.available < 10%)", Kind: "crit"}, {V: 85, Label: "image GC high 85%", Kind: "muted", Below: true}}
			d.Chart = newChart(fmt.Sprintf("%s: disk usage over 24 hours, now %d%%", row.Name, row.Disk.Pct), nm.FSHistory[kfs.Mountpoint], 1, now, lines, nil)
		}
	}
	d.Host = append(d.Host, fact{"OS", info.OSImage}, fact{"Kernel", info.KernelVersion}, fact{"Kubelet", info.KubeletVersion},
		fact{"Container runtime", info.ContainerRuntimeVersion})
	return d
}

func pctOr(v float64) string {
	if !snapshot.Known(v) {
		return "—"
	}
	return fmt.Sprintf("%.0f%%", v*100)
}

func orText(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// bytesIEC renders a size in binary units: "9.5 GiB".
func bytesIEC(v float64) string {
	if !snapshot.Known(v) {
		return "—"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for math.Abs(v) >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 || v >= 100 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.1f", v), "0"), ".") + " " + units[i]
}

// bytesPlain renders a size for Basic mode: "9.8 GB".
func bytesPlain(v float64) string {
	if !snapshot.Known(v) {
		return "—"
	}
	units := []string{"bytes", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for math.Abs(v) >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 || v >= 100 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.1f", v), "0"), ".") + " " + units[i]
}

// ---------------------------------------------------------------------------
// Storage

type mountRef struct {
	Pod, Node, Link string
}

type volumeRow struct {
	Namespace, Name, Phase string
	Class, Size            string
	Owner                  string // the app using it, for Basic mode
	Used                   usage
	UsedText, UsedPlain    string
	Inodes                 usage
	Spark, SparkLabel      string
	FullIn, FullPlain      string
	FullIcon, FullMark     string
	Growing                bool
	MountedBy              []mountRef
	Note                   string // why there is no usage, for example Pending
	Link                   string
	Selected               bool
	Top                    *findings.Finding
}

type volumeDetail struct {
	Row                                 volumeRow
	UsedText, GrowthNow, Baseline, Full string
	// The same in Basic mode's units.
	UsedPlain, GrowthPlain, BaselinePlain string
	Chart                                 *chart
	Problems                              []*findings.Finding
	Top                                   *findings.Finding
}

type storageData struct {
	State      *engine.State
	Rows       []volumeRow
	Detail     *volumeDetail
	Namespaces []string
	Namespace  string
	OnlyBad    bool

	Claims, Bound, Pending int
	Over80, FullSoon       int
	FullSoonText           string
	NodeFSHigh             int
	NodeFSText             string
	DefaultClass           string
	DefaultExpand          bool
	Levels                 string
	NoUsage                string
	Source                 string
}

func storageOf(st *engine.State, t config.Thresholds, ns, selected string, onlyBad bool, now time.Time) storageData {
	d := storageData{State: st, Namespace: ns, OnlyBad: onlyBad}
	snap := st.Snapshot
	if snap == nil {
		return d
	}
	m := snap.Metrics
	promOK := st.Info != nil && st.Info.Prometheus != nil && st.Info.Prometheus.State == "ok"
	switch {
	case m != nil && m.Have["kubelet-volumes"] && fellBack(m, "volume usage"):
		d.Source = "Volume usage comes from the kubelets and is sampled here every 5 minutes, so forecasts start about an hour after k0s-monitor started."
	case m != nil && m.Have["kubelet-volumes"]:
	case promOK:
		d.NoUsage = "The metrics have no kubelet volume metrics (kubelet_volume_stats_*), and the kubelets can't be read, so volume usage is not known."
	default:
		d.NoUsage = "Volume usage needs Prometheus or VictoriaMetrics, or read access to the kubelets' stats."
	}
	if sc := snap.DefaultStorageClass(); sc != nil {
		d.DefaultClass = sc.Name
		d.DefaultExpand = sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion
	}
	vl := t.VolumeUsedPercent
	d.Levels = fmt.Sprintf("Warn at %.0f%% · high at %.0f%% · critical at %.0f%%", vl.Warn, vl.High, vl.Critical)
	if c := t.VolumeFullWithin.Critical; c > 0 {
		d.Levels += " or full within " + ago(c.D())
	}
	top, all := rootFindings(st, func(f *findings.Finding) (string, bool) {
		if f.Resource.Kind == "PersistentVolumeClaim" {
			return f.Resource.Namespace + "/" + f.Resource.Name, true
		}
		return "", false
	})
	// Symptoms still mark their claim, under the root cause's priority.
	for _, f := range st.Findings {
		if key := f.Resource.Namespace + "/" + f.Resource.Name; f.Resource.Kind == "PersistentVolumeClaim" && top[key] == nil {
			if p := st.Finding(f.ParentID); p != nil {
				top[key] = p
			}
		}
	}
	nsSeen := map[string]bool{}
	fullSoon := t.VolumeFullWithin.High.D()
	if fullSoon == 0 {
		fullSoon = 24 * time.Hour
	}
	for _, pvc := range snap.PVCs {
		key := pvc.Namespace + "/" + pvc.Name
		if !nsSeen[pvc.Namespace] {
			nsSeen[pvc.Namespace] = true
			d.Namespaces = append(d.Namespaces, pvc.Namespace)
		}
		d.Claims++
		switch pvc.Status.Phase {
		case corev1.ClaimBound:
			d.Bound++
		case corev1.ClaimPending:
			d.Pending++
		}
		r := volumeRow{Namespace: pvc.Namespace, Name: pvc.Name, Phase: string(pvc.Status.Phase), Owner: pvc.Name,
			Link: "?pvc=" + key, Top: top[key]}
		switch {
		case pvc.Spec.StorageClassName != nil:
			r.Class = *pvc.Spec.StorageClassName
		case pvc.Spec.VolumeName != "":
			if pv := persistentVolume(snap, pvc.Spec.VolumeName); pv != nil {
				r.Class = pv.Spec.StorageClassName
			}
		}
		if r.Class == "" && d.DefaultClass != "" && pvc.Spec.StorageClassName == nil {
			r.Class = d.DefaultClass + " (default)"
		}
		if q, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
			r.Size = q.String()
		} else if q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			r.Size = q.String()
		}
		for _, p := range snap.PodsUsingClaim(pvc.Namespace, pvc.Name) {
			r.MountedBy = append(r.MountedBy, mountRef{Pod: p.Name, Node: p.Spec.NodeName, Link: "/c/" + st.Name + "/pods/" + p.Namespace + "/" + p.Name})
			if w := snap.WorkloadOf(p); w.Name != "" && r.Owner == pvc.Name {
				r.Owner = w.Name
			}
		}
		var vm *snapshot.VolumeMetrics
		if m != nil {
			vm = m.Volumes[key]
		}
		switch {
		case pvc.Status.Phase == corev1.ClaimPending:
			r.Note = "Pending"
			if r.Top != nil {
				r.Note = "Pending: " + r.Top.Title
			}
		case vm == nil || !snapshot.Known(vm.Used) || !snapshot.Known(vm.Capacity) || vm.Capacity <= 0:
			r.Used = usage{Text: "—", Title: orText(d.NoUsage, "no usage reported for this volume; it may not be mounted")}
		default:
			frac := vm.Used / vm.Capacity
			r.Used = levelUsage(frac, vl, "")
			r.UsedText = bytesIEC(vm.Used) + " of " + bytesIEC(vm.Capacity)
			r.UsedPlain = bytesPlain(vm.Used) + " of " + bytesPlain(vm.Capacity)
			if vl.Warn > 0 && frac*100 >= vl.Warn {
				d.Over80++
			}
			if snapshot.Known(vm.Inodes) && vm.Inodes > 0 && snapshot.Known(vm.InodesUsed) {
				r.Inodes = levelUsage(vm.InodesUsed/vm.Inodes, t.InodesPercent, "")
			}
			var hist []snapshot.Point
			for _, p := range vm.History {
				hist = append(hist, snapshot.Point{T: p.T, V: p.V / vm.Capacity})
			}
			r.Spark, r.SparkLabel = spark(hist, 1)
			r.FullIn, r.FullPlain = "stable", "not growing"
			if ttf, ok := vm.TimeToFull(); ok {
				r.Growing = true
				r.FullIn, r.FullPlain = "~"+ago(ttf), inPlain(ttf)
				switch {
				case t.VolumeFullWithin.Critical > 0 && ttf <= t.VolumeFullWithin.Critical.D():
					r.FullIcon, r.FullMark = "crit", "!"
				case ttf <= fullSoon:
					r.FullIcon, r.FullMark = "serious", "▲"
				case ttf <= 7*24*time.Hour:
					r.FullIcon, r.FullMark = "warn", "▲"
				}
				if ttf <= fullSoon {
					d.FullSoon++
					if d.FullSoonText == "" {
						d.FullSoonText = pvc.Name + " · " + r.FullIn
					}
				}
			} else if vm.Growth == nil {
				r.FullIn, r.FullPlain = "—", "not known yet"
			}
		}
		if onlyBad && r.Top == nil {
			continue
		}
		if ns != "" && pvc.Namespace != ns {
			continue
		}
		d.Rows = append(d.Rows, r)
	}
	sort.Strings(d.Namespaces)
	// Most urgent first, then the fullest.
	sort.SliceStable(d.Rows, func(i, j int) bool {
		a, b := d.Rows[i], d.Rows[j]
		ra, rb := 9, 9
		if a.Top != nil {
			ra = a.Top.Priority.Rank()
		}
		if b.Top != nil {
			rb = b.Top.Priority.Rank()
		}
		if ra != rb {
			return ra < rb
		}
		return a.Used.Pct > b.Used.Pct
	})
	if m != nil {
		for name, nm := range m.Nodes {
			if fs, ok := nm.KubeletFilesystem(); ok {
				if u := fs.UsedFraction(); snapshot.Known(u) && t.NodeDiskPercent.High > 0 && u*100 >= t.NodeDiskPercent.High {
					d.NodeFSHigh++
					if d.NodeFSText == "" || name < d.NodeFSText {
						d.NodeFSText = fmt.Sprintf("%s %.0f%%", name, u*100)
					}
				}
			}
		}
	}

	pick := -1
	for i, r := range d.Rows {
		if r.Namespace+"/"+r.Name == selected {
			pick = i
		}
	}
	if pick < 0 && selected == "" && len(d.Rows) > 0 && d.Rows[0].Top != nil {
		pick = 0
	}
	if pick >= 0 {
		d.Rows[pick].Selected = true
		d.Detail = volumeDetailOf(snap, d.Rows[pick], all[d.Rows[pick].Namespace+"/"+d.Rows[pick].Name], t, now)
	}
	return d
}

func volumeDetailOf(snap *snapshot.Snapshot, row volumeRow, problems []*findings.Finding, t config.Thresholds, now time.Time) *volumeDetail {
	d := &volumeDetail{Row: row, Problems: problems, UsedText: row.UsedText, UsedPlain: row.UsedPlain}
	if len(problems) > 0 {
		d.Top = problems[0]
	} else {
		d.Top = row.Top
	}
	if snap.Metrics == nil {
		return d
	}
	vm := snap.Metrics.Volumes[row.Namespace+"/"+row.Name]
	if vm == nil || !snapshot.Known(vm.Capacity) || vm.Capacity <= 0 {
		return d
	}
	var proj *chartPoint
	if g := vm.Growth; g != nil {
		d.GrowthNow, d.GrowthPlain = signedRate(g.BytesPerHour, bytesIEC), signedRate(g.BytesPerHour, bytesPlain)
		if snapshot.Known(g.BaselineBytesPerHour) {
			d.Baseline, d.BaselinePlain = signedRate(g.BaselineBytesPerHour, bytesIEC), signedRate(g.BaselineBytesPerHour, bytesPlain)
		}
		if ttf, ok := vm.TimeToFull(); ok {
			at := now.Add(ttf)
			d.Full = "≈ " + at.UTC().Format("15:04") + " UTC"
			if ttf > 20*time.Hour {
				d.Full = "≈ " + at.UTC().Format("Jan 2 15:04") + " UTC"
			}
			if ttf <= 48*time.Hour {
				proj = &chartPoint{T: at.Unix(), V: 100, Label: "100% ≈ " + at.UTC().Format("15:04")}
			}
		} else {
			d.Full = "not growing"
		}
	}
	var hist []snapshot.Point
	for _, p := range vm.History {
		hist = append(hist, snapshot.Point{T: p.T, V: p.V / vm.Capacity})
	}
	vl := t.VolumeUsedPercent
	var lines []chartLine
	if vl.High > 0 {
		lines = append(lines, chartLine{V: vl.High, Label: fmt.Sprintf("%.0f%% high", vl.High), Kind: "crit"})
	}
	if vl.Warn > 0 {
		lines = append(lines, chartLine{V: vl.Warn, Label: fmt.Sprintf("%.0f%% warn", vl.Warn), Kind: "muted", Below: true})
	}
	d.Chart = newChart(fmt.Sprintf("%s usage over 24 hours, now %d%%", row.Name, row.Used.Pct), hist, 1, now, lines, proj)
	return d
}

func signedRate(perHour float64, size func(float64) string) string {
	s := size(math.Abs(perHour)) + "/h"
	if perHour < 0 {
		return "−" + s
	}
	return "+" + s
}

// inPlain says when, in words: "in about 4 hours".
func inPlain(d time.Duration) string {
	if d < time.Minute {
		return "any moment now"
	}
	return "in about " + strings.TrimPrefix(strings.TrimSuffix(agoPlain(d), " ago"), "about ")
}

func persistentVolume(snap *snapshot.Snapshot, name string) *corev1.PersistentVolume {
	for _, pv := range snap.PVs {
		if pv.Name == name {
			return pv
		}
	}
	return nil
}

// fellBack reports whether a fallback provided this kind of data.
func fellBack(m *snapshot.Metrics, what string) bool {
	for _, f := range m.Fallbacks {
		if strings.HasPrefix(f, what) {
			return true
		}
	}
	return false
}
