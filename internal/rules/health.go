package rules

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// Rules that read metrics from Prometheus (M2).

// level returns the severity v reaches, where higher is worse.
func level(v float64, l config.Levels) (findings.Severity, bool) {
	switch {
	case !snapshot.Known(v):
		return findings.Info, false
	case l.Critical > 0 && v >= l.Critical:
		return findings.Critical, true
	case l.High > 0 && v >= l.High:
		return findings.High, true
	case l.Warn > 0 && v >= l.Warn:
		return findings.Medium, true
	}
	return findings.Info, false
}

// durationLevel is level for durations, where higher is worse.
func durationLevel(d time.Duration, l config.DurationLevels) (findings.Severity, bool) {
	return level(d.Seconds(), config.Levels{Warn: l.Warn.D().Seconds(), High: l.High.D().Seconds(), Critical: l.Critical.D().Seconds()})
}

// bytesIEC renders a size for Full mode: "9.1 GiB".
func bytesIEC(v float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for math.Abs(v) >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", v)
	}
	return fmt.Sprintf("%s %s", trimFloat(v), units[i])
}

// bytesPlain renders a size for Basic mode: "9.8 GB".
func bytesPlain(v float64) string {
	units := []string{"bytes", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for math.Abs(v) >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f bytes", v)
	}
	return fmt.Sprintf("%s %s", trimFloat(v), units[i])
}

func trimFloat(v float64) string {
	if math.Abs(v) >= 100 {
		return fmt.Sprintf("%.0f", v)
	}
	s := fmt.Sprintf("%.1f", v)
	return strings.TrimSuffix(s, ".0")
}

func pct(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }

// ---------------------------------------------------------------------------
// S01 pvc.usage and S02 pvc.fill-forecast

var volumeUsageRule = Rule{
	ID: "pvc.usage", Code: "S01", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindPVC, snapshot.KindPod},
	Eval:  evalVolumeUsage,
}

var volumeForecastRule = Rule{
	ID: "pvc.fill-forecast", Code: "S02", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindPVC, snapshot.KindPod},
	Eval:  evalVolumeForecast,
}

// volumeContext is what both volume rules show about a claim.
type volumeContext struct {
	pvc     *corev1.PersistentVolumeClaim
	vm      *snapshot.VolumeMetrics
	pods    []*corev1.Pod
	owner   string
	mounts  []string
	class   string
	expand  bool // the class allows expansion
	local   bool // a local-path or hostpath class: the volume shares the node's disk
	ref     findings.ObjectRef
	workRef []findings.ObjectRef
}

func volumesWithMetrics(c *Context) []volumeContext {
	if c.S.Metrics == nil {
		return nil
	}
	var out []volumeContext
	for _, pvc := range c.S.PVCs {
		vm := c.S.Metrics.Volumes[pvc.Namespace+"/"+pvc.Name]
		if vm == nil || pvc.Status.Phase != corev1.ClaimBound {
			continue
		}
		vc := volumeContext{pvc: pvc, vm: vm, owner: pvc.Name,
			ref: findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}}
		for _, p := range c.S.PodsUsingClaim(pvc.Namespace, pvc.Name) {
			if snapshot.IsPodTerminal(p) {
				continue
			}
			vc.pods = append(vc.pods, p)
			w := workloadRef(c.S.WorkloadOf(p))
			if !containsRef(vc.workRef, w) {
				vc.workRef = append(vc.workRef, w)
			}
			for _, v := range p.Spec.Volumes {
				if v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != pvc.Name {
					continue
				}
				for _, ctr := range p.Spec.Containers {
					for _, m := range ctr.VolumeMounts {
						if m.Name == v.Name && !contains(vc.mounts, m.MountPath) {
							vc.mounts = append(vc.mounts, m.MountPath)
						}
					}
				}
			}
		}
		if len(vc.workRef) > 0 {
			vc.owner = vc.workRef[0].Name
		}
		if pvc.Spec.StorageClassName != nil {
			vc.class = *pvc.Spec.StorageClassName
		} else if def := c.S.DefaultStorageClass(); def != nil {
			vc.class = def.Name
		}
		if sc := c.S.StorageClass(vc.class); sc != nil {
			vc.expand = sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion
			p := strings.ToLower(sc.Provisioner)
			vc.local = strings.Contains(p, "local") || strings.Contains(p, "hostpath")
		}
		out = append(out, vc)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// facts adds what both volume rules show.
func (vc volumeContext) facts(f *findings.Finding, now time.Time) {
	vm := vc.vm
	f.AddFact("Used", fmt.Sprintf("%s of %s (%s)", bytesIEC(vm.Used), bytesIEC(vm.Capacity), pct(vm.Used/vm.Capacity)))
	if snapshot.Known(vm.Inodes) && vm.Inodes > 0 {
		f.AddFact("Inodes", fmt.Sprintf("%.0f of %.0f (%s)", vm.InodesUsed, vm.Inodes, pct(vm.InodesUsed/vm.Inodes)))
	}
	if g := vm.Growth; g != nil {
		f.AddFact("Growth", fmt.Sprintf("%s per day over the last %s (fit R² %.2f)", bytesIEC(g.BytesPerHour*24), ago(g.Window), g.R2))
		if snapshot.Known(g.BaselineBytesPerHour) {
			f.AddFact("7-day average", fmt.Sprintf("%s per day", bytesIEC(g.BaselineBytesPerHour*24)))
		}
		if ttf, ok := vm.TimeToFull(); ok {
			f.AddFact("Full in", ago(ttf))
		}
	}
	f.AddFact("StorageClass", vc.class)
	if vc.local {
		f.AddFact("Note", "local volumes share the node's disk: the capacity is the disk's")
	}
	f.AddFact("Mounted at", strings.Join(vc.mounts, ", "))
	f.AddFact("Used by", podNames(vc.pods, 3))
}

// steps adds the steps both volume rules share.
func (vc volumeContext) steps(f *findings.Finding) {
	ns := vc.pvc.Namespace
	if len(vc.pods) > 0 && len(vc.mounts) > 0 {
		f.AddStep(findings.Step{
			Text:    "See what uses the space inside the volume",
			Command: fmt.Sprintf("kubectl -n %s exec %s -- du -xsh %s/* | sort -h | tail -n 20", ns, vc.pods[0].Name, vc.mounts[0]),
		})
	}
	f.AddStep(findings.Step{
		Text:  "Delete what is no longer needed (old logs, exports, backups), or make the app keep less",
		Plain: "Delete data the app no longer needs, such as old logs or exports.",
	})
	size := suggestSize(vc.vm.Capacity)
	if vc.expand {
		f.AddStep(findings.Step{
			Text:    fmt.Sprintf("Or make the volume bigger (its StorageClass %s allows expansion)", vc.class),
			Plain:   "Or make the storage bigger.",
			Command: fmt.Sprintf(`kubectl -n %s patch pvc %s -p '{"spec":{"resources":{"requests":{"storage":"%s"}}}}'`, ns, vc.pvc.Name, size),
		})
	} else if vc.class != "" {
		f.AddStep(findings.Step{Text: fmt.Sprintf("The StorageClass %s does not allow expansion: a bigger volume means moving the data to a new claim", vc.class),
			Plain: "This storage can't simply be made bigger: moving the data to bigger storage is a job for your support team."})
	}
}

// suggestSize proposes double the capacity, as a Gi quantity.
func suggestSize(capacity float64) string {
	gi := math.Ceil(capacity * 2 / (1 << 30))
	return fmt.Sprintf("%.0fGi", math.Max(gi, 1))
}

func evalVolumeUsage(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, vc := range volumesWithMetrics(c) {
		vm := vc.vm
		if !snapshot.Known(vm.Used) || !snapshot.Known(vm.Capacity) || vm.Capacity <= 0 {
			continue
		}
		used := vm.Used / vm.Capacity
		inodes := snapshot.Missing
		if snapshot.Known(vm.Inodes) && vm.Inodes > 0 && snapshot.Known(vm.InodesUsed) {
			inodes = vm.InodesUsed / vm.Inodes
		}
		worst := used
		byInodes := snapshot.Known(inodes) && inodes > used
		if byInodes {
			worst = inodes
		}
		sev, ok := level(worst*100, c.T.VolumeUsedPercent)
		if !ok {
			continue
		}
		f := c.newFinding(sev, vc.ref)
		f.Impact.AffectedPods = len(vc.pods)
		f.Links.Claims = []findings.ObjectRef{vc.ref}
		f.Links.Workloads = vc.workRef
		f.Links.Nodes = nodesOf(vc.pods)
		f.Affected = podRefs(vc.pods, 10)
		vc.facts(f, c.S.Now)
		if byInodes {
			f.Title = fmt.Sprintf("%s of its inodes used (%s of the space)", pct(inodes), pct(used))
			f.Summary = fmt.Sprintf("Claim %s has used %s of its inodes (file slots). When they run out, no new file can be created even with free space.", vc.pvc.Name, pct(inodes))
			f.Remedy.LikelyCause = "The app creates many small files and never removes old ones."
		} else {
			f.Title = fmt.Sprintf("%s full: %s of %s used", pct(used), bytesIEC(vm.Used), bytesIEC(vm.Capacity))
			f.Summary = fmt.Sprintf("Claim %s is %s full. When it is full, the app's writes fail.", vc.pvc.Name, pct(used))
			f.Remedy.LikelyCause = "The app keeps more data than the volume was sized for, or never removes old data."
		}
		vc.steps(f)
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The storage of %s is almost full (%s)", vc.owner, pct(worst)),
			WhatHappened: fmt.Sprintf("It holds %s of %s.", bytesPlain(vm.Used), bytesPlain(vm.Capacity)),
			Why:          "The app keeps writing data, such as logs, uploads or database records, and nothing removes old data. When the storage is full, the app stops working properly.",
			WhatToDo:     "Delete data the app no longer needs, or make the storage bigger (steps below). Send the report to your support team if you are unsure.",
		}
		if byInodes {
			f.Plain.WhatHappened = fmt.Sprintf("It has used %s of its file slots: it holds very many small files.", pct(inodes))
		}
		out = append(out, f)
	}
	return out
}

func evalVolumeForecast(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, vc := range volumesWithMetrics(c) {
		vm, g := vc.vm, vc.vm.Growth
		if g == nil || g.Samples < 12 || g.R2 < 0.5 || g.BytesPerHour <= 0 {
			continue
		}
		ttf, ok := vm.TimeToFull()
		if !ok {
			continue
		}
		var sev findings.Severity
		switch {
		case c.T.VolumeFullWithin.Critical > 0 && ttf <= c.T.VolumeFullWithin.Critical.D():
			sev = findings.Critical
		case c.T.VolumeFullWithin.High > 0 && ttf <= c.T.VolumeFullWithin.High.D():
			sev = findings.High
		case c.T.VolumeFullWithin.Warn > 0 && ttf <= c.T.VolumeFullWithin.Warn.D():
			sev = findings.Medium
		default:
			continue
		}
		f := c.newFinding(sev, vc.ref)
		f.Impact.AffectedPods = len(vc.pods)
		f.Impact.BlocksWorkload = len(vc.pods) > 0
		f.Impact.BreachIn = max(ttf, time.Minute)
		f.Links.Claims = []findings.ObjectRef{vc.ref}
		f.Links.Workloads = vc.workRef
		f.Links.Nodes = nodesOf(vc.pods)
		f.Affected = podRefs(vc.pods, 10)
		vc.facts(f, c.S.Now)
		jumped := snapshot.Known(g.BaselineBytesPerHour) && g.BaselineBytesPerHour > 0 && g.BytesPerHour >= 3*g.BaselineBytesPerHour
		if jumped {
			f.AddFact("Change", fmt.Sprintf("growing %.0f× faster than its 7-day average", g.BytesPerHour/g.BaselineBytesPerHour))
		}
		f.Title = fmt.Sprintf("Full in about %s at %s per hour (now %s)", ago(ttf), bytesIEC(g.BytesPerHour), pct(vm.Used/vm.Capacity))
		f.Summary = fmt.Sprintf("Claim %s grows by %s per hour and has %s left, so it will be full in about %s.",
			vc.pvc.Name, bytesIEC(g.BytesPerHour), bytesIEC(vm.Capacity-vm.Used), ago(ttf))
		f.Remedy.LikelyCause = "The app writes more than usual, or keeps everything it writes. Find what grows first."
		if jumped {
			f.Remedy.LikelyCause = "It grows much faster than usual: something changed, for example a log level, a loop that retries and logs, or a new import."
		}
		vc.steps(f)
		why := "The app keeps writing data and nothing removes old data."
		if jumped {
			why = "It fills up much faster than it used to, so something in the app changed, for example it logs much more."
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The storage of %s will be full in about %s", vc.owner, agoPlain(ttf)),
			WhatHappened: fmt.Sprintf("It grows by %s per hour and has %s left.", bytesPlain(g.BytesPerHour), bytesPlain(vm.Capacity-vm.Used)),
			Why:          why,
			WhatToDo:     "Find out what the app writes and delete what isn't needed, or make the storage bigger before it is full (steps below). Send the report to your support team if you are unsure.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// N04 node.fs-high, N05 node.inodes-high and V08 vm.host-fs

var nodeDiskRule = Rule{
	ID: "node.fs-high", Code: "N04", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodeDisk,
}

var nodeInodesRule = Rule{
	ID: "node.inodes-high", Code: "N05", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalNodeInodes,
}

var hostDiskRule = Rule{
	ID: "vm.host-fs", Code: "V08", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalHostDisk,
}

// k0sDataDir is where k0s keeps the kubelet's and containerd's data.
const k0sDataDir = snapshot.K0sDataDir

// metricNodes returns the nodes with metrics, sorted by name.
func metricNodes(c *Context) []struct {
	node *corev1.Node
	m    *snapshot.NodeMetrics
} {
	var out []struct {
		node *corev1.Node
		m    *snapshot.NodeMetrics
	}
	if c.S.Metrics == nil {
		return nil
	}
	for _, n := range c.S.Nodes {
		if m := c.S.Metrics.Nodes[n.Name]; m != nil {
			out = append(out, struct {
				node *corev1.Node
				m    *snapshot.NodeMetrics
			}{n, m})
		}
	}
	return out
}

func evalNodeDisk(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		fs, ok := nm.m.KubeletFilesystem()
		if !ok {
			continue
		}
		used := fs.UsedFraction()
		sev, hit := level(used*100, c.T.NodeDiskPercent)
		if !hit && !fs.ReadOnly {
			continue
		}
		if fs.ReadOnly {
			sev = findings.Critical
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		pods := activePodsOn(c, nm.node.Name)
		f.Impact.AffectedPods = len(pods)
		f.AddFact("Filesystem", fmt.Sprintf("%s (%s, %s)", fs.Mountpoint, fs.Device, fs.FSType))
		f.AddFact("Used", fmt.Sprintf("%s of %s (%s), %s free", bytesIEC(fs.Size-fs.Avail), bytesIEC(fs.Size), pct(used), bytesIEC(fs.Avail)))
		f.AddFact("Holds", k0sDataDir+": container images, container logs, emptyDir volumes, and local volumes")
		f.AddFact("Kubelet evicts pods at", "less than 10% free (the default; worker profiles can change it)")
		f.AddFact("Pods on node", fmt.Sprintf("%d", len(pods)))
		host := nm.node.Name
		if fs.ReadOnly {
			f.Title = fmt.Sprintf("The filesystem of %s is read-only", fs.Mountpoint)
			f.Summary = fmt.Sprintf("The filesystem holding %s on node %s turned read-only, usually after disk errors. Containers can't be created or write there.", k0sDataDir, nm.node.Name)
			f.Remedy.LikelyCause = "The disk reported errors and the kernel mounted it read-only to protect the data."
			f.AddStep(findings.Step{Text: "On the node: look for disk errors in the kernel log", Command: "sudo dmesg -T | grep -i -E 'I/O error|EXT4-fs error|XFS|remount' | tail -n 30", Host: host})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The disk of server %s can't be written to", nm.node.Name),
				WhatHappened: "Its disk switched to read-only, so apps on it can't save anything and new apps can't start there.",
				Why:          "This usually happens after disk errors.",
				WhatToDo:     "Send the report to whoever manages your servers: the disk needs to be checked.",
			}
			out = append(out, f)
			continue
		}
		f.Title = fmt.Sprintf("Disk %s full on %s: %s free", pct(used), fs.Mountpoint, bytesIEC(fs.Avail))
		f.Summary = fmt.Sprintf("The filesystem that holds %s on node %s is %s full. At 90%% the kubelet starts evicting pods to free space.", k0sDataDir, nm.node.Name, pct(used))
		f.Remedy.LikelyCause = "Unused container images, large container logs or emptyDir volumes fill the node's disk."
		f.AddStep(findings.Step{
			Text:    "On the node: find what uses the space",
			Plain:   "If you can log in to it, find out what fills its disk.",
			Command: fmt.Sprintf("df -h %s\nsudo du -xhd1 %s | sort -h | tail\nsudo du -xhd1 /var/log | sort -h | tail", fs.Mountpoint, k0sDataDir),
			Host:    host,
		})
		f.AddStep(findings.Step{
			Text:    "On the node: remove container images that no pod uses (needs crictl)",
			Plain:   "Remove old app images that are no longer used.",
			Command: "sudo crictl --runtime-endpoint unix:///run/k0s/containerd.sock rmi --prune",
			Host:    host,
		})
		f.AddStep(findings.Step{Text: "Find pods with large emptyDir volumes or logs on the node", Command: fmt.Sprintf("kubectl get pods -A -o wide --field-selector spec.nodeName=%s", nm.node.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s is running out of disk space (%s full)", nm.node.Name, pct(used)),
			WhatHappened: fmt.Sprintf("Its disk for apps is %s full; %s are left. When it gets fuller, Kubernetes starts stopping apps on it to free space.", pct(used), bytesPlain(fs.Avail)),
			Why:          "Old app images, app logs and temporary files fill it up over time.",
			WhatToDo:     "Free up space on the server (steps below), or send the report to whoever manages your servers.",
		}
		out = append(out, f)
	}
	return out
}

func activePodsOn(c *Context, node string) []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range c.S.PodsOnNode(node) {
		if !snapshot.IsPodTerminal(p) {
			out = append(out, p)
		}
	}
	return out
}

func evalNodeInodes(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		var worst snapshot.Filesystem
		wv := -1.0
		for _, fs := range nm.m.Filesystems {
			if v := fs.InodesUsedFraction(); snapshot.Known(v) && v > wv {
				worst, wv = fs, v
			}
		}
		sev, ok := level(wv*100, c.T.InodesPercent)
		if !ok {
			continue
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		f.AddFact("Filesystem", fmt.Sprintf("%s (%s)", worst.Mountpoint, worst.Device))
		f.AddFact("Inodes", fmt.Sprintf("%.0f of %.0f used (%s)", worst.Files-worst.FilesFree, worst.Files, pct(wv)))
		f.AddFact("Space", fmt.Sprintf("%s used", pct(worst.UsedFraction())))
		f.Title = fmt.Sprintf("Inodes %s used on %s", pct(wv), worst.Mountpoint)
		f.Summary = fmt.Sprintf("Node %s has used %s of the inodes (file slots) of %s. When they run out, no new file can be created, even with free space.", nm.node.Name, pct(wv), worst.Mountpoint)
		f.Remedy.LikelyCause = "Something creates very many small files: a cache, a mail or session directory, or leftover container layers."
		f.AddStep(findings.Step{
			Text:    "On the node: find the directories with the most files",
			Command: fmt.Sprintf("sudo find %s -xdev -printf '%%h\\n' | sort | uniq -c | sort -n | tail -n 15", worst.Mountpoint),
			Host:    nm.node.Name,
		})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s is running out of file slots", nm.node.Name),
			WhatHappened: fmt.Sprintf("Its disk %s has used %s of the number of files it can hold, even if space is left.", worst.Mountpoint, pct(wv)),
			Why:          "Something on it creates very many small files and doesn't remove them.",
			WhatToDo:     "Send the report to whoever manages your servers, or find and delete the small files (step below).",
		}
		out = append(out, f)
	}
	return out
}

func evalHostDisk(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		kfs, _ := nm.m.KubeletFilesystem()
		type hit struct {
			fs  snapshot.Filesystem
			sev findings.Severity
		}
		var hits []hit
		for _, fs := range nm.m.Filesystems {
			if fs.Mountpoint == kfs.Mountpoint || fs.Device == kfs.Device {
				continue // node.fs-high covers it
			}
			sev, ok := level(fs.UsedFraction()*100, c.T.HostDiskPercent)
			if fs.ReadOnly && fs.Mountpoint == "/" {
				sev, ok = findings.High, true
			}
			if ok {
				hits = append(hits, hit{fs, sev})
			}
		}
		if len(hits) == 0 {
			continue
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].fs.UsedFraction() > hits[j].fs.UsedFraction() })
		top := hits[0]
		sev := top.sev
		var list []string
		for _, h := range hits {
			if h.sev > sev {
				sev = h.sev
			}
			list = append(list, fmt.Sprintf("%s %s full (%s free)", h.fs.Mountpoint, pct(h.fs.UsedFraction()), bytesIEC(h.fs.Avail)))
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		f.AddFact("Filesystems", strings.Join(list, "; "))
		if top.fs.ReadOnly {
			f.Title = "The root filesystem is read-only"
			f.Summary = fmt.Sprintf("The root filesystem of node %s turned read-only, usually after disk errors.", nm.node.Name)
			f.Remedy.LikelyCause = "The disk reported errors and the kernel mounted it read-only."
			f.AddStep(findings.Step{Text: "On the node: look for disk errors", Command: "sudo dmesg -T | grep -i -E 'I/O error|remount|EXT4-fs error|XFS' | tail -n 30", Host: nm.node.Name})
		} else {
			f.Title = fmt.Sprintf("Host disk %s %s full: %s free", top.fs.Mountpoint, pct(top.fs.UsedFraction()), bytesIEC(top.fs.Avail))
			f.Summary = fmt.Sprintf("A filesystem of node %s outside Kubernetes' data is filling up: %s. Kubernetes doesn't see or clean it, but a full root disk stops the system services, including k0s.", nm.node.Name, strings.Join(list, "; "))
			f.Remedy.LikelyCause = "System logs, the journal, old kernels or files outside Kubernetes fill the disk."
			f.AddStep(findings.Step{
				Text:    "On the node: find what uses the space",
				Plain:   "If you can log in to it, find out what fills its disk.",
				Command: fmt.Sprintf("df -h %s\nsudo du -xhd1 %s | sort -h | tail\nsudo journalctl --disk-usage", top.fs.Mountpoint, top.fs.Mountpoint),
				Host:    nm.node.Name,
			})
			f.AddStep(findings.Step{Text: "On the node: shrink the system journal if it is large", Command: "sudo journalctl --vacuum-size=500M", Host: nm.node.Name})
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("A disk of server %s is almost full", nm.node.Name),
			WhatHappened: fmt.Sprintf("Its disk %s is %s full; %s are left.", top.fs.Mountpoint, pct(top.fs.UsedFraction()), bytesPlain(top.fs.Avail)),
			Why:          "System logs or other files on the server fill it up. If the main disk gets full, the server's own services stop, k0s included.",
			WhatToDo:     "Free up space on the server (steps below), or send the report to whoever manages your servers.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// N06 node.saturation

var nodeSaturationRule = Rule{
	ID: "node.saturation", Code: "N06", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodeSaturation,
}

func evalNodeSaturation(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		m := nm.m
		cpu := m.CPUBusy15m
		mem := snapshot.Missing
		if snapshot.Known(m.MemTotal) && m.MemTotal > 0 && snapshot.Known(m.MemAvailable15m) {
			mem = 1 - m.MemAvailable15m/m.MemTotal
		}
		cs, cok := level(cpu*100, c.T.NodeSaturationPercent)
		ms, mok := level(mem*100, c.T.NodeSaturationPercent)
		if !cok && !mok {
			continue
		}
		sev := cs
		if !cok || (mok && ms > cs) {
			sev = ms
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		if snapshot.Known(cpu) {
			f.AddFact("CPU busy (15 min)", fmt.Sprintf("%s of %.0f CPUs", pct(cpu), m.CPUs))
		}
		if snapshot.Known(mem) {
			f.AddFact("Memory used (15 min)", fmt.Sprintf("%s of %s", pct(mem), bytesIEC(m.MemTotal)))
		}
		var what, plainWhat []string
		if cok {
			what = append(what, "CPU "+pct(cpu)+" busy")
			plainWhat = append(plainWhat, "its processors are "+pct(cpu)+" busy")
		}
		if mok {
			what = append(what, "memory "+pct(mem)+" used")
			plainWhat = append(plainWhat, pct(mem)+" of its memory is in use")
		}
		f.Title = strings.Join(what, ", ") + " for 15 min"
		f.Summary = fmt.Sprintf("Node %s is saturated: %s, averaged over 15 minutes. Its pods slow down, and at the memory limit the kernel kills processes.", nm.node.Name, strings.Join(what, " and "))
		f.Remedy.LikelyCause = "The pods on the node need more than it has. Their requests may be lower than what they really use."
		f.AddStep(findings.Step{Text: "Find the pods that use the most", Command: fmt.Sprintf("kubectl top pods -A --sort-by=%s | head -n 15", ifStr(mok, "memory", "cpu"))})
		f.AddStep(findings.Step{Text: "Compare what the pods request with what they use; raise requests that are too low so the scheduler spreads them", Command: fmt.Sprintf("kubectl describe node %s | grep -A 12 'Allocated resources'", nm.node.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s is overloaded", nm.node.Name),
			WhatHappened: fmt.Sprintf("For the last 15 minutes %s.", strings.Join(plainWhat, " and ")),
			Why:          "The apps on it need more than the server has. They get slow, and when memory runs out some are stopped.",
			WhatToDo:     "Move some apps to other servers or add a server. Send the report to your support team if you are unsure.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// V01 vm.cpu-steal, V02 vm.iowait, V03 vm.clock-skew, V06 vm.reboot,
// V07 vm.memory

var cpuStealRule = Rule{
	ID: "vm.cpu-steal", Code: "V01", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalCPUSteal,
}

func evalCPUSteal(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		sev, ok := level(nm.m.CPUSteal*100, c.T.CPUStealPercent)
		if !ok {
			continue
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		f.AddFact("CPU steal (5 min)", pct(nm.m.CPUSteal))
		if snapshot.Known(nm.m.CPUs) {
			f.AddFact("CPUs", fmt.Sprintf("%.0f", nm.m.CPUs))
		}
		f.Title = fmt.Sprintf("CPU steal %s: the hypervisor withholds CPU from this VM", pct(nm.m.CPUSteal))
		f.Summary = fmt.Sprintf("Node %s is a virtual machine that waits for its CPU %s of the time, because the host it runs on is busy with other VMs. Everything on it runs slower.", nm.node.Name, pct(nm.m.CPUSteal))
		f.Remedy.LikelyCause = "The virtualization host is overcommitted: its other VMs use the CPUs this VM needs."
		f.AddStep(findings.Step{Text: "On the node: confirm the steal time (the st column)", Command: "vmstat 5 5", Host: nm.node.Name})
		f.AddStep(findings.Step{Text: "Ask the virtualization team to move the VM to a less busy host, or to reserve CPU for it", Plain: "Ask whoever runs your virtual machines to move this one or reserve processor time for it."})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s gets less processor time than it should", nm.node.Name),
			WhatHappened: fmt.Sprintf("It is a virtual machine and has to wait for its processor %s of the time, so everything on it is slower.", pct(nm.m.CPUSteal)),
			Why:          "The physical host it runs on is busy with other virtual machines.",
			WhatToDo:     "Ask whoever runs your virtual machines to move it to a less busy host or to reserve processor time for it.",
		}
		out = append(out, f)
	}
	return out
}

var ioWaitRule = Rule{
	ID: "vm.iowait", Code: "V02", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalIOWait,
}

func evalIOWait(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		m := nm.m
		ws, wok := level(m.CPUIOWait*100, c.T.IOWaitPercent)
		lat := math.Max(orNaN0(m.DiskReadLatency), orNaN0(m.DiskWriteLatency))
		ls, lok := durationLevel(time.Duration(lat*float64(time.Second)), c.T.DiskLatency)
		if lat == 0 {
			lok = false
		}
		if !wok && !lok {
			continue
		}
		sev := ws
		if !wok || (lok && ls > ws) {
			sev = ls
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		if snapshot.Known(m.CPUIOWait) {
			f.AddFact("iowait (5 min)", pct(m.CPUIOWait))
		}
		if snapshot.Known(m.DiskReadLatency) {
			f.AddFact("Read time", fmt.Sprintf("%.0f ms per operation", m.DiskReadLatency*1000))
		}
		if snapshot.Known(m.DiskWriteLatency) {
			f.AddFact("Write time", fmt.Sprintf("%.0f ms per operation", m.DiskWriteLatency*1000))
		}
		f.AddFact("Slowest disk", m.DiskDevice)
		var what []string
		if lok {
			what = append(what, fmt.Sprintf("%.0f ms per operation on %s", lat*1000, orDefault(m.DiskDevice, "a disk")))
		}
		if wok {
			what = append(what, "iowait "+pct(m.CPUIOWait))
		}
		f.Title = "Slow disk: " + strings.Join(what, ", ")
		f.Summary = fmt.Sprintf("Node %s waits for its disk: %s. Databases, etcd and image pulls slow down or time out.", nm.node.Name, strings.Join(what, ", "))
		f.Remedy.LikelyCause = "The disk is overloaded, shared with other busy VMs, or failing."
		f.AddStep(findings.Step{Text: "On the node: see which disk is busy and how long operations take (the await column)", Command: "iostat -x 5 3", Host: nm.node.Name})
		f.AddStep(findings.Step{Text: "Ask the virtualization or storage team about the disk's performance; move busy volumes to faster storage", Plain: "Ask whoever runs your servers to check the disk's speed."})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The disk of server %s is slow", nm.node.Name),
			WhatHappened: "Reading and writing to its disk takes much longer than it should, so apps on it wait.",
			Why:          "The disk is overloaded, shared with other busy machines, or failing.",
			WhatToDo:     "Ask whoever runs your servers to check the disk's speed and health.",
		}
		out = append(out, f)
	}
	return out
}

func orNaN0(v float64) float64 {
	if snapshot.Known(v) {
		return v
	}
	return 0
}

var clockSkewRule = Rule{
	ID: "vm.clock-skew", Code: "V03", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalClockSkew,
}

func evalClockSkew(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		m := nm.m
		off := math.Abs(m.ClockOffset)
		sev, ok := durationLevel(time.Duration(off*float64(time.Second)), c.T.ClockSkew)
		unsynced := snapshot.Known(m.ClockSynced) && m.ClockSynced == 0
		if !snapshot.Known(m.ClockOffset) {
			ok = false
		}
		if !ok && !unsynced {
			continue
		}
		if !ok {
			sev = findings.Low
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.System = true
		f.Links.Nodes = []string{nm.node.Name}
		if snapshot.Known(m.ClockOffset) {
			f.AddFact("Clock offset", fmt.Sprintf("%.2f s", m.ClockOffset))
		}
		f.AddFact("Synchronized", ifStr(unsynced, "no", "yes"))
		switch {
		case ok && unsynced:
			f.Title = fmt.Sprintf("Clock %.1f s off and not synchronized", off)
		case ok:
			f.Title = fmt.Sprintf("Clock %.1f s off", off)
		default:
			f.Title = "Clock not synchronized with a time server"
		}
		f.Summary = fmt.Sprintf("The clock of node %s is not kept in sync. TLS certificates, tokens and etcd depend on correct time; a few seconds off can break sign-ins and leader elections.", nm.node.Name)
		f.Remedy.LikelyCause = "The time service (chrony or systemd-timesyncd) is stopped, or can't reach its time servers."
		f.AddStep(findings.Step{Text: "On the node: check the time service", Command: "timedatectl status\nchronyc tracking || systemctl status systemd-timesyncd", Host: nm.node.Name})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The clock of server %s is wrong", nm.node.Name),
			WhatHappened: ifStr(ok, fmt.Sprintf("Its clock is %.1f seconds off.", off), "Its clock isn't kept in sync with a time server."),
			Why:          "Security certificates and the cluster's coordination need correct time on every server.",
			WhatToDo:     "Turn on time synchronization on the server (for example chrony), or send the report to whoever manages your servers.",
		}
		out = append(out, f)
	}
	return out
}

var rebootRule = Rule{
	ID: "vm.reboot", Code: "V06", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalReboot,
}

// rebootWindow is how long a reboot is reported.
const rebootWindow = 24 * time.Hour

func evalReboot(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		bt := nm.m.BootTime
		if bt.IsZero() || c.S.Now.Sub(bt) > rebootWindow || c.S.Now.Before(bt) {
			continue
		}
		if created := nm.node.CreationTimestamp.Time; !created.IsZero() && bt.Sub(created) < 10*time.Minute {
			continue // a new node, not a reboot
		}
		since := c.S.Now.Sub(bt)
		f := c.newFinding(findings.Low, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.Since = &bt
		f.Links.Nodes = []string{nm.node.Name}
		f.AddFact("Booted", fmt.Sprintf("%s (%s ago)", bt.Format("2006-01-02 15:04 MST"), ago(since)))
		f.Title = fmt.Sprintf("Rebooted %s ago", ago(since))
		f.Summary = fmt.Sprintf("Node %s started %s ago. If nobody rebooted it on purpose, look for the reason: a crash, a power loss, or an automatic update.", nm.node.Name, ago(since))
		f.Remedy.LikelyCause = "A planned reboot, an automatic update, a kernel panic or a host problem."
		f.AddStep(findings.Step{Text: "On the node: see the previous boot's last messages", Command: "journalctl -b -1 -n 50 --no-pager\nlast -x reboot | head -n 5", Host: nm.node.Name})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s restarted %s ago", nm.node.Name, agoPlain(since)),
			WhatHappened: "It was restarted. Its apps were stopped and started again.",
			Why:          "If nobody restarted it on purpose, it may have crashed, lost power, or installed updates.",
			WhatToDo:     "If this wasn't planned, send the report to whoever manages your servers.",
		}
		out = append(out, f)
	}
	return out
}

var swapRule = Rule{
	ID: "vm.memory", Code: "V07", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindNode},
	Eval:  evalSwap,
}

func evalSwap(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, nm := range metricNodes(c) {
		m := nm.m
		if !snapshot.Known(m.SwapTotal) || m.SwapTotal <= 0 || !snapshot.Known(m.SwapFree) {
			continue
		}
		used := 1 - m.SwapFree/m.SwapTotal
		if used < 0.5 {
			continue
		}
		f := c.newFinding(findings.Low, findings.ObjectRef{Kind: "Node", Name: nm.node.Name})
		f.Links.Nodes = []string{nm.node.Name}
		f.AddFact("Swap used", fmt.Sprintf("%s of %s (%s)", bytesIEC(m.SwapTotal-m.SwapFree), bytesIEC(m.SwapTotal), pct(used)))
		if snapshot.Known(m.MemTotal) && snapshot.Known(m.MemAvailable15m) {
			f.AddFact("Memory available", bytesIEC(m.MemAvailable15m))
		}
		f.Title = fmt.Sprintf("Swap %s used", pct(used))
		f.Summary = fmt.Sprintf("Node %s moved %s of memory to disk (swap). Programs whose memory is swapped out are much slower.", nm.node.Name, bytesIEC(m.SwapTotal-m.SwapFree))
		f.Remedy.LikelyCause = "The node ran short of memory at some point, often because of programs outside Kubernetes."
		f.AddStep(findings.Step{Text: "On the node: see which processes use the most swap", Command: "for f in /proc/[0-9]*/status; do awk '/^(Name|VmSwap)/{printf \"%s \", $2} END{print \"\"}' $f; done | sort -k2 -n | tail", Host: nm.node.Name})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s is using its disk as memory", nm.node.Name),
			WhatHappened: fmt.Sprintf("It moved %s of memory to its disk, which is much slower.", bytesPlain(m.SwapTotal-m.SwapFree)),
			Why:          "It ran short of memory at some point.",
			WhatToDo:     "Send the report to whoever manages your servers; the server may need more memory.",
		}
		out = append(out, f)
	}
	return out
}

func ifStr(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
