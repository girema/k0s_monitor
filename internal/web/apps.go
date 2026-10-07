package web

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// The Apps page (Workloads in Full mode) lists every workload and its pods,
// so any pod's logs are a click away, not only those with a problem. Its
// Services tab lists the Services and what they reach.

type podRow struct {
	Name, Node, IP     string
	Status, Icon, Mark string
	Ready              string // ready containers of all, like kubectl: "1/1"
	Restarts           int32
	Age                string
	Link               string
}

type appRow struct {
	Kind, Namespace, Name string
	Short                 string // deploy, sts, ds, cj, job, rs, pod
	Noun                  string // Basic mode's word: app, scheduled job, job, app part
	Ready                 string // "2/3", or a CronJob's schedule
	Status, Plain         string // Full and Basic status text
	Icon, Mark            string // how it runs; its problem, if any, is Top
	Detail                string // for example "last run 3 h ago"
	Restarts              int32
	Age                   string
	Nodes                 []string
	Images                []string
	Pods                  []podRow
	System                bool
	Top                   *findings.Finding
	Problems              int
	Search                string // lower-case text the search box matches
	Hidden                bool   // by the search: the page script can show it again
	Anchor                string
	// Friendly is the name a product pack gives it, and Docs the link to
	// its documentation.
	Friendly, About, Docs string
}

type backend struct{ Name, Link string }

type serviceRow struct {
	Namespace, Name, Type string
	ClusterIP             string
	Ports                 string
	External              string
	Ready, NotReady       int
	Apps                  []backend
	Pods                  []backend
	Status, Plain         string
	Icon, Mark            string
	Ingress               bool
	System                bool
	Top                   *findings.Finding
	Search                string
	Hidden                bool
}

type appsQuery struct {
	Tab       string // "" (apps) or "services"
	Query     string
	Namespace string
	OnlyBad   bool
	// System shows kube-system and the API server's own Service. Full
	// mode always does; SystemAsked is Basic mode's checkbox.
	System, SystemAsked bool
}

// link returns the page's query string for a tab, keeping the filters.
func (q appsQuery) link(tab string) string {
	v := url.Values{}
	if tab != "" {
		v.Set("tab", tab)
	}
	if q.Query != "" {
		v.Set("q", q.Query)
	}
	if q.Namespace != "" {
		v.Set("ns", q.Namespace)
	}
	if q.OnlyBad {
		v.Set("problems", "1")
	}
	if q.SystemAsked {
		v.Set("system", "1")
	}
	return "?" + v.Encode()
}

type appsData struct {
	State      *engine.State
	Q          appsQuery
	Apps       []appRow
	Services   []serviceRow
	Namespaces []string

	// Tiles, over what the filters leave, before the search.
	// Total counts Deployments, StatefulSets, DaemonSets and CronJobs,
	// like the overview; Others the Jobs, single pods and the rest.
	Total, Others, Bad, NotRunning, Pods, Restarting int
	BadText, NotRunningText                          string
	HiddenSystem                                     int
	ServiceCount, NoEndpoints                        int
	// Shown counts the rows of the tab the search leaves visible.
	Shown                  int
	AppsLink, ServicesLink string
	// SecretsLink opens the Secrets, in Full mode when the cluster's
	// Secrets can be read.
	SecretsLink string
}

// systemNamespace holds k0s's own components: what Basic mode calls the
// cluster itself rather than your apps.
func systemNamespace(ns string) bool { return ns == "kube-system" }

// appKey identifies a workload.
func appKey(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

func appsOf(st *engine.State, q appsQuery, now time.Time) appsData {
	d := appsData{State: st, Q: q}
	snap := st.Snapshot
	if snap == nil {
		return d
	}
	top, count := appFindings(st, snap)
	nsSeen := map[string]bool{}
	seeNamespace := func(ns string) {
		if !nsSeen[ns] {
			nsSeen[ns] = true
			d.Namespaces = append(d.Namespaces, ns)
		}
	}
	words := strings.Fields(strings.ToLower(q.Query))

	var rows []appRow
	add := func(r appRow) {
		r.Top, r.Problems = top[appKey(r.Kind, r.Namespace, r.Name)], count[appKey(r.Kind, r.Namespace, r.Name)]
		r.System = systemNamespace(r.Namespace)
		r.Anchor = "app-" + strings.ToLower(r.Short) + "-" + r.Namespace + "-" + r.Name
		pods := snap.PodsOf(snapshot.Workload{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name})
		nodes := map[string]bool{}
		for _, p := range pods {
			pr := podRowOf(st.Name, p, now)
			r.Pods = append(r.Pods, pr)
			r.Restarts += pr.Restarts
			if p.Spec.NodeName != "" && !nodes[p.Spec.NodeName] {
				nodes[p.Spec.NodeName] = true
				r.Nodes = append(r.Nodes, p.Spec.NodeName)
			}
		}
		sort.Strings(r.Nodes)
		// Newest pods first: in a CronJob that is the last run.
		sortPodsNewestFirst(r.Pods, pods)
		var search []string
		search = append(search, r.Kind, r.Short, r.Namespace, r.Name, r.Status, r.Plain)
		search = append(search, r.Nodes...)
		search = append(search, r.Images...)
		for _, p := range r.Pods {
			search = append(search, p.Name, p.Status)
		}
		if r.Top != nil {
			search = append(search, r.Top.Title, r.Top.Plain.Title)
		}
		r.Search = strings.ToLower(strings.Join(search, " "))
		rows = append(rows, r)
	}

	for _, o := range snap.Deployments {
		r := appRow{Kind: "Deployment", Namespace: o.Namespace, Name: o.Name, Short: "deploy", Noun: "app",
			Age: ageOf(o.CreationTimestamp, now), Images: images(o.Spec.Template.Spec)}
		desired := replicas(o.Spec.Replicas)
		r.Ready = fmt.Sprintf("%d/%d", o.Status.ReadyReplicas, desired)
		replicaStatus(&r, desired, o.Status.ReadyReplicas, o.Status.UpdatedReplicas)
		add(r)
	}
	for _, o := range snap.StatefulSets {
		r := appRow{Kind: "StatefulSet", Namespace: o.Namespace, Name: o.Name, Short: "sts", Noun: "app",
			Age: ageOf(o.CreationTimestamp, now), Images: images(o.Spec.Template.Spec)}
		desired := replicas(o.Spec.Replicas)
		r.Ready = fmt.Sprintf("%d/%d", o.Status.ReadyReplicas, desired)
		replicaStatus(&r, desired, o.Status.ReadyReplicas, desired)
		add(r)
	}
	for _, o := range snap.DaemonSets {
		r := appRow{Kind: "DaemonSet", Namespace: o.Namespace, Name: o.Name, Short: "ds", Noun: "app",
			Age: ageOf(o.CreationTimestamp, now), Images: images(o.Spec.Template.Spec)}
		desired := o.Status.DesiredNumberScheduled
		r.Ready = fmt.Sprintf("%d/%d", o.Status.NumberReady, desired)
		if desired == 0 {
			r.Status, r.Plain, r.Icon, r.Mark = "No matching nodes", "not running on any server", "info", "i"
		} else {
			replicaStatus(&r, desired, o.Status.NumberReady, o.Status.UpdatedNumberScheduled)
		}
		add(r)
	}
	for _, o := range snap.CronJobs {
		r := appRow{Kind: "CronJob", Namespace: o.Namespace, Name: o.Name, Short: "cj", Noun: "scheduled job",
			Age: ageOf(o.CreationTimestamp, now), Images: images(o.Spec.JobTemplate.Spec.Template.Spec), Ready: o.Spec.Schedule}
		cronStatus(&r, o, snap.JobsOf(o), now)
		add(r)
	}
	for _, o := range snap.Jobs {
		if c := metav1.GetControllerOf(o); c != nil && c.Kind == "CronJob" {
			continue // shown with its CronJob
		}
		r := appRow{Kind: "Job", Namespace: o.Namespace, Name: o.Name, Short: "job", Noun: "job",
			Age: ageOf(o.CreationTimestamp, now), Images: images(o.Spec.Template.Spec)}
		r.Ready = fmt.Sprintf("%d/%d", o.Status.Succeeded, replicas(o.Spec.Completions))
		jobStatus(&r, o)
		add(r)
	}
	for _, o := range snap.ReplicaSets {
		if c := metav1.GetControllerOf(o); c != nil {
			continue // part of its Deployment
		}
		r := appRow{Kind: "ReplicaSet", Namespace: o.Namespace, Name: o.Name, Short: "rs", Noun: "app",
			Age: ageOf(o.CreationTimestamp, now), Images: images(o.Spec.Template.Spec)}
		desired := replicas(o.Spec.Replicas)
		r.Ready = fmt.Sprintf("%d/%d", o.Status.ReadyReplicas, desired)
		replicaStatus(&r, desired, o.Status.ReadyReplicas, desired)
		add(r)
	}
	// Pods that no collected workload owns: bare pods, and pods of kinds
	// k0s-monitor doesn't collect (for example an operator's own kinds).
	listed := map[string]bool{}
	for _, r := range rows {
		listed[appKey(r.Kind, r.Namespace, r.Name)] = true
	}
	for _, p := range snap.Pods {
		w := snap.WorkloadOf(p)
		if listed[appKey(w.Kind, w.Namespace, w.Name)] {
			continue
		}
		listed[appKey(w.Kind, w.Namespace, w.Name)] = true
		r := appRow{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, Short: shortKind(w.Kind), Noun: w.PlainNoun(),
			Age: ageOf(p.CreationTimestamp, now), Images: images(p.Spec)}
		if w.Kind == "Pod" {
			pr := podRowOf(st.Name, p, now)
			r.Ready, r.Status, r.Icon, r.Mark = pr.Ready, pr.Status, pr.Icon, pr.Mark
			r.Plain = plainPodStatus(pr)
		} else {
			// Owned by something else: count its pods like a ReplicaSet.
			ready, all := int32(0), int32(0)
			for _, q := range snap.PodsOf(w) {
				all++
				if snapshot.IsPodReady(q) {
					ready++
				}
			}
			r.Ready = fmt.Sprintf("%d/%d", ready, all)
			replicaStatus(&r, all, ready, all)
		}
		add(r)
	}

	for _, r := range rows {
		if r.System && !q.System {
			d.HiddenSystem++
			continue
		}
		seeNamespace(r.Namespace)
		if q.Namespace != "" && r.Namespace != q.Namespace {
			continue
		}
		bad := r.Top != nil || r.Icon == "crit" || r.Icon == "warn"
		if q.OnlyBad && !bad {
			continue
		}
		// Apps are what the overview counts; Jobs, single pods and pods
		// of other owners are counted apart.
		switch r.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "CronJob":
			d.Total++
		default:
			d.Others++
		}
		if r.Top != nil {
			d.Bad++
		}
		if r.Icon == "crit" || r.Icon == "warn" {
			d.NotRunning++
		}
		d.Pods += len(r.Pods)
		for _, p := range r.Pods {
			if p.Restarts > 0 {
				d.Restarting++
			}
		}
		r.Hidden = !matches(r.Search, words)
		if !r.Hidden {
			d.Shown++
		}
		d.Apps = append(d.Apps, r)
	}
	sort.SliceStable(d.Apps, func(i, j int) bool {
		a, b := d.Apps[i], d.Apps[j]
		if ra, rb := appRank(a), appRank(b); ra != rb {
			return ra < rb
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	// The tiles name the most urgent.
	for _, r := range d.Apps {
		if r.Top != nil && d.BadText == "" {
			d.BadText = r.Name
		}
		if (r.Icon == "crit" || r.Icon == "warn") && d.NotRunningText == "" {
			d.NotRunningText = r.Name + " · " + r.Status
		}
	}
	d.AppsLink, d.ServicesLink = q.link(""), q.link("services")

	d.Services = servicesOf(st, snap, q, words)
	for _, s := range snap.Services {
		if !q.System && serviceIsSystem(s) {
			continue
		}
		seeNamespace(s.Namespace)
		if q.Namespace != "" && s.Namespace != q.Namespace {
			continue
		}
		d.ServiceCount++
		if len(s.Spec.Selector) > 0 && snap.ReadyEndpoints(s.Namespace, s.Name) == 0 {
			d.NoEndpoints++
		}
	}
	sort.Strings(d.Namespaces)
	if q.Tab == "services" {
		d.Shown = 0
		for _, r := range d.Services {
			if !r.Hidden {
				d.Shown++
			}
		}
	}
	return d
}

// sortPodsNewestFirst orders pod rows by their pods' creation, newest first.
func sortPodsNewestFirst(rows []podRow, pods []*corev1.Pod) {
	created := map[string]time.Time{}
	for _, p := range pods {
		created[p.Name] = p.CreationTimestamp.Time
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := created[rows[i].Name], created[rows[j].Name]
		if !a.Equal(b) {
			return a.After(b)
		}
		return rows[i].Name < rows[j].Name
	})
}

// appFindings maps each workload to its most urgent root problem and counts
// the root problems about it or its pods. A symptom counts under its root
// cause.
func appFindings(st *engine.State, snap *snapshot.Snapshot) (map[string]*findings.Finding, map[string]int) {
	podOwner := map[string]string{}
	for _, p := range snap.Pods {
		w := snap.WorkloadOf(p)
		podOwner[p.Namespace+"/"+p.Name] = appKey(w.Kind, w.Namespace, w.Name)
	}
	keyOf := func(r findings.ObjectRef) string {
		switch r.Kind {
		case "Pod":
			return podOwner[r.Namespace+"/"+r.Name]
		case "Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "ReplicaSet":
			return appKey(r.Kind, r.Namespace, r.Name)
		}
		return ""
	}
	top, count := map[string]*findings.Finding{}, map[string]int{}
	seen := map[string]map[string]bool{}
	for _, f := range st.Findings { // in priority order
		if f.IsHygiene() {
			continue // a suggestion, not a problem of the app
		}
		root := f
		if f.IsSymptom() {
			if p := st.Finding(f.ParentID); p != nil {
				root = p
			}
		}
		refs := append([]findings.ObjectRef{f.Resource}, f.Affected...)
		refs = append(refs, f.Links.Workloads...)
		for _, ref := range refs {
			k := keyOf(ref)
			if k == "" {
				continue
			}
			if seen[k] == nil {
				seen[k] = map[string]bool{}
			}
			if seen[k][root.ID] {
				continue
			}
			seen[k][root.ID] = true
			count[k]++
			if top[k] == nil || root.Priority.Rank() < top[k].Priority.Rank() {
				top[k] = root
			}
		}
	}
	return top, count
}

// appRank orders apps: the most urgent problem first, then apps that are
// not running, then the rest.
func appRank(r appRow) int {
	if r.Top != nil {
		return r.Top.Priority.Rank()
	}
	switch r.Icon {
	case "crit":
		return 5
	case "warn":
		return 6
	}
	return 9
}

func matches(text string, words []string) bool {
	for _, w := range words {
		if !strings.Contains(text, w) {
			return false
		}
	}
	return true
}

func replicas(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}

func ageOf(t metav1.Time, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return ago(now.Sub(t.Time))
}

func images(spec corev1.PodSpec) []string {
	var out []string
	for _, c := range spec.Containers {
		out = append(out, c.Image)
	}
	return out
}

// replicaStatus says how a workload with replicas runs.
func replicaStatus(r *appRow, desired, ready, updated int32) {
	switch {
	case desired == 0:
		r.Status, r.Plain, r.Icon, r.Mark = "Scaled to 0", "turned off (0 parts)", "info", "i"
	case ready >= desired && updated >= desired:
		r.Status, r.Plain, r.Icon, r.Mark = "Running", "running normally", "good", "✓"
	case updated < desired && ready > 0:
		r.Status, r.Plain, r.Icon, r.Mark = "Updating", "being updated", "info", "…"
	case ready == 0:
		r.Status, r.Plain, r.Icon, r.Mark = "Not running", "not running", "crit", "✕"
	default:
		r.Status, r.Plain, r.Icon, r.Mark = "Partly ready", fmt.Sprintf("%d of %d parts running", ready, desired), "warn", "▲"
	}
}

func cronStatus(r *appRow, cj *batchv1.CronJob, jobs []*batchv1.Job, now time.Time) {
	if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
		r.Status, r.Plain, r.Icon, r.Mark = "Suspended", "paused", "info", "i"
		return
	}
	if len(cj.Status.Active) > 0 {
		r.Status, r.Plain, r.Icon, r.Mark = "Running now", "running now", "info", "…"
		return
	}
	if len(jobs) == 0 {
		r.Status, r.Plain, r.Icon, r.Mark = "Not run yet", "hasn't run yet", "info", "i"
		if t := cj.Status.LastScheduleTime; t != nil {
			r.Detail = "last scheduled " + ago(now.Sub(t.Time)) + " ago"
		}
		return
	}
	last := jobs[len(jobs)-1]
	when := last.CreationTimestamp.Time
	if last.Status.CompletionTime != nil {
		when = last.Status.CompletionTime.Time
	}
	r.Detail = "last run " + ago(now.Sub(when)) + " ago"
	if jobFailed(last) {
		r.Status, r.Plain, r.Icon, r.Mark = "Last run failed", "the last run failed", "crit", "✕"
		return
	}
	r.Status, r.Plain, r.Icon, r.Mark = "Last run OK", "the last run worked", "good", "✓"
}

func jobFailed(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func jobStatus(r *appRow, j *batchv1.Job) {
	for _, c := range j.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			r.Status, r.Plain, r.Icon, r.Mark = "Completed", "finished", "good", "✓"
			return
		case batchv1.JobFailed:
			r.Status, r.Plain, r.Icon, r.Mark = "Failed", "failed", "crit", "✕"
			return
		}
	}
	if j.Status.Active > 0 {
		r.Status, r.Plain, r.Icon, r.Mark = "Running", "running now", "info", "…"
		return
	}
	r.Status, r.Plain, r.Icon, r.Mark = "Pending", "waiting to start", "info", "…"
}

// podRowOf describes a pod with the status kubectl get pods shows.
func podRowOf(cluster string, p *corev1.Pod, now time.Time) podRow {
	r := podRow{Name: p.Name, Node: p.Spec.NodeName, IP: p.Status.PodIP, Age: ageOf(p.CreationTimestamp, now),
		Link: "/c/" + url.PathEscape(cluster) + "/pods/" + url.PathEscape(p.Namespace) + "/" + url.PathEscape(p.Name)}
	ready := 0
	for _, s := range p.Status.ContainerStatuses {
		r.Restarts += s.RestartCount
		if s.Ready {
			ready++
		}
	}
	r.Ready = fmt.Sprintf("%d/%d", ready, len(p.Spec.Containers))
	r.Status = podStatusText(p)
	switch {
	case p.DeletionTimestamp != nil:
		r.Icon, r.Mark = "info", "…"
	case r.Status == "Completed" || p.Status.Phase == corev1.PodSucceeded:
		r.Icon, r.Mark = "good", "✓"
	case r.Status == "Running" && snapshot.IsPodReady(p):
		r.Icon, r.Mark = "good", "✓"
	case r.Status == "Running":
		r.Icon, r.Mark = "warn", "▲"
	case r.Status == "Pending" || r.Status == "ContainerCreating" || r.Status == "PodInitializing" || strings.HasPrefix(r.Status, "Init:") && !strings.Contains(r.Status, "Err") && !strings.Contains(r.Status, "BackOff"):
		r.Icon, r.Mark = "info", "…"
	default:
		r.Icon, r.Mark = "crit", "✕"
	}
	return r
}

// podStatusText is the STATUS column of kubectl get pods.
func podStatusText(p *corev1.Pod) string {
	if p.DeletionTimestamp != nil {
		return "Terminating"
	}
	reason := string(p.Status.Phase)
	if p.Status.Reason != "" {
		reason = p.Status.Reason
	}
	for i, s := range p.Status.InitContainerStatuses {
		switch {
		case s.State.Terminated != nil && s.State.Terminated.ExitCode == 0:
			continue
		case s.State.Terminated != nil:
			if s.State.Terminated.Reason != "" {
				return "Init:" + s.State.Terminated.Reason
			}
			return fmt.Sprintf("Init:ExitCode:%d", s.State.Terminated.ExitCode)
		case s.State.Waiting != nil && s.State.Waiting.Reason != "" && s.State.Waiting.Reason != "PodInitializing":
			return "Init:" + s.State.Waiting.Reason
		default:
			return fmt.Sprintf("Init:%d/%d", i, len(p.Spec.InitContainers))
		}
	}
	running := false
	for i := len(p.Status.ContainerStatuses) - 1; i >= 0; i-- {
		s := p.Status.ContainerStatuses[i]
		switch {
		case s.State.Waiting != nil && s.State.Waiting.Reason != "":
			reason = s.State.Waiting.Reason
		case s.State.Terminated != nil && s.State.Terminated.Reason != "":
			reason = s.State.Terminated.Reason
		case s.State.Terminated != nil:
			reason = fmt.Sprintf("ExitCode:%d", s.State.Terminated.ExitCode)
		case s.State.Running != nil && s.Ready:
			running = true
		}
	}
	if reason == "Completed" && running {
		reason = "Running"
	}
	return reason
}

func plainPodStatus(r podRow) string {
	switch r.Icon {
	case "good":
		if r.Status == "Completed" {
			return "finished"
		}
		return "running normally"
	case "info":
		return "starting"
	case "warn":
		return "running, not ready"
	}
	return "not running: " + r.Status
}

// ---------------------------------------------------------------------------
// Services

func serviceIsSystem(s *corev1.Service) bool {
	return systemNamespace(s.Namespace) || (s.Namespace == "default" && s.Name == "kubernetes")
}

func servicesOf(st *engine.State, snap *snapshot.Snapshot, q appsQuery, words []string) []serviceRow {
	top := map[string]*findings.Finding{}
	for _, f := range st.Findings { // in priority order
		root := f
		if f.IsSymptom() {
			if p := st.Finding(f.ParentID); p != nil {
				root = p
			}
		}
		refs := append([]findings.ObjectRef{f.Resource}, f.Links.Services...)
		for _, r := range refs {
			if r.Kind != "Service" {
				continue
			}
			if k := r.Namespace + "/" + r.Name; top[k] == nil || root.Priority.Rank() < top[k].Priority.Rank() {
				top[k] = root
			}
		}
	}
	var out []serviceRow
	for _, s := range snap.Services {
		if !q.System && serviceIsSystem(s) {
			continue
		}
		if q.Namespace != "" && s.Namespace != q.Namespace {
			continue
		}
		r := serviceRow{Namespace: s.Namespace, Name: s.Name, Type: string(s.Spec.Type), ClusterIP: s.Spec.ClusterIP,
			Ingress: snap.IsIngressBackend(s.Namespace, s.Name), System: serviceIsSystem(s), Top: top[s.Namespace+"/"+s.Name]}
		if r.Type == "" {
			r.Type = "ClusterIP"
		}
		if s.Spec.ClusterIP == corev1.ClusterIPNone {
			r.Type, r.ClusterIP = "Headless", ""
		}
		r.Ports = servicePorts(s)
		var ext []string
		for _, in := range s.Status.LoadBalancer.Ingress {
			ext = append(ext, orText(in.IP, in.Hostname))
		}
		ext = append(ext, s.Spec.ExternalIPs...)
		r.External = strings.Join(ext, ", ")
		podSeen := map[string]bool{}
		for _, es := range snap.EndpointSlicesFor(s.Namespace, s.Name) {
			for _, ep := range es.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					r.Ready++
				} else {
					r.NotReady++
				}
				if t := ep.TargetRef; t != nil && t.Kind == "Pod" && !podSeen[t.Name] {
					podSeen[t.Name] = true
					r.Pods = append(r.Pods, backend{Name: t.Name,
						Link: "/c/" + url.PathEscape(st.Name) + "/pods/" + url.PathEscape(s.Namespace) + "/" + url.PathEscape(t.Name)})
				}
			}
		}
		sort.Slice(r.Pods, func(i, j int) bool { return r.Pods[i].Name < r.Pods[j].Name })
		for _, w := range snap.SelectWorkloads(s.Namespace, s.Spec.Selector) {
			r.Apps = append(r.Apps, backend{Name: w.Name,
				Link: "/c/" + url.PathEscape(st.Name) + "/apps?ns=" + url.QueryEscape(w.Namespace) + "&q=" + url.QueryEscape(w.Name) + "#app-" + shortKind(w.Kind) + "-" + w.Namespace + "-" + w.Name})
		}
		switch {
		case s.Spec.Type == corev1.ServiceTypeExternalName:
			r.Status, r.Plain, r.Icon, r.Mark = "ExternalName → "+s.Spec.ExternalName, "points to "+s.Spec.ExternalName, "info", "i"
		case len(s.Spec.Selector) == 0 && r.Ready > 0:
			r.Status, r.Plain, r.Icon, r.Mark = fmt.Sprintf("%d ready (manual endpoints)", r.Ready), fmt.Sprintf("reaches %d addresses", r.Ready), "good", "✓"
		case len(s.Spec.Selector) == 0:
			r.Status, r.Plain, r.Icon, r.Mark = "No selector, no endpoints", "reaches nothing (set up by hand)", "info", "i"
		case r.Ready == 0 && r.NotReady == 0 && len(r.Apps) > 0 && allScaledDown(snap, s.Namespace, s.Spec.Selector):
			r.Status, r.Plain, r.Icon, r.Mark = "No endpoints: scaled to 0", "its apps are turned off", "info", "i"
		case r.Ready == 0:
			// A rule says how bad it is (and waits for new Services); the
			// state alone is a warning.
			r.Status, r.Plain, r.Icon, r.Mark = "No ready endpoints", "reaches no running app part", "warn", "▲"
		case r.NotReady > 0:
			r.Status, r.Plain, r.Icon, r.Mark = fmt.Sprintf("%d ready, %d not ready", r.Ready, r.NotReady), fmt.Sprintf("%d of %d app parts ready", r.Ready, r.Ready+r.NotReady), "warn", "▲"
		default:
			r.Status, r.Plain, r.Icon, r.Mark = fmt.Sprintf("%d ready", r.Ready), fmt.Sprintf("%s ready", plural(r.Ready, "app part")), "good", "✓"
		}
		bad := r.Top != nil || r.Icon == "crit" || r.Icon == "warn"
		if q.OnlyBad && !bad {
			continue
		}
		search := []string{r.Namespace, r.Name, r.Type, r.ClusterIP, r.Ports, r.External, r.Status}
		for _, a := range r.Apps {
			search = append(search, a.Name)
		}
		for _, p := range r.Pods {
			search = append(search, p.Name)
		}
		r.Search = strings.ToLower(strings.Join(search, " "))
		r.Hidden = !matches(r.Search, words)
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ra, rb := serviceRank(a), serviceRank(b)
		if ra != rb {
			return ra < rb
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return out
}

// allScaledDown reports whether every workload a selector matches wants no
// pods.
func allScaledDown(snap *snapshot.Snapshot, ns string, selector map[string]string) bool {
	ws := snap.SelectWorkloads(ns, selector)
	for _, w := range ws {
		if n, ok := snap.DesiredReplicas(w); !ok || n > 0 {
			return false
		}
	}
	return len(ws) > 0
}

func serviceRank(r serviceRow) int {
	if r.Top != nil {
		return r.Top.Priority.Rank()
	}
	switch r.Icon {
	case "crit":
		return 5
	case "warn":
		return 6
	}
	return 9
}

// servicePorts shows a Service's ports as "80→8080/TCP, 443/TCP (30443)".
func servicePorts(s *corev1.Service) string {
	var out []string
	for _, p := range s.Spec.Ports {
		t := fmt.Sprint(p.Port)
		if tp := p.TargetPort.String(); tp != "" && tp != "0" && tp != t {
			t += "→" + tp
		}
		t += "/" + string(orProto(p.Protocol))
		if p.NodePort != 0 {
			t += fmt.Sprintf(" (node %d)", p.NodePort)
		}
		out = append(out, t)
	}
	return strings.Join(out, ", ")
}

func orProto(p corev1.Protocol) corev1.Protocol {
	if p == "" {
		return corev1.ProtocolTCP
	}
	return p
}

func shortKind(kind string) string {
	switch kind {
	case "Deployment":
		return "deploy"
	case "StatefulSet":
		return "sts"
	case "DaemonSet":
		return "ds"
	case "CronJob":
		return "cj"
	case "Job":
		return "job"
	case "ReplicaSet":
		return "rs"
	}
	return strings.ToLower(kind)
}
