// Package glossary explains the technical terms k0s-monitor uses, in plain
// words: the pages mark a term's first mention, and the explanation shows
// on hover, focus or tap (plan section 2, "technical terms explain
// themselves").
package glossary

import (
	"fmt"
	"html"
	"html/template"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

// Term is one explained term.
type Term struct {
	// Name is how the glossary lists it.
	Name string
	// Also are other words for it: plurals, Basic mode's words, short
	// names.
	Also []string
	// Text explains it in plain words.
	Text string
	// From names the product pack that explains it; empty for built-in
	// terms.
	From string
}

// Terms are the explained terms, in glossary order.
var Terms = []Term{
	{Name: "API server", Text: "The entry point of the cluster. Every tool, including kubectl and k0s-monitor, talks to it; k0s runs it on the controllers."},
	{Name: "Autopilot", Text: "k0s's updater: it updates the controllers and nodes to a new k0s version one by one, following a plan."},
	{Name: "certificate", Also: []string{"certificates"}, Text: "Proves the identity of a server or user. Clients refuse a certificate that has expired or was made for another name."},
	{Name: "CNI", Also: []string{"network driver"}, Text: "The network driver that gives pods their addresses and connects them. In k0s it is kube-router or Calico."},
	{Name: "ConfigMap", Also: []string{"ConfigMaps"}, Text: "Settings for an app, kept in the cluster and given to its pods as files or environment variables."},
	{Name: "container", Also: []string{"containers"}, Text: "A program packed with everything it needs, started from an image. A pod runs one or more containers."},
	{Name: "container runtime", Also: []string{"containerd"}, Text: "The service on each node that starts and stops containers. k0s brings containerd."},
	{Name: "control plane", Text: "The cluster's brain: the API server, etcd, the scheduler and the controller manager. k0s runs it on the controllers."},
	{Name: "controller", Also: []string{"controllers"}, Text: "In k0s, a machine that runs the control plane. It runs apps only if it is also a worker."},
	{Name: "CoreDNS", Also: []string{"DNS"}, Text: "The cluster's name service: it turns the names of Services into addresses."},
	{Name: "cordon", Also: []string{"cordoned"}, Text: "Marking a node so that no new pods are placed on it. Pods already on it keep running."},
	{Name: "CrashLoopBackOff", Text: "A container that stops right after starting, again and again. Kubernetes keeps restarting it, with longer and longer pauses."},
	{Name: "CronJob", Also: []string{"CronJobs"}, Text: "Starts a Job on a schedule, for example every night."},
	{Name: "DaemonSet", Also: []string{"DaemonSets"}, Text: "Runs one pod on every node, or on chosen ones: for agents such as network or storage drivers."},
	{Name: "Deployment", Also: []string{"Deployments"}, Text: "Keeps a number of identical pods of an app running, and replaces them step by step when the app is updated."},
	{Name: "disruption budget", Also: []string{"disruption budgets", "PodDisruptionBudget", "PodDisruptionBudgets", "PDB"}, Text: "How many pods of an app may be stopped at the same time for maintenance, such as moving them to another node."},
	{Name: "drain", Also: []string{"draining"}, Text: "Moving all pods off a node, for maintenance or an update. The node is cordoned first."},
	{Name: "endpoint", Also: []string{"endpoints"}, Text: "The address of one pod behind a Service. A Service without ready endpoints can't answer."},
	{Name: "etcd", Text: "The database where the cluster keeps its state. When it is full or doesn't answer, nothing in the cluster can change."},
	{Name: "eviction", Also: []string{"evicted", "evicts"}, Text: "Kubernetes stopping pods on a node that runs low on memory or disk, to protect the node. They are started again elsewhere if they belong to an app."},
	{Name: "Helm chart", Also: []string{"chart", "charts"}, Text: "A package of an app's objects for Kubernetes. k0s can install charts as add-ons."},
	{Name: "image", Also: []string{"images"}, Text: "The package a container starts from: the program and its files, stored in a registry under a name and a version (its tag)."},
	{Name: "Ingress", Also: []string{"Ingresses"}, Text: "Rules that route web traffic from outside the cluster to Services, by host name and path."},
	{Name: "Job", Also: []string{"Jobs"}, Text: "Runs pods until a task is done, for example a backup or a migration."},
	{Name: "konnectivity", Text: "k0s's tunnel from the controllers to the nodes. Logs, exec and webhooks go through it."},
	{Name: "kube-proxy", Text: "Sets up each node so that the address of a Service reaches the pods behind it."},
	{Name: "kube-system", Text: "The namespace of the cluster's own parts, such as CoreDNS and the network driver."},
	{Name: "kubeconfig", Text: "The file with a cluster's address and the credentials to reach it."},
	{Name: "kubelet", Text: "The agent on each node that starts and watches its pods and reports how the node is."},
	{Name: "limits", Also: []string{"memory limit", "memory limits", "CPU limit", "CPU limits"}, Text: "The most memory or CPU a container may use. At its memory limit it is stopped (OOMKilled); at its CPU limit it is slowed down."},
	{Name: "liveness probe", Also: []string{"livenessProbe"}, Text: "A health check that restarts a container when it fails, for apps that can hang."},
	{Name: "namespace", Also: []string{"namespaces"}, Text: "A folder for the objects in a cluster. The apps of one product or team are usually in one namespace."},
	{Name: "node", Also: []string{"nodes", "server", "servers"}, Text: "A machine, virtual or physical, that runs pods. Basic mode calls it a server."},
	{Name: "node-problem-detector", Text: "An optional agent that watches each node's kernel and services, and reports problems as conditions of the node."},
	{Name: "OOMKilled", Also: []string{"out of memory"}, Text: "Stopped by the kernel for using more memory than allowed (out of memory)."},
	{Name: "pod", Also: []string{"pods", "app part", "app parts"}, Text: "The smallest thing Kubernetes runs: one or more containers that start, stop and move together. An app usually runs as several pods. Basic mode calls it an app part."},
	{Name: "privileged", Text: "A container with full access to its node: its devices, kernel settings and other containers. Drivers need it; apps shouldn't."},
	{Name: "probe", Also: []string{"probes", "health check", "health checks"}, Text: "A check Kubernetes runs in a container: the readiness probe decides whether it gets traffic, the liveness probe whether it is restarted."},
	{Name: "readiness probe", Also: []string{"readinessProbe"}, Text: "A health check that decides whether a pod gets traffic from its Services."},
	{Name: "registry", Also: []string{"registries"}, Text: "The server that stores images, such as docker.io or your company's own."},
	{Name: "replica", Also: []string{"replicas", "copy", "copies"}, Text: "One of the identical pods of an app. More replicas keep an app running when one fails."},
	{Name: "ReplicaSet", Also: []string{"ReplicaSets"}, Text: "The pods of one version of a Deployment. Each update makes a new ReplicaSet: a revision."},
	{Name: "requests", Also: []string{"resource requests"}, Text: "The memory and CPU a container is promised. The scheduler places pods on nodes by their requests."},
	{Name: "revision", Also: []string{"revisions"}, Text: "One version of a Deployment's settings. Undoing a rollout goes back to an earlier revision."},
	{Name: "rollout", Also: []string{"rollouts"}, Text: "Replacing an app's pods with a new version, step by step."},
	{Name: "Secret", Also: []string{"Secrets"}, Text: "Like a ConfigMap, for passwords and keys. k0s-monitor reads Secrets only if you allow it, and shows their values only when that is turned on in Settings."},
	{Name: "TLS Secret", Also: []string{"TLS Secrets"}, Text: "A Secret that holds a certificate and its private key, for HTTPS. k0s-monitor can read the certificate, to warn before it expires."},
	{Name: "Service", Also: []string{"Services"}, Text: "A stable name and address for an app's pods. It sends traffic to the pods that are ready."},
	{Name: "StatefulSet", Also: []string{"StatefulSets"}, Text: "Like a Deployment, for apps that keep data, such as databases: each pod keeps its name and its own volume."},
	{Name: "StorageClass", Also: []string{"StorageClasses"}, Text: "A kind of storage the cluster can make volumes from, such as local disks or network storage."},
	{Name: "taint", Also: []string{"taints"}, Text: "A mark on a node that keeps pods away, except those that tolerate it."},
	{Name: "volume", Also: []string{"volumes"}, Text: "Storage a pod uses. A persistent volume keeps its data when the pod is replaced."},
	{Name: "volume claim", Also: []string{"volume claims", "PVC", "PVCs", "PersistentVolumeClaim"}, Text: "An app's request for storage. The cluster binds it to a volume of the requested size and StorageClass."},
	{Name: "webhook", Also: []string{"webhooks"}, Text: "A service the API server asks before it accepts a change. When it is down, changes can be refused."},
	{Name: "worker", Also: []string{"workers"}, Text: "In k0s, a machine that runs the apps' pods: a node."},
}

// dict is the terms in use: the built-in ones and those of product packs.
type dict struct {
	terms   []Term
	byWord  map[string]*Term
	pattern *regexp.Regexp
}

var (
	current atomic.Pointer[dict]
	tipSeq  atomic.Uint64
)

func init() { SetExtra(nil) }

// SetExtra adds product packs' terms to the built-in ones, replacing those
// set before. A pack's term doesn't replace a built-in one of the same
// name.
func SetExtra(extra []Term) {
	d := &dict{byWord: map[string]*Term{}}
	d.terms = append(append([]Term{}, Terms...), extra...)
	var words []string
	for i := range d.terms {
		t := &d.terms[i]
		for _, w := range append([]string{t.Name}, t.Also...) {
			w = strings.TrimSpace(w)
			key := strings.ToLower(w)
			if w == "" || d.byWord[key] != nil {
				continue
			}
			d.byWord[key] = t
			words = append(words, w)
		}
	}
	// Longer words first, so "API server" wins over "server".
	sort.SliceStable(words, func(i, j int) bool { return len(words[i]) > len(words[j]) })
	for i, w := range words {
		words[i] = regexp.QuoteMeta(w)
	}
	d.pattern = regexp.MustCompile(`(?i)\b(?:` + strings.Join(words, "|") + `)\b`)
	current.Store(d)
}

// Lookup returns the term a word names, or nil.
func Lookup(word string) *Term { return current.Load().byWord[strings.ToLower(word)] }

// Sorted returns the terms in alphabetical order.
func Sorted() []Term {
	d := current.Load()
	out := make([]Term, 0, len(d.terms))
	seen := map[string]bool{}
	for _, t := range d.terms {
		if k := strings.ToLower(t.Name); !seen[k] {
			seen[k] = true
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Anchor is the id of a term on the glossary page.
func Anchor(t *Term) string {
	return "t-" + strings.NewReplacer(" ", "-", "/", "-").Replace(strings.ToLower(t.Name))
}

// inName reports whether the match text[start:end] is part of a name, such
// as "pod/web-1", "node-exporter" or "image:tag", rather than a word.
func inName(text string, start, end int) bool {
	joins := func(b byte) bool { return b == '/' || b == '-' || b == '_' || b == '=' || b == '.' || b == ':' }
	if start > 0 && joins(text[start-1]) {
		return true
	}
	if end < len(text) {
		switch b := text[end]; {
		case b == '.' || b == ':':
			// The end of a sentence or a label, unless the name goes on.
			return end+1 < len(text) && text[end+1] != ' ' && text[end+1] != '\n'
		case joins(b):
			return true
		}
	}
	return false
}

// Annotate escapes text for HTML and marks the first mention of each term,
// so its explanation shows on hover, focus or tap.
func Annotate(text string) template.HTML { return NewMarker().Mark(text) }

// Marker marks each term once over several texts, such as the paragraphs
// of one page.
type Marker struct{ seen map[*Term]bool }

// NewMarker starts marking a page.
func NewMarker() *Marker { return &Marker{seen: map[*Term]bool{}} }

// Mark is Annotate, leaving out the terms marked already.
func (mk *Marker) Mark(text string) template.HTML {
	var b strings.Builder
	seen := mk.seen
	last := 0
	d := current.Load()
	for _, m := range d.pattern.FindAllStringIndex(text, -1) {
		start, end := m[0], m[1]
		if inName(text, start, end) {
			continue
		}
		t := d.byWord[strings.ToLower(text[start:end])]
		if t == nil || seen[t] {
			continue
		}
		seen[t] = true
		id := fmt.Sprintf("gt%d", tipSeq.Add(1))
		b.WriteString(html.EscapeString(text[last:start]))
		fmt.Fprintf(&b, `<span class="gloss"><span class="term" tabindex="0" aria-describedby="%s">%s</span><span class="gtip" role="tooltip" id="%s"><b>%s</b> %s</span></span>`,
			id, html.EscapeString(text[start:end]), id, html.EscapeString(t.Name), html.EscapeString(t.Text))
		last = end
	}
	b.WriteString(html.EscapeString(text[last:]))
	return template.HTML(b.String()) // #nosec G203 -- every piece of text above is escaped
}
