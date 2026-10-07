package pack

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/correlate"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

// compiled holds the parsed texts of a pack, by the text they come from.
type compiled struct {
	texts map[*string]text
}

func compile(p *Pack) (*compiled, error) {
	c := &compiled{texts: map[*string]text{}}
	add := func(where string, s *string) error {
		t, err := parseText(where, *s)
		if err != nil {
			return err
		}
		c.texts[s] = t
		return nil
	}
	for i := range p.Checks {
		ch := &p.Checks[i]
		where := "check " + ch.ID
		for name, s := range map[string]*string{"title": &ch.Title, "summary": &ch.Summary, "likelyCause": &ch.LikelyCause,
			"plain.title": &ch.Plain.Title, "plain.whatHappened": &ch.Plain.WhatHappened, "plain.why": &ch.Plain.Why, "plain.whatToDo": &ch.Plain.WhatToDo} {
			if err := add(where+" "+name, s); err != nil {
				return nil, err
			}
		}
		for j := range ch.Steps {
			st := &ch.Steps[j]
			for name, s := range map[string]*string{"text": &st.Text, "plain": &st.Plain, "command": &st.Command} {
				if err := add(fmt.Sprintf("%s steps[%d].%s", where, j, name), s); err != nil {
					return nil, err
				}
			}
		}
	}
	return c, nil
}

// f fills one of the pack's texts.
func (p *Pack) f(s *string, values map[string]any) string {
	if p.compiled == nil {
		return *s
	}
	return fill(*s, p.compiled.texts[s], values)
}

// Rules turns the pack's checks into rules for a cluster.
func (p *Pack) Rules() []rules.Rule {
	var out []rules.Rule
	for i := range p.Checks {
		ch := &p.Checks[i]
		cat := categories[ch.Category]
		r := rules.Rule{ID: p.RuleID(ch.ID), Category: cat}
		switch ch.Kind {
		case KindReplicas:
			r.Needs = []snapshot.Kind{snapshot.KindDeployment, snapshot.KindStatefulSet, snapshot.KindDaemonSet}
			r.Eval = func(c *rules.Context) []*findings.Finding { return p.evalReplicas(c, ch) }
			if cat == "" {
				r.Category = findings.Workloads
			}
		case KindVolume:
			r.Needs = []snapshot.Kind{snapshot.KindPVC, snapshot.KindMetrics}
			r.Eval = func(c *rules.Context) []*findings.Finding { return p.evalVolume(c, ch) }
			if cat == "" {
				r.Category = findings.Storage
			}
		case KindExists:
			r.Needs = []snapshot.Kind{existKinds[ch.Select.Kind]}
			r.Eval = func(c *rules.Context) []*findings.Finding { return p.evalExists(c, ch) }
			if cat == "" {
				r.Category = findings.Workloads
			}
		case KindNodes:
			r.Needs = []snapshot.Kind{snapshot.KindNode}
			r.Eval = func(c *rules.Context) []*findings.Finding { return p.evalNodes(c, ch) }
			if cat == "" {
				r.Category = findings.Nodes
			}
		case KindImage:
			r.Needs = []snapshot.Kind{snapshot.KindDeployment, snapshot.KindStatefulSet, snapshot.KindDaemonSet}
			r.Eval = func(c *rules.Context) []*findings.Finding { return p.evalImage(c, ch) }
			if cat == "" {
				r.Category = findings.Workloads
			}
		case KindQuery:
			r.Needs = []snapshot.Kind{snapshot.KindMetrics}
			r.Eval = func(c *rules.Context) []*findings.Finding { return p.evalQuery(c, ch) }
			if cat == "" {
				r.Category = findings.Workloads
			}
		}
		out = append(out, r)
	}
	return out
}

// Queries are the PromQL queries of the pack's query checks.
func (p *Pack) Queries() []string {
	var out []string
	for _, ch := range p.Checks {
		if ch.Kind == KindQuery {
			out = append(out, strings.TrimSpace(ch.Query))
		}
	}
	return out
}

// matches reports whether a pattern (empty for any) matches a value.
func matches(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	ok, _ := path.Match(pattern, value)
	return ok
}

func (s *Select) matchObject(kind, ns, name string, labels map[string]string) bool {
	if s.Kind != "" && s.Kind != kind {
		return false
	}
	if !matches(s.Namespace, ns) || !matches(s.Name, name) {
		return false
	}
	for k, v := range s.Labels {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// exact says whether the selector names one object, with no patterns.
func (s *Select) exact() bool {
	return !strings.ContainsAny(s.Name+s.Namespace, "*?[") && s.Namespace != "" && len(s.Labels) == 0
}

// newFinding starts a finding of a check, filling its texts.
func (p *Pack) newFinding(c *rules.Context, ch *Check, res findings.ObjectRef, values map[string]any, def defaults) *findings.Finding {
	f := findings.New(c.S.Cluster, "", "", severities[ch.Severity], res)
	text := func(s *string, d string) string {
		if *s != "" {
			return p.f(s, values)
		}
		return d
	}
	f.Title = text(&ch.Title, def.title)
	f.Summary = text(&ch.Summary, def.summary)
	f.Remedy.LikelyCause = text(&ch.LikelyCause, def.likelyCause)
	f.Plain = findings.PlainText{
		Title:        text(&ch.Plain.Title, def.plainTitle),
		WhatHappened: text(&ch.Plain.WhatHappened, def.whatHappened),
		Why:          text(&ch.Plain.Why, def.why),
		WhatToDo:     text(&ch.Plain.WhatToDo, def.whatToDo),
	}
	if f.Plain.Title == "" {
		f.Plain.Title = f.Title
	}
	if f.Plain.WhatHappened == "" {
		f.Plain.WhatHappened = f.Summary
	}
	if f.Plain.WhatToDo == "" {
		f.Plain.WhatToDo = "Follow the steps below, or send the report to your support team."
	}
	for i := range ch.Steps {
		st := &ch.Steps[i]
		f.AddStep(findings.Step{Text: p.f(&st.Text, values), Plain: p.f(&st.Plain, values), Command: p.f(&st.Command, values), Host: st.Host})
	}
	if len(ch.Steps) == 0 {
		for _, st := range def.steps {
			f.AddStep(st)
		}
	}
	for _, d := range ch.Docs {
		f.Docs = append(f.Docs, findings.Doc{Title: d.Title, URL: d.URL, Pack: p.Name})
	}
	f.AddFact("Check", fmt.Sprintf("%s (product pack %s)", ch.ID, p.Name))
	return f
}

// defaults are a check kind's texts when the pack gives none.
type defaults struct {
	title, summary, likelyCause             string
	plainTitle, whatHappened, why, whatToDo string
	steps                                   []findings.Step
}

// ---------------------------------------------------------------------------
// replicas

type workload struct {
	kind, ns, name string
	labels         map[string]string
	desired, ready int
	containers     []corev1.Container
}

func workloads(s *snapshot.Snapshot) []workload {
	var out []workload
	for _, d := range s.Deployments {
		desired := 1
		if d.Spec.Replicas != nil {
			desired = int(*d.Spec.Replicas)
		}
		out = append(out, workload{kind: "Deployment", ns: d.Namespace, name: d.Name, labels: d.Labels, desired: desired,
			ready: int(d.Status.ReadyReplicas), containers: d.Spec.Template.Spec.Containers})
	}
	for _, st := range s.StatefulSets {
		desired := 1
		if st.Spec.Replicas != nil {
			desired = int(*st.Spec.Replicas)
		}
		out = append(out, workload{kind: "StatefulSet", ns: st.Namespace, name: st.Name, labels: st.Labels, desired: desired,
			ready: int(st.Status.ReadyReplicas), containers: st.Spec.Template.Spec.Containers})
	}
	for _, ds := range s.DaemonSets {
		out = append(out, dsWorkload(ds))
	}
	return out
}

func dsWorkload(ds *appsv1.DaemonSet) workload {
	return workload{kind: "DaemonSet", ns: ds.Namespace, name: ds.Name, labels: ds.Labels, desired: int(ds.Status.DesiredNumberScheduled),
		ready: int(ds.Status.NumberReady), containers: ds.Spec.Template.Spec.Containers}
}

func kubectlKind(kind string) string {
	switch kind {
	case "Deployment":
		return "deploy"
	case "StatefulSet":
		return "sts"
	case "DaemonSet":
		return "ds"
	}
	return strings.ToLower(kind)
}

func (p *Pack) evalReplicas(c *rules.Context, ch *Check) []*findings.Finding {
	var out []*findings.Finding
	found := false
	for _, w := range workloads(c.S) {
		if !ch.Select.matchObject(w.kind, w.ns, w.name, w.labels) {
			continue
		}
		found = true
		if w.ready >= ch.Min {
			continue
		}
		v := map[string]any{"Kind": w.kind, "Namespace": w.ns, "Name": w.name, "App": w.name, "Ready": w.ready, "Desired": w.desired, "Min": ch.Min}
		target := kubectlKind(w.kind) + "/" + w.name
		d := defaults{
			title:        fmt.Sprintf("%s %s/%s: %d of the %d replicas the product needs are ready", w.kind, w.ns, w.name, w.ready, ch.Min),
			summary:      fmt.Sprintf("The product needs at least %d ready replicas of %s; %d of %d are ready.", ch.Min, w.name, w.ready, w.desired),
			plainTitle:   fmt.Sprintf("%s runs with fewer copies than the product needs", w.name),
			whatHappened: fmt.Sprintf("The product needs at least %d working copies of %s, and %d are working.", ch.Min, w.name, w.ready),
			why:          "With fewer copies it can be slow, and it stops when one more fails.",
			whatToDo:     "Look at the other problems of this app first: they usually say why copies don't start.",
			steps: []findings.Step{{Text: "See the replicas and their pods", Plain: "These commands show its copies",
				Command: fmt.Sprintf("kubectl -n %s get %s\nkubectl -n %s describe %s", w.ns, target, w.ns, target)}},
		}
		configured := w.desired < ch.Min
		if configured {
			d.likelyCause = fmt.Sprintf("It is set to %d replicas, fewer than the product needs.", w.desired)
			d.whatHappened = fmt.Sprintf("It is set to run %d copies, and the product needs at least %d.", w.desired, ch.Min)
			d.whatToDo = fmt.Sprintf("Ask your support team to set it to at least %d copies, the way the product is installed.", ch.Min)
		}
		f := p.newFinding(c, ch, findings.ObjectRef{Kind: w.kind, Namespace: w.ns, Name: w.name}, v, d)
		f.AddFact("Ready", fmt.Sprintf("%d of %d (at least %d needed)", w.ready, w.desired, ch.Min))
		f.Impact.FractionDown = 1 - float64(w.ready)/float64(ch.Min)
		f.Impact.AllReplicasDown = w.ready == 0
		f.Links.Workloads = append(f.Links.Workloads, f.Resource)
		if !configured {
			// Its pods don't work: their problems explain it.
			f.Links.Cause = correlate.ReplicasDown
		}
		out = append(out, f)
	}
	if !found && ch.Select.exact() {
		out = append(out, p.missingFinding(c, ch, ch.Select.Kind))
	}
	return out
}

// missingFinding reports that an object a check names doesn't exist.
func (p *Pack) missingFinding(c *rules.Context, ch *Check, kind string) *findings.Finding {
	if kind == "" {
		kind = "Deployment"
	}
	s := ch.Select
	v := map[string]any{"Kind": kind, "Namespace": s.Namespace, "Name": s.Name, "App": s.Name}
	d := defaults{
		title:        fmt.Sprintf("%s %s/%s, which the product needs, doesn't exist", kind, s.Namespace, s.Name),
		summary:      fmt.Sprintf("The product pack %s expects %s %s in namespace %s, and the cluster has none.", p.Name, strings.ToLower(kind), s.Name, s.Namespace),
		plainTitle:   fmt.Sprintf("Part of the product is missing: %s", s.Name),
		whatHappened: fmt.Sprintf("The product needs %s, and it isn't installed in the cluster.", s.Name),
		why:          "What it does for the product is missing.",
		whatToDo:     "Send the report to your support team: part of the product must be installed again.",
		steps: []findings.Step{{Text: "Look for it in every namespace", Plain: "This command looks for it",
			Command: fmt.Sprintf("kubectl get %s -A | grep %s", strings.ToLower(kind), strings.Trim(s.Name, "*"))}},
	}
	f := p.newFinding(c, ch, findings.ObjectRef{Kind: kind, Namespace: s.Namespace, Name: s.Name}, v, d)
	if ch.Severity == "" {
		f.Severity = findings.High
	}
	return f
}

// ---------------------------------------------------------------------------
// volume

func (p *Pack) evalVolume(c *rules.Context, ch *Check) []*findings.Finding {
	m := c.S.Metrics
	if m == nil {
		return nil
	}
	var out []*findings.Finding
	for _, pvc := range c.S.PVCs {
		if !ch.Select.matchObject("PersistentVolumeClaim", pvc.Namespace, pvc.Name, pvc.Labels) {
			continue
		}
		vm := m.Volumes[pvc.Namespace+"/"+pvc.Name]
		if vm == nil || !snapshot.Known(vm.Used) || !snapshot.Known(vm.Capacity) || vm.Capacity <= 0 {
			continue
		}
		pct := vm.Used / vm.Capacity * 100
		if pct <= *ch.Above {
			continue
		}
		v := map[string]any{"Namespace": pvc.Namespace, "Name": pvc.Name, "Used": int(math.Round(pct)), "Above": trim(*ch.Above),
			"UsedBytes": bytesPlain(vm.Used), "Capacity": bytesPlain(vm.Capacity), "App": pvc.Name}
		d := defaults{
			title:        fmt.Sprintf("Volume %s/%s is %.0f%% full; the product allows %s%%", pvc.Namespace, pvc.Name, pct, trim(*ch.Above)),
			summary:      fmt.Sprintf("%s of %s used (%.0f%%). The product pack %s sets the limit at %s%%.", bytesPlain(vm.Used), bytesPlain(vm.Capacity), pct, p.Name, trim(*ch.Above)),
			plainTitle:   fmt.Sprintf("The storage %s is fuller than the product allows", pvc.Name),
			whatHappened: fmt.Sprintf("It is %.0f%% full, and the product should stay below %s%%.", pct, trim(*ch.Above)),
			why:          "When it fills up, the app that writes to it stops working.",
			whatToDo:     "Send the report to your support team: old data may need to be removed, or the storage made larger.",
			steps: []findings.Step{{Text: "See the volume claim and who uses it", Plain: "This command shows the storage",
				Command: fmt.Sprintf("kubectl -n %s describe pvc %s", pvc.Namespace, pvc.Name)}},
		}
		f := p.newFinding(c, ch, findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}, v, d)
		f.AddFact("Used", fmt.Sprintf("%.0f%% (%s of %s), limit %s%%", pct, bytesPlain(vm.Used), bytesPlain(vm.Capacity), trim(*ch.Above)))
		f.Links.Claims = append(f.Links.Claims, f.Resource)
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// exists

func (p *Pack) evalExists(c *rules.Context, ch *Check) []*findings.Finding {
	s := c.S
	type obj struct {
		ns, name string
		labels   map[string]string
	}
	var objs []obj
	switch ch.Select.Kind {
	case "Deployment":
		for _, o := range s.Deployments {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "StatefulSet":
		for _, o := range s.StatefulSets {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "DaemonSet":
		for _, o := range s.DaemonSets {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "CronJob":
		for _, o := range s.CronJobs {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "Job":
		for _, o := range s.Jobs {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "Service":
		for _, o := range s.Services {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "Ingress":
		for _, o := range s.Ingresses {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "PersistentVolumeClaim":
		for _, o := range s.PVCs {
			objs = append(objs, obj{o.Namespace, o.Name, o.Labels})
		}
	case "Namespace":
		for _, o := range s.Namespaces {
			objs = append(objs, obj{"", o.Name, o.Labels})
		}
	case "StorageClass":
		for _, o := range s.StorageClasses {
			objs = append(objs, obj{"", o.Name, o.Labels})
		}
	}
	for _, o := range objs {
		if ch.Select.matchObject(ch.Select.Kind, o.ns, o.name, o.labels) {
			return nil
		}
	}
	return []*findings.Finding{p.missingFinding(c, ch, ch.Select.Kind)}
}

// ---------------------------------------------------------------------------
// nodes

func (p *Pack) evalNodes(c *rules.Context, ch *Check) []*findings.Finding {
	total, ready := 0, 0
	for _, n := range c.S.Nodes {
		if !ch.Select.matchObject("Node", "", n.Name, n.Labels) {
			continue
		}
		total++
		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue && !n.Spec.Unschedulable {
				ready++
			}
		}
	}
	if ready >= ch.Min {
		return nil
	}
	which := "nodes"
	if len(ch.Select.Labels) > 0 || ch.Select.Name != "" {
		which = "selected nodes"
	}
	v := map[string]any{"Ready": ready, "Total": total, "Min": ch.Min}
	d := defaults{
		title:        fmt.Sprintf("%d of the %d %s are ready to run pods; the product needs %d", ready, total, which, ch.Min),
		summary:      fmt.Sprintf("The product pack %s needs at least %d ready, schedulable %s; %d are.", p.Name, ch.Min, which, ready),
		plainTitle:   "The cluster has fewer working servers than the product needs",
		whatHappened: fmt.Sprintf("The product needs at least %d working servers, and %d are working.", ch.Min, ready),
		why:          "Apps may not fit, or stop when one more server fails.",
		whatToDo:     "Look at the problems of the servers first. If a server is missing, add one.",
		steps:        []findings.Step{{Text: "See the nodes", Plain: "This command lists the servers", Command: "kubectl get nodes -o wide"}},
	}
	f := p.newFinding(c, ch, findings.ObjectRef{Kind: "Cluster", Name: c.S.Cluster}, v, d)
	f.AddFact("Ready nodes", fmt.Sprintf("%d of %d (at least %d needed)", ready, total, ch.Min))
	f.Impact.ClusterWide = true
	return []*findings.Finding{f}
}

// ---------------------------------------------------------------------------
// image

// imageTag is the tag of an image reference, or "" for none or a digest.
func imageTag(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	slash := strings.LastIndex(image, "/")
	if i := strings.LastIndex(image, ":"); i > slash {
		return image[i+1:]
	}
	return ""
}

func (p *Pack) evalImage(c *rules.Context, ch *Check) []*findings.Finding {
	var out []*findings.Finding
	for _, w := range workloads(c.S) {
		if !ch.Select.matchObject(w.kind, w.ns, w.name, w.labels) {
			continue
		}
		var wrong []string
		var first corev1.Container
		for _, ct := range w.containers {
			if ch.Container != "" && ct.Name != ch.Container {
				continue
			}
			if !matches(ch.Tag, imageTag(ct.Image)) {
				if len(wrong) == 0 {
					first = ct
				}
				wrong = append(wrong, ct.Name+": "+ct.Image)
			}
		}
		if len(wrong) == 0 {
			continue
		}
		tag := imageTag(first.Image)
		if tag == "" {
			tag = "none"
		}
		v := map[string]any{"Kind": w.kind, "Namespace": w.ns, "Name": w.name, "App": w.name, "Container": first.Name, "Image": first.Image, "Tag": tag, "Want": ch.Tag}
		d := defaults{
			title:        fmt.Sprintf("%s %s/%s runs version %s; the product expects %s", w.kind, w.ns, w.name, tag, ch.Tag),
			summary:      fmt.Sprintf("Container %s runs %s, and the product pack %s expects tag %s.", first.Name, first.Image, p.Name, ch.Tag),
			likelyCause:  "An update of the product didn't reach this app, or it was changed by hand.",
			plainTitle:   fmt.Sprintf("%s runs another version than the product", w.name),
			whatHappened: fmt.Sprintf("It runs version %s, and the product comes with %s.", tag, ch.Tag),
			why:          "Parts of the product that don't match can fail in ways that are hard to see.",
			whatToDo:     "Send the report to your support team: this changes with a product update.",
			steps: []findings.Step{{Text: "See which images it runs, and its rollout history", Plain: "These commands show its versions",
				Command: fmt.Sprintf("kubectl -n %s get %s/%s -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{\"\\t\"}{.image}{\"\\n\"}{end}'\nkubectl -n %s rollout history %s/%s", w.ns, kubectlKind(w.kind), w.name, w.ns, kubectlKind(w.kind), w.name)}},
		}
		f := p.newFinding(c, ch, findings.ObjectRef{Kind: w.kind, Namespace: w.ns, Name: w.name}, v, d)
		f.AddFact("Images", strings.Join(wrong, "\n"))
		f.AddFact("Expected tag", ch.Tag)
		f.Links.Workloads = append(f.Links.Workloads, f.Resource)
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// query

func (p *Pack) evalQuery(c *rules.Context, ch *Check) []*findings.Finding {
	m := c.S.Metrics
	if m == nil || m.Queries == nil {
		return nil
	}
	samples, ok := m.Queries[strings.TrimSpace(ch.Query)]
	if !ok {
		return nil
	}
	var out []*findings.Finding
	for _, s := range samples {
		breach := (ch.Above != nil && s.Value > *ch.Above) || (ch.Below != nil && s.Value < *ch.Below)
		if !breach || math.IsNaN(s.Value) {
			continue
		}
		limit, cmp := ch.Above, "above"
		if ch.Below != nil {
			limit, cmp = ch.Below, "below"
		}
		values := map[string]any{"Value": formatValue(s.Value, ch.Unit), "Limit": formatValue(*limit, ch.Unit), "Labels": s.Labels}
		for k, v := range s.Labels {
			values[k] = v
		}
		res := queryObject(ch, s.Labels, c.S.Cluster)
		values["Name"], values["Namespace"], values["App"] = res.Name, res.Namespace, res.Name
		d := defaults{
			title:        fmt.Sprintf("%s: %s is %s %s", ch.ID, formatValue(s.Value, ch.Unit), cmp, formatValue(*limit, ch.Unit)),
			summary:      fmt.Sprintf("The product pack %s's query returned %s for %s, %s the limit of %s.", p.Name, formatValue(s.Value, ch.Unit), labelText(s.Labels), cmp, formatValue(*limit, ch.Unit)),
			plainTitle:   fmt.Sprintf("A measurement of the product is out of range (%s)", ch.ID),
			whatHappened: fmt.Sprintf("It is %s, and should not be %s %s.", formatValue(s.Value, ch.Unit), cmp, formatValue(*limit, ch.Unit)),
			whatToDo:     "Send the report to your support team.",
			steps:        []findings.Step{{Text: "Run the query in Prometheus to see its history", Command: strings.TrimSpace(ch.Query)}},
		}
		f := p.newFinding(c, ch, res, values, d)
		f.AddFact("Value", formatValue(s.Value, ch.Unit))
		f.AddFact("Limit", cmp+" "+formatValue(*limit, ch.Unit))
		if len(s.Labels) > 0 {
			f.AddFact("Series", labelText(s.Labels))
		}
		out = append(out, f)
	}
	return out
}

// queryObject names what a query's series is about, from its labels: a
// workload or pod when it has one, else the series itself.
func queryObject(ch *Check, labels map[string]string, cluster string) findings.ObjectRef {
	ns := labels["namespace"]
	for _, k := range []struct{ label, kind string }{{"deployment", "Deployment"}, {"statefulset", "StatefulSet"}, {"daemonset", "DaemonSet"},
		{"persistentvolumeclaim", "PersistentVolumeClaim"}, {"pod", "Pod"}, {"node", "Node"}} {
		if v := labels[k.label]; v != "" {
			if k.kind == "Node" {
				ns = ""
			}
			return findings.ObjectRef{Kind: k.kind, Namespace: ns, Name: v}
		}
	}
	name := ch.ID
	if l := labelText(labels); l != "" {
		name += " " + l
	}
	return findings.ObjectRef{Kind: "Measurement", Namespace: ns, Name: name}
}

func labelText(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if k != "__name__" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ", ")
}

func formatValue(v float64, unit string) string {
	switch unit {
	case "%":
		return trim(v) + "%"
	case "s":
		return trim(v) + " s"
	case "bytes":
		return bytesPlain(v)
	}
	return trim(v)
}

func trim(v float64) string {
	switch {
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return fmt.Sprintf("%.0f", v)
	case math.Abs(v) >= 100:
		return fmt.Sprintf("%.0f", v)
	case math.Abs(v) >= 10:
		return fmt.Sprintf("%.1f", v)
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".")
}

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
	return trim(v) + " " + units[i]
}
