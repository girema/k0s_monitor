package remedy

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Change is one difference between two revisions of a pod template.
type Change struct {
	// Container is empty for a change to the pod itself.
	Container string `json:"container,omitempty"`
	// What names the setting: "image", "env DB_HOST", "memory limit", ...
	What string `json:"what"`
	// Old and New are the values, "" when absent. Values of secret-looking
	// names are masked.
	Old string `json:"old,omitempty"`
	New string `json:"new,omitempty"`
}

// String is the change in one line: `api: env DB_HOST postgresql → postgres`.
func (c Change) String() string {
	s := c.What
	if c.Container != "" {
		s = c.Container + ": " + s
	}
	switch {
	case c.Old == "" && c.New == "":
		return s
	case c.Old == "":
		return s + " added (" + c.New + ")"
	case c.New == "":
		return s + " removed (was " + c.Old + ")"
	case c.Old == c.New:
		// A masked value that changed.
		return s + " changed (value hidden)"
	}
	return s + " " + c.Old + " → " + c.New
}

// restartedAt is the annotation `kubectl rollout restart` sets.
const restartedAt = "kubectl.kubernetes.io/restartedAt"

// TemplateChanges lists what changed from one pod template to the next:
// images, commands, environment, resources, probes, mounts, volumes and
// security settings. A rollout that only restarted the pods says so.
func TemplateChanges(old, cur *corev1.PodTemplateSpec) []Change {
	if old == nil || cur == nil {
		return nil
	}
	var out []Change
	add := func(container, what, o, n string) {
		if o != n {
			out = append(out, Change{Container: container, What: what, Old: o, New: n})
		}
	}
	os, ns := &old.Spec, &cur.Spec
	add("", "service account", os.ServiceAccountName, ns.ServiceAccountName)
	add("", "node selector", mapText(os.NodeSelector), mapText(ns.NodeSelector))
	add("", "host network", boolText(os.HostNetwork), boolText(ns.HostNetwork))
	add("", "run as user", podUser(os.SecurityContext), podUser(ns.SecurityContext))
	add("", "fs group", podGroup(os.SecurityContext), podGroup(ns.SecurityContext))
	oldVols, newVols := volumes(os.Volumes), volumes(ns.Volumes)
	for _, name := range keys(oldVols, newVols) {
		add("", "volume "+name, oldVols[name], newVols[name])
	}

	oldCs, newCs := containers(os), containers(ns)
	for _, name := range orderedNames(os, ns) {
		oc, nc := oldCs[name], newCs[name]
		switch {
		case oc == nil:
			add(name, "container", "", nc.Image)
			continue
		case nc == nil:
			add(name, "container", oc.Image, "")
			continue
		}
		add(name, "image", oc.Image, nc.Image)
		add(name, "command", Redact(strings.Join(oc.Command, " ")), Redact(strings.Join(nc.Command, " ")))
		add(name, "args", Redact(strings.Join(oc.Args, " ")), Redact(strings.Join(nc.Args, " ")))
		oe, oraw := envs(oc)
		ne, nraw := envs(nc)
		for _, k := range keys(oraw, nraw) {
			if oraw[k] != nraw[k] {
				out = append(out, Change{Container: name, What: "env " + k, Old: oe[k], New: ne[k]})
			}
		}
		add(name, "env from", envFrom(oc), envFrom(nc))
		for _, r := range []struct {
			what string
			get  func(corev1.ResourceRequirements) string
		}{
			{"memory limit", func(r corev1.ResourceRequirements) string { return qty(r.Limits, corev1.ResourceMemory) }},
			{"memory request", func(r corev1.ResourceRequirements) string { return qty(r.Requests, corev1.ResourceMemory) }},
			{"CPU limit", func(r corev1.ResourceRequirements) string { return qty(r.Limits, corev1.ResourceCPU) }},
			{"CPU request", func(r corev1.ResourceRequirements) string { return qty(r.Requests, corev1.ResourceCPU) }},
		} {
			add(name, r.what, r.get(oc.Resources), r.get(nc.Resources))
		}
		add(name, "liveness probe", probe(oc.LivenessProbe), probe(nc.LivenessProbe))
		add(name, "readiness probe", probe(oc.ReadinessProbe), probe(nc.ReadinessProbe))
		add(name, "startup probe", probe(oc.StartupProbe), probe(nc.StartupProbe))
		om, nm := mounts(oc), mounts(nc)
		for _, k := range keys(om, nm) {
			add(name, "mount "+k, om[k], nm[k])
		}
		add(name, "ports", ports(oc), ports(nc))
		add(name, "run as user", containerUser(oc), containerUser(nc))
		add(name, "read-only root filesystem", boolText(roRoot(oc)), boolText(roRoot(nc)))
		add(name, "privileged", boolText(privileged(oc)), boolText(privileged(nc)))
	}
	if len(out) == 0 && old.Annotations[restartedAt] != cur.Annotations[restartedAt] && cur.Annotations[restartedAt] != "" {
		out = append(out, Change{What: "restarted (kubectl rollout restart), nothing else changed"})
	}
	return out
}

func containers(s *corev1.PodSpec) map[string]*corev1.Container {
	m := map[string]*corev1.Container{}
	for i := range s.InitContainers {
		m[s.InitContainers[i].Name] = &s.InitContainers[i]
	}
	for i := range s.Containers {
		m[s.Containers[i].Name] = &s.Containers[i]
	}
	return m
}

// orderedNames lists the containers of both templates, in the new one's
// order, then those that were removed.
func orderedNames(old, cur *corev1.PodSpec) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range []*corev1.PodSpec{cur, old} {
		for _, list := range [][]corev1.Container{s.InitContainers, s.Containers} {
			for _, c := range list {
				if !seen[c.Name] {
					seen[c.Name] = true
					out = append(out, c.Name)
				}
			}
		}
	}
	return out
}

// envs is a container's environment as shown, with secret-looking values
// masked, and as compared.
func envs(c *corev1.Container) (shown, raw map[string]string) {
	m, raw := map[string]string{}, map[string]string{}
	for _, e := range c.Env {
		switch vf := e.ValueFrom; {
		case vf == nil:
			// A value can hide a password even under a harmless name,
			// as in postgres://user:password@host.
			m[e.Name] = Redact(MaskValue(e.Name, e.Value))
			if e.Value == "" {
				m[e.Name] = `""`
			}
			raw[e.Name] = "=" + e.Value
			continue
		case vf.ConfigMapKeyRef != nil:
			m[e.Name] = "ConfigMap " + vf.ConfigMapKeyRef.Name + " key " + vf.ConfigMapKeyRef.Key
		case vf.SecretKeyRef != nil:
			m[e.Name] = "Secret " + vf.SecretKeyRef.Name + " key " + vf.SecretKeyRef.Key
		case vf.FieldRef != nil:
			m[e.Name] = "field " + vf.FieldRef.FieldPath
		case vf.ResourceFieldRef != nil:
			m[e.Name] = "resource " + vf.ResourceFieldRef.Resource
		default:
			m[e.Name] = "from elsewhere"
		}
		raw[e.Name] = m[e.Name]
	}
	return m, raw
}

func envFrom(c *corev1.Container) string {
	var parts []string
	for _, e := range c.EnvFrom {
		switch {
		case e.ConfigMapRef != nil:
			parts = append(parts, "ConfigMap "+e.ConfigMapRef.Name)
		case e.SecretRef != nil:
			parts = append(parts, "Secret "+e.SecretRef.Name)
		}
	}
	return strings.Join(parts, ", ")
}

func volumes(vs []corev1.Volume) map[string]string {
	m := map[string]string{}
	for _, v := range vs {
		switch s := v.VolumeSource; {
		case s.ConfigMap != nil:
			m[v.Name] = "ConfigMap " + s.ConfigMap.Name
		case s.Secret != nil:
			m[v.Name] = "Secret " + s.Secret.SecretName
		case s.PersistentVolumeClaim != nil:
			m[v.Name] = "claim " + s.PersistentVolumeClaim.ClaimName
		case s.EmptyDir != nil:
			m[v.Name] = "emptyDir"
		case s.HostPath != nil:
			m[v.Name] = "hostPath " + s.HostPath.Path
		case s.Projected != nil:
			m[v.Name] = "projected"
		default:
			m[v.Name] = "volume"
		}
	}
	return m
}

func mounts(c *corev1.Container) map[string]string {
	m := map[string]string{}
	for _, vm := range c.VolumeMounts {
		v := vm.Name
		if vm.SubPath != "" {
			v += " (" + vm.SubPath + ")"
		}
		if vm.ReadOnly {
			v += ", read-only"
		}
		m[vm.MountPath] = v
	}
	return m
}

func ports(c *corev1.Container) string {
	var ps []string
	for _, p := range c.Ports {
		ps = append(ps, fmt.Sprintf("%d/%s", p.ContainerPort, strings.ToLower(string(p.Protocol))))
	}
	return strings.Join(ps, ", ")
}

func probe(p *corev1.Probe) string {
	if p == nil {
		return ""
	}
	var what string
	switch h := p.ProbeHandler; {
	case h.HTTPGet != nil:
		what = fmt.Sprintf("GET :%s%s", h.HTTPGet.Port.String(), h.HTTPGet.Path)
	case h.TCPSocket != nil:
		what = "TCP :" + h.TCPSocket.Port.String()
	case h.Exec != nil:
		what = "exec " + strings.Join(h.Exec.Command, " ")
	case h.GRPC != nil:
		what = fmt.Sprintf("gRPC :%d", h.GRPC.Port)
	}
	return fmt.Sprintf("%s after %ds, every %ds, timeout %ds, %d failures", what,
		p.InitialDelaySeconds, orInt(p.PeriodSeconds, 10), orInt(p.TimeoutSeconds, 1), orInt(p.FailureThreshold, 3))
}

func orInt(v, def int32) int32 {
	if v == 0 {
		return def
	}
	return v
}

func qty(l corev1.ResourceList, name corev1.ResourceName) string {
	if q, ok := l[name]; ok {
		return q.String()
	}
	return ""
}

func podUser(sc *corev1.PodSecurityContext) string {
	if sc == nil || sc.RunAsUser == nil {
		return ""
	}
	return fmt.Sprint(*sc.RunAsUser)
}

func podGroup(sc *corev1.PodSecurityContext) string {
	if sc == nil || sc.FSGroup == nil {
		return ""
	}
	return fmt.Sprint(*sc.FSGroup)
}

func containerUser(c *corev1.Container) string {
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil {
		return ""
	}
	return fmt.Sprint(*c.SecurityContext.RunAsUser)
}

func roRoot(c *corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem
}

func privileged(c *corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

func mapText(m map[string]string) string {
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keys lists the keys of both maps, sorted.
func keys(a, b map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]string{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}
