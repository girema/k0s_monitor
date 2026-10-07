package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// S03 pvc.pending

var pvcPendingRule = Rule{
	ID: "pvc.pending", Code: "S03", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindPVC, snapshot.KindStorageClass, snapshot.KindPod},
	Eval:  evalPVCPending,
}

func evalPVCPending(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, pvc := range c.S.PVCs {
		if pvc.Status.Phase != corev1.ClaimPending || pvc.DeletionTimestamp != nil {
			continue
		}
		created := pvc.CreationTimestamp.Time
		if c.S.Now.Sub(created) < c.T.PVCPendingAfter.D() {
			continue
		}
		consumers := c.S.PodsUsingClaim(pvc.Namespace, pvc.Name)
		var active []*corev1.Pod
		for _, p := range consumers {
			if !snapshot.IsPodTerminal(p) {
				active = append(active, p)
			}
		}

		className := ""
		var sc *storagev1.StorageClass
		kind := "provisioning"
		switch {
		case pvc.Spec.StorageClassName == nil:
			if def := c.S.DefaultStorageClass(); def == nil {
				kind = "no-default"
			} else {
				className, sc = def.Name, def
			}
		case *pvc.Spec.StorageClassName == "":
			kind = "static"
		default:
			className = *pvc.Spec.StorageClassName
			if sc = c.S.StorageClass(className); sc == nil {
				kind = "class-missing"
			}
		}
		if sc != nil && sc.VolumeBindingMode != nil && *sc.VolumeBindingMode == storagev1.VolumeBindingWaitForFirstConsumer {
			if len(active) == 0 {
				continue // normal: the volume is created when a pod uses it
			}
			scheduled := false
			for _, p := range active {
				if p.Spec.NodeName != "" {
					scheduled = true
				}
			}
			if !scheduled {
				kind = "waits-for-pod"
			}
		}

		sev := findings.High
		if len(active) == 0 || kind == "waits-for-pod" {
			sev = findings.Medium
		}
		ref := findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}
		f := c.newFinding(sev, ref)
		f.Since = &created
		f.Impact.BlocksWorkload = len(active) > 0
		f.Impact.AffectedPods = len(active)
		f.Links.Claims = []findings.ObjectRef{ref}
		f.Links.WaitsForPod = kind == "waits-for-pod"
		if kind == "no-default" {
			f.Links.Cause = "no-default-class"
		}
		for _, p := range active {
			w := workloadRef(c.S.WorkloadOf(p))
			if !containsRef(f.Links.Workloads, w) {
				f.Links.Workloads = append(f.Links.Workloads, w)
			}
		}
		f.Affected = podRefs(active, 10)

		size := ""
		if q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			size = q.String()
		}
		classText := className
		if classText == "" {
			classText = "none"
		}
		f.AddFact("StorageClass", classText)
		f.AddFact("Size", size)
		f.AddFact("Access modes", accessModes(pvc.Spec.AccessModes))
		f.AddFact("Used by", podNames(active, 3))
		f.AddFact("Pending for", ago(c.S.Now.Sub(created)))
		event := ""
		if c.S.Has(snapshot.KindEvent) {
			for _, e := range c.S.EventsFor(pvc.UID, "PersistentVolumeClaim", pvc.Namespace, pvc.Name) {
				event = e.Reason + ": " + e.Message
				break
			}
		}
		f.AddFact("Last event", truncate(event, 300))

		owner := pvc.Name
		if len(f.Links.Workloads) > 0 {
			owner = f.Links.Workloads[0].Name
		}
		ns := pvc.Namespace
		f.AddStep(findings.Step{Text: "See the claim's events", Command: fmt.Sprintf("kubectl -n %s describe pvc %s", ns, pvc.Name)})
		plainWhy, plainDo := "", ""
		switch kind {
		case "no-default":
			f.Title = "Pending: no StorageClass set and the cluster has no default StorageClass"
			f.Remedy.LikelyCause = "k0s does not install a storage provisioner or a default StorageClass. The claim names no class, so nothing can create the volume."
			f.AddStep(findings.Step{Text: "List the storage classes", Command: "kubectl get storageclass"})
			f.AddStep(findings.Step{
				Text:    "Install a storage provisioner, or mark an existing class as the default",
				Command: `kubectl patch storageclass <name> -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'`,
			})
			plainWhy = "The cluster has no default storage type, so there is nothing to create the disk from. k0s doesn't include one on its own; your product normally sets it up."
			plainDo = "Send the report to your support team; the cluster's storage setup needs to be checked."
		case "class-missing":
			f.Title = fmt.Sprintf("Pending: StorageClass %q does not exist", className)
			f.Remedy.LikelyCause = "The claim asks for a storage class that is not installed."
			f.AddStep(findings.Step{Text: "List the storage classes that exist", Command: "kubectl get storageclass"})
			plainWhy = fmt.Sprintf("It asks for a storage type (%s) that isn't installed in this cluster.", className)
			plainDo = "Send the report to your support team; either the storage type must be installed or the app must use another one."
		case "static":
			f.Title = "Pending: waiting for a matching PersistentVolume"
			f.Remedy.LikelyCause = "The claim sets storageClassName to \"\", so it only binds to a pre-created PersistentVolume, and none matches."
			f.AddStep(findings.Step{Text: "List the volumes and compare size, access mode and labels", Command: "kubectl get pv"})
			plainWhy = "It waits for a disk that must be created by hand, and none that fits exists."
			plainDo = "Send the report to your support team."
		case "waits-for-pod":
			f.Title = "Pending: waits for its pod to be scheduled"
			f.Remedy.LikelyCause = "The class creates volumes only once the pod is placed on a node, and the pod cannot be scheduled."
			plainWhy = "The disk is created only when its app gets a server, and the app can't get one."
			plainDo = "Fix the app's scheduling problem first (see the related problem)."
		default:
			f.Title = fmt.Sprintf("Pending: StorageClass %q has not created the volume", className)
			if sc != nil {
				f.AddFact("Provisioner", sc.Provisioner)
			}
			f.Remedy.LikelyCause = "The storage provisioner failed, or is not running."
			f.AddStep(findings.Step{Text: "Check that the provisioner's pods are running", Command: "kubectl get pods -A | grep -i -E 'provisioner|csi|openebs|longhorn'"})
			plainWhy = "The storage system didn't create the disk. It may be stopped or failing."
			plainDo = "Send the report to your support team."
		}
		f.Summary = fmt.Sprintf("Claim %s (%s) has been Pending for %s. %s", pvc.Name, size, ago(c.S.Now.Sub(created)), f.Remedy.LikelyCause)
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("A storage volume for %s can't be created", owner),
			WhatHappened: fmt.Sprintf("The volume %s (%s) has been waiting for %s.", pvc.Name, size, agoPlain(c.S.Now.Sub(created))),
			Why:          plainWhy,
			WhatToDo:     plainDo,
		}
		out = append(out, f)
	}
	return out
}

func accessModes(m []corev1.PersistentVolumeAccessMode) string {
	var parts []string
	for _, a := range m {
		parts = append(parts, string(a))
	}
	return strings.Join(parts, ", ")
}

func containsRef(refs []findings.ObjectRef, r findings.ObjectRef) bool {
	for _, x := range refs {
		if x == r {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// S05 volume.mount-failure

var mountFailureRule = Rule{
	ID: "volume.mount-failure", Code: "S05", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindEvent, snapshot.KindPVC},
	Eval:  evalMountFailure,
}

var volumeInMessage = regexp.MustCompile(`volume "([^"]+)"`)

// mountEvent picks the most telling volume event of a pod: a Multi-Attach
// error, then an attach failure, then a mount failure, then the generic
// "unable to attach or mount" timeout.
func mountEvent(evs []*corev1.Event) *corev1.Event {
	for _, pick := range []func(*corev1.Event) bool{
		func(e *corev1.Event) bool { return strings.Contains(e.Message, "Multi-Attach") },
		func(e *corev1.Event) bool { return e.Reason == "FailedAttachVolume" },
		func(e *corev1.Event) bool { return !strings.HasPrefix(e.Message, "Unable to attach or mount") },
		func(*corev1.Event) bool { return true },
	} {
		for _, e := range evs {
			if pick(e) {
				return e
			}
		}
	}
	return nil
}

// claimOfEvent finds the claim a volume event is about: the message names
// either the PersistentVolume or the pod's volume.
func claimOfEvent(s *snapshot.Snapshot, p *corev1.Pod, msg string) string {
	claims := snapshot.ClaimsOfPod(p)
	if m := volumeInMessage.FindStringSubmatch(msg); m != nil {
		for _, v := range p.Spec.Volumes {
			if v.Name == m[1] && v.PersistentVolumeClaim != nil {
				return v.PersistentVolumeClaim.ClaimName
			}
		}
		for _, c := range claims {
			if pvc := s.PVC(p.Namespace, c); pvc != nil && pvc.Spec.VolumeName == m[1] {
				return c
			}
		}
	}
	if len(claims) == 1 {
		return claims[0]
	}
	return ""
}

func evalMountFailure(c *Context) []*findings.Finding {
	type hit struct {
		pod   *corev1.Pod
		event *corev1.Event
		since time.Time
	}
	groups := map[findings.ObjectRef][]hit{}
	var order []findings.ObjectRef
	for _, p := range c.S.Pods {
		since, ok := creatingSince(p)
		if !ok || c.S.Now.Sub(since) < c.T.PendingAfter.D() {
			continue
		}
		e := mountEvent(podEvents(c, p, "FailedMount", "FailedAttachVolume", "FailedMapVolume"))
		if e == nil || missingObject.MatchString(e.Message) {
			continue // a missing ConfigMap or Secret: pod.stuck-creating explains it
		}
		ref := workloadRef(c.S.WorkloadOf(p))
		if claim := claimOfEvent(c.S, p, e.Message); claim != "" {
			ref = findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: p.Namespace, Name: claim}
		}
		if _, ok := groups[ref]; !ok {
			order = append(order, ref)
		}
		groups[ref] = append(groups[ref], hit{p, e, since})
	}
	var out []*findings.Finding
	for _, ref := range order {
		hits := groups[ref]
		var pods []*corev1.Pod
		since := hits[0].since
		for _, h := range hits {
			pods = append(pods, h.pod)
			if h.since.Before(since) {
				since = h.since
			}
		}
		e := hits[0].event
		first := hits[0].pod
		f := c.newFinding(findings.High, ref)
		f.Since = &since
		f.Impact.BlocksWorkload = true
		f.Impact.AffectedPods = len(pods)
		f.Affected = podRefs(pods, 10)
		f.Links.Nodes = nodesOf(pods)
		f.Links.Claims = claimsOf(pods)
		for _, p := range pods {
			if w := workloadRef(c.S.WorkloadOf(p)); !containsRef(f.Links.Workloads, w) {
				f.Links.Workloads = append(f.Links.Workloads, w)
			}
		}
		pv := ""
		if ref.Kind == "PersistentVolumeClaim" {
			if pvc := c.S.PVC(ref.Namespace, ref.Name); pvc != nil {
				pv = pvc.Spec.VolumeName
				if pvc.Spec.StorageClassName != nil {
					f.AddFact("StorageClass", *pvc.Spec.StorageClassName)
				}
				f.AddFact("Access modes", accessModes(pvc.Spec.AccessModes))
			}
		}
		f.AddFact("Volume", orDefault(pv, "unknown"))
		f.AddFact("Event", truncate(e.Reason+": "+e.Message, 400))
		f.AddFact("Node", strings.Join(f.Links.Nodes, ", "))
		f.AddFact("Waiting for", ago(c.S.Now.Sub(since)))
		f.AddFact("Pods", podNames(pods, 3))

		ns := first.Namespace
		f.AddStep(findings.Step{Text: "See the pod's volume events", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, first.Name)})
		owner := f.Links.Workloads[0].Name
		f.Plain.Title = fmt.Sprintf("The storage of %s can't be connected", owner)
		f.Plain.WhatHappened = fmt.Sprintf("Its app part has been waiting %s for its storage to be connected to the server %s, so it can't start.", agoPlain(c.S.Now.Sub(since)), strings.Join(f.Links.Nodes, ", "))
		switch {
		case strings.Contains(e.Message, "Multi-Attach"):
			f.Title = "Multi-Attach error: the volume is still attached to another node"
			f.Remedy.LikelyCause = "The volume can be attached to one node at a time (ReadWriteOnce) and is still attached to the old node, usually because that node went down or the old pod is still stopping. Kubernetes detaches it by itself about 6 minutes after the old node is confirmed down."
			f.AddStep(findings.Step{Text: "See which node the volume is attached to", Command: "kubectl get volumeattachments" + grepFor(pv)})
			f.AddStep(findings.Step{Text: "If the old node is gone for good, delete it from the cluster so the volume is released", Command: "kubectl get nodes\nkubectl delete node <old node>"})
			f.Plain.Why = "The storage is still connected to the server the app ran on before, and can only be connected to one server at a time. This usually clears up by itself after a few minutes."
			f.Plain.WhatToDo = "Wait a few minutes. If the old server is down, fix it or remove it from the cluster. Otherwise send the report to your support team."
		case e.Reason == "FailedAttachVolume":
			f.Title = "FailedAttachVolume: " + truncate(e.Message, 140)
			f.Remedy.LikelyCause = "The storage driver (CSI) can't attach the volume to the node."
			f.AddStep(findings.Step{Text: "Check the storage driver's pods", Command: "kubectl get pods -A -o wide | grep -i -E 'csi|provisioner|openebs|longhorn|rook'"})
			f.Plain.Why = "The storage system can't connect the disk to this server."
			f.Plain.WhatToDo = "Send the report to your support team."
		default:
			f.Title = "FailedMount: " + truncate(e.Message, 140)
			f.Remedy.LikelyCause = "The volume is attached but can't be mounted on the node: the storage driver's node plugin is failing, or the filesystem has a problem."
			f.AddStep(findings.Step{Text: "Check the storage driver's pods on the node", Command: fmt.Sprintf("kubectl get pods -A -o wide --field-selector spec.nodeName=%s | grep -i -E 'csi|openebs|longhorn|rook'", first.Spec.NodeName)})
			f.AddStep(findings.Step{
				Text:    "On the node: look for mount errors",
				Command: "sudo journalctl -u k0sworker --since '30 min ago' --no-pager | grep -i mount | tail -n 50",
				Host:    first.Spec.NodeName,
			})
			f.Plain.Why = "The disk can't be opened on this server. The storage system on that server may have a problem."
			f.Plain.WhatToDo = "Send the report to your support team."
		}
		f.Summary = fmt.Sprintf("%s can't start: its volume is not available on %s for %s. %s", podNames(pods, 1), strings.Join(f.Links.Nodes, ", "), ago(c.S.Now.Sub(since)), f.Remedy.LikelyCause)
		out = append(out, f)
	}
	return out
}

func grepFor(s string) string {
	if s == "" {
		return ""
	}
	return " | grep " + s
}

// ---------------------------------------------------------------------------
// S06 sc.no-default

var noDefaultClassRule = Rule{
	ID: "sc.no-default", Code: "S06", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindPVC, snapshot.KindStorageClass, snapshot.KindPod},
	Eval:  evalNoDefaultClass,
}

func evalNoDefaultClass(c *Context) []*findings.Finding {
	if c.S.DefaultStorageClass() != nil {
		return nil
	}
	var waiting []*corev1.PersistentVolumeClaim
	for _, pvc := range c.S.PVCs {
		if pvc.Spec.StorageClassName == nil && pvc.Status.Phase == corev1.ClaimPending && pvc.DeletionTimestamp == nil &&
			c.S.Now.Sub(pvc.CreationTimestamp.Time) >= c.T.PVCPendingAfter.D() {
			waiting = append(waiting, pvc)
		}
	}
	if len(waiting) == 0 {
		return nil
	}
	f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "StorageClass", Name: "(default)"})
	f.System = true
	since := waiting[0].CreationTimestamp.Time
	var names []string
	users := 0
	for _, pvc := range waiting {
		ref := findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}
		f.Links.Claims = append(f.Links.Claims, ref)
		names = append(names, pvc.Namespace+"/"+pvc.Name)
		if pvc.CreationTimestamp.Before(&metav1.Time{Time: since}) {
			since = pvc.CreationTimestamp.Time
		}
		for _, p := range c.S.PodsUsingClaim(pvc.Namespace, pvc.Name) {
			if !snapshot.IsPodTerminal(p) {
				users++
				if w := workloadRef(c.S.WorkloadOf(p)); !containsRef(f.Links.Workloads, w) {
					f.Links.Workloads = append(f.Links.Workloads, w)
				}
			}
		}
	}
	f.Since = &since
	f.Impact.BlocksWorkload = users > 0
	f.Impact.AffectedPods = users
	var classes []string
	for _, sc := range c.S.StorageClasses {
		classes = append(classes, fmt.Sprintf("%s (%s)", sc.Name, sc.Provisioner))
	}
	f.AddFact("StorageClasses", orDefault(strings.Join(classes, ", "), "none installed"))
	f.AddFact("Claims without a class", truncate(strings.Join(names, ", "), 300))
	f.AddFact("Waiting pods", fmt.Sprintf("%d", users))

	claims := plural(len(waiting), "claim", "claims")
	f.AddStep(findings.Step{Text: "List the storage classes", Command: "kubectl get storageclass"})
	if len(classes) > 0 {
		f.Title = fmt.Sprintf("No default StorageClass: %s without a class can't get a volume", claims)
		f.Remedy.LikelyCause = "Storage classes exist, but none is marked as the default, and these claims don't name one."
		f.AddStep(findings.Step{
			Text:    "Mark the class that should serve these claims as the default",
			Command: fmt.Sprintf(`kubectl patch storageclass %s -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'`, c.S.StorageClasses[0].Name),
		})
		f.Plain.Why = "Storage types are installed, but none is set as the default, and these apps don't choose one."
	} else {
		f.Title = fmt.Sprintf("No StorageClass is installed: %s can't get a volume", claims)
		f.Remedy.LikelyCause = "k0s does not install a storage provisioner or a StorageClass. Claims stay Pending until one is installed and marked as the default."
		f.AddStep(findings.Step{Text: "Install a storage provisioner (for example OpenEBS local PV or Longhorn) and mark its class as the default"})
		f.Plain.Why = "The cluster has no storage system installed. k0s doesn't include one on its own; your product normally sets it up."
	}
	f.Summary = fmt.Sprintf("The cluster has no default StorageClass, and %s name no class, so nothing creates their volumes. %s", claims, f.Remedy.LikelyCause)
	f.Plain.Title = "Apps that need storage can't get it"
	f.Plain.WhatHappened = fmt.Sprintf("%s for storage %s been waiting for up to %s.", plural(len(waiting), "request", "requests"), ifPlural(len(waiting), "has", "have"), agoPlain(c.S.Now.Sub(since)))
	f.Plain.WhatToDo = "Send the report to your support team; the cluster's storage setup needs to be checked."
	return []*findings.Finding{f}
}

func ifPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
