package rules

import (
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // CronJob time zones must work without host tzdata

	"github.com/robfig/cron/v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// systemDaemonSets are checked by their own rules (X05, X06, X07), with
// better explanations than ds.unavailable could give.
var systemDaemonSets = map[string]bool{
	"kube-router": true, "calico-node": true, "konnectivity-agent": true, "kube-proxy": true,
}

// notReadyPods returns the workload's pods that are not ready, and the
// earliest time one of them stopped being ready.
func notReadyPods(s *snapshot.Snapshot, w snapshot.Workload) ([]*corev1.Pod, time.Time) {
	var out []*corev1.Pod
	var since time.Time
	for _, p := range s.PodsOf(w) {
		if snapshot.IsPodTerminal(p) || snapshot.IsPodReady(p) {
			continue
		}
		out = append(out, p)
		t := p.CreationTimestamp.Time
		if cond := snapshot.PodCondition(p, corev1.PodReady); cond != nil && !cond.LastTransitionTime.IsZero() && cond.LastTransitionTime.After(t) {
			t = cond.LastTransitionTime.Time
		}
		if since.IsZero() || t.Before(since) {
			since = t
		}
	}
	return out, since
}

// newestPodCreation returns the creation time of the workload's newest pod.
func newestPodCreation(s *snapshot.Snapshot, w snapshot.Workload, created time.Time) time.Time {
	t := created
	for _, p := range s.PodsOf(w) {
		if p.CreationTimestamp.After(t) {
			t = p.CreationTimestamp.Time
		}
	}
	return t
}

// ---------------------------------------------------------------------------
// W13 sts.unavailable

var statefulSetUnavailableRule = Rule{
	ID: "sts.unavailable", Code: "W13", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindStatefulSet, snapshot.KindPod},
	Eval:  evalStatefulSetUnavailable,
}

func evalStatefulSetUnavailable(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, o := range c.S.StatefulSets {
		w := snapshot.Workload{Kind: "StatefulSet", Namespace: o.Namespace, Name: o.Name}
		desired, _ := c.S.DesiredReplicas(w)
		ready := o.Status.ReadyReplicas
		if desired == 0 || ready >= desired || o.DeletionTimestamp != nil {
			continue
		}
		notReady, since := notReadyPods(c.S, w)
		if len(notReady) == 0 {
			// Only missing pods: the controller has not created the next one
			// since the newest pod appeared.
			since = newestPodCreation(c.S, w, o.CreationTimestamp.Time)
		}
		if c.S.Now.Sub(since) < c.T.DeploymentUnavailableAfter.D() {
			continue
		}
		f := c.newFinding(replicaSeverity(ready, desired), workloadRef(w))
		f.Impact.AllReplicasDown = ready == 0
		f.Impact.FractionDown = float64(desired-ready) / float64(desired)
		f.Impact.AffectedPods = len(notReady)
		f.Impact.Exposed = exposed(c.S, w)
		f.Since = &since
		f.Affected = podRefs(notReady, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(notReady)
		f.Links.Claims = claimsOf(notReady)

		missing := missingOrdinals(c.S, o, desired)
		f.Title = fmt.Sprintf("%d of %d replicas ready", ready, desired)
		if len(missing) > 0 && len(notReady) > 0 && (o.Spec.PodManagementPolicy == "" || o.Spec.PodManagementPolicy == appsv1.OrderedReadyPodManagement) {
			f.Title += fmt.Sprintf(", %s waits for %s", strings.Join(missing, ", "), notReady[0].Name)
		}
		f.Summary = fmt.Sprintf("The StatefulSet wants %d replicas but only %d are ready, for %s.", desired, ready, ago(c.S.Now.Sub(since)))
		f.AddFact("Replicas", fmt.Sprintf("desired %d, current %d, ready %d, updated %d", desired, o.Status.CurrentReplicas, ready, o.Status.UpdatedReplicas))
		f.AddFact("Not ready pods", podNames(notReady, 3))
		f.AddFact("Missing pods", strings.Join(missing, ", "))
		if o.Status.UpdateRevision != "" && o.Status.CurrentRevision != o.Status.UpdateRevision {
			f.AddFact("Rollout", fmt.Sprintf("updating from %s to %s", o.Status.CurrentRevision, o.Status.UpdateRevision))
		}

		ns := o.Namespace
		f.Remedy.LikelyCause = "Its pods are not becoming ready. With ordered start-up, one stuck pod also keeps the next ones from being created."
		f.AddStep(findings.Step{Text: "See its pods and where they run", Command: fmt.Sprintf("kubectl -n %s get pods -o wide -l %s", ns, selectorString(o.Spec.Selector.MatchLabels))})
		f.AddStep(findings.Step{Text: "See the StatefulSet's events", Command: fmt.Sprintf("kubectl -n %s describe sts %s", ns, o.Name)})
		if len(notReady) > 0 {
			f.AddStep(findings.Step{Text: "See why the first stuck pod is not ready", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, notReady[0].Name)})
		}
		title := fmt.Sprintf("The app %s is down", o.Name)
		if ready > 0 {
			title = fmt.Sprintf("The app %s runs with fewer copies than it should (%d of %d)", o.Name, ready, desired)
		}
		f.Plain = findings.PlainText{
			Title:        title,
			WhatHappened: fmt.Sprintf("%d of its %d copies are working, for %s.", ready, desired, agoPlain(c.S.Now.Sub(since))),
			Why:          "Its app parts are not getting ready. They start one after the other, so one stuck part holds up the rest. Related problems usually explain why.",
			WhatToDo:     "Look at the related problems of its app parts first. If there are none, send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// replicaSeverity scales with the share of replicas down, like W12.
func replicaSeverity(ready, desired int32) findings.Severity {
	switch {
	case ready == 0:
		return findings.Critical
	case ready*2 <= desired:
		return findings.High
	}
	return findings.Medium
}

// missingOrdinals names the pods a StatefulSet should have but doesn't.
func missingOrdinals(s *snapshot.Snapshot, o *appsv1.StatefulSet, desired int32) []string {
	have := map[string]bool{}
	for _, p := range s.PodsOf(snapshot.Workload{Kind: "StatefulSet", Namespace: o.Namespace, Name: o.Name}) {
		have[p.Name] = true
	}
	start := int32(0)
	if o.Spec.Ordinals != nil {
		start = o.Spec.Ordinals.Start
	}
	var out []string
	for i := start; i < start+desired; i++ {
		name := fmt.Sprintf("%s-%d", o.Name, i)
		if !have[name] {
			out = append(out, name)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// W13 ds.unavailable

var daemonSetUnavailableRule = Rule{
	ID: "ds.unavailable", Code: "W13", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindDaemonSet, snapshot.KindPod},
	Eval:  evalDaemonSetUnavailable,
}

func evalDaemonSetUnavailable(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, o := range c.S.DaemonSets {
		if o.Namespace == "kube-system" && systemDaemonSets[o.Name] {
			continue
		}
		st := o.Status
		desired := st.DesiredNumberScheduled
		down := max(st.NumberUnavailable, desired-st.NumberReady)
		if desired == 0 || o.DeletionTimestamp != nil || (down <= 0 && st.NumberMisscheduled == 0) {
			continue
		}
		w := snapshot.Workload{Kind: "DaemonSet", Namespace: o.Namespace, Name: o.Name}
		notReady, since := notReadyPods(c.S, w)
		if len(notReady) == 0 {
			since = newestNode(c.S, newestPodCreation(c.S, w, o.CreationTimestamp.Time))
		}
		if c.S.Now.Sub(since) < c.T.DeploymentUnavailableAfter.D() {
			continue
		}
		sev := findings.Medium
		if down > 0 && st.NumberReady == 0 {
			sev = findings.High
		}
		f := c.newFinding(sev, workloadRef(w))
		f.Impact.AllReplicasDown = down > 0 && st.NumberReady == 0
		if down > 0 {
			f.Impact.FractionDown = float64(down) / float64(desired)
		}
		f.Impact.AffectedPods = len(notReady)
		f.Since = &since
		f.Affected = podRefs(notReady, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(notReady)

		switch {
		case down > 0:
			f.Title = fmt.Sprintf("%d of %d nodes without a ready pod", down, desired)
		default:
			f.Title = fmt.Sprintf("%s on nodes where it should not run", plural(int(st.NumberMisscheduled), "pod runs", "pods run"))
		}
		f.Summary = fmt.Sprintf("The DaemonSet should run a ready pod on %d nodes; %d are ready and %d unavailable.", desired, st.NumberReady, max(down, 0))
		f.AddFact("Pods", fmt.Sprintf("desired %d, scheduled %d, ready %d, unavailable %d, misscheduled %d",
			desired, st.CurrentNumberScheduled, st.NumberReady, st.NumberUnavailable, st.NumberMisscheduled))
		f.AddFact("Nodes affected", strings.Join(f.Links.Nodes, ", "))
		f.AddFact("Not ready pods", podNames(notReady, 3))

		ns := o.Namespace
		f.Remedy.LikelyCause = "Its pods are not ready on some nodes. Their own problems, or the nodes' problems, explain why."
		if down <= 0 {
			f.Remedy.LikelyCause = "Node labels or the DaemonSet's node selector changed, so some pods run where they no longer should."
		}
		f.AddStep(findings.Step{Text: "See its pods and their nodes", Command: fmt.Sprintf("kubectl -n %s get pods -o wide -l %s", ns, selectorString(o.Spec.Selector.MatchLabels))})
		f.AddStep(findings.Step{Text: "See the DaemonSet's events", Command: fmt.Sprintf("kubectl -n %s describe ds %s", ns, o.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The app %s doesn't run on every server", o.Name),
			WhatHappened: fmt.Sprintf("It should run on %s, but works on only %d.", plural(int(desired), "server", "servers"), st.NumberReady),
			Why:          "Its parts on some servers are not ready. Related problems usually explain why.",
			WhatToDo:     "Look at the related problems first. If there are none, send the report to your support team.",
		}
		if down <= 0 {
			f.Plain.WhatHappened = "Some of its parts run on servers where they shouldn't."
			f.Plain.Why = "The servers' labels or the app's placement rules changed."
		}
		out = append(out, f)
	}
	return out
}

// newestNode returns the newer of t and the newest node's creation time:
// a pod may be missing only because its node joined a moment ago.
func newestNode(s *snapshot.Snapshot, t time.Time) time.Time {
	for _, n := range s.Nodes {
		if n.CreationTimestamp.After(t) {
			t = n.CreationTimestamp.Time
		}
	}
	return t
}

// ---------------------------------------------------------------------------
// W14 job.failed

var jobFailedRule = Rule{
	ID: "job.failed", Code: "W14", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindJob, snapshot.KindPod},
	Eval:  evalJobFailed,
}

// jobCondition returns the job's condition of the type when it is true.
func jobCondition(j *batchv1.Job, t batchv1.JobConditionType) *batchv1.JobCondition {
	for i := range j.Status.Conditions {
		if j.Status.Conditions[i].Type == t && j.Status.Conditions[i].Status == corev1.ConditionTrue {
			return &j.Status.Conditions[i]
		}
	}
	return nil
}

// lastExit describes how the newest failed pod of a job ended.
func lastExit(s *snapshot.Snapshot, ns, job string) (string, *corev1.Pod) {
	var newest *corev1.Pod
	for _, p := range s.Pods {
		ref := metav1.GetControllerOf(p)
		if p.Namespace != ns || ref == nil || ref.Kind != "Job" || ref.Name != job || p.Status.Phase != corev1.PodFailed {
			continue
		}
		if newest == nil || p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = p
		}
	}
	if newest == nil {
		return "", nil
	}
	for _, cs := range newest.Status.ContainerStatuses {
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			exit := fmt.Sprintf("container %s exited with code %d", cs.Name, t.ExitCode)
			if m := exitCodeMeaning(t.ExitCode, t.Reason); !strings.HasPrefix(m, "it stopped with exit code") {
				exit += " (" + m + ")"
			}
			return exit, newest
		}
	}
	if newest.Status.Reason != "" {
		return newest.Status.Reason + ": " + truncate(newest.Status.Message, 200), newest
	}
	return "", newest
}

func evalJobFailed(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, j := range c.S.Jobs {
		if ref := metav1.GetControllerOf(j); ref != nil && ref.Kind == "CronJob" {
			continue // reported by cronjob.failing
		}
		cond := jobCondition(j, batchv1.JobFailed)
		if cond == nil {
			continue
		}
		since := cond.LastTransitionTime.Time
		sev := findings.Medium
		if c.S.Now.Sub(since) > 24*time.Hour {
			sev = findings.Low
		}
		w := snapshot.Workload{Kind: "Job", Namespace: j.Namespace, Name: j.Name}
		f := c.newFinding(sev, workloadRef(w))
		f.Since = &since
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		exit, pod := lastExit(c.S, j.Namespace, j.Name)
		if pod != nil {
			f.Affected = podRefs([]*corev1.Pod{pod}, 1)
		}
		f.AddFact("Reason", cond.Reason)
		f.AddFact("Message", truncate(cond.Message, 300))
		f.AddFact("Failed pods", fmt.Sprintf("%d", j.Status.Failed))
		f.AddFact("Last exit", exit)
		f.AddFact("Failed", ago(c.S.Now.Sub(since))+" ago")

		ns := j.Namespace
		f.Title = fmt.Sprintf("Failed %s ago: %s", ago(c.S.Now.Sub(since)), cond.Reason)
		if exit != "" {
			f.Title += ", " + exit
		}
		f.Summary = fmt.Sprintf("Job %s failed (%s): %s", j.Name, cond.Reason, truncate(cond.Message, 200))
		f.Remedy.LikelyCause = jobFailureCause(cond.Reason)
		f.AddStep(findings.Step{Text: "See the job's events and pods", Command: fmt.Sprintf("kubectl -n %s describe job %s", ns, j.Name)})
		if pod != nil {
			f.AddStep(findings.Step{Text: "Read the log of the last failed run", Command: fmt.Sprintf("kubectl -n %s logs %s --all-containers --tail=100", ns, pod.Name)})
		}
		f.AddStep(findings.Step{Text: "After fixing the cause, delete the job and create it again; a failed job does not retry by itself"})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The job %s failed", j.Name),
			WhatHappened: fmt.Sprintf("It gave up %s ago after %s.", agoPlain(c.S.Now.Sub(since)), plural(int(j.Status.Failed), "failed attempt", "failed attempts")),
			Why:          plainJobWhy(cond.Reason, exit),
			WhatToDo:     "Look at its log to see the error (step 2). Send the report to your support team if the job belongs to your product.",
		}
		out = append(out, f)
	}
	return out
}

func jobFailureCause(reason string) string {
	switch reason {
	case "BackoffLimitExceeded":
		return "Every attempt failed until the retry limit (backoffLimit) was reached. The pods' logs show why they failed."
	case "DeadlineExceeded":
		return "The job ran longer than its activeDeadlineSeconds and was stopped."
	case "PodFailurePolicy":
		return "A pod failure matched the job's pod failure policy, which fails the job at once."
	}
	return "The job's pods failed. Their logs show why."
}

func plainJobWhy(reason, exit string) string {
	switch reason {
	case "DeadlineExceeded":
		return "It took longer than it is allowed to and was stopped."
	}
	if exit != "" {
		// "container migrate exited with code 2 (…)" → "migrate stopped with code 2 (…)".
		exit = strings.Replace(strings.TrimPrefix(exit, "container "), " exited with code ", " stopped with code ", 1)
		return "Each attempt ended with an error: " + exit + "."
	}
	return "Each attempt ended with an error."
}

// ---------------------------------------------------------------------------
// W14 cronjob.failing

var cronJobFailingRule = Rule{
	ID: "cronjob.failing", Code: "W14", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindCronJob, snapshot.KindJob, snapshot.KindPod},
	Eval:  evalCronJobFailing,
}

func evalCronJobFailing(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, cj := range c.S.CronJobs {
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			continue
		}
		var failed []*batchv1.Job
		for _, j := range reverse(c.S.JobsOf(cj)) {
			if jobCondition(j, batchv1.JobComplete) != nil || jobCondition(j, batchv1.JobSuccessCriteriaMet) != nil {
				break
			}
			if jobCondition(j, batchv1.JobFailed) != nil {
				failed = append(failed, j)
			}
		}
		if len(failed) == 0 {
			continue
		}
		last := failed[0]
		cond := jobCondition(last, batchv1.JobFailed)
		w := snapshot.Workload{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name}
		f := c.newFinding(findings.Medium, workloadRef(w))
		since := failed[len(failed)-1].CreationTimestamp.Time
		f.Since = &since
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		exit, pod := lastExit(c.S, last.Namespace, last.Name)
		if pod != nil {
			f.Affected = podRefs([]*corev1.Pod{pod}, 1)
		}
		lastSuccess := "never"
		if t := cj.Status.LastSuccessfulTime; t != nil {
			lastSuccess = ago(c.S.Now.Sub(t.Time)) + " ago"
		}
		f.AddFact("Schedule", cj.Spec.Schedule)
		f.AddFact("Failed runs in a row", fmt.Sprintf("%d (of the runs Kubernetes keeps)", len(failed)))
		f.AddFact("Last failed run", fmt.Sprintf("%s, %s ago", last.Name, ago(c.S.Now.Sub(last.CreationTimestamp.Time))))
		f.AddFact("Reason", cond.Reason+": "+truncate(cond.Message, 200))
		f.AddFact("Last exit", exit)
		f.AddFact("Last success", lastSuccess)

		ns := cj.Namespace
		f.Title = fmt.Sprintf("%s in a row failed (%s)", plural(len(failed), "run", "runs"), cond.Reason)
		if exit != "" {
			f.Title += ": " + exit
		}
		f.Summary = fmt.Sprintf("The last %s of CronJob %s failed; the last success was %s.", plural(len(failed), "run", "runs"), cj.Name, lastSuccess)
		f.Remedy.LikelyCause = jobFailureCause(cond.Reason)
		f.AddStep(findings.Step{Text: "See the last failed run", Command: fmt.Sprintf("kubectl -n %s describe job %s", ns, last.Name)})
		if pod != nil {
			f.AddStep(findings.Step{Text: "Read its log", Command: fmt.Sprintf("kubectl -n %s logs %s --all-containers --tail=100", ns, pod.Name)})
		}
		f.AddStep(findings.Step{Text: "After fixing the cause, start a run by hand to check it", Command: fmt.Sprintf("kubectl -n %s create job --from=cronjob/%s %s-manual", ns, cj.Name, cj.Name)})
		successText := "It hasn't succeeded since " + strings.TrimSuffix(lastSuccess, " ago") + "."
		if lastSuccess == "never" {
			successText = "It has never succeeded."
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The scheduled job %s keeps failing", cj.Name),
			WhatHappened: fmt.Sprintf("Its last %s failed. %s", plural(len(failed), "run", "runs"), successText),
			Why:          plainJobWhy(cond.Reason, exit),
			WhatToDo:     "Look at the log of the last run to see the error (step 2), or send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

func reverse[T any](s []T) []T {
	out := make([]T, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// W14 cronjob.missed

var cronJobMissedRule = Rule{
	ID: "cronjob.missed", Code: "W14", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindCronJob, snapshot.KindJob},
	Eval:  evalCronJobMissed,
}

// cronGrace is how late a scheduled run may start before it counts as
// missed. The controller normally starts runs within seconds.
const cronGrace = 5 * time.Minute

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func evalCronJobMissed(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, cj := range c.S.CronJobs {
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend || cj.DeletionTimestamp != nil {
			continue
		}
		spec := cj.Spec.Schedule
		if cj.Spec.TimeZone != nil && *cj.Spec.TimeZone != "" {
			spec = "CRON_TZ=" + *cj.Spec.TimeZone + " " + spec
		}
		sched, err := cronParser.Parse(spec)
		if err != nil {
			continue // the API server validates schedules; nothing to add
		}
		last := cj.CreationTimestamp.Time
		ran, plainRan := "never", "It has never run."
		if t := cj.Status.LastScheduleTime; t != nil {
			last = t.Time
			ran = ago(c.S.Now.Sub(t.Time)) + " ago"
			plainRan = fmt.Sprintf("Its last run was %s ago.", agoPlain(c.S.Now.Sub(t.Time)))
		}
		expected := sched.Next(last)
		grace := cronGrace
		if d := cj.Spec.StartingDeadlineSeconds; d != nil && time.Duration(*d)*time.Second > grace {
			grace = time.Duration(*d) * time.Second
		}
		if expected.IsZero() || c.S.Now.Sub(expected) < grace {
			continue
		}
		w := snapshot.Workload{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name}
		f := c.newFinding(findings.Medium, workloadRef(w))
		f.Since = &expected
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.AddFact("Schedule", spec)
		f.AddFact("Expected run", fmt.Sprintf("%s (%s ago)", expected.UTC().Format("2006-01-02 15:04 MST"), ago(c.S.Now.Sub(expected))))
		f.AddFact("Last run", ran)
		f.AddFact("Concurrency", string(cj.Spec.ConcurrencyPolicy))
		f.AddFact("Active runs", fmt.Sprintf("%d", len(cj.Status.Active)))
		if cj.Spec.StartingDeadlineSeconds != nil {
			f.AddFact("Starting deadline", fmt.Sprintf("%ds", *cj.Spec.StartingDeadlineSeconds))
		}
		ns := cj.Namespace
		f.Title = fmt.Sprintf("Missed its schedule: expected a run %s ago, last run %s", ago(c.S.Now.Sub(expected)), ran)
		f.AddStep(findings.Step{Text: "See the CronJob's events and active runs", Command: fmt.Sprintf("kubectl -n %s describe cronjob %s", ns, cj.Name)})
		plainWhy := "Kubernetes didn't start it on time."
		if len(cj.Status.Active) > 0 && cj.Spec.ConcurrencyPolicy == batchv1.ForbidConcurrent {
			f.Remedy.LikelyCause = "The previous run is still active, and concurrencyPolicy Forbid skips new runs until it ends. The active run may hang."
			f.AddStep(findings.Step{Text: "Check the active run; if it hangs, delete it so the next run can start", Command: fmt.Sprintf("kubectl -n %s get jobs --sort-by=.metadata.creationTimestamp", ns)})
			plainWhy = "Its previous run is still going, and it is set to never run twice at the same time. The previous run may be stuck."
		} else {
			f.Remedy.LikelyCause = "The CronJob controller did not start the run: it was down or overloaded past the starting deadline, or the clock of the controllers is wrong."
			f.AddStep(findings.Step{Text: "Check the controllers' time and the kube-controller-manager log (on a controller)", Command: "date -u\nsudo journalctl -u k0scontroller --since '1 h ago' --no-pager | grep -i cronjob | tail -n 50", Host: "a controller"})
		}
		f.AddStep(findings.Step{Text: "Start a run by hand if it is needed now", Command: fmt.Sprintf("kubectl -n %s create job --from=cronjob/%s %s-manual", ns, cj.Name, cj.Name)})
		f.Summary = fmt.Sprintf("CronJob %s (%s) should have run at %s but did not. %s", cj.Name, spec, expected.UTC().Format("15:04 MST"), f.Remedy.LikelyCause)
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The scheduled job %s didn't run at its planned time", cj.Name),
			WhatHappened: fmt.Sprintf("It should have run %s ago. %s", agoPlain(c.S.Now.Sub(expected)), plainRan),
			Why:          plainWhy,
			WhatToDo:     "Send the report to your support team. If the job is needed now, it can be started by hand (last step).",
		}
		out = append(out, f)
	}
	return out
}
