package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func appNamed(t *testing.T, d appsData, name string) appRow {
	t.Helper()
	for _, a := range d.Apps {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("no app %s in %+v", name, d.Apps)
	return appRow{}
}

func TestAppsPage(t *testing.T) {
	st := stateOf(t, "crashloop.yaml")
	d := appsOf(st, appsQuery{}, fixedNow)
	if d.Total != 1 || d.Bad != 1 || d.NotRunning != 1 || d.Pods != 3 || d.Restarting != 3 || d.Shown != 1 {
		t.Errorf("tiles: total %d, bad %d, not running %d, pods %d, restarting %d, shown %d", d.Total, d.Bad, d.NotRunning, d.Pods, d.Restarting, d.Shown)
	}
	a := appNamed(t, d, "payments-api")
	if a.Kind != "Deployment" || a.Ready != "0/3" || a.Status != "Not running" || a.Icon != "crit" || a.Restarts != 66 {
		t.Errorf("row: %+v", a)
	}
	if a.Top == nil || a.Top.RuleID != "pod.crashloop" || a.Problems != 1 {
		t.Errorf("its problem: %+v (%d)", a.Top, a.Problems)
	}
	if len(a.Pods) != 3 || a.Pods[0].Link != "/c/test/pods/shop/"+a.Pods[0].Name || a.Pods[0].Status == "" {
		t.Fatalf("pods: %+v", a.Pods)
	}

	// The search matches pod names, images and more, and hides the rest.
	for q, visible := range map[string]bool{"x2kqp": true, "SHOP payments": true, "crashloopbackoff": true, "billing": false} {
		d := appsOf(st, appsQuery{Query: q}, fixedNow)
		if got := !appNamed(t, d, "payments-api").Hidden; got != visible || (d.Shown == 1) != visible {
			t.Errorf("search %q: visible %v, shown %d", q, got, d.Shown)
		}
	}
	if d := appsOf(st, appsQuery{Namespace: "billing"}, fixedNow); len(d.Apps) != 0 || d.Total != 0 {
		t.Errorf("another namespace lists nothing: %+v", d.Apps)
	}

	basic, full := renderPage(t, "apps", d)
	for _, s := range []string{"<h1>Apps</h1>", "The app payments-api keeps crashing", a.Pods[0].Link + "?mode=full#logs", "Whole log", `data-filter="#rows"`} {
		if !strings.Contains(basic, s) {
			t.Errorf("Basic page lacks %q", s)
		}
	}
	for _, s := range []string{"<h1>Workloads</h1>", ">deploy<", "CrashLoopBackOff", a.Pods[0].Link + "#logs", `data-search="`, "id=\"app-deploy-shop-payments-api\""} {
		if !strings.Contains(full, s) {
			t.Errorf("Full page lacks %q", s)
		}
	}
}

func TestAppsJobs(t *testing.T) {
	d := appsOf(stateOf(t, "jobs.yaml"), appsQuery{}, fixedNow)
	if d.Total != 2 || d.Others != 1 {
		t.Errorf("CronJobs are apps, a Job on its own is not: total %d, others %d", d.Total, d.Others)
	}
	nightly := appNamed(t, d, "nightly-report")
	if nightly.Ready != "0 2 * * *" || nightly.Status != "Last run failed" || nightly.Detail != "last run 12 h ago" || len(nightly.Pods) != 1 {
		t.Errorf("cronjob: %+v", nightly)
	}
	if m := appNamed(t, d, "migrate-v3"); m.Kind != "Job" || m.Status != "Failed" || m.Top == nil {
		t.Errorf("job: %+v", m)
	}
	// The CronJob's Jobs are not listed on their own.
	for _, a := range d.Apps {
		if strings.HasPrefix(a.Name, "nightly-report-") {
			t.Errorf("listed a CronJob's Job: %s", a.Name)
		}
	}
}

func TestAppsHideSystemInBasic(t *testing.T) {
	st := stateOf(t, "dns-down.yaml")
	d := appsOf(st, appsQuery{}, fixedNow)
	if len(d.Apps) != 0 || d.HiddenSystem != 1 || d.Total != userApps(st.Snapshot) {
		t.Errorf("Basic hides kube-system: apps %d, hidden %d, total %d", len(d.Apps), d.HiddenSystem, d.Total)
	}
	d = appsOf(st, appsQuery{System: true}, fixedNow)
	c := appNamed(t, d, "coredns")
	if c.Status != "Scaled to 0" || !c.System || c.Top == nil {
		t.Errorf("coredns: %+v", c)
	}
	if len(d.Services) != 1 || d.Services[0].Status != "No endpoints: scaled to 0" {
		t.Errorf("kube-dns: %+v", d.Services)
	}
}

func TestServicesTab(t *testing.T) {
	st := stateOf(t, "services.yaml")
	d := appsOf(st, appsQuery{Tab: "services"}, fixedNow)
	if d.ServiceCount != 4 || d.NoEndpoints != 2 || d.Shown != 4 {
		t.Errorf("tiles: services %d, without endpoints %d, shown %d", d.ServiceCount, d.NoEndpoints, d.Shown)
	}
	byName := map[string]serviceRow{}
	for _, s := range d.Services {
		byName[s.Name] = s
	}
	if o := byName["orphan"]; o.Type != "NodePort" || o.Ports != "80/TCP (node 30080)" || o.Top == nil || o.Top.RuleID != "svc.selector-mismatch" || d.Services[0].Name != "orphan" {
		t.Errorf("orphan comes first with its problem: %+v", o)
	}
	if f := byName["fresh"]; f.Icon != "warn" || f.Top != nil {
		t.Errorf("a new Service without endpoints is a warning, not a problem yet: %+v", f)
	}
	if h := byName["healthy"]; h.Status != "1 ready" || h.Icon != "good" {
		t.Errorf("healthy: %+v", h)
	}
	if e := byName["external"]; e.Status != "ExternalName → db.example.com" {
		t.Errorf("external: %+v", e)
	}
	if d := appsOf(st, appsQuery{Tab: "services", Query: "30080"}, fixedNow); d.Shown != 1 {
		t.Errorf("search by node port: %d shown", d.Shown)
	}
	basic, full := renderPage(t, "apps", d)
	for _, s := range []string{"<h1>Services</h1>", "reaches no running app part", "points to db.example.com"} {
		if !strings.Contains(basic, s) {
			t.Errorf("Basic page lacks %q", s)
		}
	}
	for _, s := range []string{"NodePort", "80/TCP (node 30080)", "/c/test/problems/" + byName["orphan"].Top.ID, "ExternalName"} {
		if !strings.Contains(full, s) && !strings.Contains(full, strings.ReplaceAll(s, "→", "&rarr;")) {
			t.Errorf("Full page lacks %q", s)
		}
	}
}

func TestPodStatusText(t *testing.T) {
	now := metav1.NewTime(fixedNow)
	waiting := func(r string) corev1.ContainerStatus {
		return corev1.ContainerStatus{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: r}}}
	}
	running := corev1.ContainerStatus{Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	done := corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}}}
	for want, p := range map[string]*corev1.Pod{
		"Running":           {Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{running}}},
		"CrashLoopBackOff":  {Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{running, waiting("CrashLoopBackOff")}}},
		"Init:1/2":          {Spec: corev1.PodSpec{InitContainers: []corev1.Container{{}, {}}}, Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{done, {State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
		"Init:ErrImagePull": {Spec: corev1.PodSpec{InitContainers: []corev1.Container{{}}}, Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{waiting("ErrImagePull")}}},
		"Completed":         {Status: corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{done}}},
		"Evicted":           {Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}},
		"Terminating":       {ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	} {
		if got := podStatusText(p); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	// A running pod that isn't ready is a warning; one starting is not.
	p := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	if r := podRowOf("c", p, fixedNow.Add(time.Hour)); r.Icon != "warn" || r.Ready != "0/0" {
		t.Errorf("not ready: %+v", r)
	}
	p.Status = corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{waiting("ContainerCreating")}}
	if r := podRowOf("c", p, fixedNow); r.Icon != "info" {
		t.Errorf("creating: %+v", r)
	}
}

func TestAppsRoute(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	for path, want := range map[string][]string{
		"/c/edge-prod/apps":                        {"<h1>Apps</h1>", `href="/c/edge-prod/apps" class="active"`, "payments-api"},
		"/c/edge-prod/apps?mode=full&q=payments":   {"<h1>Workloads</h1>", `value="payments"`},
		"/c/edge-prod/apps?tab=services&mode=full": {"<h1>Services</h1>"},
	} {
		resp := env.do("GET", path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
		mustContain(t, readBody(t, resp), want...)
	}
	// The pod page sits under Apps now.
	crash := findingByRule(env, "pod.crashloop")
	pod := crash.Affected[0]
	body := readBody(t, env.do("GET", "/c/edge-prod/pods/"+pod.Namespace+"/"+pod.Name+"?mode=full", nil, nil))
	mustContain(t, body, `<a href="/c/edge-prod/apps">Workloads</a>`, `href="/c/edge-prod/apps?ns=shop&amp;q=payments-api"`)
}
