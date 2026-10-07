package snapshot

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCordonTimeSurvivesStrippedManagedFields(t *testing.T) {
	at := metav1.NewTime(time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC))
	later := metav1.NewTime(at.Add(time.Hour))
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "w", ManagedFields: []metav1.ManagedFieldsEntry{
			{Manager: "kubelet", Time: &later, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:status":{}}`)}},
			{Manager: "kubectl-cordon", Time: &at, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:spec":{"f:unschedulable":{}}}`)}},
		}},
		Spec: corev1.NodeSpec{Unschedulable: true},
	}
	if got, ok := CordonedSince(n); !ok || !got.Equal(at.Time) {
		t.Fatalf("from managed fields: %v %v", got, ok)
	}
	KeepCordonTime(n)
	n.ManagedFields = nil // what the collector does next
	if got, ok := CordonedSince(n); !ok || !got.Equal(at.Time) {
		t.Fatalf("from the annotation: %v %v", got, ok)
	}
	n.Spec.Unschedulable = false
	if _, ok := CordonedSince(n); ok {
		t.Fatalf("an uncordoned node has no cordon time")
	}
	plain := &corev1.Node{Spec: corev1.NodeSpec{Unschedulable: true}}
	KeepCordonTime(plain)
	if _, ok := CordonedSince(plain); ok || plain.Annotations != nil {
		t.Fatalf("without managed fields the time is unknown")
	}
}

func TestDaemonSetShouldRun(t *testing.T) {
	ds := &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
		Tolerations:  []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "edge", Effect: corev1.TaintEffectNoSchedule}},
	}}}}
	node := func(labels map[string]string, taints ...corev1.Taint) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.NodeSpec{Taints: taints}}
	}
	linux := map[string]string{"kubernetes.io/os": "linux"}
	cases := []struct {
		name string
		n    *corev1.Node
		want bool
	}{
		{"matching node", node(linux), true},
		{"other OS", node(map[string]string{"kubernetes.io/os": "windows"}), false},
		{"tolerated taint", node(linux, corev1.Taint{Key: "dedicated", Value: "edge", Effect: corev1.TaintEffectNoSchedule}), true},
		{"untolerated taint", node(linux, corev1.Taint{Key: "gpu", Effect: corev1.TaintEffectNoSchedule}), false},
		{"condition taint", node(linux, corev1.Taint{Key: corev1.TaintNodeNotReady, Effect: corev1.TaintEffectNoExecute}), true},
		{"cordoned", node(linux, corev1.Taint{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule}), true},
	}
	for _, c := range cases {
		if got := DaemonSetShouldRun(ds, c.n); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseAPIServices(t *testing.T) {
	list := `{"kind":"APIServiceList","items":[
	 {"metadata":{"name":"v1.apps"},"spec":{},"status":{"conditions":[{"type":"Available","status":"True","reason":"Local"}]}},
	 {"metadata":{"name":"v1beta1.metrics.k8s.io"},"spec":{"service":{"namespace":"kube-system","name":"metrics-server"}},
	  "status":{"conditions":[{"type":"Available","status":"False","reason":"MissingEndpoints","message":"no addresses","lastTransitionTime":"2026-09-27T12:00:00Z"}]}}]}`
	as, err := ParseAPIServices([]byte(list))
	if err != nil || len(as) != 2 {
		t.Fatalf("got %+v, %v", as, err)
	}
	m := as[1]
	if m.Name != "v1beta1.metrics.k8s.io" || m.Service != "kube-system/metrics-server" || m.Available || m.Reason != "MissingEndpoints" || m.Since.IsZero() {
		t.Errorf("metrics = %+v", m)
	}
	if !as[0].Available || as[0].Service != "" {
		t.Errorf("apps = %+v", as[0])
	}
	one, err := ParseAPIServices([]byte(`{"kind":"APIService","metadata":{"name":"v1.x"},"spec":{}}`))
	if err != nil || len(one) != 1 || !one[0].Available {
		t.Errorf("single = %+v, %v", one, err)
	}
}

func TestMetricsForRules(t *testing.T) {
	var none *Metrics
	cases := []struct {
		m    *Metrics
		want bool
	}{
		{none, false},
		{&Metrics{Source: "prometheus", Have: map[string]bool{"node-exporter": true}}, true},
		{&Metrics{Source: "prometheus", Have: map[string]bool{}}, true},
		{&Metrics{Source: "kubelet and metrics API", Have: map[string]bool{}, Fallbacks: []string{"node CPU and memory from the metrics API"}}, false},
		{&Metrics{Source: "kubelet and metrics API", Have: map[string]bool{"kubelet-volumes": true}, Fallbacks: []string{"volume usage from the kubelets"}}, true},
	}
	for i, c := range cases {
		if got := c.m.ForRules(); got != c.want {
			t.Errorf("case %d: %v, want %v", i, got, c.want)
		}
	}
}

func TestTimeToFull(t *testing.T) {
	const gib = 1 << 30
	for _, c := range []struct {
		used, rate float64
		want       time.Duration
		ok         bool
	}{
		{9 * gib, gib / 2, 2 * time.Hour, true},
		{10 * gib, gib, 0, true},
		{2 * gib, 0, 0, false},
		{2 * gib, -gib, 0, false},
		{2 * gib, Missing, 0, false},
		// 8 GiB left at a few bytes an hour: never, not a wrapped-around
		// negative duration that reads as full now.
		{2 * gib, 3, 0, false},
		{2 * gib, 1000, 0, false},
		// Nine years ahead is still a forecast.
		{2 * gib, 8.0 * gib / (9 * 365 * 24), 9 * 365 * 24 * time.Hour, true},
	} {
		v := &VolumeMetrics{Used: c.used, Capacity: 10 * gib, Growth: &Growth{BytesPerHour: c.rate}}
		got, ok := v.TimeToFull()
		if ok != c.ok || (got-c.want).Abs() > time.Second {
			t.Errorf("used %.0f at %g B/h: %v %v, want %v %v", c.used, c.rate, got, ok, c.want, c.ok)
		}
	}
}
