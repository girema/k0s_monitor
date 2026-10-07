package podview

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func pod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "shop", UID: "u1",
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
			Annotations:   map[string]string{corev1.LastAppliedConfigAnnotation: `{"secret":"stuff"}`}},
		Spec: corev1.PodSpec{NodeName: "worker-1", Containers: []corev1.Container{{Name: "api", Image: "shop/api:1",
			Env: []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: "hunter2"},
				{Name: "API_TOKEN", Value: "abc123"},
				{Name: "DATABASE_URL", Value: "postgres://shop:s3cret@db:5432/shop"},
				{Name: "LOG_LEVEL", Value: "debug"},
				{Name: "FROM_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "password"}}},
			}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestMasking(t *testing.T) {
	for name, want := range map[string]string{"DB_PASSWORD": Mask, "api_key": Mask, "LOG_LEVEL": "x", "HOST": "x"} {
		if got := MaskValue(name, "x"); got != want {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := MaskValue("DATABASE_URL", "postgres://shop:s3cret@db:5432/shop"); got != "postgres://shop:"+Mask+"@db:5432/shop" {
		t.Errorf("url: %q", got)
	}
}

func TestYAML(t *testing.T) {
	out, err := PodYAML(pod())
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"hunter2", "abc123", "s3cret", "managedFields", "last-applied"} {
		if strings.Contains(out, leak) {
			t.Errorf("YAML leaks %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "LOG_LEVEL") || !strings.Contains(out, "value: debug") || !strings.Contains(out, "kind: Pod") {
		t.Errorf("YAML:\n%s", out)
	}
}

func TestDescribeAndEvents(t *testing.T) {
	ev := &corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "shop"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "api-1", Namespace: "shop"},
		Type:           "Warning", Reason: "BackOff", Message: "Back-off restarting failed container", Count: 7,
		Source: corev1.EventSource{Component: "kubelet", Host: "worker-1"}}
	other := &corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "e2", Namespace: "shop"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "other", Namespace: "shop"}, Reason: "Pulled"}
	cs := fake.NewClientset(pod(), ev, other)
	out, err := Describe(cs, "shop", "api-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Name:") || !strings.Contains(out, "api-1") || !strings.Contains(out, "LOG_LEVEL:") {
		t.Errorf("describe:\n%s", out)
	}
	for _, leak := range []string{"hunter2", "abc123", "s3cret"} {
		if strings.Contains(out, leak) {
			t.Errorf("describe leaks %q", leak)
		}
	}
	if !strings.Contains(out, "<set to the key 'password' in secret 'db'>") {
		t.Errorf("secret references stay visible:\n%s", out)
	}
	evs, err := Events(context.Background(), cs, "shop", "api-1")
	if err != nil || len(evs) != 1 || evs[0].Reason != "BackOff" || evs[0].Count != 7 || evs[0].Source != "kubelet, worker-1" {
		t.Errorf("events = %+v %v", evs, err)
	}
}

func TestLogs(t *testing.T) {
	cs := fake.NewClientset(pod())
	out, err := ReadLog(context.Background(), cs, "shop", "api-1", LogOptions{Container: "api"})
	if err != nil || out == "" {
		t.Errorf("logs = %q %v", out, err)
	}
}

func TestImportantLines(t *testing.T) {
	log := "starting\nlistening on :8080\nERROR dial tcp: lookup postgres: no such host\nretrying\nFATAL cannot start without database\n"
	got := ImportantLines(log, 10)
	if len(got) != 2 || !strings.HasPrefix(got[0], "ERROR") || !strings.HasPrefix(got[1], "FATAL") {
		t.Errorf("lines = %q", got)
	}
	if got := ImportantLines(log, 1); len(got) != 1 || !strings.HasPrefix(got[0], "FATAL") {
		t.Errorf("the newest are kept: %q", got)
	}
}

func TestMaskDescribe(t *testing.T) {
	in := `Containers:
  api:
    Environment:
      DB_PASSWORD:   hunter2
      DATABASE_URL:  postgres://u:pw@db/x
      FROM_SECRET:   <set to the key 'password' in secret 'db'>  Optional: false
    Mounts:
      /data from data (rw)
Annotations: secret-token: value
`
	out := MaskDescribe(in)
	if strings.Contains(out, "hunter2") || strings.Contains(out, ":pw@") {
		t.Errorf("masked:\n%s", out)
	}
	if !strings.Contains(out, "Annotations: secret-token: value") || !strings.Contains(out, "/data from data") {
		t.Errorf("only environment values are masked:\n%s", out)
	}
}

func TestLogGone(t *testing.T) {
	if !logGone([]byte("unable to retrieve container logs for containerd://5380af86b5a9\n")) {
		t.Errorf("the kubelet's answer for a removed container is not a log")
	}
	if logGone([]byte("unable to retrieve container logs for x\nand a real second line\n")) {
		t.Errorf("a real log that happens to start like that is still a log")
	}
	if logGone([]byte("FATAL cannot reach database\n")) {
		t.Errorf("an ordinary log")
	}
}
