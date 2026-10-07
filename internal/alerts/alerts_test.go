package alerts_test

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/alerts"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/snapshot"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func alertNames(f *findings.Finding) []string {
	var out []string
	for _, a := range f.Alerts {
		out = append(out, a.Name)
	}
	return out
}

func TestLink(t *testing.T) {
	s, err := snapshot.FromYAMLFile("test", "../rules/testdata/alerts.yaml", now)
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	byRule := map[string]*findings.Finding{}
	for _, f := range fs {
		byRule[f.RuleID+" "+f.Resource.String()] = f
	}
	for key, want := range map[string]string{
		// A pod's alert reaches the app's problems through the pod.
		"pod.crashloop shop/deployment/web":                            "KubePodCrashLooping",
		"deploy.unavailable shop/deployment/web":                       "KubePodCrashLooping",
		"pvc.fill-forecast shop/persistentvolumeclaim/data-postgres-0": "KubePersistentVolumeFillingUp",
		"pvc.usage shop/persistentvolumeclaim/data-postgres-0":         "KubePersistentVolumeFillingUp",
		// node-exporter's address, matched to worker-2.
		"vm.clock-skew node/worker-2": "NodeClockNotSynchronising",
	} {
		f := byRule[key]
		if f == nil {
			var got []string
			for k := range byRule {
				got = append(got, k)
			}
			t.Fatalf("no finding %s; got %v", key, got)
		}
		if names := alertNames(f); len(names) != 1 || names[0] != want {
			t.Errorf("%s: alerts %v, want %s", key, names, want)
		}
	}
	crash := byRule["pod.crashloop shop/deployment/web"].Alerts[0]
	if crash.About != (findings.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "web-6f7e8d9c0-q2w3e"}) || crash.Summary != "Pod is crash looping." ||
		crash.Since == nil || !crash.Since.Equal(now.Add(-15*time.Minute)) || crash.Runbook == "" || crash.ID == "" {
		t.Errorf("crash alert: %+v", crash)
	}
	for _, f := range fs {
		if f.IsHygiene() && len(f.Alerts) > 0 {
			t.Errorf("a suggestion has alerts: %s %v", f.RuleID, alertNames(f))
		}
	}

	// Linking again from scratch returns the alert no problem is about.
	for _, f := range fs {
		f.Alerts = nil
	}
	unmatched := alerts.Link(fs, s)
	if len(unmatched) != 1 || unmatched[0].Name != "CheckoutLatencyHigh" {
		t.Errorf("unmatched: %+v", unmatched)
	}
}

func TestObjects(t *testing.T) {
	s := snapshot.New(&snapshot.Snapshot{
		Pods: []*corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "node-exporter-7xk2p", Namespace: "monitoring"}, Spec: corev1.PodSpec{NodeName: "worker-1"}}},
		Nodes: []*corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.11"}}}}},
		ControlPlane: &snapshot.ControlPlane{Controllers: []*snapshot.Controller{{Name: "ctrl-1", Address: "10.0.0.1:6443"}}},
	})
	cases := []struct {
		labels map[string]string
		want   []findings.ObjectRef
	}{
		{map[string]string{"namespace": "shop", "statefulset": "db"}, []findings.ObjectRef{{Kind: "StatefulSet", Namespace: "shop", Name: "db"}}},
		{map[string]string{"namespace": "shop", "job_name": "migrate"}, []findings.ObjectRef{{Kind: "Job", Namespace: "shop", Name: "migrate"}}},
		// A pod's alert is about the pod, not the node it runs on.
		{map[string]string{"namespace": "shop", "pod": "lonely", "node": "worker-1"}, []findings.ObjectRef{{Kind: "Pod", Namespace: "shop", Name: "lonely"}}},
		{map[string]string{"node": "worker-1"}, []findings.ObjectRef{{Kind: "Node", Name: "worker-1"}}},
		{map[string]string{"node": "not-a-node"}, nil},
		{map[string]string{"instance": "10.0.0.11:9100"}, []findings.ObjectRef{{Kind: "Node", Name: "worker-1"}}},
		{map[string]string{"instance": "10.0.0.1:9100"}, []findings.ObjectRef{{Kind: "Controller", Name: "ctrl-1"}}},
		{map[string]string{"namespace": "shop", "service": "checkout"}, []findings.ObjectRef{{Kind: "Service", Namespace: "shop", Name: "checkout"}}},
		// node-exporter's own pod is not what its alerts are about: its host is.
		{map[string]string{"namespace": "monitoring", "pod": "node-exporter-7xk2p", "container": "node-exporter", "device": "sdc"}, []findings.ObjectRef{{Kind: "Node", Name: "worker-1"}}},
		{map[string]string{"namespace": "monitoring", "pod": "vm-prometheus-node-exporter-x", "job": "node-exporter", "instance": "10.0.0.11:9100"}, []findings.ObjectRef{{Kind: "Node", Name: "worker-1"}}},
		{map[string]string{"namespace": "monitoring", "pod": "gone", "container": "node-exporter"}, nil},
		{map[string]string{"namespace": "shop"}, []findings.ObjectRef{{Kind: "Namespace", Name: "shop"}}},
		{map[string]string{"job": "something"}, nil},
	}
	for _, c := range cases {
		got := alerts.Objects(snapshot.Alert{Name: "A", Labels: c.labels}, s)
		if len(got) != len(c.want) {
			t.Errorf("%v: got %v, want %v", c.labels, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%v: got %v, want %v", c.labels, got, c.want)
			}
		}
	}
}

func TestTopicOf(t *testing.T) {
	for name, want := range map[string]string{
		"HighIOUtilization": alerts.TopicDisk, "NodeFilesystemAlmostOutOfSpace": alerts.TopicDisk, "NodeDiskIOSaturation": alerts.TopicDisk,
		"NodeClockNotSynchronising": alerts.TopicClock, "NodeMemoryHighUtilization": alerts.TopicMemory, "HostOomKillDetected": alerts.TopicMemory,
		"NodeCPUHighUsage": alerts.TopicCPU, "NodeNetworkReceiveErrs": alerts.TopicNetwork, "KubeNodeNotReady": alerts.TopicDown,
		"KubeletDown": alerts.TopicDown, "NodeSystemdServiceFailed": alerts.TopicDown, "SomethingElse": "",
	} {
		if got := alerts.TopicOf(snapshot.Alert{Name: name}); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	// A device label says disk, unless it is a network interface.
	if got := alerts.TopicOf(snapshot.Alert{Name: "HighUtilization", Labels: map[string]string{"device": "sdc"}}); got != alerts.TopicDisk {
		t.Errorf("device sdc: %q", got)
	}
	if got := alerts.TopicOf(snapshot.Alert{Name: "HighUtilization", Labels: map[string]string{"device": "eth0"}}); got == alerts.TopicDisk {
		t.Error("eth0 is a disk")
	}
}

// A server's alert joins only the problems about the same thing: a disk
// alert on worker-2 isn't about its clock.
func TestServerAlertsByTopic(t *testing.T) {
	s, err := snapshot.FromYAMLFile("test", "../rules/testdata/alerts.yaml", now)
	if err != nil {
		t.Fatal(err)
	}
	s.Metrics.Alerts = append(s.Metrics.Alerts, snapshot.Alert{Name: "HighIOUtilization", Severity: "critical",
		Labels: map[string]string{"container": "node-exporter", "namespace": "monitoring", "pod": "node-exporter-7xk2p", "instance": "10.0.0.12:9100", "device": "sdc"}})
	fs, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	for _, f := range fs {
		if f.RuleID == "vm.clock-skew" {
			if names := alertNames(f); len(names) != 1 || names[0] != "NodeClockNotSynchronising" {
				t.Errorf("clock problem's alerts: %v", names)
			}
		}
	}
}
