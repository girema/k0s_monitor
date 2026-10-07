package rules

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

func TestParseSchedulerMessage(t *testing.T) {
	got := parseSchedulerMessage("0/5 nodes are available: 3 Insufficient memory, 1 node(s) had untolerated taint {dedicated: gpu}, 1 node(s) were unschedulable. preemption: 0/5 nodes are available: 5 No preemption victims found for incoming pod.")
	want := []schedReason{
		{3, "Insufficient memory"},
		{1, "node(s) had untolerated taint {dedicated: gpu}"},
		{1, "node(s) were unschedulable"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("part %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if m := mainSchedulingReason(got); m.kind != "resources" || m.short != "not enough free memory on any node" {
		t.Errorf("main reason = %+v", m)
	}
}

// Kubernetes 1.36 (seen on k0s v1.36.4) adds a DRA note before preemption.
func TestParseSchedulerMessageWithClaimsNote(t *testing.T) {
	got := parseSchedulerMessage("0/1 nodes are available: 1 Insufficient cpu. no new claims to deallocate, preemption: 0/1 nodes are available: 1 No preemption victims found for incoming pod.")
	if len(got) != 1 || got[0] != (schedReason{1, "Insufficient cpu"}) {
		t.Fatalf("got %+v", got)
	}
	if m := mainSchedulingReason(got); m.short != "not enough free cpu on any node" {
		t.Errorf("short = %q", m.short)
	}
}

func TestMainSchedulingReasonKinds(t *testing.T) {
	cases := map[string]string{
		"0/1 nodes are available: 1 node(s) had untolerated taint {node.kubernetes.io/not-ready: }.": "taints",
		"0/2 nodes are available: 2 node(s) didn't match Pod's node affinity/selector.":              "placement",
		"0/1 nodes are available: 1 Too many pods.":                                                  "pods",
		"0/1 nodes are available: 1 node(s) had volume node affinity conflict.":                      "storage",
		"0/3 nodes are available: 3 node(s) were unschedulable.":                                     "cordoned",
		"something unexpected": "other",
	}
	for msg, kind := range cases {
		if got := mainSchedulingReason(parseSchedulerMessage(msg)).kind; got != kind {
			t.Errorf("%q: kind = %s, want %s", msg, got, kind)
		}
	}
}

func TestClassifyPullError(t *testing.T) {
	cases := []struct{ reason, msg, short string }{
		{"ErrImagePull", `failed to pull and unpack image "docker.io/library/busybox:nope": failed to resolve reference "docker.io/library/busybox:nope": docker.io/library/busybox:nope: not found`, "the image or tag does not exist"},
		{"ErrImagePull", `pull access denied, repository does not exist or may require authorization: server message: insufficient_scope`, "the repository does not exist or needs credentials"},
		{"ErrImagePull", `failed to authorize: failed to fetch anonymous token: unexpected status: 401 Unauthorized`, "the registry refused access"},
		{"ErrImagePull", `429 Too Many Requests - Server message: toomanyrequests: You have reached your pull rate limit.`, "the registry's rate limit was reached"},
		{"ErrImagePull", `tls: failed to verify certificate: x509: certificate signed by unknown authority`, "the registry's certificate is not trusted"},
		{"ErrImagePull", `dial tcp: lookup registry.local on 10.0.0.2:53: no such host`, "the registry's name cannot be resolved"},
		{"ErrImagePull", `dial tcp 10.1.2.3:443: i/o timeout`, "the registry cannot be reached"},
		{"InvalidImageName", `Failed to apply default image tag "Bad Name": couldn't parse image name`, "the image name is invalid"},
	}
	for _, c := range cases {
		if got := classifyPullError(c.reason, c.msg).short; got != c.short {
			t.Errorf("%q: got %q, want %q", c.msg, got, c.short)
		}
	}
}

func TestRegistryOf(t *testing.T) {
	cases := map[string]string{
		"busybox:1.36":                       "docker.io",
		"library/nginx":                      "docker.io",
		"quay.io/k0sproject/pause:3.10":      "quay.io",
		"registry.local:5000/team/app:1":     "registry.local:5000",
		"localhost/app":                      "localhost",
		"registry.local/payments-api:1.14.0": "registry.local",
	}
	for image, want := range cases {
		if got := registryOf(image); got != want {
			t.Errorf("registryOf(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestSuggestMemory(t *testing.T) {
	cases := map[string]string{"512Mi": "768Mi", "100Mi": "192Mi", "1Gi": "1536Mi", "64Mi": "128Mi"}
	for in, want := range cases {
		if got := suggestMemory(resource.MustParse(in)); got != want {
			t.Errorf("suggestMemory(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestExitCodeMeaning(t *testing.T) {
	if got := exitCodeMeaning(137, "Error"); got != "it was killed (out of memory, or a failed liveness probe)" {
		t.Errorf("137: %q", got)
	}
	if got := exitCodeMeaning(1, "OOMKilled"); got != "it used more memory than it is allowed to" {
		t.Errorf("OOMKilled reason wins: %q", got)
	}
}

func TestCronParserTimeZone(t *testing.T) {
	s, err := cronParser.Parse("CRON_TZ=Europe/Berlin 0 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	next := s.Next(time.Date(2026, 9, 27, 0, 30, 0, 0, time.UTC))
	if want := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC); !next.Equal(want) {
		t.Errorf("next = %s, want %s (02:00 in Berlin, summer time)", next.UTC(), want)
	}
	if _, err := cronParser.Parse("@hourly"); err != nil {
		t.Errorf("descriptors: %v", err)
	}
}

func TestProbeMessage(t *testing.T) {
	cases := map[string]string{
		"Readiness probe failed: ":                                      "Readiness probe failed",
		"Liveness probe failed: HTTP probe failed with statuscode: 500": "Liveness probe failed: HTTP probe failed with statuscode: 500",
	}
	for in, want := range cases {
		if got := probeMessage(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
