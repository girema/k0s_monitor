package crashlog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k0s_monitor/internal/podview"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func pod(name string, cs ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: cs}}
}

func looping(name string, restarts int32, code int32) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, RestartCount: restarts,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode: code, FinishedAt: metav1.NewTime(now.Add(-time.Minute))}}}
}

// fakeLogs answers reads from a map and counts them. Keys of previous runs
// end in "#previous".
type fakeLogs struct {
	mu    sync.Mutex
	logs  map[string]string
	errs  map[string]error
	reads []string
}

func (f *fakeLogs) read(_ context.Context, ns, pod string, o podview.LogOptions) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o.Tail != tail {
		return "", errors.New("wrong options")
	}
	k := ns + "/" + pod + "/" + o.Container
	if o.Previous {
		k += "#previous"
	}
	f.reads = append(f.reads, k)
	return f.logs[k], f.errs[k]
}

func source(f *fakeLogs, clock *time.Time) *Source {
	s := NewSource(nil, func() time.Time { return *clock })
	s.read = f.read
	return s
}

func TestUpdateReadsOncePerRestart(t *testing.T) {
	clock := now
	f := &fakeLogs{logs: map[string]string{
		"shop/api-1/api": "starting\ndial tcp 10.96.14.2:5432: connect: connection refused\nexit",
	}}
	s := source(f, &clock)
	running := corev1.ContainerStatus{Name: "web", RestartCount: 0, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	oom := looping("worker", 4, 137)
	oom.LastTerminationState.Terminated.Reason = "OOMKilled"
	pods := []*corev1.Pod{pod("api-1", looping("api", 3, 1), running, oom)}

	if !s.Update(context.Background(), pods) {
		t.Fatal("nothing read")
	}
	cl := s.Latest()["shop/api-1/api"]
	if cl == nil || len(cl.Matches) != 1 || cl.Matches[0].ID != "conn-refused" || cl.RestartCount != 3 || len(cl.Lines) != 1 {
		t.Fatalf("crash log = %+v", cl)
	}
	if len(f.reads) != 1 {
		t.Errorf("reads = %v, want only the crashing api container", f.reads)
	}
	// The same crash isn't read again; the next one is.
	if s.Update(context.Background(), pods) || len(f.reads) != 1 {
		t.Errorf("read again: %v", f.reads)
	}
	pods[0].Status.ContainerStatuses[0].RestartCount = 4
	if !s.Update(context.Background(), pods) || len(f.reads) != 2 {
		t.Errorf("next crash not read: %v", f.reads)
	}
	// A container that recovered is forgotten.
	pods[0].Status.ContainerStatuses[0] = running
	pods[0].Status.ContainerStatuses[0].Name = "api"
	s.Update(context.Background(), pods)
	if len(s.Latest()) != 0 {
		t.Errorf("recovered container kept: %v", s.Latest())
	}
}

func TestUpdateRecentCrashOfARunningContainer(t *testing.T) {
	clock := now
	f := &fakeLogs{logs: map[string]string{}}
	s := source(f, &clock)
	c := looping("api", 1, 2)
	c.State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	old := looping("api", 1, 2)
	old.State = c.State
	old.LastTerminationState.Terminated.FinishedAt = metav1.NewTime(now.Add(-2 * time.Hour))
	clean := looping("api", 1, 0)
	clean.State = c.State
	s.Update(context.Background(), []*corev1.Pod{pod("a", c), pod("b", old), pod("c", clean)})
	// It runs again: the crash is its previous run.
	if len(f.reads) != 1 || f.reads[0] != "shop/a/api#previous" {
		t.Errorf("reads = %v, want only the recent failure's previous run", f.reads)
	}
}

func TestUpdateFollowsOneCrashThroughItsStates(t *testing.T) {
	clock := now
	f := &fakeLogs{}
	s := source(f, &clock)
	c := looping("api", 3, 1)
	stopped := corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, FinishedAt: metav1.NewTime(now)}}
	// Run 3 stops, waits in back-off, and run 4 starts: one crash, read once.
	for _, st := range []struct {
		state    corev1.ContainerState
		restarts int32
	}{{stopped, 3}, {c.State, 3}, {corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}, 4}} {
		c.State, c.RestartCount = st.state, st.restarts
		s.Update(context.Background(), []*corev1.Pod{pod("a", c)})
	}
	if len(f.reads) != 1 {
		t.Errorf("reads = %v, want one", f.reads)
	}
	// Run 4 stops too: a new crash.
	c.State, c.RestartCount = stopped, 4
	s.Update(context.Background(), []*corev1.Pod{pod("a", c)})
	if len(f.reads) != 2 || s.Latest()["shop/a/api"].RestartCount != 4 {
		t.Errorf("reads = %v, log = %+v", f.reads, s.Latest()["shop/a/api"])
	}
}

func TestUpdateContainerThatJustStopped(t *testing.T) {
	clock := now
	f := &fakeLogs{logs: map[string]string{"shop/a/api": "open /etc/app/config.yaml: no such file or directory"}}
	s := source(f, &clock)
	// Stopped a moment ago, before the back-off: its current run is the
	// crash; the run before it is usually gone.
	c := looping("api", 5, 1)
	c.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error", FinishedAt: metav1.NewTime(now)}}
	s.Update(context.Background(), []*corev1.Pod{pod("a", c)})
	cl := s.Latest()["shop/a/api"]
	if len(f.reads) != 1 || f.reads[0] != "shop/a/api" || cl == nil || len(cl.Matches) != 1 || cl.Matches[0].ID != "no-such-file" {
		t.Errorf("reads = %v, log = %+v", f.reads, cl)
	}
	// Stopped for memory: nothing to read.
	c.State.Terminated.Reason = "OOMKilled"
	s.Update(context.Background(), []*corev1.Pod{pod("b", c)})
	if len(f.reads) != 1 {
		t.Errorf("read an OOMKilled container: %v", f.reads)
	}
}

func TestUpdateErrors(t *testing.T) {
	clock := now
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods/log"}, "api-1", errors.New("no"))
	f := &fakeLogs{errs: map[string]error{
		"shop/api-1/api": podview.ErrLogGone,
		"shop/api-2/api": forbidden,
	}}
	s := source(f, &clock)
	pods := []*corev1.Pod{pod("api-1", looping("api", 3, 1)), pod("api-2", looping("api", 3, 1))}
	s.Update(context.Background(), pods)
	got := s.Latest()
	if got["shop/api-1/api"].Error != "the log of the last crash is gone" || got["shop/api-2/api"].Error != "k0s-monitor may not read logs" {
		t.Fatalf("errors = %+v %+v", got["shop/api-1/api"], got["shop/api-2/api"])
	}
	// Reading pauses after a refusal, and failed reads are tried again
	// later.
	clock = now.Add(6 * time.Minute)
	s.Update(context.Background(), pods)
	if len(f.reads) != 2 {
		t.Errorf("read while paused: %v", f.reads)
	}
	clock = now.Add(11 * time.Minute)
	s.Update(context.Background(), pods)
	if len(f.reads) != 4 {
		t.Errorf("not tried again: %v", f.reads)
	}
}

func TestUpdateBudget(t *testing.T) {
	clock := now
	f := &fakeLogs{}
	s := source(f, &clock)
	var pods []*corev1.Pod
	for i := range 25 {
		pods = append(pods, pod(string(rune('a'+i)), looping("api", 3, 1)))
	}
	s.Update(context.Background(), pods)
	if len(f.reads) != perRound {
		t.Errorf("reads = %d, want %d", len(f.reads), perRound)
	}
	s.Update(context.Background(), pods)
	s.Update(context.Background(), pods)
	if len(f.reads) != 25 || len(s.Latest()) != 25 {
		t.Errorf("reads = %d, logs = %d", len(f.reads), len(s.Latest()))
	}
}
