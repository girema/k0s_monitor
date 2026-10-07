// Package crashlog reads the log of the last crash of containers that keep
// crashing, once per restart, so the rules can say what the error was.
package crashlog

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"

	"k0s_monitor/internal/podview"
	"k0s_monitor/internal/snapshot"
)

const (
	// perRound bounds the logs read in one round; the rest wait for the
	// next.
	perRound = 10
	// parallel is how many logs are read at once.
	parallel = 4
	// tail is how many lines of each log are read.
	tail = 200
	// readTimeout bounds reading one log.
	readTimeout = 8 * time.Second
	// retryAfter is when a log that couldn't be read is tried again.
	retryAfter = 5 * time.Minute
	// forbiddenPause is how long reading stops when the account may not
	// read logs.
	forbiddenPause = 10 * time.Minute
	// window is how recent a crash must be for a container that runs again.
	window = time.Hour
)

// Source keeps the crash logs of a cluster's crashing containers.
type Source struct {
	now  func() time.Time
	read func(ctx context.Context, ns, pod string, o podview.LogOptions) (string, error)

	mu          sync.Mutex
	logs        map[string]*snapshot.CrashLog
	pausedUntil time.Time
}

// NewSource reads logs through cs.
func NewSource(cs kubernetes.Interface, now func() time.Time) *Source {
	if now == nil {
		now = time.Now
	}
	s := &Source{now: now, logs: map[string]*snapshot.CrashLog{}}
	if cs != nil {
		s.read = func(ctx context.Context, ns, pod string, o podview.LogOptions) (string, error) {
			return podview.ReadLog(ctx, cs, ns, pod, o)
		}
	}
	return s
}

// Latest returns the crash logs read so far, by snapshot.CrashLogKey. Do not
// modify them.
func (s *Source) Latest() map[string]*snapshot.CrashLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*snapshot.CrashLog, len(s.logs))
	for k, v := range s.logs {
		out[k] = v
	}
	return out
}

// crash is a container whose last crash is to be read.
type crash struct {
	ns, pod, container string
	// restarts is the restart count of the crashed run.
	restarts int32
	looping  bool
	// previous is true while the container runs again: its last crash is
	// then the previous run. Otherwise the kubelet serves the latest
	// crashed run as the current log, and "previous" is the run before
	// it, which is usually cleaned up already.
	previous bool
}

func (c crash) key() string { return snapshot.CrashLogKey(c.ns, c.pod, c.container) }

// crashes lists the containers whose last run ended in a crash: those
// waiting in CrashLoopBackOff, and those that failed within the last hour
// and were restarted, whether they run again or just stopped. A container
// the kernel killed for memory is left out: its log just stops.
func crashes(pods []*corev1.Pod, now time.Time) []crash {
	var out []crash
	for _, p := range pods {
		if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			t := cs.LastTerminationState.Terminated
			if cs.State.Terminated != nil {
				t = cs.State.Terminated // it just stopped
			}
			if cs.RestartCount == 0 || t == nil || t.Reason == "OOMKilled" {
				continue
			}
			looping := cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff"
			if !looping && (t.ExitCode == 0 || now.Sub(t.FinishedAt.Time) > window) {
				continue
			}
			// The crashed run is known by its restart count: the current
			// one's, or the one before while the container runs again.
			running := cs.State.Running != nil
			run := cs.RestartCount
			if running {
				run--
			}
			out = append(out, crash{ns: p.Namespace, pod: p.Name, container: cs.Name, restarts: run,
				looping: looping, previous: running})
		}
	}
	// Containers in CrashLoopBackOff first; then by name, so each round
	// reads the same ones.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].looping != out[j].looping {
			return out[i].looping
		}
		return out[i].key() < out[j].key()
	})
	return out
}

// Update reads the logs of new crashes. It returns true when something new
// was read.
func (s *Source) Update(ctx context.Context, pods []*corev1.Pod) bool {
	now := s.now()
	found := crashes(pods, now)

	s.mu.Lock()
	// Containers that no longer crash are forgotten.
	current := map[string]bool{}
	for _, c := range found {
		current[c.key()] = true
	}
	for k := range s.logs {
		if !current[k] {
			delete(s.logs, k)
		}
	}
	var todo []crash
	for _, c := range found {
		old := s.logs[c.key()]
		if old != nil && old.RestartCount == c.restarts && (old.Error == "" || now.Sub(old.At) < retryAfter) {
			continue
		}
		todo = append(todo, c)
	}
	paused := now.Before(s.pausedUntil)
	s.mu.Unlock()
	if paused || len(todo) == 0 || s.read == nil {
		return false
	}
	if len(todo) > perRound {
		todo = todo[:perRound]
	}

	results := make([]*snapshot.CrashLog, len(todo))
	forbidden := false
	var wg sync.WaitGroup
	var fmu sync.Mutex
	sem := make(chan struct{}, parallel)
	for i, c := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, readTimeout)
			log, err := s.read(rctx, c.ns, c.pod, podview.LogOptions{Container: c.container, Previous: c.previous, Tail: tail})
			cancel()
			cl := snapshot.NewCrashLog(c.ns, c.pod, c.container, c.restarts, log, now)
			switch {
			case err == nil:
			case errors.Is(err, podview.ErrLogGone):
				cl.Error = "the log of the last crash is gone"
			case apierrors.IsForbidden(err):
				cl.Error = "k0s-monitor may not read logs"
				fmu.Lock()
				forbidden = true
				fmu.Unlock()
			case apierrors.IsNotFound(err):
				return // the pod is gone
			default:
				if ctx.Err() != nil {
					return
				}
				cl.Error = "the log couldn't be read: " + err.Error()
			}
			results[i] = cl
		}()
	}
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	if forbidden {
		s.pausedUntil = now.Add(forbiddenPause)
	}
	changed := false
	for _, cl := range results {
		if cl != nil {
			s.logs[snapshot.CrashLogKey(cl.Namespace, cl.Pod, cl.Container)] = cl
			changed = true
		}
	}
	return changed
}
