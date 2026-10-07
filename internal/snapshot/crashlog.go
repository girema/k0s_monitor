package snapshot

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"k0s_monitor/internal/remedy"
)

// CrashLog is what the log of a container's last crash says. k0s-monitor
// reads it once per restart of a container that keeps crashing.
type CrashLog struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	// RestartCount identifies the crashed run whose log this is, by the
	// restart count the container had during that run.
	RestartCount int32 `json:"restartCount"`
	// Matches are the known errors found in it, most specific first.
	Matches []remedy.Match `json:"matches,omitempty"`
	// Lines are its last lines that look like errors, secrets masked.
	Lines []string `json:"lines,omitempty"`
	// Error says why the log couldn't be read; the rest is then empty.
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

// crashLogLines is how many error lines a crash log keeps.
const crashLogLines = 5

// NewCrashLog reads what a crash log says.
func NewCrashLog(ns, pod, container string, restarts int32, log string, at time.Time) *CrashLog {
	return &CrashLog{Namespace: ns, Pod: pod, Container: container, RestartCount: restarts, At: at,
		Matches: remedy.Find(log), Lines: remedy.ErrorLines(log, crashLogLines)}
}

// CrashLogKey is how crash logs are keyed: "namespace/pod/container".
func CrashLogKey(ns, pod, container string) string { return ns + "/" + pod + "/" + container }

// CrashLog returns what the log of the container's last crash says, or nil
// when it wasn't read.
func (s *Snapshot) CrashLog(ns, pod, container string) *CrashLog {
	return s.CrashLogs[CrashLogKey(ns, pod, container)]
}

// crashLogsDoc is a fixture document with the logs of the last crashes:
//
//	apiVersion: k0s-monitor.io/v1
//	kind: CrashLogs
//	logs:
//	- pod: shop/api-7d9f-abc12
//	  container: api
//	  log: |
//	    dial tcp 10.96.14.2:5432: connect: connection refused
type crashLogsDoc struct {
	Logs []struct {
		Pod       string `json:"pod"`
		Container string `json:"container"`
		Log       string `json:"log"`
		Error     string `json:"error"`
	} `json:"logs"`
}

func parseCrashLogsDoc(js []byte, now time.Time, s *Snapshot) error {
	var doc crashLogsDoc
	if err := json.Unmarshal(js, &doc); err != nil {
		return err
	}
	if s.CrashLogs == nil {
		s.CrashLogs = map[string]*CrashLog{}
	}
	for _, l := range doc.Logs {
		ns, pod, ok := strings.Cut(l.Pod, "/")
		if !ok || l.Container == "" {
			return fmt.Errorf("pod %q: want namespace/name and a container", l.Pod)
		}
		cl := NewCrashLog(ns, pod, l.Container, 0, l.Log, now)
		cl.Error = l.Error
		s.CrashLogs[CrashLogKey(ns, pod, l.Container)] = cl
	}
	return nil
}
