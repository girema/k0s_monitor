// Package podview gathers what the pod page shows (plan section 11.4):
// real `kubectl describe` output, events, logs and YAML. Values of
// environment variables whose names look secret, and passwords in URLs,
// are masked everywhere (plan section 13).
package podview

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubectl/pkg/describe"
	"sigs.k8s.io/yaml"

	"k0s_monitor/internal/remedy"
)

// Mask replaces a hidden value.
const Mask = remedy.Mask

// MaskValue hides a value if its name looks secret, and passwords in URLs.
func MaskValue(name, value string) string { return remedy.MaskValue(name, value) }

// Describe returns `kubectl describe pod` output, with secret-looking
// environment values masked.
func Describe(cs kubernetes.Interface, ns, name string) (string, error) {
	d := describe.PodDescriber{Interface: cs}
	out, err := d.Describe(ns, name, describe.DescriberSettings{ShowEvents: true, ChunkSize: 500})
	if err != nil {
		return "", err
	}
	return MaskDescribe(out), nil
}

var envLine = regexp.MustCompile(`^(\s+)([A-Za-z_][A-Za-z0-9_.-]*):(\s+)(.*)$`)

// MaskDescribe masks environment values in describe output. Values that
// come from Secrets or ConfigMaps are shown by reference only already.
func MaskDescribe(out string) string {
	var b strings.Builder
	inEnv := false
	envIndent := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		switch {
		case strings.HasPrefix(trimmed, "Environment:"):
			inEnv, envIndent = true, indent
		case inEnv && (indent <= envIndent || trimmed == ""):
			inEnv = false
		case inEnv:
			if m := envLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(m[4], "<set to the key") && !strings.HasPrefix(m[4], "(v1:") {
				line = m[1] + m[2] + ":" + m[3] + MaskValue(m[2], m[4])
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// Event is one event about the pod.
type Event struct {
	Type    string    `json:"type"`
	Reason  string    `json:"reason"`
	Message string    `json:"message"`
	Count   int32     `json:"count"`
	Source  string    `json:"source,omitempty"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// Events lists the pod's events, newest first.
func Events(ctx context.Context, cs kubernetes.Interface, ns, name string) ([]Event, error) {
	sel := fields.Set{"involvedObject.name": name, "involvedObject.namespace": ns, "involvedObject.kind": "Pod"}.AsSelector().String()
	list, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{FieldSelector: sel})
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, e := range list.Items {
		if e.InvolvedObject.Name != name || (e.InvolvedObject.Kind != "" && e.InvolvedObject.Kind != "Pod") {
			continue // fake clients ignore the field selector
		}
		ev := Event{Type: e.Type, Reason: e.Reason, Message: e.Message, Count: max(e.Count, 1),
			First: e.FirstTimestamp.Time, Last: e.LastTimestamp.Time}
		if ev.Last.IsZero() {
			ev.Last = e.EventTime.Time
		}
		if ev.Last.IsZero() {
			ev.Last = e.CreationTimestamp.Time
		}
		if ev.First.IsZero() {
			ev.First = ev.Last
		}
		if e.Source.Component != "" {
			ev.Source = e.Source.Component
			if e.Source.Host != "" {
				ev.Source += ", " + e.Source.Host
			}
		} else if e.ReportingController != "" {
			ev.Source = e.ReportingController
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out, nil
}

// YAML returns the pod as YAML without managed fields, with secret-looking
// environment values masked.
func YAML(ctx context.Context, cs kubernetes.Interface, ns, name string) (string, error) {
	p, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return PodYAML(p)
}

// PodYAML renders a pod for display.
func PodYAML(p *corev1.Pod) (string, error) {
	p = Sanitize(p)
	p.APIVersion, p.Kind = "v1", "Pod"
	out, err := yaml.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Sanitize returns a copy of the pod without managed fields and with
// secret-looking environment values masked.
func Sanitize(p *corev1.Pod) *corev1.Pod {
	p = p.DeepCopy()
	p.ManagedFields = nil
	if p.Annotations != nil {
		delete(p.Annotations, corev1.LastAppliedConfigAnnotation)
	}
	mask := func(cs []corev1.Container) {
		for i := range cs {
			for j := range cs[i].Env {
				e := &cs[i].Env[j]
				e.Value = MaskValue(e.Name, e.Value)
			}
		}
	}
	mask(p.Spec.InitContainers)
	mask(p.Spec.Containers)
	for i := range p.Spec.EphemeralContainers {
		for j := range p.Spec.EphemeralContainers[i].Env {
			e := &p.Spec.EphemeralContainers[i].Env[j]
			e.Value = MaskValue(e.Name, e.Value)
		}
	}
	return p
}

// LogOptions select which log to read.
type LogOptions struct {
	Container string
	Previous  bool
	Tail      int64
	Follow    bool
}

// Log limits.
const (
	DefaultTail = 500
	MaxTail     = 10000
	MaxBytes    = 4 << 20
)

// Logs opens a container log.
func Logs(ctx context.Context, cs kubernetes.Interface, ns, name string, o LogOptions) (io.ReadCloser, error) {
	if o.Tail <= 0 {
		o.Tail = DefaultTail
	}
	o.Tail = min(o.Tail, MaxTail)
	limit := int64(MaxBytes)
	opts := &corev1.PodLogOptions{Container: o.Container, Previous: o.Previous, TailLines: &o.Tail, Follow: o.Follow}
	if !o.Follow {
		opts.LimitBytes = &limit
	}
	return cs.CoreV1().Pods(ns).GetLogs(name, opts).Stream(ctx)
}

var important = remedy.ErrorLine

// ImportantLines returns up to n lines that look like errors, in the order
// they appeared, keeping the newest.
func ImportantLines(log string, n int) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" || !important.MatchString(l) {
			continue
		}
		if len(l) > 400 {
			l = l[:400] + "…"
		}
		out = append(out, l)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// ErrLogGone means the container runtime on the node no longer has that
// run of the container, so its log is gone. The kubelet reports this as a
// successful response whose body is an error message.
var ErrLogGone = errors.New("the container runtime no longer has this run of the container, so its log is gone")

// ReadLog reads a whole (limited) log into a string.
func ReadLog(ctx context.Context, cs kubernetes.Interface, ns, name string, o LogOptions) (string, error) {
	rc, err := Logs(ctx, cs, ns, name, o)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, MaxBytes))
	if err != nil {
		return string(b), fmt.Errorf("reading the log: %w", err)
	}
	if logGone(b) {
		return "", ErrLogGone
	}
	return string(b), nil
}

// logGone recognizes the kubelet's "unable to retrieve container logs for
// containerd://..." answer.
func logGone(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return len(t) < 300 && !strings.Contains(t, "\n") && strings.HasPrefix(t, "unable to retrieve container logs for ")
}
