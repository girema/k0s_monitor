package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/podview"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
)

type containerView struct {
	Name     string
	Image    string
	Init     bool
	Ready    bool
	Restarts int32
	State    string
	Detail   string
	Icon     string
	LastExit string
	// ExitMeans and ExitPlain explain the last exit code.
	ExitMeans, ExitPlain string
	// Crash lists the known errors in the log of the last crash.
	Crash []remedy.Match
}

type podData struct {
	Cluster    string
	Pod        *corev1.Pod
	Workload   findings.ObjectRef
	Findings   []*findings.Finding
	Main       *findings.Finding
	Containers []containerView
	Age        string
	Important  []string
	Matches    []remedy.Match
	LogSource  string
	LogError   string
	Live       bool
	Stale      string
	// Secrets are the Secrets the pod uses, and how.
	Secrets []podSecret
}

// podSecret is a Secret a pod uses; Link opens it when the cluster's
// Secrets can be read.
type podSecret struct {
	Name, Link string
	How        []string
}

// podSecretsOf lists the Secrets a pod uses, in the order it names them.
func podSecretsOf(clusterName string, p *corev1.Pod, link bool) []podSecret {
	idx := map[string]int{}
	var out []podSecret
	for _, u := range podSecretUses(p) {
		i, ok := idx[u.Secret]
		if !ok {
			i = len(out)
			idx[u.Secret] = i
			ps := podSecret{Name: u.Secret}
			if link {
				ps.Link = secretLink(clusterName, p.Namespace, u.Secret)
			}
			out = append(out, ps)
		}
		how := u.How
		if u.Key != "" {
			how = "key " + u.Key + " as " + how
		}
		if u.Optional {
			how += " (optional)"
		}
		out[i].How = append(out[i].How, how)
	}
	return out
}

// podFor finds the pod: live when connected, else from the last snapshot.
func podFor(ctx context.Context, e *engine.Engine, ns, name string) (*corev1.Pod, bool, error) {
	if conn := e.Conn(); conn != nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		p, err := conn.Client.CoreV1().Pods(ns).Get(cctx, name, metav1.GetOptions{})
		if err == nil {
			return p, true, nil
		}
		if !apierrors.IsNotFound(err) {
			return nil, false, err
		}
	}
	if snap := e.State().Snapshot; snap != nil {
		for _, p := range snap.Pods {
			if p.Namespace == ns && p.Name == name {
				return p, false, nil
			}
		}
	}
	return nil, false, errPodGone
}

var errPodGone = errors.New("this pod does not exist (any more)")

// findingsForPod returns the findings about the pod or its workload.
func findingsForPod(st *engine.State, p *corev1.Pod, workload findings.ObjectRef) []*findings.Finding {
	ref := findings.ObjectRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}
	var out []*findings.Finding
	for _, f := range st.Findings {
		match := f.Resource == ref || (!workload.IsZero() && f.Resource == workload)
		for _, a := range f.Affected {
			if a == ref {
				match = true
			}
		}
		if f.Resource.Kind == "Node" && f.Resource.Name == p.Spec.NodeName {
			match = true
		}
		if match {
			out = append(out, f)
		}
	}
	return out
}

// containersOf describes the pod's containers; snap, when set, adds what
// the logs of their last crashes say.
func containersOf(p *corev1.Pod, snap *snapshot.Snapshot) []containerView {
	statuses := map[string]corev1.ContainerStatus{}
	for _, s := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		statuses[s.Name] = s
	}
	var out []containerView
	add := func(c corev1.Container, init bool) {
		v := containerView{Name: c.Name, Image: c.Image, Init: init, State: "waiting", Icon: "info"}
		if s, ok := statuses[c.Name]; ok {
			v.Ready, v.Restarts = s.Ready, s.RestartCount
			switch {
			case s.State.Running != nil:
				v.State, v.Icon = "running", "good"
				if !s.Ready && !init {
					v.State, v.Icon = "running, not ready", "warn"
				}
			case s.State.Waiting != nil:
				v.State, v.Detail, v.Icon = s.State.Waiting.Reason, s.State.Waiting.Message, "crit"
				if s.State.Waiting.Reason == "ContainerCreating" || s.State.Waiting.Reason == "PodInitializing" {
					v.Icon = "info"
				}
			case s.State.Terminated != nil:
				v.State, v.Detail = s.State.Terminated.Reason, s.State.Terminated.Message
				v.Icon = "good"
				if s.State.Terminated.ExitCode != 0 {
					v.Icon = "crit"
				}
			}
			if t := s.LastTerminationState.Terminated; t != nil {
				v.LastExit = fmt.Sprintf("%s, exit code %d, at %s", t.Reason, t.ExitCode, t.FinishedAt.UTC().Format("15:04:05"))
				ex := remedy.ExitCode(t.ExitCode, t.Reason)
				v.ExitMeans, v.ExitPlain = ex.Technical, ex.Plain
			}
			if snap != nil {
				if cl := snap.CrashLog(p.Namespace, p.Name, c.Name); cl != nil {
					v.Crash = cl.Matches
				}
			}
		}
		out = append(out, v)
	}
	for _, c := range p.Spec.InitContainers {
		add(c, true)
	}
	for _, c := range p.Spec.Containers {
		add(c, false)
	}
	return out
}

// logToExplain picks the container and run whose log explains a problem:
// the last crashed run of a restarted container (crashed), else the first
// container's current run. The crashed run is the previous one while the
// container runs again; while it waits or just stopped, the kubelet serves
// it as the current log, and the run before it is usually cleaned up.
func logToExplain(p *corev1.Pod) (container string, previous, crashed bool) {
	for _, s := range p.Status.ContainerStatuses {
		if s.RestartCount > 0 && (s.LastTerminationState.Terminated != nil || s.State.Terminated != nil) {
			return s.Name, s.State.Running != nil, true
		}
	}
	for _, s := range p.Status.ContainerStatuses {
		if s.State.Waiting == nil || s.State.Waiting.Reason != "ContainerCreating" {
			return s.Name, false, false
		}
	}
	if len(p.Spec.Containers) > 0 {
		return p.Spec.Containers[0].Name, false, false
	}
	return "", false, false
}

func (s *Server) podPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	ns, name := r.PathValue("ns"), r.PathValue("name")
	p, live, err := podFor(r.Context(), e, ns, name)
	if err != nil {
		if errors.Is(err, errPodGone) {
			s.notFound(w, r, fmt.Sprintf("The pod %s/%s does not exist (any more). Pods are replaced when they restart on another node or after an update.", ns, name))
		} else {
			s.notFound(w, r, "The pod can't be read right now: "+err.Error())
		}
		return
	}
	st := e.State()
	d := podData{Cluster: e.Name(), Pod: podview.Sanitize(p), Live: live, Containers: containersOf(p, st.Snapshot), Age: "—",
		Secrets: podSecretsOf(e.Name(), p, secretsReadable(e))}
	if !p.CreationTimestamp.IsZero() {
		d.Age = ago(s.now().Sub(p.CreationTimestamp.Time))
	}
	if !live {
		d.Stale = "The cluster can't be reached, so this is the pod as last seen."
	}
	if snap := st.Snapshot; snap != nil {
		w := snap.WorkloadOf(p)
		d.Workload = findings.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
	}
	d.Findings = findingsForPod(st, p, d.Workload)
	for _, f := range d.Findings {
		if !f.IsSymptom() && !f.IsHygiene() {
			d.Main = f
			break
		}
	}
	if d.Main == nil {
		for _, f := range d.Findings {
			if !f.IsHygiene() {
				d.Main = f
				break
			}
		}
	}
	// The log lines that matter, for Basic mode.
	if conn := e.Conn(); conn != nil && s.modeOf(w, r) == "basic" {
		container, previous, crashed := logToExplain(p)
		if container != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			log, err := podview.ReadLog(ctx, conn.Client, ns, name, podview.LogOptions{Container: container, Previous: previous, Tail: 300})
			cancel()
			if err != nil {
				d.LogError = "The log can't be read right now."
			} else {
				d.Important = podview.ImportantLines(log, 8)
				d.Matches = remedy.Find(log)
				d.LogSource = fmt.Sprintf("the %s of %s", ifStr(crashed, "last crashed run", "current run"), container)
			}
		}
	}
	nav := navOf(st)
	s.render(w, r, "pod", &page{Title: name, Nav: "apps", Cluster: &nav, Data: d})
}

// liveConn returns the connection for live calls, or writes an error.
func (s *Server) liveConn(w http.ResponseWriter, e *engine.Engine) *cluster.Conn {
	conn := e.Conn()
	if conn == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "the cluster can't be reached right now", Hint: "The overview says why; the data comes back when it answers again."})
	}
	return conn
}

func (s *Server) apiPod(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	p, live, err := podFor(r.Context(), e, r.PathValue("ns"), r.PathValue("name"))
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errPodGone) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	var workload findings.ObjectRef
	if snap := e.State().Snapshot; snap != nil {
		wl := snap.WorkloadOf(p)
		workload = findings.ObjectRef{Kind: wl.Kind, Namespace: wl.Namespace, Name: wl.Name}
	}
	writeJSON(w, http.StatusOK, map[string]any{"pod": podview.Sanitize(p), "live": live,
		"findings": findingsForPod(e.State(), p, workload)})
}

func (s *Server) apiPodDescribe(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	conn := s.liveConn(w, e)
	if conn == nil {
		return
	}
	out, err := podview.Describe(conn.Client, r.PathValue("ns"), r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeText(w, out)
}

func (s *Server) apiPodEvents(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	conn := s.liveConn(w, e)
	if conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	evs, err := podview.Events(ctx, conn.Client, r.PathValue("ns"), r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if evs == nil {
		evs = []podview.Event{}
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) apiPodYAML(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	conn := s.liveConn(w, e)
	if conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := podview.YAML(ctx, conn.Client, r.PathValue("ns"), r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeText(w, out)
}

// apiPodLogs returns a log as text, or follows it as server-sent events.
func (s *Server) apiPodLogs(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	conn := s.liveConn(w, e)
	if conn == nil {
		return
	}
	q := r.URL.Query()
	o := podview.LogOptions{Container: q.Get("container"), Previous: q.Get("previous") == "true", Follow: q.Get("follow") == "true"}
	if t, err := strconv.ParseInt(q.Get("tail"), 10, 64); err == nil {
		o.Tail = t
	}
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if !o.Follow {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		out, err := podview.ReadLog(ctx, conn.Client, ns, name, o)
		if err != nil && out == "" {
			writeError(w, http.StatusBadGateway, logError(err))
			return
		}
		writeText(w, out)
		return
	}
	// Follow: one event per line, for at most 30 minutes.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	rc, err := podview.Logs(ctx, conn.Client, ns, name, o)
	if err != nil {
		writeError(w, http.StatusBadGateway, logError(err))
		return
	}
	defer rc.Close()
	ctl := http.NewResponseController(w)
	_ = ctl.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	lines := make(chan string, 256)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	fmt.Fprint(w, "retry: 3000\n\n")
	_ = ctl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
		case l, ok := <-lines:
			ended := !ok
			if ok {
				writeLogLine(w, l)
				// Send what is already buffered, then flush once.
			drain:
				for n := 0; n < 200; n++ {
					select {
					case l, ok := <-lines:
						if !ok {
							ended = true
							break drain
						}
						writeLogLine(w, l)
					default:
						break drain
					}
				}
			}
			if ended {
				fmt.Fprint(w, "event: end\ndata: the log stream ended\n\n")
				_ = ctl.Flush()
				return
			}
		}
		if err := ctl.Flush(); err != nil {
			return
		}
	}
}

func writeLogLine(w io.Writer, l string) {
	fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(l, "\r", ""))
}

func logError(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, podview.ErrLogGone):
		return "the node no longer has this run of the container (it was cleaned up), so its log is gone; the current run's log may still be there"
	case strings.Contains(msg, "previous terminated container") && strings.Contains(msg, "not found"):
		return "this container has not restarted, so there is no previous log"
	case strings.Contains(msg, "ContainerCreating") || strings.Contains(msg, "is waiting to start"):
		return "the container has not started yet, so it has no log"
	case strings.Contains(msg, "konnectivity") || strings.Contains(msg, "dial"):
		return "the log can't be fetched from the node: " + msg + " (logs travel through konnectivity-agent on that node)"
	}
	return msg
}

func writeText(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, s)
}
