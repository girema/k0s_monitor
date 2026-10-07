package engine

import (
	"context"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/version"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/snapshot"
)

// Failover (plan section 5.2): when the kubeconfig's server stops
// answering, k0s-monitor connects to another controller of the cluster,
// one it has asked directly before, and goes back to the kubeconfig's
// server once that answers again. Another controller gets the credentials
// only when its certificate is signed by the kubeconfig's CA for
// kubernetes.default.svc, which every API server k0s runs has.

// KnownController is a controller k0s-monitor has reached at its own
// address.
type KnownController struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"` // host:port
}

// dialed is a connection whose API server answered.
type dialed struct {
	conn *cluster.Conn
	v    *version.Info
}

// fallbackState is what a run of failovers keeps: since when, and whether
// the kubeconfig's server was a controller k0s-monitor knew.
type fallbackState struct {
	since        time.Time
	isController bool
}

// learn keeps the controllers of a control plane view that answered, and
// those known before that k0s still lists, and stores them so failover
// works after a restart too. A view where none answered changes nothing.
func (e *Engine) learn(cp *snapshot.ControlPlane) {
	if cp == nil {
		return
	}
	e.knownMu.Lock()
	before := map[string]bool{}
	for _, k := range e.known {
		before[k.Address] = true
	}
	var next []KnownController
	reached := false
	for _, c := range cp.Controllers {
		reached = reached || c.Reached
		if c.Reached || before[c.Address] {
			next = append(next, KnownController{Name: c.Name, Address: c.Address})
		}
	}
	changed := reached && !slices.Equal(next, e.known)
	if changed {
		e.known = next
	}
	e.knownMu.Unlock()
	if changed && e.o.Store != nil {
		_ = e.o.Store.SetControllers(e.Name(), next)
	}
}

// alternates returns the known controllers other than the one at server.
func (e *Engine) alternates(server string) []KnownController {
	addr := cluster.Address(server)
	e.knownMu.Lock()
	defer e.knownMu.Unlock()
	var out []KnownController
	for _, k := range e.known {
		if k.Address != addr {
			out = append(out, k)
		}
	}
	return out
}

func (e *Engine) isKnown(server string) bool {
	addr := cluster.Address(server)
	e.knownMu.Lock()
	defer e.knownMu.Unlock()
	return slices.ContainsFunc(e.known, func(k KnownController) bool { return k.Address == addr })
}

// failsOver says whether another controller may help: not when the
// credentials or the kubeconfig are the problem.
func failsOver(k cluster.ErrorKind) bool {
	switch k {
	case cluster.KindConfig, cluster.KindUnauthorized, cluster.KindForbidden:
		return false
	}
	return true
}

// dial connects to the kubeconfig's server or, when that doesn't answer, to
// another known controller that does. The others are asked at the same
// time, so failing over costs no extra wait. On failure it returns the
// kubeconfig's connection, for the error's server, with the error.
func (e *Engine) dial(ctx context.Context) (*dialed, error) {
	timeout := e.o.Timeouts.ConnectTimeout.D()
	conn, err := e.o.Connect(e.o.Cluster, timeout)
	if err != nil {
		return nil, err
	}
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	var other chan *dialed
	if alts := e.alternates(conn.Server); len(alts) > 0 {
		other = make(chan *dialed, 1)
		go func() { other <- e.firstAnswering(actx, alts) }()
	}
	pctx, pcancel := context.WithTimeout(ctx, timeout)
	v, err := conn.Ping(pctx)
	pcancel()
	if err == nil {
		e.fallback = nil
		return &dialed{conn: conn, v: v}, nil
	}
	ce := cluster.Classify(err, conn.Server, e.o.Cluster.Proxy)
	if other == nil || !failsOver(ce.Kind) {
		return &dialed{conn: conn}, err
	}
	d := <-other
	if d == nil {
		return &dialed{conn: conn}, err
	}
	if e.fallback == nil {
		e.fallback = &fallbackState{since: e.o.Now(), isController: e.isKnown(conn.Server)}
	}
	d.conn.Fallback.Server = conn.Server
	d.conn.Fallback.Error = ce
	d.conn.Fallback.ServerIsController = e.fallback.isController
	d.conn.Fallback.Since = e.fallback.since
	return d, nil
}

// firstAnswering connects to each controller at its own address and
// returns the first whose API server answers, or nil.
func (e *Engine) firstAnswering(ctx context.Context, alts []KnownController) *dialed {
	timeout := e.o.Timeouts.ConnectTimeout.D()
	results := make(chan *dialed, len(alts))
	for _, k := range alts {
		go func() {
			c := e.o.Cluster
			c.Server, c.ServerName = "https://"+k.Address, cluster.InClusterName
			conn, err := e.o.Connect(c, timeout)
			if err != nil {
				results <- nil
				return
			}
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			v, err := conn.Ping(pctx)
			if err != nil {
				results <- nil
				return
			}
			name := k.Name
			if name == "" {
				name = k.Address
			}
			conn.Fallback = &cluster.Fallback{Controller: name}
			results <- &dialed{conn: conn, v: v}
		}()
	}
	for range alts {
		if d := <-results; d != nil {
			return d
		}
	}
	return nil
}

// kubeconfigServer connects to the kubeconfig's own server, or returns nil
// when it still doesn't answer.
func (e *Engine) kubeconfigServer(ctx context.Context) *dialed {
	timeout := e.o.Timeouts.ConnectTimeout.D()
	conn, err := e.o.Connect(e.o.Cluster, timeout)
	if err != nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	v, err := conn.Ping(pctx)
	if err != nil {
		return nil
	}
	return &dialed{conn: conn, v: v}
}
