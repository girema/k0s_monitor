package engine

import (
	"context"
	"fmt"
	"sync"

	"k0s_monitor/internal/config"
)

// Fleet runs one engine per cluster. Clusters can be added and removed
// while it runs.
type Fleet struct {
	ctx  context.Context
	base Options

	mu      sync.RWMutex
	running []*running
}

type running struct {
	e      *Engine
	cancel context.CancelFunc
	done   chan struct{}
}

// NewFleet creates a fleet whose engines stop when ctx ends. base supplies
// everything but the cluster: thresholds, timeouts, store, events, timing.
func NewFleet(ctx context.Context, base Options) *Fleet {
	return &Fleet{ctx: ctx, base: base}
}

// Add starts monitoring a cluster.
func (f *Fleet) Add(c config.Cluster) (*Engine, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.running) >= config.MaxClusters {
		return nil, fmt.Errorf("already %d clusters: one instance is sized for up to %d", len(f.running), config.MaxClusters)
	}
	for _, r := range f.running {
		if r.e.Name() == c.Name {
			return nil, fmt.Errorf("a cluster named %q already exists", c.Name)
		}
	}
	o := f.base
	o.Cluster = c
	e := New(o)
	ctx, cancel := context.WithCancel(f.ctx)
	r := &running{e: e, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		e.Run(ctx)
	}()
	f.running = append(f.running, r)
	return e, nil
}

// Replace restarts a cluster's engine with new settings, in the same place
// in the list. The old engine stops before the new one starts; what was
// found is kept in the store, so nothing is reported as new again.
func (f *Fleet) Replace(c config.Cluster) (*Engine, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	idx := -1
	for i, r := range f.running {
		if r.e.Name() == c.Name {
			idx = i
		}
	}
	if idx < 0 {
		f.mu.Unlock()
		return nil, fmt.Errorf("no cluster named %q", c.Name)
	}
	old := f.running[idx]
	o := f.base
	o.Cluster = c
	e := New(o)
	ctx, cancel := context.WithCancel(f.ctx)
	r := &running{e: e, cancel: cancel, done: make(chan struct{})}
	f.running[idx] = r
	f.mu.Unlock()

	old.cancel()
	<-old.done
	go func() {
		defer close(r.done)
		e.Run(ctx)
	}()
	return e, nil
}

// Remove stops monitoring a cluster and waits for its engine to stop.
func (f *Fleet) Remove(name string) bool {
	f.mu.Lock()
	var r *running
	for i, x := range f.running {
		if x.e.Name() == name {
			r = x
			f.running = append(f.running[:i], f.running[i+1:]...)
			break
		}
	}
	f.mu.Unlock()
	if r == nil {
		return false
	}
	r.cancel()
	<-r.done
	return true
}

// Get returns the engine of a cluster, or nil.
func (f *Fleet) Get(name string) *Engine {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, r := range f.running {
		if r.e.Name() == name {
			return r.e
		}
	}
	return nil
}

// Engines returns the engines in the order the clusters were added.
func (f *Fleet) Engines() []*Engine {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]*Engine, len(f.running))
	for i, r := range f.running {
		out[i] = r.e
	}
	return out
}

// Stop stops every engine and waits for them.
func (f *Fleet) Stop() {
	f.mu.Lock()
	rs := f.running
	f.running = nil
	f.mu.Unlock()
	for _, r := range rs {
		r.cancel()
	}
	for _, r := range rs {
		<-r.done
	}
}
