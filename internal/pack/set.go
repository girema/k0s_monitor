package pack

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/glossary"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

// Loaded is a pack and where it comes from.
type Loaded struct {
	*Pack
	// File is the pack's file in the directory, or "" when uploaded.
	File string
	// UploadedBy and Uploaded say who uploaded it, and when.
	UploadedBy string
	Uploaded   time.Time
	// Data is the pack's file as written.
	Data []byte
}

// Problem is a pack file that couldn't be used.
type Problem struct {
	Source string
	Err    string
}

// Set is the packs in use. A nil Set has no packs.
type Set struct {
	Packs    []*Loaded
	Problems []Problem
}

// For returns the packs that apply to a cluster, in order.
func (s *Set) For(cluster string) []*Pack {
	if s == nil {
		return nil
	}
	var out []*Pack
	for _, l := range s.Packs {
		if l.AppliesTo(cluster) {
			out = append(out, l.Pack)
		}
	}
	return out
}

// Get returns a pack by name, or nil.
func (s *Set) Get(name string) *Loaded {
	if s == nil {
		return nil
	}
	for _, l := range s.Packs {
		if l.Name == name {
			return l
		}
	}
	return nil
}

// Rules are the packs' checks for a cluster.
func (s *Set) Rules(cluster string) []rules.Rule {
	var out []rules.Rule
	for _, p := range s.For(cluster) {
		out = append(out, p.Rules()...)
	}
	return out
}

// Queries are the packs' PromQL queries for a cluster.
func (s *Set) Queries(cluster string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range s.For(cluster) {
		for _, q := range p.Queries() {
			if !seen[q] {
				seen[q] = true
				out = append(out, q)
			}
		}
	}
	return out
}

// K0sVersion is the k0s version a pack sets for a cluster, and the pack.
func (s *Set) K0sVersion(cluster string) (version, pack string) {
	for _, p := range s.For(cluster) {
		if p.K0sVersion != "" {
			return p.K0sVersion, p.Name
		}
	}
	return "", ""
}

// Expected is the k0s version a cluster should run: the one set for the
// cluster in k0s-monitor or its configuration file wins over a pack's,
// which wins over the version of an uploaded k0sctl.yaml (plan section
// 10.2).
func (s *Set) Expected(cluster, version, from string) *snapshot.ExpectedK0s {
	e := snapshot.ExpectedOf(version, from)
	if v, name := s.K0sVersion(cluster); v != "" && (e == nil || from == "k0sctl.yaml") {
		return &snapshot.ExpectedK0s{Version: v, From: "product pack " + name}
	}
	return e
}

// Support is who helps with a cluster's product, and the pack that says so.
func (s *Set) Support(cluster string) (*Support, string) {
	for _, p := range s.For(cluster) {
		if p.Support != nil {
			return p.Support, p.Name
		}
	}
	return nil, ""
}

// AddNode is a pack's guide for adding a node to a cluster, if one has it.
func (s *Set) AddNode(cluster string) (*AddNode, string) {
	for _, p := range s.For(cluster) {
		if p.AddNode != nil {
			return p.AddNode, p.Name
		}
	}
	return nil, ""
}

// AppName is the friendly name of an app in a cluster, if a pack gives one.
func (s *Set) AppName(cluster, kind, namespace, name string, labels map[string]string) *App {
	a, _ := app(s.For(cluster), appRef{ObjectRef: findings.ObjectRef{Kind: kind, Namespace: namespace, Name: name}, labels: labels})
	return a
}

// Apply adds the packs' guides, friendly names and links to a cluster's
// findings.
func (s *Set) Apply(cluster string, fs []*findings.Finding, snap *snapshot.Snapshot) {
	apply(s.For(cluster), fs, snap)
}

// Terms are the packs' glossary words.
func (s *Set) Terms() []glossary.Term {
	if s == nil {
		return nil
	}
	var out []glossary.Term
	for _, l := range s.Packs {
		for _, t := range l.Glossary {
			out = append(out, glossary.Term{Name: strings.TrimSpace(t.Term), Also: t.Also, Text: strings.TrimSpace(t.Text), From: l.Name})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Loading

// Stored is an uploaded pack.
type Stored struct {
	Name string
	Data []byte
	By   string
	At   time.Time
}

// Store keeps the uploaded packs.
type Store interface {
	Packs() ([]Stored, error)
}

// Registry loads the packs from a directory and the store, and keeps the
// current set. A nil Registry has no packs.
type Registry struct {
	dir   string
	store Store
	mu    sync.Mutex
	cur   atomic.Pointer[Set]
}

// NewRegistry returns a registry; dir and store may be empty.
func NewRegistry(dir string, store Store) *Registry {
	r := &Registry{dir: dir, store: store}
	r.cur.Store(&Set{})
	return r
}

// Dir is the directory packs are read from.
func (r *Registry) Dir() string {
	if r == nil {
		return ""
	}
	return r.dir
}

// Current returns the packs in use.
func (r *Registry) Current() *Set {
	if r == nil {
		return nil
	}
	return r.cur.Load()
}

// Load reads the packs again and makes them current; the glossary gets
// their words.
func (r *Registry) Load() *Set {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &Set{}
	names := map[string]string{}
	add := func(l *Loaded, source string) {
		if other, ok := names[l.Name]; ok {
			s.Problems = append(s.Problems, Problem{Source: source, Err: fmt.Sprintf("a pack named %s comes from %s already", l.Name, other)})
			return
		}
		names[l.Name] = source
		s.Packs = append(s.Packs, l)
	}
	if r.dir != "" {
		files, _ := filepath.Glob(filepath.Join(r.dir, "*.yaml"))
		more, _ := filepath.Glob(filepath.Join(r.dir, "*.yml"))
		files = append(files, more...)
		sort.Strings(files)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err == nil && len(data) > MaxSize {
				err = fmt.Errorf("the file is larger than %d KiB", MaxSize>>10)
			}
			if err != nil {
				s.Problems = append(s.Problems, Problem{Source: f, Err: err.Error()})
				continue
			}
			p, err := Parse(data)
			if err != nil {
				s.Problems = append(s.Problems, Problem{Source: f, Err: err.Error()})
				continue
			}
			add(&Loaded{Pack: p, File: f, Data: data}, f)
		}
	}
	if r.store != nil {
		stored, err := r.store.Packs()
		if err != nil {
			s.Problems = append(s.Problems, Problem{Source: "uploaded packs", Err: err.Error()})
		}
		for _, st := range stored {
			p, err := Parse(st.Data)
			if err != nil {
				s.Problems = append(s.Problems, Problem{Source: "uploaded pack " + st.Name, Err: err.Error()})
				continue
			}
			add(&Loaded{Pack: p, UploadedBy: st.By, Uploaded: st.At, Data: st.Data}, "the upload of "+st.By)
		}
	}
	r.cur.Store(s)
	glossary.SetExtra(s.Terms())
	return s
}
