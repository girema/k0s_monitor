// Package pack reads product packs (plan section 10.6): YAML files in which
// a team describes its products to k0s-monitor without code. A pack can
//
//   - add checks, such as "the database volume stays below 70% full" or
//     "payments-api runs at least 2 replicas";
//   - give apps friendly names, such as "Payments service" for payments-api,
//     with a description and a link to their documentation;
//   - add guides to built-in problems: what to do, steps and links, for
//     some apps or all;
//   - explain the product's own words in the glossary;
//   - set the k0s version the product ships, and who to contact for
//     support.
//
// Packs come from a directory on the jump host and from uploads in the UI.
package pack

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"sigs.k8s.io/yaml"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// APIVersion and Kind identify a pack file.
const (
	APIVersion = "k0s-monitor/v1"
	Kind       = "ProductPack"
)

// MaxSize is the largest pack file accepted.
const MaxSize = 512 << 10

// Pack is one product pack, as written in its file.
type Pack struct {
	APIVersion  string `json:"apiVersion"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	// Clusters limits the pack to clusters whose names match one of these
	// patterns (shop-*); empty applies it to every cluster.
	Clusters []string `json:"clusters,omitempty"`
	// K0sVersion is the k0s version the product ships.
	K0sVersion string    `json:"k0sVersion,omitempty"`
	Support    *Support  `json:"support,omitempty"`
	Apps       []App     `json:"apps,omitempty"`
	Glossary   []Term    `json:"glossary,omitempty"`
	Guides     []Guide   `json:"guides,omitempty"`
	Checks     []Check   `json:"checks,omitempty"`
	AddNode    *AddNode  `json:"addNode,omitempty"`
	compiled   *compiled `json:"-"`
}

// Support says who helps with the product.
type Support struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	URL   string `json:"url,omitempty"`
	Hours string `json:"hours,omitempty"`
}

// Contact is the support contact in one line.
func (s *Support) Contact() string {
	if s == nil {
		return ""
	}
	var parts []string
	for _, p := range []string{s.Name, s.Email, s.Phone, s.Hours} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

// Select chooses objects: by kind, namespace and name (both may be
// patterns like shop-* or data-*), and labels.
type Select struct {
	Kind      string            `json:"kind,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// App gives an app (a workload) a friendly name.
type App struct {
	Select      Select `json:"select"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Docs        string `json:"docs,omitempty"`
}

// Term is a word of the product, for the glossary.
type Term struct {
	Term string   `json:"term"`
	Also []string `json:"also,omitempty"`
	Text string   `json:"text"`
}

// Doc is a link to documentation.
type Doc struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Step is a step of a fix guide: Text in Full mode, Plain in Basic mode,
// and an optional command to copy. Host says where the command runs when
// not through kubectl.
type Step struct {
	Text    string `json:"text"`
	Plain   string `json:"plain,omitempty"`
	Command string `json:"command,omitempty"`
	Host    string `json:"host,omitempty"`
}

// Guide adds the product's advice to built-in problems.
type Guide struct {
	// Rules are rule IDs or patterns (pod.*); empty means every rule.
	Rules []string `json:"rules,omitempty"`
	// Select limits it to problems of some objects or apps.
	Select *Select `json:"select,omitempty"`
	// WhatToDo and Why replace the Basic mode texts; LikelyCause the Full
	// mode one.
	WhatToDo    string `json:"whatToDo,omitempty"`
	Why         string `json:"why,omitempty"`
	LikelyCause string `json:"likelyCause,omitempty"`
	// Steps come before the built-in steps.
	Steps []Step `json:"steps,omitempty"`
	Docs  []Doc  `json:"docs,omitempty"`
}

// Plain are the Basic mode texts of a check.
type Plain struct {
	Title        string `json:"title,omitempty"`
	WhatHappened string `json:"whatHappened,omitempty"`
	Why          string `json:"why,omitempty"`
	WhatToDo     string `json:"whatToDo,omitempty"`
}

// Check is a check of the product's own. Its texts may use values such as
// {{.Name}}; each kind lists the values it has.
type Check struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Select chooses what the check looks at.
	Select Select `json:"select,omitempty"`
	// Min is the least number of ready replicas (replicas) or ready nodes
	// (nodes).
	Min int `json:"min,omitempty"`
	// Above is the highest allowed value: a volume's use in percent
	// (volume), or a query's result (query). Below is the lowest allowed
	// result of a query.
	Above *float64 `json:"above,omitempty"`
	Below *float64 `json:"below,omitempty"`
	// Tag is the image tag the selected workloads must run (image), a
	// pattern like 2.3.*; Container limits it to one container.
	Tag       string `json:"tag,omitempty"`
	Container string `json:"container,omitempty"`
	// Query is a PromQL query (query); every series it returns is checked.
	// Unit formats its values: %, s, bytes or none.
	Query string `json:"query,omitempty"`
	Unit  string `json:"unit,omitempty"`

	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`

	Title       string `json:"title,omitempty"`
	Summary     string `json:"summary,omitempty"`
	LikelyCause string `json:"likelyCause,omitempty"`
	Plain       Plain  `json:"plain,omitempty"`
	Steps       []Step `json:"steps,omitempty"`
	Docs        []Doc  `json:"docs,omitempty"`
}

// AddNode replaces the built-in guide for adding a node.
type AddNode struct {
	Text  string `json:"text,omitempty"`
	Steps []Step `json:"steps,omitempty"`
	Docs  []Doc  `json:"docs,omitempty"`
}

// Check kinds.
const (
	KindReplicas = "replicas"
	KindVolume   = "volume"
	KindExists   = "exists"
	KindNodes    = "nodes"
	KindImage    = "image"
	KindQuery    = "query"
)

var (
	nameRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	severities = map[string]findings.Severity{"": findings.Medium, "info": findings.Info, "low": findings.Low,
		"medium": findings.Medium, "high": findings.High, "critical": findings.Critical}
	categories = map[string]findings.Category{"nodes": findings.Nodes, "workloads": findings.Workloads,
		"storage": findings.Storage, "network": findings.Network, "controlplane": findings.ControlPlane, "hygiene": findings.Hygiene}
	// existKinds are the kinds an exists check can look for: those in the
	// snapshot.
	existKinds = map[string]snapshot.Kind{
		"Deployment": snapshot.KindDeployment, "StatefulSet": snapshot.KindStatefulSet, "DaemonSet": snapshot.KindDaemonSet,
		"CronJob": snapshot.KindCronJob, "Job": snapshot.KindJob, "Service": snapshot.KindService, "Ingress": snapshot.KindIngress,
		"PersistentVolumeClaim": snapshot.KindPVC, "Namespace": snapshot.KindNamespace, "StorageClass": snapshot.KindStorageClass,
	}
	workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true}
	units         = map[string]bool{"": true, "%": true, "s": true, "bytes": true}
)

// Parse reads and checks a pack. Errors name the field that is wrong.
func Parse(data []byte) (*Pack, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("the file is larger than %d KiB", MaxSize>>10)
	}
	var p Pack
	if err := yaml.UnmarshalStrict(data, &p); err != nil {
		return nil, fmt.Errorf("not a valid pack: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	c, err := compile(&p)
	if err != nil {
		return nil, err
	}
	p.compiled = c
	return &p, nil
}

func (p *Pack) validate() error {
	if p.APIVersion != APIVersion || p.Kind != Kind {
		return fmt.Errorf("a pack starts with apiVersion: %s and kind: %s", APIVersion, Kind)
	}
	if !nameRE.MatchString(p.Name) {
		return fmt.Errorf("name %q: use lower-case letters, digits and dashes", p.Name)
	}
	for _, c := range p.Clusters {
		if _, err := path.Match(c, ""); err != nil {
			return fmt.Errorf("clusters: bad pattern %q", c)
		}
	}
	if p.K0sVersion != "" {
		if _, ok := snapshot.ParseK0sVersion(p.K0sVersion); !ok {
			return fmt.Errorf("k0sVersion %q: write it like v1.36.4+k0s.1", p.K0sVersion)
		}
	}
	if s := p.Support; s != nil && s.URL != "" {
		if err := checkURL(s.URL); err != nil {
			return fmt.Errorf("support.url: %w", err)
		}
	}
	for i, a := range p.Apps {
		where := fmt.Sprintf("apps[%d]", i)
		if a.Name == "" {
			return fmt.Errorf("%s: name is missing", where)
		}
		if a.Select.Name == "" {
			return fmt.Errorf("%s: select.name is missing", where)
		}
		if err := a.Select.validate(); err != nil {
			return fmt.Errorf("%s.select: %w", where, err)
		}
		if a.Docs != "" {
			if err := checkURL(a.Docs); err != nil {
				return fmt.Errorf("%s.docs: %w", where, err)
			}
		}
	}
	for i, t := range p.Glossary {
		if strings.TrimSpace(t.Term) == "" || strings.TrimSpace(t.Text) == "" {
			return fmt.Errorf("glossary[%d]: term and text are needed", i)
		}
	}
	for i, g := range p.Guides {
		where := fmt.Sprintf("guides[%d]", i)
		for _, r := range g.Rules {
			if _, err := path.Match(r, ""); err != nil {
				return fmt.Errorf("%s.rules: bad pattern %q", where, r)
			}
		}
		if g.Select != nil {
			if err := g.Select.validate(); err != nil {
				return fmt.Errorf("%s.select: %w", where, err)
			}
		}
		if g.WhatToDo == "" && g.Why == "" && g.LikelyCause == "" && len(g.Steps) == 0 && len(g.Docs) == 0 {
			return fmt.Errorf("%s: add whatToDo, why, likelyCause, steps or docs", where)
		}
		if err := checkSteps(where, g.Steps, g.Docs); err != nil {
			return err
		}
	}
	ids := map[string]bool{}
	for i, c := range p.Checks {
		where := fmt.Sprintf("checks[%d]", i)
		if c.ID != "" {
			where = fmt.Sprintf("check %s", c.ID)
		}
		if !nameRE.MatchString(c.ID) {
			return fmt.Errorf("%s: id %q: use lower-case letters, digits and dashes", where, c.ID)
		}
		if ids[c.ID] {
			return fmt.Errorf("%s: the id is used twice", where)
		}
		ids[c.ID] = true
		if err := c.validate(); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if err := checkSteps(where, c.Steps, c.Docs); err != nil {
			return err
		}
	}
	if a := p.AddNode; a != nil {
		if a.Text == "" && len(a.Steps) == 0 {
			return fmt.Errorf("addNode: add text or steps")
		}
		if err := checkSteps("addNode", a.Steps, a.Docs); err != nil {
			return err
		}
	}
	return nil
}

func (s *Select) validate() error {
	for _, pat := range []string{s.Namespace, s.Name} {
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("bad pattern %q", pat)
		}
	}
	return nil
}

func (c *Check) validate() error {
	if _, ok := severities[c.Severity]; !ok {
		return fmt.Errorf("severity %q: use info, low, medium, high or critical", c.Severity)
	}
	if _, ok := categories[c.Category]; !ok && c.Category != "" {
		return fmt.Errorf("category %q: use nodes, workloads, storage, network, controlplane or hygiene", c.Category)
	}
	if err := c.Select.validate(); err != nil {
		return fmt.Errorf("select: %w", err)
	}
	switch c.Kind {
	case KindReplicas:
		if c.Min < 1 {
			return fmt.Errorf("a replicas check needs min: 1 or more")
		}
		if c.Select.Name == "" {
			return fmt.Errorf("a replicas check needs select.name")
		}
		if k := c.Select.Kind; k != "" && !workloadKinds[k] {
			return fmt.Errorf("select.kind %q: use Deployment, StatefulSet or DaemonSet", k)
		}
	case KindVolume:
		if c.Above == nil || *c.Above <= 0 || *c.Above >= 100 {
			return fmt.Errorf("a volume check needs above: a percentage between 0 and 100")
		}
		if c.Select.Name == "" {
			return fmt.Errorf("a volume check needs select.name: the volume claim's name")
		}
	case KindExists:
		if _, ok := existKinds[c.Select.Kind]; !ok {
			kinds := make([]string, 0, len(existKinds))
			for k := range existKinds {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			return fmt.Errorf("an exists check needs select.kind, one of %s", strings.Join(kinds, ", "))
		}
		if c.Select.Name == "" {
			return fmt.Errorf("an exists check needs select.name")
		}
	case KindNodes:
		if c.Min < 1 {
			return fmt.Errorf("a nodes check needs min: 1 or more")
		}
	case KindImage:
		if c.Tag == "" {
			return fmt.Errorf("an image check needs tag: the version to run, like 2.3.*")
		}
		if _, err := path.Match(c.Tag, ""); err != nil {
			return fmt.Errorf("tag: bad pattern %q", c.Tag)
		}
		if c.Select.Name == "" {
			return fmt.Errorf("an image check needs select.name")
		}
		if k := c.Select.Kind; k != "" && !workloadKinds[k] {
			return fmt.Errorf("select.kind %q: use Deployment, StatefulSet or DaemonSet", k)
		}
	case KindQuery:
		if strings.TrimSpace(c.Query) == "" {
			return fmt.Errorf("a query check needs query: a PromQL query")
		}
		if (c.Above == nil) == (c.Below == nil) {
			return fmt.Errorf("a query check needs either above or below")
		}
		if !units[c.Unit] {
			return fmt.Errorf("unit %q: use %%, s, bytes or leave it out", c.Unit)
		}
	default:
		return fmt.Errorf("kind %q: use replicas, volume, exists, nodes, image or query", c.Kind)
	}
	return nil
}

func checkSteps(where string, steps []Step, docs []Doc) error {
	for i, s := range steps {
		if strings.TrimSpace(s.Text) == "" {
			return fmt.Errorf("%s.steps[%d]: text is missing", where, i)
		}
	}
	for i, d := range docs {
		if d.Title == "" {
			return fmt.Errorf("%s.docs[%d]: title is missing", where, i)
		}
		if err := checkURL(d.URL); err != nil {
			return fmt.Errorf("%s.docs[%d].url: %w", where, i, err)
		}
	}
	return nil
}

// checkURL accepts http and https links only: a pack's links end up in
// pages, and javascript: or data: links must not.
func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%q is not an http or https link", s)
	}
	return nil
}

// AppliesTo reports whether the pack is for a cluster.
func (p *Pack) AppliesTo(cluster string) bool {
	if len(p.Clusters) == 0 {
		return true
	}
	for _, pat := range p.Clusters {
		if ok, _ := path.Match(pat, cluster); ok {
			return true
		}
	}
	return false
}

// RuleID is the rule ID of one of the pack's checks.
func (p *Pack) RuleID(check string) string { return "pack." + p.Name + "." + check }

// ---------------------------------------------------------------------------
// Texts with values

// text is a pack text with {{.Value}} places, parsed once.
type text struct{ t *template.Template }

func parseText(where, s string) (text, error) {
	if !strings.Contains(s, "{{") {
		return text{}, nil
	}
	t, err := template.New(where).Option("missingkey=zero").Parse(s)
	if err != nil {
		return text{}, fmt.Errorf("%s: %w", where, err)
	}
	return text{t}, nil
}

// fill puts the values into s; texts without places stay as they are.
func fill(s string, t text, values map[string]any) string {
	if t.t == nil {
		return s
	}
	var b bytes.Buffer
	if err := t.t.Execute(&b, values); err != nil {
		return s
	}
	return strings.ReplaceAll(b.String(), "<no value>", "")
}

// Example is the example pack, internal/pack/example.yaml, which the
// settings page offers for download.
//
//go:embed example.yaml
var Example []byte
