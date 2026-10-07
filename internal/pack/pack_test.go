package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/glossary"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func example(t *testing.T) *Pack {
	t.Helper()
	p, err := Parse(Example)
	if err != nil {
		t.Fatalf("the example pack: %v", err)
	}
	return p
}

// evaluate runs the built-in rules and the pack's checks on the Shop
// cluster, and applies the pack, as the engine does.
func evaluate(t *testing.T, set *Set, cluster string) []*findings.Finding {
	t.Helper()
	s, err := snapshot.FromYAMLFile(cluster, "testdata/shop-cluster.yaml", now)
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := rules.EvaluateRules(append(rules.All(), set.Rules(cluster)...), s, config.DefaultThresholds())
	set.Apply(cluster, fs, s)
	return fs
}

func byRule(fs []*findings.Finding, id string) *findings.Finding {
	for _, f := range fs {
		if f.RuleID == id {
			return f
		}
	}
	return nil
}

func TestExamplePack(t *testing.T) {
	p := example(t)
	set := &Set{Packs: []*Loaded{{Pack: p}}}
	if !p.AppliesTo("shop-prod") || !p.AppliesTo("edge-prod") || p.AppliesTo("other") {
		t.Error("clusters")
	}
	if got := set.Rules("other"); len(got) != 0 {
		t.Errorf("rules for a cluster the pack isn't for: %d", len(got))
	}
	fs := evaluate(t, set, "shop-prod")

	// replicas: 1 of 2, with the pack's texts and values.
	f := byRule(fs, "pack.shop.payments-replicas")
	if f == nil {
		t.Fatalf("no replicas finding; got %v", ruleIDs(fs))
	}
	if f.Severity != findings.High || f.Category != findings.Workloads || f.Resource.Name != "payments-api" {
		t.Errorf("replicas: %+v", f)
	}
	if f.Plain.WhatHappened != "1 of the 2 copies it needs are working." || f.Plain.Title != "The payments service runs with fewer copies than it needs" {
		t.Errorf("replicas texts: %+v", f.Plain)
	}
	if !strings.Contains(f.Title, "1 of the 2 replicas") {
		t.Errorf("default title: %q", f.Title)
	}
	// volume: 82% > 70%.
	f = byRule(fs, "pack.shop.db-volume")
	if f == nil || f.Plain.Title != "The shop database is 82% full" || f.Category != findings.Storage {
		t.Fatalf("volume: %+v", f)
	}
	if !strings.Contains(f.Plain.WhatHappened, "8.8 GB of 10.7 GB") {
		t.Errorf("volume values: %q", f.Plain.WhatHappened)
	}
	// The volume belongs to postgres, which the pack names "Shop database".
	if f.App != "Shop database" {
		t.Errorf("volume app: %q", f.App)
	}
	// exists: the backup CronJob is missing.
	if f = byRule(fs, "pack.shop.nightly-backup"); f == nil || f.Resource.Kind != "CronJob" || f.Plain.Title != "The nightly backup of the shop isn't set up" {
		t.Errorf("exists: %+v", f)
	}
	// image: payments-api runs 2.2.0 and the pack wants 2.3.*; storefront
	// and postgres are fine.
	var images []string
	for _, f := range fs {
		if f.RuleID == "pack.shop.shop-version" {
			images = append(images, f.Resource.Name)
		}
	}
	if strings.Join(images, ",") != "payments-api" {
		t.Errorf("image findings: %v", images)
	}
	// query: 3.5 errors/s > 1.
	f = byRule(fs, "pack.shop.checkout-errors")
	if f == nil || f.Title != "Checkout returns 3.5 errors per second" || len(f.Docs) == 0 || f.Docs[0].Pack != "shop" {
		t.Fatalf("query: %+v", f)
	}

	// Guides: the crash loop of payments-api gets the pack's advice and
	// steps first, and the app's friendly name.
	crash := byRule(fs, "pod.crashloop")
	if crash == nil {
		t.Fatal("no crash loop")
	}
	if !strings.HasPrefix(crash.Plain.WhatToDo, "Open the Shop admin console") {
		t.Errorf("guide whatToDo: %q", crash.Plain.WhatToDo)
	}
	if crash.Remedy.LikelyCause != "The payments service stops when it can't reach the payment provider or the shop database." {
		t.Errorf("guide likely cause: %q", crash.Remedy.LikelyCause)
	}
	if len(crash.Remedy.Steps) < 2 || crash.Remedy.Steps[0].Pack != "shop" || !strings.Contains(crash.Remedy.Steps[0].Command, "k0s kubectl -n shop exec") {
		t.Errorf("guide steps: %+v", crash.Remedy.Steps)
	}
	if crash.App != "Payments service" || !strings.Contains(crash.Plain.Title, "Payments service") || strings.Contains(crash.Plain.Title, "payments-api") {
		t.Errorf("friendly name: %q %q", crash.App, crash.Plain.Title)
	}
	var docs []string
	for _, d := range crash.Docs {
		docs = append(docs, d.Title)
	}
	if strings.Join(docs, "|") != "Runbook: the payments service crashes|About Payments service" {
		t.Errorf("docs: %v", docs)
	}
	// The Full mode title stays technical.
	if !strings.Contains(crash.Title, "api") || crash.App == "" {
		t.Errorf("title: %q", crash.Title)
	}

	// Values the pack gives: the k0s version, support and the add-node guide.
	if e := set.Expected("shop-prod", "", ""); e == nil || e.Version != "v1.36.4+k0s.1" || e.From != "product pack shop" {
		t.Errorf("expected: %+v", e)
	}
	if e := set.Expected("shop-prod", "v1.35.0+k0s.1", "set in k0s-monitor"); e.Version != "v1.35.0+k0s.1" {
		t.Errorf("a version set in k0s-monitor wins: %+v", e)
	}
	if e := set.Expected("shop-prod", "v1.35.0+k0s.1", "k0sctl.yaml"); e.Version != "v1.36.4+k0s.1" {
		t.Errorf("the pack wins over k0sctl.yaml: %+v", e)
	}
	if e := set.Expected("other", "", ""); e != nil {
		t.Errorf("no version for other clusters: %+v", e)
	}
	if s, name := set.Support("shop-prod"); s == nil || name != "shop" || !strings.Contains(s.Contact(), "support@shop.example") {
		t.Errorf("support: %+v", s)
	}
	if a, _ := set.AddNode("edge-prod"); a == nil || len(a.Steps) != 1 {
		t.Errorf("add node: %+v", a)
	}
	if a := set.AppName("shop-prod", "Deployment", "shop", "payments-api", nil); a == nil || a.Name != "Payments service" {
		t.Errorf("app name: %+v", a)
	}
	if q := set.Queries("shop-prod"); len(q) != 1 || !strings.HasPrefix(q[0], "sum by (namespace)") {
		t.Errorf("queries: %v", q)
	}
}

func ruleIDs(fs []*findings.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestParseErrors(t *testing.T) {
	head := "apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: x\n"
	for body, want := range map[string]string{
		"apiVersion: v1\nkind: ProductPack\nname: x\n":                                     "a pack starts with",
		head + "unknown: 1\n":                                                              "unknown field",
		"apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: Shop Pack\n":                 "lower-case",
		head + "k0sVersion: latest\n":                                                      "k0sVersion",
		head + "checks: [{id: a, kind: replicas, select: {name: x}}]\n":                    "min: 1 or more",
		head + "checks: [{id: a, kind: volume, select: {name: x}, above: 120}]\n":          "between 0 and 100",
		head + "checks: [{id: a, kind: exists, select: {kind: Secret, name: x}}]\n":        "select.kind, one of",
		head + "checks: [{id: a, kind: query, query: up}]\n":                               "either above or below",
		head + "checks: [{id: a, kind: nope}]\n":                                           "use replicas, volume",
		head + "checks: [{id: a, kind: nodes, min: 1}, {id: a, kind: nodes, min: 2}]\n":    "used twice",
		head + "checks: [{id: a, kind: nodes, min: 1, title: '{{.Ready'}]\n":               "check a title",
		head + "checks: [{id: a, kind: nodes, min: 1, severity: urgent}]\n":                "severity",
		head + "guides: [{rules: [pod.crashloop]}]\n":                                      "add whatToDo",
		head + "guides: [{whatToDo: x, docs: [{title: a, url: 'javascript:alert(1)'}]}]\n": "not an http or https link",
		head + "apps: [{select: {name: x}, name: X, docs: 'data:text/html,hi'}]\n":         "not an http or https link",
		head + "support: {url: 'ftp://x'}\n":                                               "support.url",
	} {
		_, err := Parse([]byte(body))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error with %q", body, err, want)
		}
	}
	if _, err := Parse([]byte(head)); err != nil {
		t.Errorf("a minimal pack: %v", err)
	}
}

func TestReplaceName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"The app payments-api keeps crashing.", "The app Payments service keeps crashing."},
		{"payments-api", "Payments service"},
		{"pod payments-api-6d4b9-aaaaa crashed", "pod payments-api-6d4b9-aaaaa crashed"},
		{"see shop/payments-api and payments-api.shop.svc", "see shop/payments-api and payments-api.shop.svc"},
		{"payments-apis and my-payments-api", "payments-apis and my-payments-api"},
		{"payments-api, payments-api", "Payments service, Payments service"},
	} {
		if got := replaceName(c.in, "payments-api", "Payments service"); got != c.want {
			t.Errorf("replaceName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

type fakeStore []Stored

func (f fakeStore) Packs() ([]Stored, error) { return f, nil }

func TestRegistry(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "shop.yaml"), Example, 0o644)
	os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: broken\nchecks: [{id: a}]\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a pack"), 0o644)
	other := "apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: crm\nglossary: [{term: lead, text: A possible customer.}]\n"
	dup := "apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: shop\n"
	r := NewRegistry(dir, fakeStore{{Name: "crm", Data: []byte(other), By: "anna", At: now}, {Name: "shop", Data: []byte(dup), By: "ivan", At: now}})
	if r.Current() == nil || len(r.Current().Packs) != 0 {
		t.Error("an empty set before loading")
	}
	set := r.Load()
	var names []string
	for _, p := range set.Packs {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "shop,crm" {
		t.Errorf("packs: %v", names)
	}
	if set.Get("crm").UploadedBy != "anna" || set.Get("shop").File == "" {
		t.Errorf("sources: %+v %+v", set.Get("crm"), set.Get("shop"))
	}
	if len(set.Problems) != 2 || !strings.Contains(set.Problems[0].Source+set.Problems[1].Source, "broken.yaml") ||
		!strings.Contains(set.Problems[0].Err+set.Problems[1].Err, "a pack named shop comes from") {
		t.Errorf("problems: %+v", set.Problems)
	}
	// The glossary has the packs' words now.
	if glossary.Lookup("lead") == nil || glossary.Lookup("web shop") == nil || glossary.Lookup("lead").From != "crm" {
		t.Error("the packs' words aren't in the glossary")
	}
	if !strings.Contains(string(glossary.Annotate("A lead opened the storefront.")), "A possible customer.") {
		t.Error("pack words aren't explained in texts")
	}
	glossary.SetExtra(nil)
	var nilReg *Registry
	if nilReg.Current() != nil || nilReg.Load() != nil || nilReg.Current().Rules("x") != nil {
		t.Error("a nil registry has no packs")
	}
}
