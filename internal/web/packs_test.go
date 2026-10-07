package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/pack"
)

// newPackEnv runs the crash-loop cluster (payments-api in namespace shop)
// with the example pack in the packs directory.
func newPackEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shop.yaml"), pack.Example, 0o644); err != nil {
		t.Fatal(err)
	}
	var reg *pack.Registry
	env := newEnv(t, func(o *Options) {
		reg = pack.NewRegistry(dir, o.Store)
		reg.Load()
		o.Packs = reg
	})
	t.Cleanup(func() { pack.NewRegistry("", nil).Load() }) // the glossary without packs
	env.login()
	env.waitFor(func(e *engine.Engine) bool { return hasRule(e, "pack.shop.payments-replicas") })
	return env
}

func hasRule(e *engine.Engine, rule string) bool {
	for _, f := range e.State().Findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func (env *testEnv) uploadPack(name string, data []byte) *http.Response {
	env.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf", env.csrf)
	fw, _ := mw.CreateFormFile("pack", name)
	fw.Write(data)
	mw.Close()
	return env.do("POST", "/settings/packs", &body, map[string]string{"Content-Type": mw.FormDataContentType()})
}

func TestProductPacks(t *testing.T) {
	env := newPackEnv(t)

	// The pack's checks run, and its advice, names and links show.
	for _, id := range []string{"pack.shop.payments-replicas", "pack.shop.nightly-backup", "pack.shop.shop-version"} {
		findingByRule(env, id)
	}
	crash := findingByRule(env, "pod.crashloop")
	if crash == nil || crash.App != "Payments service" {
		t.Fatalf("crash loop: %+v", crash)
	}
	// Too few replicas is a symptom of the crash loop.
	if r := findingByRule(env, "pack.shop.payments-replicas"); r.ParentID != crash.ID {
		t.Errorf("the replicas check isn't folded under the crash loop: %q", r.ParentID)
	}
	resp := env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=basic", nil, nil)
	body := readBody(t, resp)
	mustContain(t, body, "Open the Shop admin console", "from your product's guide", "Runbook: the payments service crashes",
		`href="https://docs.shop.example/payments"`, "Payments service", "send it to Shop support, support@shop.example")
	resp = env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=full", nil, nil)
	mustContain(t, readBody(t, resp), "App <b>Payments service</b>", "pack shop", "DOCUMENTATION")
	resp = env.do("GET", "/c/edge-prod/apps?mode=basic", nil, nil)
	mustContain(t, readBody(t, resp), `>Payments service</b>`, "payments-api, app in shop")
	resp = env.do("GET", "/glossary", nil, nil)
	mustContain(t, readBody(t, resp), "storefront", "from shop")
	resp = env.do("GET", "/c/edge-prod/k0s?mode=full", nil, nil)
	mustContain(t, readBody(t, resp), "product pack shop")

	// Settings lists it, from the directory.
	resp = env.do("GET", "/settings", nil, nil)
	body = readBody(t, resp)
	mustContain(t, body, "Product packs", "<b>shop</b>", "5 checks, 2 app names, 2 guides, 2 glossary words, the add-node guide", "shop.yaml", "edge-prod", "Example pack")
	resp = env.do("GET", "/settings/packs/example.yaml", nil, nil)
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 || !bytes.Equal(b, pack.Example) {
		t.Errorf("example: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Upload a pack: it is used at once, and audited.
	crm := []byte("apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: crm\nversion: \"1.0\"\nglossary: [{term: lead, text: A possible customer.}]\n" +
		"checks: [{id: two-nodes, kind: nodes, min: 2, plain: {title: The CRM needs two servers}}]\n")
	resp = env.uploadPack("crm.yaml", crm)
	body = readBody(t, resp)
	mustContain(t, body, "The pack crm is in use", "uploaded by admin", "Remove")
	env.waitFor(func(e *engine.Engine) bool { return hasRule(e, "pack.crm.two-nodes") })
	if f := findingByRule(env, "pack.crm.two-nodes"); f.Plain.Title != "The CRM needs two servers" {
		t.Errorf("crm check: %+v", f.Plain)
	}
	resp = env.do("GET", "/glossary", nil, nil)
	mustContain(t, readBody(t, resp), "A possible customer.", "from crm")

	// A pack named like one in the directory, or a broken one, is refused.
	resp = env.uploadPack("shop.yaml", []byte("apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: shop\n"))
	mustContain(t, readBody(t, resp), "The pack wasn&#39;t added: a pack named shop comes from")
	resp = env.uploadPack("bad.yaml", []byte("apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: bad\nchecks: [{id: x, kind: replicas}]\n"))
	mustContain(t, readBody(t, resp), "min: 1 or more")
	// Without the CSRF token, nothing is uploaded.
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	fw, _ := mw.CreateFormFile("pack", "x.yaml")
	fw.Write([]byte("apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: sneaky\n"))
	mw.Close()
	resp = env.do("POST", "/settings/packs", &b, map[string]string{"Content-Type": mw.FormDataContentType()})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("upload without CSRF: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// The API lists, adds and removes packs.
	resp = env.do("GET", "/api/v1/packs", nil, nil)
	var list struct {
		Packs []struct {
			Name   string   `json:"name"`
			Checks []string `json:"checks"`
		} `json:"packs"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Packs) != 2 || list.Packs[1].Name != "crm" || list.Packs[1].Checks[0] != "pack.crm.two-nodes" {
		t.Errorf("packs: %+v", list)
	}
	code, out := env.api("POST", "/api/v1/packs", "apiVersion: k0s-monitor/v1\nkind: ProductPack\nname: api-pack\n")
	if code != http.StatusCreated {
		t.Errorf("API upload: %d %s", code, out)
	}
	if code, out := env.api("DELETE", "/api/v1/packs/shop", ""); code != http.StatusBadRequest || !strings.Contains(out, "remove that file") {
		t.Errorf("removing a directory pack: %d %s", code, out)
	}
	if code, _ := env.api("DELETE", "/api/v1/packs/api-pack", ""); code != http.StatusNoContent {
		t.Errorf("API remove: %d", code)
	}

	// Remove the uploaded pack in Settings: its check goes.
	resp = env.do("POST", "/settings/packs/crm/remove", strings.NewReader("csrf="+env.csrf), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	mustContain(t, readBody(t, resp), "The pack crm was removed")
	env.waitFor(func(e *engine.Engine) bool { return !hasRule(e, "pack.crm.two-nodes") })
	log, _ := env.st.AuditLog(30)
	var actions []string
	for _, a := range log {
		actions = append(actions, a.Action)
	}
	if all := strings.Join(actions, " "); !strings.Contains(all, "pack.upload") || !strings.Contains(all, "pack.remove") {
		t.Errorf("audit: %v", actions)
	}

	// The report names the support contact and the pack.
	resp = env.do("GET", "/api/v1/clusters/edge-prod/report?preview=true", nil, nil)
	resp.Body.Close()
	resp = env.do("GET", "/c/edge-prod/report?mode=basic", nil, nil)
	mustContain(t, readBody(t, resp), "send to Shop support")
}

// A problem that is gone from the history shows "not known" instead of
// failing.
func TestUnknownFinding(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	resp := env.do("GET", "/c/edge-prod/problems/0123456789ab", nil, nil)
	if body := readBody(t, resp); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "This problem is not known") {
		t.Errorf("unknown finding: %d", resp.StatusCode)
	}
}
