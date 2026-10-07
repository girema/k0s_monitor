package web

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeModel is an OpenAI-compatible API that streams a short answer. It
// keeps the requests it got.
type fakeModel struct {
	*httptest.Server
	mu   sync.Mutex
	auth []string
	sent []string
}

func newFakeModel(t *testing.T) *fakeModel {
	m := &fakeModel{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.auth = append(m.auth, r.Header.Get("Authorization"))
		m.mu.Unlock()
		switch r.URL.Path {
		case "/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"m1"},{"id":"m2"}]}`)
		case "/v1/chat/completions":
			b, _ := io.ReadAll(r.Body)
			m.mu.Lock()
			m.sent = append(m.sent, string(b))
			m.mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			for _, p := range []string{"The app **crashes** because ", "a setting is missing.\n\n1. Add `DATABASE_URL`."} {
				b, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]string{"content": p}}}})
				fmt.Fprintf(w, "data: %s\n\n", b)
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func TestExplainWithAI(t *testing.T) {
	model := newFakeModel(t)
	env := newEnv(t, nil)
	env.login()
	jsonHdr := map[string]string{"X-CSRF-Token": env.csrf, "Content-Type": "application/json"}
	crash := findingByRule(env, "pod.crashloop")
	explain := "/api/v1/clusters/edge-prod/findings/" + crash.ID + "/explain"

	// Off until turned on: no card, and nothing is sent.
	resp := env.do("POST", explain, strings.NewReader(`{"mode":"basic"}`), jsonHdr)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("explain while off: %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
	if page := readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID, nil, nil)); strings.Contains(page, "data-ai-ask") {
		t.Error("the page offers AI while it is off")
	}

	// Turned on through the API, with a key that is never shown again.
	body := fmt.Sprintf(`{"enabled":true,"provider":"custom","baseUrl":%q,"model":"m1","apiKey":"sk-test-123","maskIPs":true}`, model.URL+"/v1/chat/completions")
	resp = env.do("PUT", "/api/v1/settings/ai", strings.NewReader(body), jsonHdr)
	got := readBody(t, resp)
	var saved struct {
		BaseURL string `json:"baseUrl"`
		HasKey  bool   `json:"hasKey"`
		Presets []struct {
			ID string `json:"id"`
		} `json:"presets"`
	}
	_ = json.Unmarshal([]byte(got), &saved)
	if resp.StatusCode != 200 || !saved.HasKey || strings.Contains(got, "sk-test") || saved.BaseURL != model.URL+"/v1" || len(saved.Presets) < 10 {
		t.Fatalf("settings: %d %s", resp.StatusCode, got)
	}
	if raw, _ := env.st.Setting(settingAIKey); raw == "" || strings.Contains(raw, "sk-test") {
		t.Errorf("the key is stored as %q", raw)
	}
	if page := readBody(t, env.do("GET", "/settings", nil, nil)); strings.Contains(page, "sk-test") || !strings.Contains(page, "stored: leave empty to keep it") {
		t.Error("the settings page shows the key, or not that one is stored")
	}

	// The page offers it, and shows what would be sent.
	page := html.UnescapeString(readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=basic", nil, nil)))
	mustContain(t, page, "Ask AI to explain", "data-ai-ask", "What is sent to 127.0.0.1", "[system]", "not a Kubernetes expert", crash.Title)

	// Asked: the answer streams back.
	resp = env.do("POST", explain, strings.NewReader(`{"mode":"basic"}`), jsonHdr)
	stream := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("explain: %d %s", resp.StatusCode, stream)
	}
	for _, want := range []string{"event: text\ndata: \"The app **crashes** because \"", "event: done\ndata: {\"at\""} {
		if !strings.Contains(stream, want) {
			t.Errorf("stream lacks %q:\n%s", want, stream)
		}
	}
	model.mu.Lock()
	sent, auth := strings.Join(model.sent, "\n"), strings.Join(model.auth, ",")
	model.mu.Unlock()
	if !strings.Contains(auth, "Bearer sk-test-123") || !strings.Contains(sent, `"model":"m1"`) || !strings.Contains(sent, `"stream":true`) {
		t.Errorf("request: auth %q, body %s", auth, sent)
	}
	// IP addresses are hidden as asked.
	if strings.Contains(sent, "10.0.10.5") {
		t.Error("the cluster's address was sent")
	}

	// It is recorded, and the answer stays on the page.
	audit, _ := env.st.AuditLog(10)
	found := false
	for _, a := range audit {
		if a.Action == "ai.explain" && strings.Contains(a.Detail, "pod.crashloop") && strings.Contains(a.Detail, "model m1") {
			found = true
		}
	}
	if !found {
		t.Errorf("no ai.explain in the audit log: %+v", audit)
	}
	page = readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=basic", nil, nil))
	mustContain(t, page, "The app **crashes** because a setting is missing.", "Written by m1", "Ask again")
	// Full mode has its own answer.
	page = readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=full", nil, nil))
	if strings.Contains(page, "Written by m1") {
		t.Error("Full mode shows Basic mode's answer")
	}

	// The settings form tests without saving.
	form := url.Values{"csrf": {env.csrf}, "action": {"test"}, "enabled": {"on"}, "provider": {"custom"}, "baseUrl": {model.URL + "/v1"}, "model": {"m2"}}
	page = readBody(t, env.do("POST", "/settings/ai", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}))
	mustContain(t, page, "and the model m2 replied", `<option value="m1">`)
	if c := env.srv.aiConfig(); c.Model != "m1" {
		t.Errorf("Test saved the form: %+v", c)
	}
	// Saving another model forgets the answers.
	form.Set("action", "save")
	readBody(t, env.do("POST", "/settings/ai", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}))
	if c := env.srv.aiConfig(); c.Model != "m2" || !c.Enabled {
		t.Errorf("saved: %+v", c)
	}
	page = readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=basic", nil, nil))
	if strings.Contains(page, "Written by m1") {
		t.Error("an answer of the former model stays")
	}
	// The key stayed: the form left it empty.
	if env.srv.aiAPIKey() != "sk-test-123" {
		t.Error("the key was lost")
	}
}

func TestAISettingsRefused(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	jsonHdr := map[string]string{"X-CSRF-Token": env.csrf, "Content-Type": "application/json"}
	for _, body := range []string{`{"enabled":true,"baseUrl":"ftp://x/v1","model":"m"}`, `{"enabled":true,"baseUrl":"http://x/v1"}`} {
		resp := env.do("PUT", "/api/v1/settings/ai", strings.NewReader(body), jsonHdr)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", body, resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Without the CSRF token, nothing changes.
	resp := env.do("PUT", "/api/v1/settings/ai", strings.NewReader(`{"enabled":false,"baseUrl":"http://x/v1"}`), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("without CSRF: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// The stored key goes only to the API it was entered for: nobody can make
// k0s-monitor send it to another address, and saving another address
// removes it.
func TestAIKeyStaysWithItsAPI(t *testing.T) {
	model, other := newFakeModel(t), newFakeModel(t)
	env := newEnv(t, nil)
	env.login()
	jsonHdr := map[string]string{"X-CSRF-Token": env.csrf, "Content-Type": "application/json"}
	resp := env.do("PUT", "/api/v1/settings/ai", strings.NewReader(fmt.Sprintf(`{"enabled":true,"baseUrl":%q,"model":"m1","apiKey":"sk-secret"}`, model.URL+"/v1")), jsonHdr)
	readBody(t, resp)

	// Testing another address doesn't send the stored key.
	resp = env.do("POST", "/api/v1/settings/ai/test", strings.NewReader(fmt.Sprintf(`{"baseUrl":%q,"model":"m1"}`, other.URL+"/v1")), jsonHdr)
	readBody(t, resp)
	other.mu.Lock()
	asked, auth := len(other.auth), strings.Join(other.auth, ",")
	other.mu.Unlock()
	if asked == 0 {
		t.Fatal("the other API wasn't asked")
	}
	if strings.Contains(auth, "sk-secret") {
		t.Errorf("the stored key went to another address: %q", auth)
	}

	// Saving another address removes the key, and says so.
	form := url.Values{"csrf": {env.csrf}, "action": {"save"}, "enabled": {"on"}, "provider": {"custom"}, "baseUrl": {other.URL + "/v1"}, "model": {"m1"}}
	page := html.UnescapeString(readBody(t, env.do("POST", "/settings/ai", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})))
	mustContain(t, page, "The stored API key was for 127.0.0.1")
	if env.srv.aiAPIKey() != "" {
		t.Error("the key stayed for another address")
	}
}
