package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/snapshot"
)

// fakeAPI is an OpenAI-compatible API: it lists two models and streams
// the answer in pieces, with a model's thinking before it.
func fakeAPI(t *testing.T, got *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"message":"Incorrect API key provided."}}`)
			return
		}
		switch r.URL.Path {
		case "/v1/models":
			fmt.Fprint(w, `{"object":"list","data":[{"id":"qwen3:8b"},{"id":"llama3.1:8b"}]}`)
		case "/v1/chat/completions":
			b, _ := io.ReadAll(r.Body)
			if got != nil {
				_ = json.Unmarshal(b, got)
			}
			var req map[string]any
			_ = json.Unmarshal(b, &req)
			if _, ok := req["max_tokens"]; ok {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":{"message":"Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead."}}`)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			for _, piece := range []string{
				`{"choices":[{"delta":{"reasoning_content":"Let me think."}}]}`,
				`{"choices":[{"delta":{"content":"<thi"}}]}`,
				`{"choices":[{"delta":{"content":"nk>hidden</think>The app "}}]}`,
				`{"choices":[{"delta":{"content":"lacks DATABASE_URL."}}]}`,
				`[DONE]`,
			} {
				fmt.Fprintf(w, "data: %s\n\n", piece)
				w.(http.Flusher).Flush()
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAsk(t *testing.T) {
	var req map[string]any
	srv := fakeAPI(t, &req)
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL + "/v1", Model: "qwen3:8b", MaxTokens: 800}, "sk-test")
	var pieces []string
	thinking := 0
	answer, err := c.Ask(context.Background(), []Message{{Role: "user", Content: "Why?"}},
		Handler{Text: func(s string) { pieces = append(pieces, s) }, Thinking: func() { thinking++ }})
	if err != nil {
		t.Fatal(err)
	}
	if answer != "The app lacks DATABASE_URL." || strings.Join(pieces, "") != answer || thinking == 0 {
		t.Errorf("answer %q, pieces %q, thinking %d", answer, pieces, thinking)
	}
	// It retried with max_completion_tokens, and asked for a stream.
	if req["max_completion_tokens"] != float64(800) || req["stream"] != true || req["model"] != "qwen3:8b" {
		t.Errorf("request: %v", req)
	}

	models, reply, err := c.Test(context.Background())
	if err != nil || reply != "The app lacks DATABASE_URL." || strings.Join(models, ",") != "llama3.1:8b,qwen3:8b" {
		t.Errorf("test: %v %q %v", models, reply, err)
	}
}

func TestErrors(t *testing.T) {
	srv := fakeAPI(t, nil)
	defer srv.Close()
	_, err := New(Config{BaseURL: srv.URL + "/v1", Model: "m"}, "wrong").Ask(context.Background(), nil, Handler{})
	if err == nil || !strings.Contains(err.Error(), "refused the key (HTTP 401)") || !strings.Contains(err.Error(), "Incorrect API key provided.") {
		t.Errorf("wrong key: %v", err)
	}
	_, err = New(Config{BaseURL: srv.URL + "/v2", Model: "m"}, "sk-test").Models(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("wrong path: %v", err)
	}
	// Nothing listens there.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	_, err = New(Config{BaseURL: "http://" + addr + "/v1", Model: "m"}, "").Ask(context.Background(), nil, Handler{})
	if err == nil || !strings.Contains(err.Error(), "nothing answers at "+addr) {
		t.Errorf("no server: %v", err)
	}
	// Too slow.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	defer slow.Close()
	_, err = New(Config{BaseURL: slow.URL, Model: "m", TimeoutSeconds: 1}, "").Ask(context.Background(), nil, Handler{})
	if err == nil || !strings.Contains(err.Error(), "no answer within 1 seconds") {
		t.Errorf("slow: %v", err)
	}
}

// An API that doesn't stream answers in one piece.
func TestAskWithoutStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"<think>x</think>All good."}}]}`)
	}))
	defer srv.Close()
	answer, err := New(Config{BaseURL: srv.URL, Model: "m"}, "").Ask(context.Background(), nil, Handler{})
	if err != nil || answer != "All good." {
		t.Errorf("%q %v", answer, err)
	}
}

func TestThinkFilter(t *testing.T) {
	for _, pieces := range [][]string{
		{"Hello <think>secret</think>world"},
		{"Hello <", "think>sec", "ret</th", "ink>world"},
		{"Hello ", "<think>", "secret", "</think>", "world"},
	} {
		f := &thinkFilter{}
		var out strings.Builder
		for _, p := range pieces {
			s, _ := f.feed(p)
			out.WriteString(s)
		}
		out.WriteString(f.flush())
		if out.String() != "Hello world" {
			t.Errorf("%q: %q", pieces, out.String())
		}
	}
	// A lone "<" is text.
	f := &thinkFilter{}
	s, _ := f.feed("a < b")
	if s+f.flush() != "a < b" {
		t.Errorf("lone <: %q", s)
	}
}

func TestConfig(t *testing.T) {
	c := Config{BaseURL: " https://api.openai.com/v1/chat/completions/ ", Model: " gpt ", Enabled: true}
	c.Normalize()
	if c.BaseURL != "https://api.openai.com/v1" || c.Model != "gpt" || c.Provider != "custom" || c.Check() != nil {
		t.Errorf("normalized: %+v %v", c, c.Check())
	}
	for _, bad := range []Config{{BaseURL: "ftp://x"}, {BaseURL: "https://user:pw@x/v1"}, {BaseURL: "http://x", Enabled: true}} {
		if bad.Check() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	if p, ok := PresetOf("ollama"); !ok || !p.Local || p.Key {
		t.Errorf("ollama: %+v", p)
	}
}

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func TestMessages(t *testing.T) {
	s, err := snapshot.FromYAMLFile("shop-prod", "../rules/testdata/alerts.yaml", now)
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	var crash *findings.Finding
	var children []*findings.Finding
	for _, f := range fs {
		if f.RuleID == "pod.crashloop" {
			crash = f
		}
	}
	for _, f := range fs {
		if f.ParentID == crash.ID {
			children = append(children, f)
		}
	}
	in := Input{Cluster: "shop-prod", Kubernetes: "v1.36.4+k0s", Nodes: 2, Finding: crash, Children: children, Snapshot: s, Basic: true, Now: now}
	msgs := Messages(in, Config{Language: "Deutsch"})
	if len(msgs) != 2 || msgs[0].Role != "system" || msgs[1].Role != "user" {
		t.Fatalf("messages: %+v", msgs)
	}
	sys, user := msgs[0].Content, msgs[1].Content
	for _, want := range []string{"not a Kubernetes expert", "Answer in Deutsch.", "k0s kubectl"} {
		if !strings.Contains(sys, want) {
			t.Errorf("instructions lack %q", want)
		}
	}
	for _, want := range []string{"Cluster: shop-prod (Kubernetes v1.36.4+k0s, 2 nodes)", "Rule: pod.crashloop", "## Evidence",
		"## It started with an update", "env DATABASE_URL: postgres://web@postgres:5432/web → —", "## Steps k0s-monitor suggests",
		"rollout undo deploy/web --to-revision=4", "## Caused by this problem too", "KubePodCrashLooping (warning): Pod is crash looping.",
		"## Log lines from the last crash", "environment variable DATABASE_URL is not set"} {
		if !strings.Contains(user, want) {
			t.Errorf("the description lacks %q:\n%s", want, user)
		}
	}
	// The API key changed in the update, and its value stays hidden.
	if !strings.Contains(user, "env API_KEY changed (value hidden)") {
		t.Errorf("API_KEY:\n%s", user)
	}

	full := Messages(Input{Finding: crash, Snapshot: s, Cluster: "shop-prod"}, Config{NoLogs: true, MaskIPs: true})
	if !strings.Contains(full[0].Content, "administers the cluster") || !strings.Contains(full[0].Content, "Answer in English.") {
		t.Errorf("full instructions: %s", full[0].Content)
	}
	if strings.Contains(full[1].Content, "Log lines") {
		t.Error("logs were sent though turned off")
	}
}

// Secrets in what the cluster says never leave: values of secret-looking
// names, passwords in URLs, tokens; and IP addresses when asked.
func TestMessagesRedact(t *testing.T) {
	f := &findings.Finding{Title: "API down at 10.1.2.3", RuleID: "x", Resource: findings.ObjectRef{Kind: "Pod", Namespace: "a", Name: "b"},
		Summary:  "connecting to postgres://admin:hunter22@10.1.2.3:5432/db failed",
		Evidence: []findings.Fact{{Label: "Env", Value: "PASSWORD=Sup3rSecret"}, {Label: "Header", Value: "Authorization: Bearer abc.def.ghi"}}}
	msgs := Messages(Input{Finding: f, Cluster: "c"}, Config{MaskIPs: true})
	for _, leak := range []string{"hunter22", "Sup3rSecret", "abc.def.ghi", "10.1.2.3"} {
		if strings.Contains(msgs[1].Content, leak) {
			t.Errorf("sent %q:\n%s", leak, msgs[1].Content)
		}
	}
	if !strings.Contains(msgs[1].Content, "ip-1") {
		t.Errorf("no masked address:\n%s", msgs[1].Content)
	}
}
