package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"k0s_monitor/internal/ai"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
)

// "Explain with AI" (M5): a problem explained by a language model that an
// administrator sets up in Settings, through any OpenAI-compatible API.
// It is off until turned on. What is sent is redacted, shown before it is
// sent, and each request is recorded in the audit log: if it can't be
// recorded, nothing is sent.

const (
	settingAI    = "ai.config"
	settingAIKey = "ai.key"
	// aiAnswersKept is how many answers are remembered, and for how long.
	aiAnswersKept = 200
	aiAnswerTTL   = 24 * time.Hour
	// aiAtOnce is how many answers may be written at the same time.
	aiAtOnce = 2
)

// aiAnswer is an explanation, remembered so that it stays on the page.
type aiAnswer struct {
	Text  string
	By    string
	Model string
	Host  string
	At    time.Time
}

// aiState holds the remembered answers and bounds the requests.
type aiState struct {
	mu      sync.Mutex
	answers map[string]*aiAnswer
	slots   chan struct{}
}

func newAIState() *aiState {
	return &aiState{answers: map[string]*aiAnswer{}, slots: make(chan struct{}, aiAtOnce)}
}

func aiKey(cluster, id string, basic bool) string {
	return cluster + "/" + id + "/" + ifStr(basic, "basic", "full")
}

func (a *aiState) answer(key string, now time.Time) *aiAnswer {
	a.mu.Lock()
	defer a.mu.Unlock()
	ans := a.answers[key]
	if ans != nil && now.Sub(ans.At) > aiAnswerTTL {
		delete(a.answers, key)
		return nil
	}
	return ans
}

func (a *aiState) keep(key string, ans *aiAnswer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.answers[key] = ans
	if len(a.answers) <= aiAnswersKept {
		return
	}
	// Forget the oldest.
	keys := make([]string, 0, len(a.answers))
	for k := range a.answers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return a.answers[keys[i]].At.Before(a.answers[keys[j]].At) })
	for _, k := range keys[:len(keys)-aiAnswersKept] {
		delete(a.answers, k)
	}
}

func (a *aiState) forgetAll() {
	a.mu.Lock()
	a.answers = map[string]*aiAnswer{}
	a.mu.Unlock()
}

// aiConfig is the saved configuration; the zero one when there is none.
func (s *Server) aiConfig() ai.Config {
	var c ai.Config
	if v, _ := s.o.Store.Setting(settingAI); v != "" {
		_ = json.Unmarshal([]byte(v), &c)
	}
	return c
}

func (s *Server) aiAPIKey() string {
	b, err := s.o.Store.SealedSetting(settingAIKey)
	if err != nil {
		s.log.Error("reading the AI API key", "err", err)
	}
	return string(b)
}

// aiForm is the settings form, as saved or as submitted.
type aiForm struct {
	ai.Config
	HasKey bool
	// Models are the API's models, after Test.
	Models  []string
	Message string
	Error   string
}

// aiRequest is the form or API body that changes the settings. APIKey
// empty keeps the stored key; RemoveKey removes it.
type aiRequest struct {
	ai.Config
	APIKey    string `json:"apiKey,omitempty"`
	RemoveKey bool   `json:"removeKey,omitempty"`
}

func aiRequestOf(r *http.Request) aiRequest {
	num := func(name string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
		return n
	}
	q := aiRequest{Config: ai.Config{
		Enabled: r.PostFormValue("enabled") == "on", Provider: r.PostFormValue("provider"), BaseURL: r.PostFormValue("baseUrl"),
		Model: r.PostFormValue("model"), Language: r.PostFormValue("language"), MaxTokens: num("maxTokens"),
		TimeoutSeconds: num("timeoutSeconds"), MaskIPs: r.PostFormValue("maskIPs") == "on", NoLogs: r.PostFormValue("logs") != "on",
	}, APIKey: strings.TrimSpace(r.PostFormValue("apiKey")), RemoveKey: r.PostFormValue("removeKey") == "on"}
	if q.BaseURL == "" {
		if p, ok := ai.PresetOf(q.Provider); ok {
			q.BaseURL = p.BaseURL
		}
	}
	q.Normalize()
	return q
}

// keyFor is the key a request would use. The stored key goes only to the
// API it was entered for: with another address it must be entered again,
// so that nobody can send it to an address of their choosing.
func (s *Server) keyFor(q aiRequest) string {
	switch {
	case q.APIKey != "":
		return q.APIKey
	case q.RemoveKey || !sameAPI(s.aiConfig().BaseURL, q.BaseURL):
		return ""
	}
	return s.aiAPIKey()
}

// sameAPI reports whether two addresses are the same API: the same scheme
// and host.
func sameAPI(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Host != "" &&
		strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// saveAI stores the settings and the key. A stored key that was for
// another address is removed: note says so.
func (s *Server) saveAI(r *http.Request, q aiRequest) (note string, err error) {
	if err := q.Check(); err != nil {
		return "", err
	}
	if old := s.aiConfig(); q.APIKey == "" && !q.RemoveKey && !sameAPI(old.BaseURL, q.BaseURL) && s.aiAPIKey() != "" {
		q.RemoveKey = true
		note = fmt.Sprintf(" The stored API key was for %s, so it was removed: enter the key for %s.", old.Host(), q.Host())
	}
	b, _ := json.Marshal(q.Config)
	if err := s.o.Store.SetSetting(settingAI, string(b)); err != nil {
		return "", err
	}
	switch {
	case q.APIKey != "":
		if err := s.o.Store.SetSealedSetting(settingAIKey, []byte(q.APIKey)); err != nil {
			return "", fmt.Errorf("the API key can't be stored: %w", err)
		}
	case q.RemoveKey:
		if err := s.o.Store.SetSealedSetting(settingAIKey, nil); err != nil {
			return "", err
		}
	}
	// Answers from another model or provider don't stay.
	s.ai.forgetAll()
	detail := fmt.Sprintf("%s, %s, model %s", ifStr(q.Enabled, "on", "off"), q.Host(), q.Model)
	if q.APIKey != "" {
		detail += ", new API key"
	} else if q.RemoveKey {
		detail += ", API key removed"
	}
	s.audit(r, "ai.settings", detail)
	return note, nil
}

// testAI checks a configuration without saving it.
func (s *Server) testAI(ctx context.Context, q aiRequest) (models []string, msg string, err error) {
	if err := q.Check(); err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	models, reply, err := ai.New(q.Config, s.keyFor(q)).Test(ctx)
	if err != nil {
		return models, "", err
	}
	switch {
	case q.Model != "":
		msg = fmt.Sprintf("%s answers, and the model %s replied: %q.", q.Host(), q.Model, short(reply, 80))
	case len(models) > 0:
		msg = fmt.Sprintf("%s answers and offers %s. Choose the model to use.", q.Host(), plural(len(models), "model"))
	default:
		msg = q.Host() + " answers. Enter the model to use."
	}
	if q.Model != "" && len(models) > 0 && !contains(models, q.Model) {
		msg += fmt.Sprintf(" The model isn't in the API's list of %s, but it answered.", plural(len(models), "model"))
	}
	return models, msg, nil
}

func short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// aiSettingsForm saves the settings, or tests them (action=test).
func (s *Server) aiSettingsForm(w http.ResponseWriter, r *http.Request) {
	q := aiRequestOf(r)
	form := &aiForm{Config: q.Config, HasKey: s.keyFor(q) != ""}
	if r.PostFormValue("action") == "test" {
		models, msg, err := s.testAI(r.Context(), q)
		form.Models, form.Message = models, msg
		if err != nil {
			form.Error = err.Error()
		}
		s.renderSettingsAI(w, r, form)
		return
	}
	note, err := s.saveAI(r, q)
	if err != nil {
		form.Error = err.Error()
		s.renderSettingsAI(w, r, form)
		return
	}
	form.HasKey = s.aiAPIKey() != ""
	form.Message = ifStr(q.Enabled, "Saved. Problem pages now offer an explanation by "+q.Model+".", "Saved. Explain with AI is off.") + note
	s.renderSettingsAI(w, r, form)
}

func (s *Server) renderSettingsAI(w http.ResponseWriter, r *http.Request, form *aiForm) {
	s.renderSettingsWith(w, r, "", "", form)
}

// savedAIForm is the form with the saved settings.
func (s *Server) savedAIForm() *aiForm {
	c := s.aiConfig()
	if c.Provider == "" {
		c.Provider, c.BaseURL, c.MaskIPs = "ollama", "http://127.0.0.1:11434/v1", true
	}
	return &aiForm{Config: c, HasKey: s.aiAPIKey() != ""}
}

type apiAISettings struct {
	ai.Config
	HasKey  bool        `json:"hasKey"`
	Presets []ai.Preset `json:"presets"`
}

func (s *Server) apiGetAI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, apiAISettings{Config: s.aiConfig(), HasKey: s.aiAPIKey() != "", Presets: ai.Presets})
}

func (s *Server) apiPutAI(w http.ResponseWriter, r *http.Request) {
	var q aiRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q); err != nil {
		writeError(w, http.StatusBadRequest, "the body isn't valid JSON: "+err.Error())
		return
	}
	q.Normalize()
	if _, err := s.saveAI(r, q); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.apiGetAI(w, r)
}

func (s *Server) apiTestAI(w http.ResponseWriter, r *http.Request) {
	var q aiRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q); err != nil {
		writeError(w, http.StatusBadRequest, "the body isn't valid JSON: "+err.Error())
		return
	}
	q.Normalize()
	models, msg, err := s.testAI(r.Context(), q)
	out := map[string]any{"ok": err == nil, "models": models, "message": msg}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// aiView is what a problem's page shows about AI.
type aiView struct {
	Ready bool
	Host  string
	Model string
	Local bool
	// Answer is the last explanation, in this page's mode.
	Answer *aiAnswer
	// Sent is what would be sent, to look at first.
	Sent []ai.Message
}

// aiInput is what a problem is explained from.
func aiInput(st *engine.State, f *findings.Finding, basic bool, now time.Time) ai.Input {
	in := ai.Input{Cluster: st.Name, Finding: f, Snapshot: st.Snapshot, Basic: basic, Now: now}
	if i := st.Info; i != nil {
		in.Kubernetes, in.Nodes = i.Version, i.Nodes
	}
	if snap := st.Snapshot; snap != nil {
		if v, _, ok := snap.ExpectedVersion(); ok {
			in.K0s = v.Raw
		}
	}
	for _, c := range st.Findings {
		if c.ParentID == f.ID {
			in.Children = append(in.Children, c)
		}
	}
	return in
}

// aiViewOf is the AI part of a problem's page.
func (s *Server) aiViewOf(st *engine.State, f *findings.Finding, basic bool) *aiView {
	cfg := s.aiConfig()
	if !cfg.Ready() || f == nil {
		return nil
	}
	v := &aiView{Ready: true, Host: cfg.Host(), Model: cfg.Model, Answer: s.ai.answer(aiKey(st.Name, f.ID, basic), s.now())}
	for _, p := range ai.Presets {
		if p.ID == cfg.Provider && p.Local {
			v.Local = true
		}
	}
	v.Sent = ai.Messages(aiInput(st, f, basic, s.now()), cfg)
	return v
}

// apiExplainPreview shows what an explanation would send.
func (s *Server) apiExplainPreview(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	f := st.Finding(r.PathValue("id"))
	if f == nil {
		writeError(w, http.StatusNotFound, "there is no open problem with this ID")
		return
	}
	cfg := s.aiConfig()
	basic := r.URL.Query().Get("mode") != "full"
	out := map[string]any{"enabled": cfg.Ready(), "host": cfg.Host(), "model": cfg.Model,
		"messages": ai.Messages(aiInput(st, f, basic, s.now()), cfg)}
	if ans := s.ai.answer(aiKey(st.Name, f.ID, basic), s.now()); ans != nil {
		out["answer"] = map[string]any{"text": ans.Text, "by": ans.By, "model": ans.Model, "at": ans.At}
	}
	writeJSON(w, http.StatusOK, out)
}

var errAIOff = errors.New("Explain with AI is off: an administrator turns it on in Settings")

// apiExplain asks the model and streams its answer as server-sent events:
// "thinking" while the model thinks, "text" with each piece of the
// answer, then "done", or "error".
func (s *Server) apiExplain(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	f := st.Finding(r.PathValue("id"))
	if f == nil {
		writeError(w, http.StatusNotFound, "there is no open problem with this ID")
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
	basic := req.Mode != "full"
	cfg := s.aiConfig()
	if !cfg.Ready() {
		writeError(w, http.StatusConflict, errAIOff.Error())
		return
	}
	select {
	case s.ai.slots <- struct{}{}:
		defer func() { <-s.ai.slots }()
	default:
		writeError(w, http.StatusTooManyRequests, "other explanations are being written: try again in a moment")
		return
	}
	user := sessionUser(r)
	// Recorded first: if it can't be, nothing leaves.
	if err := s.o.Store.Audit(user, clientIP(r), "ai.explain", fmt.Sprintf("%s: %s %s (%s mode) to %s, model %s",
		e.Name(), f.RuleID, f.Resource.String(), ifStr(basic, "Basic", "Full"), cfg.Host(), cfg.Model)); err != nil {
		s.log.Error("writing the audit log", "err", err)
		writeError(w, http.StatusInternalServerError, "nothing was sent: the audit log can't be written")
		return
	}
	msgs := ai.Messages(aiInput(st, f, basic, s.now()), cfg)
	fl, _ := w.(http.Flusher)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(event string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if fl != nil {
			fl.Flush()
		}
	}
	thinking := false
	answer, err := ai.New(cfg, s.aiAPIKey()).Ask(r.Context(), msgs, ai.Handler{
		Text: func(t string) { send("text", t) },
		Thinking: func() {
			if !thinking {
				thinking = true
				send("thinking", true)
			}
		},
	})
	if err != nil {
		send("error", map[string]string{"message": err.Error()})
		return
	}
	if strings.TrimSpace(answer) == "" {
		send("error", map[string]string{"message": "the model answered with nothing"})
		return
	}
	ans := &aiAnswer{Text: answer, By: user, Model: cfg.Model, Host: cfg.Host(), At: s.now()}
	s.ai.keep(aiKey(st.Name, f.ID, basic), ans)
	send("done", map[string]any{"model": ans.Model, "by": ans.By, "at": ans.At})
}
