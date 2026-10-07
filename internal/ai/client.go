package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Message is one message of a chat.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Client talks to an OpenAI-compatible API.
type Client struct {
	cfg Config
	key string
	hc  *http.Client
}

// New returns a client. key may be empty: local servers need none. The
// usual proxy variables (HTTPS_PROXY, NO_PROXY) apply.
func New(cfg Config, key string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	return &Client{cfg: cfg, key: key, hc: &http.Client{Transport: tr}}
}

func (c *Client) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+"/"+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, c.connError(ctx, err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, &APIError{Status: resp.StatusCode, Message: providerMessage(b)}
	}
	return resp, nil
}

// Models lists the models the API offers, by name.
func (c *Client) Models(ctx context.Context) ([]string, error) {
	resp, err := c.request(ctx, http.MethodGet, "models", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("the model list isn't in the expected form: %w", err)
	}
	var out []string
	for _, m := range r.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Handler receives an answer as it arrives: pieces of its text, and a
// note while the model thinks before answering.
type Handler struct {
	Text     func(string)
	Thinking func()
}

// Ask sends the messages and streams the answer to h; it returns the
// whole answer. A model's thinking ("reasoning", or text between <think>
// and </think>) is left out.
func (c *Client) Ask(ctx context.Context, msgs []Message, h Handler) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout())
	defer cancel()
	body := map[string]any{"model": c.cfg.Model, "messages": msgs, "stream": true}
	if c.cfg.MaxTokens > 0 {
		body["max_tokens"] = c.cfg.MaxTokens
	}
	resp, err := c.request(ctx, http.MethodPost, "chat/completions", body)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest && strings.Contains(apiErr.Message, "max_completion_tokens") {
		// Newer OpenAI models take max_completion_tokens instead.
		delete(body, "max_tokens")
		body["max_completion_tokens"] = c.cfg.MaxTokens
		resp, err = c.request(ctx, http.MethodPost, "chat/completions", body)
	}
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out strings.Builder
	f := &thinkFilter{}
	emit := func(s string, thinking bool) {
		if thinking && h.Thinking != nil {
			h.Thinking()
		}
		if s == "" {
			return
		}
		out.WriteString(s)
		if h.Text != nil {
			h.Text(s)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		// An API that doesn't stream answers at once.
		var r chunk
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); err != nil {
			return "", fmt.Errorf("the answer isn't in the expected form: %w", err)
		}
		if r.Error != nil {
			return "", &APIError{Status: resp.StatusCode, Message: r.Error.Message}
		}
		if len(r.Choices) > 0 {
			emit(f.feed(r.Choices[0].Message.Content))
		}
		emit(f.flush(), false)
		return strings.TrimSpace(out.String()), nil
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			break
		}
		var ch chunk
		if json.Unmarshal([]byte(data), &ch) != nil {
			continue
		}
		if ch.Error != nil {
			return out.String(), &APIError{Status: http.StatusOK, Message: ch.Error.Message}
		}
		for _, choice := range ch.Choices {
			if choice.Delta.ReasoningContent != "" || choice.Delta.Reasoning != "" {
				emit("", true)
			}
			emit(f.feed(choice.Delta.Content))
		}
	}
	emit(f.flush(), false)
	if err := sc.Err(); err != nil {
		return out.String(), c.connError(ctx, err)
	}
	return strings.TrimSpace(out.String()), nil
}

// Test checks the settings: it lists the models, and asks the model for a
// word when one is set. reply is what the model said.
func (c *Client) Test(ctx context.Context) (models []string, reply string, err error) {
	mctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	models, merr := c.Models(mctx)
	cancel()
	if c.cfg.Model == "" {
		return models, "", merr
	}
	reply, err = c.Ask(ctx, []Message{{Role: "user", Content: "Reply with the single word OK."}}, Handler{})
	if err != nil {
		return models, "", err
	}
	return models, reply, nil
}

// chunk is a streamed piece of an answer, or a whole answer.
type chunk struct {
	Choices []struct {
		Delta struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
			Reasoning        string `json:"reasoning"`
		} `json:"delta"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// APIError is an error the API answered with.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	head, advice := "The API answered with an error", ""
	switch {
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		head, advice = "The API refused the key", ": check the API key, and that it may use this model"
	case e.Status == http.StatusNotFound:
		head, advice = "The API has no such address or model", ": check the address (it usually ends in /v1) and the model's name"
	case e.Status == http.StatusTooManyRequests:
		head, advice = "The API says there were too many requests", ", or the account has no credit left"
	case e.Status == http.StatusBadRequest:
		head = "The API refused the request"
	case e.Status >= 500:
		head = "The API had an error"
	}
	if e.Status != http.StatusOK {
		head += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	msg := head + advice + "."
	if e.Message != "" {
		msg += " It says: " + e.Message
	}
	return msg
}

// providerMessage takes the message out of an error answer.
func providerMessage(b []byte) string {
	var r struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Detail  string          `json:"detail"`
	}
	msg := ""
	if json.Unmarshal(b, &r) == nil {
		var obj struct {
			Message string `json:"message"`
		}
		var s string
		switch {
		case json.Unmarshal(r.Error, &obj) == nil && obj.Message != "":
			msg = obj.Message
		case json.Unmarshal(r.Error, &s) == nil && s != "":
			msg = s
		case r.Message != "":
			msg = r.Message
		case r.Detail != "":
			msg = r.Detail
		}
	}
	if msg == "" {
		msg = strings.TrimSpace(string(b))
		if strings.HasPrefix(msg, "<") {
			msg = "" // an HTML error page says nothing useful
		}
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

// connError explains a failed connection.
func (c *Client) connError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("no answer within %d seconds: the model may be slow, or the time limit in Settings too short", int(c.cfg.Timeout().Seconds()))
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.New("stopped")
	}
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return fmt.Errorf("the name %s can't be resolved from this host", dnsErr.Name)
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return fmt.Errorf("nothing answers at %s: is the server running, and can this host reach it? (%v)", c.cfg.Host(), opErr.Err)
	}
	return fmt.Errorf("can't reach %s: %v", c.cfg.Host(), err)
}

// thinkFilter removes <think>…</think> from a streamed answer, which some
// models (DeepSeek R1, Qwen) write before the answer itself.
type thinkFilter struct {
	in   bool
	hold string
}

const thinkOpen, thinkClose = "<think>", "</think>"

// feed returns the text to show, and whether the model is thinking.
func (f *thinkFilter) feed(s string) (string, bool) {
	s = f.hold + s
	f.hold = ""
	var out strings.Builder
	thinking := false
	for s != "" {
		if f.in {
			thinking = true
			if i := strings.Index(s, thinkClose); i >= 0 {
				f.in = false
				s = s[i+len(thinkClose):]
				continue
			}
			f.hold = partialSuffix(s, thinkClose)
			return out.String(), thinking
		}
		if i := strings.Index(s, thinkOpen); i >= 0 {
			out.WriteString(s[:i])
			f.in = true
			s = s[i+len(thinkOpen):]
			continue
		}
		f.hold = partialSuffix(s, thinkOpen)
		out.WriteString(s[:len(s)-len(f.hold)])
		break
	}
	return out.String(), thinking
}

// flush returns what was held back at the end.
func (f *thinkFilter) flush() string {
	h := f.hold
	f.hold = ""
	if f.in {
		return ""
	}
	return h
}

// partialSuffix returns the end of s that could start tag.
func partialSuffix(s, tag string) string {
	for n := min(len(tag)-1, len(s)); n > 0; n-- {
		if strings.HasPrefix(tag, s[len(s)-n:]) {
			return s[len(s)-n:]
		}
	}
	return ""
}
