// Package ai explains a problem with a language model the administrator
// chooses ("Explain with AI", plan section 10.5 and M5). It talks to any API
// that follows OpenAI's chat completions: the providers' own (OpenAI,
// Anthropic, DeepSeek, Qwen, Gemini, Mistral, OpenRouter) and the servers
// that run a model locally (Ollama, LM Studio, llama.cpp, vLLM). It is
// off until someone turns it on, and sends only a redacted description of
// one problem, which the user can see first.
package ai

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Config is how to reach the model. The API key is kept apart, encrypted.
type Config struct {
	Enabled bool `json:"enabled"`
	// Provider is a preset's ID, or "custom".
	Provider string `json:"provider"`
	// BaseURL is the API's address up to /chat/completions, such as
	// https://api.openai.com/v1.
	BaseURL string `json:"baseUrl"`
	Model   string `json:"model"`
	// Language is the language of the answers, such as English.
	Language string `json:"language,omitempty"`
	// MaxTokens caps the answer's length; 0 leaves it to the provider.
	MaxTokens int `json:"maxTokens,omitempty"`
	// TimeoutSeconds is how long an answer may take; 0 means 180.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// MaskIPs replaces IP addresses in what is sent with ip-1, ip-2, ….
	MaskIPs bool `json:"maskIPs"`
	// NoLogs leaves the log lines out of what is sent.
	NoLogs bool `json:"noLogs,omitempty"`
}

// Timeout is how long an answer may take.
func (c Config) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 180 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// AnswerLanguage is the language to answer in.
func (c Config) AnswerLanguage() string {
	if strings.TrimSpace(c.Language) == "" {
		return "English"
	}
	return strings.TrimSpace(c.Language)
}

// Host is the API's host, for the audit log and the pages.
func (c Config) Host() string {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return c.BaseURL
	}
	return u.Host
}

// Ready reports whether answers can be asked for.
func (c Config) Ready() bool { return c.Enabled && c.BaseURL != "" && c.Model != "" }

// Check reports what is wrong with the settings.
func (c Config) Check() error {
	if c.BaseURL == "" {
		return errors.New("enter the API's address")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%q is not an http:// or https:// address", c.BaseURL)
	}
	if u.User != nil {
		return errors.New("put the API key in its own field, not in the address")
	}
	if c.Enabled && strings.TrimSpace(c.Model) == "" {
		return errors.New("enter the model's name (Test lists the ones the API offers)")
	}
	if c.MaxTokens < 0 || c.MaxTokens > 200000 {
		return errors.New("the answer length must be between 0 (the provider's default) and 200000 tokens")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 1800 {
		return errors.New("the time limit must be between 0 (180 seconds) and 1800 seconds")
	}
	return nil
}

// Normalize trims the settings and drops a trailing /chat/completions
// from the address, which people paste from the providers' docs.
func (c *Config) Normalize() {
	c.BaseURL = strings.TrimSpace(c.BaseURL)
	c.BaseURL = strings.TrimSuffix(strings.TrimSuffix(c.BaseURL, "/"), "/chat/completions")
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	c.Model = strings.TrimSpace(c.Model)
	c.Language = strings.TrimSpace(c.Language)
	if c.Provider == "" {
		c.Provider = "custom"
	}
}

// Preset is a provider whose OpenAI-compatible address is known.
type Preset struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	BaseURL string `json:"baseUrl,omitempty"`
	// Local runs on your own machine or network: nothing leaves it.
	Local bool `json:"local"`
	// Key says whether it needs an API key.
	Key  bool   `json:"key"`
	Note string `json:"note,omitempty"`
}

// Presets are the providers the settings offer. Their addresses are the
// providers' documented OpenAI-compatible endpoints; local servers listen
// on their default ports, on 127.0.0.1 until changed.
var Presets = []Preset{
	{ID: "ollama", Name: "Ollama (local)", BaseURL: "http://127.0.0.1:11434/v1", Local: true,
		Note: "Runs open models (Llama, Qwen, Mistral, gpt-oss, …) on a machine of yours. Use that machine's address if it isn't the jump host."},
	{ID: "lmstudio", Name: "LM Studio (local)", BaseURL: "http://127.0.0.1:1234/v1", Local: true},
	{ID: "llamacpp", Name: "llama.cpp server (local)", BaseURL: "http://127.0.0.1:8080/v1", Local: true},
	{ID: "vllm", Name: "vLLM (local)", BaseURL: "http://127.0.0.1:8000/v1", Local: true},
	{ID: "openai", Name: "OpenAI (ChatGPT)", BaseURL: "https://api.openai.com/v1", Key: true},
	{ID: "anthropic", Name: "Anthropic (Claude)", BaseURL: "https://api.anthropic.com/v1", Key: true,
		Note: "Through Anthropic's OpenAI-compatible API."},
	{ID: "deepseek", Name: "DeepSeek", BaseURL: "https://api.deepseek.com/v1", Key: true},
	{ID: "qwen", Name: "Qwen (Alibaba Cloud Model Studio)", BaseURL: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", Key: true,
		Note: "In mainland China: https://dashscope.aliyuncs.com/compatible-mode/v1."},
	{ID: "gemini", Name: "Google Gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", Key: true},
	{ID: "mistral", Name: "Mistral", BaseURL: "https://api.mistral.ai/v1", Key: true},
	{ID: "openrouter", Name: "OpenRouter (many models)", BaseURL: "https://openrouter.ai/api/v1", Key: true},
	{ID: "custom", Name: "Another OpenAI-compatible API", Key: true},
}

// PresetOf returns a preset by ID.
func PresetOf(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
