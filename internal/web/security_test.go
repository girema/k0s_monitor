package web

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMetricsNeedSignInOrToken(t *testing.T) {
	token := "scrape-" + strings.Repeat("x", 20)
	file := filepath.Join(t.TempDir(), "metrics.token")
	if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newEnv(t, func(o *Options) { o.Config.MetricsTokenFile = file })
	resp := env.do("GET", "/metrics", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
		t.Errorf("without sign-in: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.do("GET", "/metrics", nil, map[string]string{"Authorization": "Bearer wrong-" + token})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong token: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.do("GET", "/metrics", nil, map[string]string{"Authorization": "Bearer " + token})
	if resp.StatusCode != http.StatusOK || !strings.Contains(readBody(t, resp), "k0s_monitor_cluster_up") {
		t.Errorf("with the token: %d", resp.StatusCode)
	}
	env.login()
	if resp := env.do("GET", "/metrics", nil, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("signed in: %d", resp.StatusCode)
	}

	// A short token is refused when the server starts.
	if err := os.WriteFile(file, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := env.srv.o
	if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Errorf("short token: %v", err)
	}
}

func TestSignInWhileBusy(t *testing.T) {
	env := newEnv(t, nil)
	// All password checks are taken: another sign-in is refused quickly
	// instead of piling up 64 MiB hashes.
	release := make(chan struct{})
	var started sync.WaitGroup
	for i := 0; i < argonSlots; i++ {
		started.Add(1)
		go env.srv.argon.Do(context.Background(), func() { started.Done(); <-release })
	}
	started.Wait()
	resp := env.do("POST", "/api/v1/session", strings.NewReader(`{"password":"`+testPassword+`"}`), map[string]string{"Content-Type": "application/json"})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "Too many sign-ins at the same time") {
		t.Errorf("busy: %d %s", resp.StatusCode, body)
	}
	close(release)
	// A busy refusal isn't a failed attempt: signing in works right after.
	env.login()
}
