package web

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const crashPod = "/c/edge-prod/pods/shop/payments-api-7c9f8d6b5-x2kqp"

func TestPodPage(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	body := readBody(t, env.do("GET", crashPod+"?mode=full", nil, nil))
	mustContain(t, body, "payments-api-7c9f8d6b5-x2kqp", "Describe", "Events", "Logs", "YAML", "Containers",
		"pod.crashloop", "/static/pod.js", "data-no-refresh", "shop/deployment/payments-api")
	body = readBody(t, env.do("GET", crashPod+"?mode=basic", nil, nil))
	mustContain(t, body, "The app payments-api", "What happened", "How to fix it", "Log lines that matter", "Show technical details")
	if strings.Contains(body, "pod.crashloop") {
		t.Error("Basic mode shows no rule IDs")
	}
	resp := env.do("GET", "/c/edge-prod/pods/shop/nope", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown pod: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPodAPI(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	base := "/api/v1/clusters/edge-prod/pods/shop/payments-api-7c9f8d6b5-x2kqp"
	var pod struct {
		Pod      map[string]any
		Live     bool
		Findings []map[string]any
	}
	resp := env.do("GET", base, nil, nil)
	json.NewDecoder(resp.Body).Decode(&pod)
	resp.Body.Close()
	if !pod.Live || len(pod.Findings) == 0 {
		t.Errorf("pod = %+v", pod)
	}
	if d := readBody(t, env.do("GET", base+"/describe", nil, nil)); !strings.Contains(d, "Name:") || !strings.Contains(d, "payments-api-7c9f8d6b5-x2kqp") {
		t.Errorf("describe = %s", d)
	}
	if y := readBody(t, env.do("GET", base+"/yaml", nil, nil)); !strings.Contains(y, "kind: Pod") || strings.Contains(y, "managedFields") {
		t.Errorf("yaml = %s", y)
	}
	if e := readBody(t, env.do("GET", base+"/events", nil, nil)); !strings.HasPrefix(strings.TrimSpace(e), "[") {
		t.Errorf("events = %s", e)
	}
	if l := readBody(t, env.do("GET", base+"/logs?container=api&tail=50", nil, nil)); l == "" {
		t.Error("logs are empty")
	}

	// Following a log is a stream of server-sent events.
	req, _ := http.NewRequest("GET", env.ts.URL+base+"/logs?container=api&follow=true", nil)
	req.AddCookie(env.cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := env.client().Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("follow content type %q", resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	sawData := false
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			sawData = true
		}
		if sc.Text() == "event: end" {
			break
		}
	}
	if !sawData {
		t.Error("no log lines were streamed")
	}
}
