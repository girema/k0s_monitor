package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"k0s_monitor/internal/auth"
)

func TestReportForSupport(t *testing.T) {
	env := newEnv(t, nil)
	env.login()

	// The page explains what goes in, in both modes.
	resp := env.do("GET", "/c/edge-prod/report?mode=basic", nil, nil)
	body := readBody(t, resp)
	mustContain(t, body, "Report for support", "Prepare the report", "Hide IP addresses", `name="logs" checked`, "data-no-refresh")
	resp = env.do("GET", "/c/edge-prod/report?mode=full", nil, nil)
	body = readBody(t, resp)
	mustContain(t, body, "Support bundle", "Prepare the bundle", "Include good-practice suggestions")
	// The Problems page and the sidebar link to it.
	resp = env.do("GET", "/c/edge-prod/problems?mode=basic", nil, nil)
	mustContain(t, readBody(t, resp), `href="/c/edge-prod/report">Download a report for support`)

	// Preparing it needs the CSRF token.
	form := url.Values{"logs": {"on"}, "maskIPs": {"on"}}
	resp = env.do("POST", "/c/edge-prod/report", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("prepare without CSRF: %d", resp.StatusCode)
	}
	resp.Body.Close()
	form.Set("csrf", env.csrf)
	resp = env.do("POST", "/c/edge-prod/report", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/c/edge-prod/report?id=") {
		t.Fatalf("prepare: %d %q", resp.StatusCode, loc)
	}
	id := strings.TrimPrefix(loc, "/c/edge-prod/report?id=")

	// The preview lists the files and frames the summary.
	resp = env.do("GET", loc+"&mode=basic", nil, nil)
	body = readBody(t, resp)
	mustContain(t, body, "Your report is ready", "Download the report", "k0s-monitor-report-edge-prod-", "describe/pod/shop/payments-api-7c9f8d6b5-x2kqp.txt",
		"logs/shop/payments-api-7c9f8d6b5-x2kqp/api.log", `<iframe class="report-frame" src="/c/edge-prod/report/`+id+`/files/index.html"`, "replaced by names")

	// The summary may be framed by this site only, and runs no scripts.
	resp = env.do("GET", "/c/edge-prod/report/"+id+"/files/index.html", nil, nil)
	sum := readBody(t, resp)
	csp := resp.Header.Get("Content-Security-Policy")
	if resp.StatusCode != 200 || !strings.Contains(csp, "frame-ancestors 'self'") || !strings.Contains(csp, "default-src 'none'") || resp.Header.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("summary: %d %q %q", resp.StatusCode, csp, resp.Header.Get("X-Frame-Options"))
	}
	mustContain(t, sum, "Report for support: edge-prod", "payments-api")
	if strings.Contains(sum, "10.0.10.5") || strings.Contains(sum, "10.244.1.37") {
		t.Error("IP addresses not masked in the summary")
	}
	// Other files are text.
	resp = env.do("GET", "/c/edge-prod/report/"+id+"/files/nodes.txt", nil, nil)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 200 || !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("nodes.txt: %d %s", resp.StatusCode, ct)
	}
	resp.Body.Close()
	resp = env.do("GET", "/c/edge-prod/report/"+id+"/files/../../etc/passwd", nil, nil)
	if resp.StatusCode == 200 {
		t.Error("a path outside the report answered")
	}
	resp.Body.Close()

	// The download is the previewed report, as a zip file, and is audited.
	resp = env.do("GET", "/c/edge-prod/report/"+id+"/download", nil, nil)
	zipped, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/zip" || !strings.Contains(resp.Header.Get("Content-Disposition"), "k0s-monitor-report-edge-prod-") {
		t.Fatalf("download: %d %v", resp.StatusCode, resp.Header)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil || len(zr.File) < 5 {
		t.Fatalf("zip: %v", err)
	}
	log, _ := env.st.AuditLog(20)
	var actions []string
	for _, a := range log {
		actions = append(actions, a.Action)
	}
	if !strings.Contains(strings.Join(actions, " "), "report.prepare") || !strings.Contains(strings.Join(actions, " "), "report.download") {
		t.Errorf("audit: %v", actions)
	}

	// Another user can't open it.
	hash, _ := auth.HashPassword("another long password")
	if err := env.st.AddUser("ivan", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	other := env.signIn("ivan", "another long password")
	resp = other.do("GET", "/c/edge-prod/report/"+id+"/download", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another user's download: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = other.do("GET", "/c/edge-prod/report?id="+id, nil, nil)
	mustContain(t, readBody(t, resp), "That report is gone")
}

func TestReportAPI(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	resp := env.do("GET", "/api/v1/clusters/edge-prod/report?preview=true&logs=false", nil, nil)
	var rep struct {
		Cluster string `json:"cluster"`
		Files   []struct {
			Path string `json:"path"`
			Size int    `json:"size"`
		} `json:"files"`
		Logs int `json:"logs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil || resp.StatusCode != 200 {
		t.Fatalf("preview: %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	if rep.Cluster != "edge-prod" || len(rep.Files) < 5 || rep.Logs != 0 {
		t.Errorf("preview: %+v", rep)
	}
	resp = env.do("GET", "/api/v1/clusters/edge-prod/report", nil, nil)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.HasPrefix(b, []byte("PK")) {
		t.Errorf("zip: %d", resp.StatusCode)
	}
	resp = env.do("GET", "/api/v1/clusters/nope/report", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown cluster: %d", resp.StatusCode)
	}
	resp.Body.Close()
}
