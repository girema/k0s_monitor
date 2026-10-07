package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"k0s_monitor/internal/auth"
)

// signIn returns a client of the same server signed in as another user.
func (env *testEnv) signIn(user, password string) *testEnv {
	env.t.Helper()
	other := *env
	other.cookie, other.csrf = nil, ""
	resp := other.do("POST", "/api/v1/session", strings.NewReader(`{"user":"`+user+`","password":"`+password+`"}`), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusOK {
		env.t.Fatalf("sign in as %s: %d %s", user, resp.StatusCode, readBody(env.t, resp))
	}
	var lr loginResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			other.cookie = c
		}
	}
	if lr.User != user || other.cookie == nil {
		env.t.Fatalf("signed in as %q", lr.User)
	}
	other.csrf = lr.CSRF
	return &other
}

func (env *testEnv) api(method, path, body string) (int, string) {
	env.t.Helper()
	resp := env.do(method, path, strings.NewReader(body), map[string]string{"Content-Type": "application/json", "X-CSRF-Token": env.csrf})
	return resp.StatusCode, readBody(env.t, resp)
}

func TestUsers(t *testing.T) {
	env := newEnv(t, nil)
	env.login()

	// Adding: the name is checked, and a taken name is refused. In this
	// order: the last one depends on the one before.
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"name":"Anna Smith","password":"annas long password"}`, http.StatusBadRequest},
		{`{"name":"anna","password":"short"}`, http.StatusBadRequest},
		{`{"name":"anna","password":"annas long password"}`, http.StatusCreated},
		{`{"name":"anna","password":"another long one"}`, http.StatusBadRequest},
	} {
		if code, msg := env.api("POST", "/api/v1/users", c.body); code != c.want {
			t.Errorf("%s: %d %s", c.body, code, msg)
		}
	}
	anna := env.signIn("anna", "annas long password")
	anna2 := env.signIn("anna", "annas long password")

	var us []apiUser
	_, body := env.api("GET", "/api/v1/users", "")
	json.Unmarshal([]byte(body), &us)
	if len(us) != 2 || us[1].Name != "anna" || us[1].SignedIn != 2 || us[1].CreatedBy != "admin" || us[1].LastSignIn == nil {
		t.Errorf("users = %s", body)
	}

	// Each page says who is signed in.
	mustContain(t, readBody(t, anna.do("GET", "/c/edge-prod", nil, nil)), "anna · Sign out")

	// "I'm on it" says who.
	crash := findingByRule(env, "pod.crashloop")
	if code, msg := anna.api("POST", "/api/v1/clusters/edge-prod/findings/"+crash.ID+"/ack", "{}"); code != http.StatusOK {
		t.Fatalf("ack: %d %s", code, msg)
	}
	if f := env.fleet.Get("edge-prod").State().Finding(crash.ID); f.StateBy != "anna" {
		t.Errorf("acknowledged by %q", f.StateBy)
	}
	mustContain(t, readBody(t, env.do("GET", "/c/edge-prod/problems?mode=full&show=all", nil, nil)), "acknowledged by anna")
	mustContain(t, readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=basic", nil, nil)), "anna is on it")

	// Each user reads their own notifications.
	if code, _ := env.api("POST", "/api/v1/notifications/read", `{"upTo":0}`); code != http.StatusOK {
		t.Fatal("mark read")
	}
	var admins struct{ Unread int }
	_, body = env.api("GET", "/api/v1/notifications", "")
	json.Unmarshal([]byte(body), &admins)
	if admins.Unread != 0 {
		t.Errorf("admin's unread after reading all: %d", admins.Unread)
	}

	// Changing your own password signs out your other browsers only.
	if code, msg := anna.api("POST", "/api/v1/password", `{"current":"annas long password","new":"annas new password"}`); code != http.StatusNoContent {
		t.Fatalf("anna's password: %d %s", code, msg)
	}
	if code, _ := anna2.api("GET", "/api/v1/users", ""); code != http.StatusUnauthorized {
		t.Errorf("anna's other browser: %d", code)
	}
	for who, e := range map[string]*testEnv{"anna": anna, "admin": env} {
		if code, _ := e.api("GET", "/api/v1/users", ""); code != http.StatusOK {
			t.Errorf("%s was signed out: %d", who, code)
		}
	}

	// Another user's password: set without the old one, and they are
	// signed out. Your own needs the current one.
	if code, _ := env.api("PUT", "/api/v1/users/admin/password", `{"password":"a new admin password"}`); code != http.StatusBadRequest {
		t.Errorf("setting your own password without the current one: %d", code)
	}
	if code, msg := env.api("PUT", "/api/v1/users/anna/password", `{"password":"set by the admin"}`); code != http.StatusNoContent {
		t.Fatalf("set anna's password: %d %s", code, msg)
	}
	if code, _ := anna.api("GET", "/api/v1/users", ""); code != http.StatusUnauthorized {
		t.Errorf("anna is still signed in after her password was set: %d", code)
	}
	anna = env.signIn("anna", "set by the admin")

	// Removing: not yourself, not the last user; the removed user is
	// signed out at once.
	if code, _ := env.api("DELETE", "/api/v1/users/admin", ""); code != http.StatusBadRequest {
		t.Errorf("removing yourself: %d", code)
	}
	if code, msg := anna.api("DELETE", "/api/v1/users/admin", ""); code != http.StatusNoContent {
		t.Fatalf("anna removes admin: %d %s", code, msg)
	}
	if code, _ := env.api("GET", "/api/v1/users", ""); code != http.StatusUnauthorized {
		t.Errorf("the removed admin is still signed in: %d", code)
	}
	if code, _ := anna.api("DELETE", "/api/v1/users/anna", ""); code != http.StatusBadRequest {
		t.Errorf("removing the last user: %d", code)
	}
	if code, _ := anna.api("DELETE", "/api/v1/users/nobody", ""); code != http.StatusBadRequest {
		t.Errorf("removing no one: %d", code)
	}

	// The audit log says who did what.
	log, _ := env.st.AuditLog(50)
	want := map[string]bool{"admin user.add anna": false, "anna finding.ack": false, "admin user.password anna": false, "anna user.remove admin": false, "anna sign-in": false}
	for _, a := range log {
		for k := range want {
			if strings.HasPrefix(a.User+" "+a.Action+" "+a.Detail, k) {
				want[k] = true
			}
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("the audit log lacks %q", k)
		}
	}
}

func TestSignInWithUserName(t *testing.T) {
	env := newEnv(t, nil)
	hash := func(pw string) string {
		h, err := auth.HashPassword(pw)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if err := env.st.AddUser("ivan", hash("ivans long password"), "admin"); err != nil {
		t.Fatal(err)
	}
	form := func(user, pw string) *http.Response {
		v := url.Values{"user": {user}, "password": {pw}, "next": {"/c/edge-prod"}}
		return env.do("POST", "/login", strings.NewReader(v.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
	// The same answer for a wrong name and a wrong password.
	for _, c := range [][2]string{{"ivan", "wrong wrong wrong"}, {"nobody", "ivans long password"}} {
		resp := form(c[0], c[1])
		if body := readBody(t, resp); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "Wrong user name or password") || !strings.Contains(body, `value="`+c[0]+`"`) {
			t.Errorf("%v: %d", c, resp.StatusCode)
		}
	}
	// A name that isn't an account isn't logged: it may be a password.
	log, _ := env.st.AuditLog(10)
	for _, a := range log {
		if a.User == "nobody" {
			t.Errorf("logged an unknown name: %+v", a)
		}
	}
	// Names are not case-sensitive; an empty name is admin.
	if resp := form(" Ivan ", "ivans long password"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/c/edge-prod" {
		t.Errorf("ivan: %d", resp.StatusCode)
	}
	if resp := form("", testPassword); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("admin without a name: %d", resp.StatusCode)
	}
	mustContain(t, readBody(t, env.do("GET", "/login", nil, nil)), `name="user"`, `autocomplete="username"`)
}

func TestHubPublishTo(t *testing.T) {
	h := newHub()
	a, b := h.subscribe("anna"), h.subscribe("ivan")
	h.publishTo("anna", "unread", map[string]int{"unread": 0})
	h.publish("state", "edge", map[string]string{})
	if len(a) != 2 || len(b) != 1 {
		t.Errorf("anna got %d, ivan %d", len(a), len(b))
	}
}
