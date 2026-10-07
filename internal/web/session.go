package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"k0s_monitor/internal/auth"
)

// sessionCookie uses the __Host- prefix: the browser only accepts it over
// HTTPS, for the whole site, and never for other hosts.
const sessionCookie = "__Host-k0sm-session"

// dummyHash is verified against for unknown user names, so that a wrong
// name takes as long as a wrong password.
var dummyHash = sync.OnceValue(func() string {
	h, _ := auth.HashPassword(auth.RandomToken())
	return h
})

// userOf reads the user name typed at sign-in; empty means admin, the
// account of versions with one password.
func userOf(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return auth.User
	}
	return name
}

func (s *Server) setSessionCookie(w http.ResponseWriter, sess *auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.ID, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

// errWrongSignIn doesn't say whether the name or the password was wrong.
const errWrongSignIn = "Wrong user name or password."

// checkPassword verifies a sign-in attempt, with the rate limit. It
// returns a message for the user when it fails.
func (s *Server) checkPassword(r *http.Request, user, password string) (bool, string) {
	ip := clientIP(r)
	if ok, wait := s.limiter.Allow(ip); !ok {
		return false, fmt.Sprintf("Too many failed attempts. Try again in %s.", roundWait(wait))
	}
	hash, err := s.o.Store.PasswordHash(user)
	if err != nil {
		// The details are for the log, not for someone not signed in.
		s.log.Error("sign-in: the user can't be read", "err", err)
		return false, "Sign-in doesn't work right now. The service's log says why."
	}
	// The audit log names the account only if it exists: what was typed
	// as a name may be a password typed into the wrong field.
	who := user
	if hash == "" {
		who = "?"
		if n, err := s.o.Store.UserCount(); err == nil && n == 0 {
			return false, "No password is set. On the jump host, run: sudo k0s-monitor passwd"
		}
		hash = dummyHash()
	}
	ok, err := s.verifyPassword(r, hash, password)
	if err != nil {
		return false, busySignIn
	}
	if !ok || hash == dummyHash() {
		s.limiter.Failure(ip)
		_ = s.o.Store.Audit(who, ip, "sign-in.failed", "")
		return false, errWrongSignIn
	}
	s.limiter.Success(ip)
	return true, ""
}

// busySignIn is the answer while too many passwords are being checked.
const busySignIn = "Too many sign-ins at the same time. Try again in a moment."

// verifyPassword checks a password, waiting for a free slot of the hashing
// gate: each check takes 64 MiB, so they are limited.
func (s *Server) verifyPassword(r *http.Request, hash, password string) (bool, error) {
	ok := false
	err := s.argon.Do(r.Context(), func() { ok = auth.VerifyPassword(hash, password) })
	return ok, err
}

// hashPassword hashes a new password through the same gate.
func (s *Server) hashPassword(r *http.Request, password string) (string, error) {
	if err := auth.CheckPasswordStrength(password); err != nil {
		return "", err
	}
	var hash string
	var herr error
	if err := s.argon.Do(r.Context(), func() { hash, herr = auth.HashPassword(password) }); err != nil {
		return "", errors.New("too many password changes at the same time; try again in a moment")
	}
	return hash, herr
}

// startSession signs a user in.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user, via string) *auth.Session {
	sess := s.sessions.Create(user, clientIP(r))
	s.setSessionCookie(w, sess)
	_ = s.o.Store.RecordSignIn(user)
	_ = s.o.Store.Audit(user, clientIP(r), "sign-in", via)
	return sess
}

func roundWait(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds())+1)
	}
	m := int(d.Round(time.Minute).Minutes())
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

// safeNext only allows local paths as the redirect target after sign-in.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.o.NoAuth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", &page{Title: "Sign in", Data: loginData{Next: safeNext(r.URL.Query().Get("next"))}})
}

type loginData struct {
	Next  string
	User  string
	Error string
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site sign-in refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	next := safeNext(r.PostFormValue("next"))
	user := userOf(r.PostFormValue("user"))
	ok, msg := s.checkPassword(r, user, r.PostFormValue("password"))
	if !ok {
		status := http.StatusUnauthorized
		if strings.HasPrefix(msg, "Too many") {
			status = http.StatusTooManyRequests
		}
		s.render(w, r, "login", &page{Title: "Sign in", Data: loginData{Next: next, User: r.PostFormValue("user"), Error: msg}, Status: status})
		return
	}
	s.startSession(w, r, user, "")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionOf(r); sess != nil && sess != s.implicit {
		s.sessions.Delete(sess.ID)
		s.audit(r, "sign-out", "")
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type loginRequest struct {
	// User is the user name; empty means admin.
	User     string `json:"user"`
	Password string `json:"password"`
}

type loginResponse struct {
	User string `json:"user"`
	CSRF string `json:"csrfToken"`
}

// apiLogin signs in API clients. The response carries the CSRF token to
// send as X-CSRF-Token with requests that change something.
func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-site sign-in refused")
		return
	}
	var req loginRequest
	if err := readJSON(r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.o.NoAuth {
		writeJSON(w, http.StatusOK, loginResponse{User: s.implicit.User, CSRF: s.implicit.CSRF})
		return
	}
	user := userOf(req.User)
	ok, msg := s.checkPassword(r, user, req.Password)
	if !ok {
		status := http.StatusUnauthorized
		if strings.HasPrefix(msg, "Too many") {
			status = http.StatusTooManyRequests
		}
		writeError(w, status, msg)
		return
	}
	sess := s.startSession(w, r, user, "api")
	writeJSON(w, http.StatusOK, loginResponse{User: sess.User, CSRF: sess.CSRF})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionOf(r); sess != nil && sess != s.implicit {
		s.sessions.Delete(sess.ID)
		s.audit(r, "sign-out", "api")
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type passwordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// changePassword checks the user's current password and stores the new
// one. It ends the user's other sessions; other users stay signed in.
func (s *Server) changePassword(r *http.Request, current, newPassword string) error {
	sess := sessionOf(r)
	if s.o.NoAuth || sess == nil {
		return fmt.Errorf("sign-in is off in this mode; there is no password to change")
	}
	if ok, msg := s.checkPassword(r, sess.User, current); !ok {
		if msg == errWrongSignIn {
			return fmt.Errorf("the current password is wrong")
		}
		return fmt.Errorf("%s", msg)
	}
	hash, err := s.hashPassword(r, newPassword)
	if err != nil {
		return err
	}
	if err := s.o.Store.SetPassword(sess.User, hash); err != nil {
		return err
	}
	s.sessions.DeleteUser(sess.User, sess.ID)
	s.audit(r, "password.change", "")
	return nil
}

func (s *Server) apiPassword(w http.ResponseWriter, r *http.Request) {
	var req passwordRequest
	if err := readJSON(r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.changePassword(r, req.Current, req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) passwordForm(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("new") != r.PostFormValue("confirm") {
		s.renderSettings(w, r, "", "The new passwords are not the same.")
		return
	}
	if err := s.changePassword(r, r.PostFormValue("current"), r.PostFormValue("new")); err != nil {
		s.renderSettings(w, r, "", upperFirst(err.Error())+".")
		return
	}
	s.renderSettings(w, r, "Your password was changed. Your other browsers were signed out.", "")
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
