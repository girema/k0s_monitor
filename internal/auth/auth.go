// Package auth implements the single-user sign-in of the web UI (plan
// section 13): an Argon2id password hash, sessions that end after a period
// without activity, a CSRF token per session, a limit on failed sign-ins,
// and the optional allow-list of client addresses.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"k0s_monitor/internal/config"
)

// User is the name of the first account, made by init. It is also the
// user of laptop mode, which has no sign-in.
const User = "admin"

var userName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// CheckUserName says what is wrong with a user name, or nil.
func CheckUserName(name string) error {
	if !userName.MatchString(name) {
		return fmt.Errorf("a user name is 1 to 32 lower-case letters, digits, dots, dashes or underscores, starting with a letter")
	}
	return nil
}

// MinPasswordLength is the shortest password accepted.
const MinPasswordLength = 10

// Argon2id parameters: 64 MiB, 3 passes, 2 threads.
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword returns an Argon2id hash in the usual encoded form.
func HashPassword(password string) (string, error) {
	if err := CheckPasswordStrength(password); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, b64(salt), b64(key)), nil
}

// CheckPasswordStrength rejects passwords that are too short.
func CheckPasswordStrength(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("the password must have at least %d characters", MinPasswordLength)
	}
	return nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Gate bounds how many password hashes are computed at once. Each takes
// 64 MiB, so without a bound, many sign-ins at the same time, even wrong
// ones, could exhaust the memory and stop the service.
type Gate struct {
	slots chan struct{}
	wait  time.Duration
}

// ErrBusy means that too many password checks are running already.
var ErrBusy = errors.New("too many sign-ins at the same time")

// NewGate allows n hashes at once; a caller waits up to wait for a turn.
func NewGate(n int, wait time.Duration) *Gate {
	return &Gate{slots: make(chan struct{}, n), wait: wait}
}

// Do runs fn when a slot is free, or returns ErrBusy after the wait.
func (g *Gate) Do(ctx context.Context, fn func()) error {
	t := time.NewTimer(g.wait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ErrBusy
	}
	defer func() { <-g.slots }()
	fn()
	return nil
}

// RandomToken returns 32 random bytes, URL-safe base64.
func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system has no randomness; nothing is safe then
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Session is a signed-in browser.
type Session struct {
	ID       string
	CSRF     string
	User     string
	IP       string
	Created  time.Time
	LastSeen time.Time
}

// Sessions keeps sessions in memory: a restart signs everyone out.
type Sessions struct {
	mu   sync.Mutex
	m    map[string]*Session
	idle time.Duration
	max  time.Duration
	now  func() time.Time
}

// NewSessions ends sessions after idle without activity, and max after
// they started whatever the activity (0: no limit).
func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{m: map[string]*Session{}, idle: idle, max: max, now: time.Now}
}

// expired says whether a session has ended.
func (s *Sessions) expired(sess *Session, now time.Time) bool {
	return now.Sub(sess.LastSeen) > s.idle || s.max > 0 && now.Sub(sess.Created) > s.max
}

// Create starts a session.
func (s *Sessions) Create(user, ip string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess := &Session{ID: RandomToken(), CSRF: RandomToken(), User: user, IP: ip, Created: now, LastSeen: now}
	s.m[sess.ID] = sess
	s.gc(now)
	return sess
}

// Get returns a live session and records the activity.
func (s *Sessions) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, false
	}
	now := s.now()
	if s.expired(sess, now) {
		delete(s.m, id)
		return nil, false
	}
	sess.LastSeen = now
	cp := *sess
	return &cp, true
}

// Delete ends a session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// DeleteUser ends a user's sessions except keep (none when keep is ""),
// for example after their password changed or they were removed.
func (s *Sessions) DeleteUser(user, keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.User == user && k != keep {
			delete(s.m, k)
		}
	}
}

// Alive reports whether a session still exists, without counting it as
// activity.
func (s *Sessions) Alive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	return ok && !s.expired(sess, s.now())
}

// SignedIn counts the live sessions of each user.
func (s *Sessions) SignedIn() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := map[string]int{}
	for _, v := range s.m {
		if !s.expired(v, now) {
			out[v.User]++
		}
	}
	return out
}

func (s *Sessions) gc(now time.Time) {
	for k, v := range s.m {
		if s.expired(v, now) {
			delete(s.m, k)
		}
	}
}

// Limiter slows down password guessing: after 5 failed sign-ins from one
// address within 15 minutes, that address must wait, 1 minute at first
// and twice as long after every further failure, up to 15 minutes.
type Limiter struct {
	mu  sync.Mutex
	m   map[string]*attempts
	now func() time.Time
}

type attempts struct {
	failures     []time.Time
	blockedUntil time.Time
	penalty      time.Duration
}

const (
	limitFailures = 5
	limitWindow   = 15 * time.Minute
	limitMaxWait  = 15 * time.Minute
)

// NewLimiter creates a limiter.
func NewLimiter() *Limiter {
	return &Limiter{m: map[string]*attempts{}, now: time.Now}
}

// Allow reports whether ip may try to sign in, and if not, how long it
// must wait.
func (l *Limiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil {
		return true, 0
	}
	if wait := a.blockedUntil.Sub(l.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Failure records a failed sign-in.
func (l *Limiter) Failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	a := l.m[ip]
	if a == nil {
		a = &attempts{}
		l.m[ip] = a
	}
	recent := a.failures[:0]
	for _, t := range a.failures {
		if now.Sub(t) < limitWindow {
			recent = append(recent, t)
		}
	}
	a.failures = append(recent, now)
	l.prune(now)
	if len(a.failures) >= limitFailures {
		if a.penalty == 0 {
			a.penalty = time.Minute
		} else {
			a.penalty = min(a.penalty*2, limitMaxWait)
		}
		a.blockedUntil = now.Add(a.penalty)
	}
}

// prune forgets addresses that are no longer blocked and have no recent
// failures, so the map doesn't grow with every address that ever failed.
func (l *Limiter) prune(now time.Time) {
	for ip, a := range l.m {
		if now.Before(a.blockedUntil) {
			continue
		}
		recent := false
		for _, t := range a.failures {
			if now.Sub(t) < limitWindow {
				recent = true
				break
			}
		}
		if !recent {
			delete(l.m, ip)
		}
	}
}

// Success forgets the failures of ip.
func (l *Limiter) Success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, ip)
}

// AllowList holds the optional allowFrom entries.
type AllowList struct {
	prefixes []netip.Prefix
}

// NewAllowList parses allowFrom entries. An empty list allows everyone.
func NewAllowList(entries []string) (*AllowList, error) {
	al := &AllowList{}
	for _, e := range entries {
		p, err := config.ParseAllow(e)
		if err != nil {
			return nil, err
		}
		al.prefixes = append(al.prefixes, p)
	}
	return al, nil
}

// Allowed reports whether a client address may open the UI. Loopback is
// always allowed, so the jump host itself never locks itself out.
func (al *AllowList) Allowed(addr string) bool {
	if len(al.prefixes) == 0 {
		return true
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, p := range al.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ErrNoPassword means init has not been run.
var ErrNoPassword = errors.New("no password is set; run k0s-monitor init")
