package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short passwords are rejected")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("hash = %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Error("the right password must verify")
	}
	if VerifyPassword(h, "correct horse batterY") || VerifyPassword("garbage", "x") || VerifyPassword("", "") {
		t.Error("wrong passwords and bad hashes must fail")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("each hash uses a new salt")
	}
}

func TestSessions(t *testing.T) {
	now := time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)
	s := NewSessions(12*time.Hour, 24*time.Hour)
	s.now = func() time.Time { return now }
	a := s.Create(User, "192.168.10.25")
	b := s.Create(User, "192.168.10.26")
	if a.ID == b.ID || a.CSRF == a.ID || len(a.ID) < 40 {
		t.Errorf("tokens must be random and distinct: %+v", a)
	}
	now = now.Add(11 * time.Hour)
	if _, ok := s.Get(a.ID); !ok {
		t.Error("activity within the idle time keeps the session")
	}
	now = now.Add(11 * time.Hour)
	if _, ok := s.Get(a.ID); !ok {
		t.Error("the last activity counts, not the creation")
	}
	if _, ok := s.Get(b.ID); ok {
		t.Error("a session idle for 22 h has ended")
	}
	now = now.Add(3 * time.Hour)
	if _, ok := s.Get(a.ID); ok || s.Alive(a.ID) {
		t.Error("a session used all along ends 24 h after sign-in")
	}
	a = s.Create(User, "192.168.10.25")
	c := s.Create(User, "x")
	anna := s.Create("anna", "y")
	if n := s.SignedIn(); n[User] != 2 || n["anna"] != 1 {
		t.Errorf("signed in: %v", n)
	}
	s.DeleteUser(User, c.ID)
	if _, ok := s.Get(a.ID); ok {
		t.Error("the user's other sessions end after a password change")
	}
	if _, ok := s.Get(c.ID); !ok || !s.Alive(anna.ID) {
		t.Error("the current session and other users' sessions stay")
	}
	s.DeleteUser("anna", "")
	if s.Alive(anna.ID) {
		t.Error("a removed user's sessions end")
	}
	s.Delete(c.ID)
	if _, ok := s.Get(c.ID); ok {
		t.Error("sign-out ends the session")
	}
}

func TestCheckUserName(t *testing.T) {
	for name, ok := range map[string]bool{"admin": true, "anna.k": true, "ivan_2": true, "o-p": true,
		"": false, "Anna": false, "2fast": false, "a b": false, "anna@corp": false, strings.Repeat("a", 33): false} {
		if err := CheckUserName(name); (err == nil) != ok {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		l.Failure("1.2.3.4")
	}
	if ok, _ := l.Allow("1.2.3.4"); !ok {
		t.Error("four failures are allowed")
	}
	l.Failure("1.2.3.4")
	if ok, wait := l.Allow("1.2.3.4"); ok || wait != time.Minute {
		t.Errorf("the fifth failure blocks for a minute: %v %v", ok, wait)
	}
	if ok, _ := l.Allow("5.6.7.8"); !ok {
		t.Error("other addresses are not affected")
	}
	now = now.Add(61 * time.Second)
	l.Failure("1.2.3.4")
	if _, wait := l.Allow("1.2.3.4"); wait != 2*time.Minute {
		t.Errorf("the wait doubles: %v", wait)
	}
	l.Success("1.2.3.4")
	if ok, _ := l.Allow("1.2.3.4"); !ok {
		t.Error("a successful sign-in resets the count")
	}

	// Addresses are forgotten once they are neither blocked nor recent.
	for i := 0; i < 100; i++ {
		l.Failure(fmt.Sprintf("10.0.0.%d", i))
	}
	now = now.Add(limitWindow + time.Second)
	l.Failure("5.6.7.8")
	l.mu.Lock()
	n := len(l.m)
	l.mu.Unlock()
	if n != 1 {
		t.Errorf("%d addresses kept, want only the recent one", n)
	}
}

func TestGate(t *testing.T) {
	g := NewGate(2, 50*time.Millisecond)
	var running, most atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- g.Do(context.Background(), func() {
				n := running.Add(1)
				for {
					m := most.Load()
					if n <= m || most.CompareAndSwap(m, n) {
						break
					}
				}
				<-release
				running.Add(-1)
			})
		}()
	}
	// Three wait for a slot and give up after 50 ms.
	busy := 0
	for i := 0; i < 3; i++ {
		if err := <-errs; errors.Is(err, ErrBusy) {
			busy++
		}
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a running hash failed: %v", err)
		}
	}
	if busy != 3 || most.Load() != 2 {
		t.Errorf("%d refused, at most %d at once; want 3 and 2", busy, most.Load())
	}
	// A slot frees up: the next one runs.
	if err := g.Do(context.Background(), func() {}); err != nil {
		t.Errorf("after the others: %v", err)
	}
}

func TestAllowList(t *testing.T) {
	open, _ := NewAllowList(nil)
	if !open.Allowed("8.8.8.8") {
		t.Error("an empty list allows everyone")
	}
	al, err := NewAllowList([]string{"192.168.10.25", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"192.168.10.25": true, "192.168.10.26": false, "10.20.30.40": true,
		"127.0.0.1": true, "::1": true, "::ffff:192.168.10.25": true, "garbage": false,
	} {
		if al.Allowed(addr) != want {
			t.Errorf("%s: allowed = %v, want %v", addr, !want, want)
		}
	}
	if _, err := NewAllowList([]string{"not-an-ip"}); err == nil {
		t.Error("bad entries are rejected")
	}
}
