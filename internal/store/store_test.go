package store

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/vault"
)

var t0 = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.New(bytes.Repeat([]byte{7}, vault.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "k0s-monitor.db")
	s, err := Open(path, v)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return t0 }
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestSettings(t *testing.T) {
	s, _ := open(t)
	if v, err := s.Setting("mode"); err != nil || v != "" {
		t.Errorf("unset: %q %v", v, err)
	}
	s.SetSetting("mode", "full")
	s.SetSetting("mode", "basic")
	if v, _ := s.Setting("mode"); v != "basic" {
		t.Errorf("mode = %q", v)
	}
}

// A secret setting is stored encrypted, and can be removed.
func TestSealedSettings(t *testing.T) {
	s, _ := open(t)
	if v, err := s.SealedSetting("ai.key"); err != nil || v != nil {
		t.Errorf("unset: %q %v", v, err)
	}
	if err := s.SetSealedSetting("ai.key", []byte("sk-live-123")); err != nil {
		t.Fatal(err)
	}
	if raw, _ := s.Setting("ai.key"); raw == "" || strings.Contains(raw, "sk-live") {
		t.Errorf("stored as %q", raw)
	}
	if v, err := s.SealedSetting("ai.key"); err != nil || string(v) != "sk-live-123" {
		t.Errorf("read back %q %v", v, err)
	}
	if err := s.SetSealedSetting("ai.key", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SealedSetting("ai.key"); v != nil {
		t.Errorf("not removed: %q", v)
	}
}

func TestControllers(t *testing.T) {
	s, _ := open(t)
	if cs, err := s.Controllers("edge"); err != nil || len(cs) != 0 {
		t.Fatalf("none yet: %v %v", cs, err)
	}
	want := []engine.KnownController{{Name: "ctrl-b", Address: "10.0.0.12:6443"}, {Address: "10.0.0.11:6443"}}
	if err := s.SetControllers("edge", want); err != nil {
		t.Fatal(err)
	}
	if err := s.SetControllers("other", want[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := s.Controllers("edge")
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("stored in order: %+v %v", got, err)
	}
	// Setting them again replaces the list.
	if err := s.SetControllers("edge", want[1:]); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Controllers("edge"); len(got) != 1 || got[0] != want[1] {
		t.Errorf("replaced: %+v", got)
	}
	// Removing a cluster forgets its controllers.
	if err := s.DeleteCluster("edge"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Controllers("edge"); len(got) != 0 {
		t.Errorf("after delete: %+v", got)
	}
	if got, _ := s.Controllers("other"); len(got) != 1 {
		t.Errorf("another cluster's: %+v", got)
	}
}

func TestUserStates(t *testing.T) {
	s, _ := open(t)
	until := t0.Add(time.Hour)
	s.SetUserState("edge", "a", engine.UserState{State: findings.StateAcknowledged, Priority: findings.P1})
	s.SetUserState("edge", "b", engine.UserState{State: findings.StateSnoozed, Until: &until, Priority: findings.P2})
	s.SetUserState("other", "c", engine.UserState{State: findings.StateAcknowledged, Priority: findings.P3})
	us, err := s.UserStates("edge")
	if err != nil || len(us) != 2 {
		t.Fatalf("states = %v %v", us, err)
	}
	if us["b"].State != findings.StateSnoozed || !us["b"].Until.Equal(until) || us["a"].Priority != findings.P1 {
		t.Errorf("states = %+v", us)
	}
	s.ClearUserState("edge", "a")
	if us, _ := s.UserStates("edge"); len(us) != 1 {
		t.Errorf("after clear: %v", us)
	}
}

func TestHistory(t *testing.T) {
	s, _ := open(t)
	first := t0.Add(-time.Hour)
	f := &findings.Finding{ID: "x1", Cluster: "edge", RuleID: "pod.crashloop", Priority: findings.P2,
		Title: "CrashLoopBackOff", Resource: findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"},
		FirstSeen: &first, LastSeen: &t0}
	f.Plain.Title = "The app api keeps crashing"
	s.RecordOpen(f)
	f.Priority = findings.P1
	s.RecordOpen(f) // an update, not a second occurrence
	open, _ := s.OpenFindings("edge")
	if len(open) != 1 || !open["x1"].Equal(first) {
		t.Fatalf("open = %v", open)
	}
	s.RecordResolved("edge", "x1", t0.Add(time.Minute))
	if open, _ := s.OpenFindings("edge"); len(open) != 0 {
		t.Errorf("still open: %v", open)
	}
	// It comes back later: a second occurrence.
	again := t0.Add(2 * time.Hour)
	f.FirstSeen, f.LastSeen = &again, &again
	s.RecordOpen(f)
	h, err := s.History("edge", "x1")
	if err != nil || len(h) != 2 {
		t.Fatalf("history = %+v %v", h, err)
	}
	if h[0].ResolvedAt != nil || h[1].ResolvedAt == nil || h[1].Priority != findings.P1 {
		t.Errorf("history = %+v", h)
	}
}

func TestNotifications(t *testing.T) {
	s, _ := open(t)
	for i, title := range []string{"one", "two", "three"} {
		n, err := s.AddNotification(Notification{Cluster: "edge", Kind: "opened", Priority: findings.P1, Title: title, PlainTitle: title})
		if err != nil || n.Seq != int64(i+1) {
			t.Fatalf("add: %+v %v", n, err)
		}
	}
	ns, unread, _ := s.Notifications("admin", 2)
	if len(ns) != 2 || ns[0].Title != "three" || unread != 3 {
		t.Errorf("list = %+v unread %d", ns, unread)
	}
	s.MarkRead("admin", 2)
	if ns, unread, _ := s.Notifications("admin", 10); unread != 1 || ns[0].Read || !ns[1].Read {
		t.Errorf("unread after marking up to 2 = %d, %+v", unread, ns)
	}
	// Each user reads for themselves; marking an older one doesn't undo.
	if _, unread, _ := s.Notifications("anna", 10); unread != 3 {
		t.Errorf("anna's unread = %d", unread)
	}
	s.MarkRead("admin", 1)
	s.MarkRead("anna", 0)
	if _, unread, _ := s.Notifications("admin", 10); unread != 1 {
		t.Errorf("admin's unread after anna read all = %d", unread)
	}
	if _, unread, _ := s.Notifications("anna", 10); unread != 0 {
		t.Errorf("anna's unread after marking all = %d", unread)
	}
}

func TestUsers(t *testing.T) {
	s, _ := open(t)
	if n, _ := s.UserCount(); n != 0 {
		t.Fatalf("a new database has no users: %d", n)
	}
	s.AddNotification(Notification{Cluster: "edge", Kind: "opened", Title: "before"})
	if err := s.AddUser("admin", "hash-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("anna", "hash-b", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("anna", "other", "admin"); err != ErrUserExists {
		t.Errorf("adding a taken name: %v", err)
	}
	if h, _ := s.PasswordHash("anna"); h != "hash-b" {
		t.Errorf("hash = %q", h)
	}
	if h, err := s.PasswordHash("nobody"); h != "" || err != nil {
		t.Errorf("unknown user: %q %v", h, err)
	}
	// A new user starts with nothing unread.
	if _, unread, _ := s.Notifications("anna", 10); unread != 0 {
		t.Errorf("a new user's unread = %d", unread)
	}
	if err := s.SetPassword("anna", "hash-c"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword("nobody", "x"); err != ErrNoUser {
		t.Errorf("password of an unknown user: %v", err)
	}
	s.RecordSignIn("anna")
	us, _ := s.Users()
	if len(us) != 2 || us[1].Name != "anna" || us[1].CreatedBy != "admin" || us[1].LastSignIn == nil || !us[1].LastSignIn.Equal(t0) || us[0].LastSignIn != nil {
		t.Errorf("users = %+v", us)
	}
	if err := s.DeleteUser("anna"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("anna"); err != ErrNoUser {
		t.Errorf("deleting twice: %v", err)
	}
	if n, _ := s.UserCount(); n != 1 {
		t.Errorf("users left: %d", n)
	}
	if err := s.DeleteUser("admin"); err != ErrLastUser {
		t.Errorf("deleting the last user: %v", err)
	}
}

// A database of a version with one password keeps it as the admin
// account, and what was read stays read.
func TestUpgradeKeepsThePassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{migrations[0], `PRAGMA user_version = 1`,
		`INSERT INTO settings (key, value) VALUES ('password', 'argon-hash')`,
		`INSERT INTO notifications (cluster, finding_id, kind, priority, title, plain_title, created, read) VALUES
			('edge', 'a', 'opened', 'P1', 'one', 'one', 1, 1), ('edge', 'b', 'opened', 'P1', 'two', 'two', 2, 0)`,
		`INSERT INTO user_state (cluster, id, state, priority, updated) VALUES ('edge', 'a', 'acknowledged', 'P1', 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if h, _ := s.PasswordHash("admin"); h != "argon-hash" {
		t.Errorf("admin's hash = %q", h)
	}
	if v, _ := s.Setting("password"); v != "" {
		t.Errorf("the old setting is gone: %q", v)
	}
	if _, unread, _ := s.Notifications("admin", 10); unread != 1 {
		t.Errorf("unread = %d", unread)
	}
	if us, _ := s.UserStates("edge"); us["a"].State != findings.StateAcknowledged || us["a"].By != "" {
		t.Errorf("user states = %+v", us)
	}
}

func TestAudit(t *testing.T) {
	s, _ := open(t)
	s.Audit("admin", "192.168.10.25", "sign-in", "")
	s.Audit("admin", "192.168.10.25", "cluster.add", "edge-prod")
	log, _ := s.AuditLog(10)
	if len(log) != 2 || log[0].Action != "cluster.add" || log[1].IP != "192.168.10.25" {
		t.Errorf("audit = %+v", log)
	}
}

func TestClustersAreEncrypted(t *testing.T) {
	s, path := open(t)
	kc := []byte("apiVersion: v1\nkind: Config\nusers: [{name: u, user: {token: s3cr3t-token}}]\n")
	err := s.SaveCluster(StoredCluster{
		Cluster: config.Cluster{Name: "edge-prod", KubeconfigData: kc, Server: "https://10.0.10.5:6443", Criticality: "high"},
		Account: "readonly", K0sctl: []byte("kind: Cluster"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	raw, _ := os.ReadFile(path)
	wal, _ := os.ReadFile(path + "-wal")
	if bytes.Contains(raw, []byte("s3cr3t-token")) || bytes.Contains(wal, []byte("s3cr3t-token")) {
		t.Fatal("credentials must be stored encrypted")
	}

	v, _ := vault.New(bytes.Repeat([]byte{7}, vault.KeySize))
	s2, err := Open(path, v)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	cs, err := s2.Clusters()
	if err != nil || len(cs) != 1 {
		t.Fatalf("clusters = %+v %v", cs, err)
	}
	c := cs[0]
	if !bytes.Equal(c.Cluster.KubeconfigData, kc) || c.Cluster.Server != "https://10.0.10.5:6443" ||
		c.Cluster.Criticality != "high" || !c.Cluster.FromUI || c.Account != "readonly" || string(c.K0sctl) != "kind: Cluster" {
		t.Errorf("cluster = %+v", c)
	}

	wrong, _ := vault.New(bytes.Repeat([]byte{8}, vault.KeySize))
	s3, _ := Open(path, wrong)
	defer s3.Close()
	if _, err := s3.Clusters(); err == nil {
		t.Error("the wrong key must not open stored credentials")
	}

	s2.SetUserState("edge-prod", "x", engine.UserState{State: findings.StateAcknowledged})
	if err := s2.DeleteCluster("edge-prod"); err != nil {
		t.Fatal(err)
	}
	if cs, _ := s2.Clusters(); len(cs) != 0 {
		t.Error("cluster not deleted")
	}
	if us, _ := s2.UserStates("edge-prod"); len(us) != 0 {
		t.Error("deleting a cluster deletes its data")
	}
}

func TestPrune(t *testing.T) {
	s, _ := open(t)
	old := t0.Add(-40 * 24 * time.Hour)
	f := &findings.Finding{ID: "old", Cluster: "edge", RuleID: "r", FirstSeen: &old, LastSeen: &old}
	s.RecordOpen(f)
	s.RecordResolved("edge", "old", old)
	s.AddNotification(Notification{Cluster: "edge", Kind: "opened", Created: old})
	past := t0.Add(-time.Minute)
	s.SetUserState("edge", "snoozed", engine.UserState{State: findings.StateSnoozed, Until: &past})
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.History("edge", "old"); len(h) != 0 {
		t.Error("old resolved findings are pruned")
	}
	if ns, _, _ := s.Notifications("admin", 10); len(ns) != 0 {
		t.Error("old notifications are pruned")
	}
	if us, _ := s.UserStates("edge"); len(us) != 0 {
		t.Error("expired snoozes are pruned")
	}
}

func TestReopenKeepsData(t *testing.T) {
	s, path := open(t)
	s.SetSetting("k", "v")
	s.Close()
	s2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, _ := s2.Setting("k"); v != "v" {
		t.Errorf("setting after reopen = %q", v)
	}
}

func TestAlertMutes(t *testing.T) {
	s, _ := open(t)
	until := t0.Add(time.Hour)
	if err := s.SetAlertMute(AlertMute{Cluster: "edge", Name: "HighIOUtilization", By: "ann", Until: &until}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertMute(AlertMute{Cluster: "edge", Name: "HighIOUtilization", Server: "worker-2", By: "bob", WhileFiring: true}); err != nil {
		t.Fatal(err)
	}
	// The same alerts again: replaced, not added.
	if err := s.SetAlertMute(AlertMute{Cluster: "edge", Name: "HighIOUtilization", By: "cy"}); err != nil {
		t.Fatal(err)
	}
	ms, err := s.AlertMutes("edge")
	if err != nil || len(ms) != 2 {
		t.Fatalf("mutes: %+v %v", ms, err)
	}
	if ms[0].Server != "" || ms[0].By != "cy" || ms[0].Until != nil || ms[1].Server != "worker-2" || !ms[1].WhileFiring || !ms[1].Created.Equal(t0) {
		t.Errorf("mutes: %+v", ms)
	}
	if other, _ := s.AlertMutes("other"); len(other) != 0 {
		t.Errorf("another cluster's: %+v", other)
	}
	if err := s.DeleteAlertMute("edge", "HighIOUtilization", "worker-2"); err != nil {
		t.Fatal(err)
	}
	if ms, _ = s.AlertMutes("edge"); len(ms) != 1 {
		t.Errorf("after delete: %+v", ms)
	}
}
