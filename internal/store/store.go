// Package store keeps what must survive a restart in one SQLite file:
// settings, acknowledgements and snoozes, finding history, notifications,
// the audit log and clusters added in the UI, whose credentials are
// encrypted.
package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/pack"
	"k0s_monitor/internal/vault"
)

// Retention is how long resolved findings, notifications and audit
// entries are kept.
const Retention = 30 * 24 * time.Hour

// Store is the database. It is safe for concurrent use.
type Store struct {
	db    *sql.DB
	vault *vault.Vault
	now   func() time.Time
}

var _ engine.Store = (*Store)(nil)

var migrations = []string{
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
	CREATE TABLE user_state (
		cluster TEXT NOT NULL, id TEXT NOT NULL, state TEXT NOT NULL,
		until INTEGER, priority TEXT NOT NULL, updated INTEGER NOT NULL,
		PRIMARY KEY (cluster, id));
	CREATE TABLE history (
		cluster TEXT NOT NULL, id TEXT NOT NULL, rule TEXT NOT NULL,
		resource TEXT NOT NULL, title TEXT NOT NULL, plain_title TEXT NOT NULL,
		priority TEXT NOT NULL, first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL, resolved_at INTEGER,
		PRIMARY KEY (cluster, id, first_seen));
	CREATE INDEX history_open ON history (cluster, resolved_at);
	CREATE TABLE notifications (
		seq INTEGER PRIMARY KEY AUTOINCREMENT, cluster TEXT NOT NULL,
		finding_id TEXT NOT NULL, kind TEXT NOT NULL, priority TEXT NOT NULL,
		title TEXT NOT NULL, plain_title TEXT NOT NULL, created INTEGER NOT NULL,
		read INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE audit (
		seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
		user TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL,
		detail TEXT NOT NULL);
	CREATE TABLE clusters (
		name TEXT PRIMARY KEY, spec TEXT NOT NULL, kubeconfig BLOB NOT NULL,
		k0sctl BLOB, k0s_config BLOB, account TEXT NOT NULL,
		created INTEGER NOT NULL);`,
	// Named users, each with a password. The one password of earlier
	// versions becomes the admin account. Notifications are read per user;
	// acknowledging or snoozing records who did it.
	`CREATE TABLE users (
		name TEXT PRIMARY KEY, hash TEXT NOT NULL, created INTEGER NOT NULL,
		created_by TEXT NOT NULL DEFAULT '', last_sign_in INTEGER);
	CREATE TABLE notification_reads (user TEXT PRIMARY KEY, seq INTEGER NOT NULL);
	ALTER TABLE user_state ADD COLUMN by_user TEXT NOT NULL DEFAULT '';
	INSERT INTO users (name, hash, created)
		SELECT 'admin', value, CAST(strftime('%s', 'now') AS INTEGER) * 1000
		FROM settings WHERE key = 'password' AND value != '';
	INSERT INTO notification_reads (user, seq)
		SELECT 'admin', COALESCE(MAX(seq), 0) FROM notifications WHERE read = 1;
	DELETE FROM settings WHERE key = 'password';`,
	// The controllers k0s-monitor reached at their own addresses, to fail
	// over to when a cluster's kubeconfig server doesn't answer.
	`CREATE TABLE controllers (
		cluster TEXT NOT NULL, address TEXT NOT NULL, name TEXT NOT NULL,
		PRIMARY KEY (cluster, address));`,
	// Product packs uploaded in the UI.
	`CREATE TABLE packs (
		name TEXT PRIMARY KEY, data BLOB NOT NULL, uploaded_by TEXT NOT NULL,
		uploaded INTEGER NOT NULL);`,
	// Prometheus alerts hidden in k0s-monitor, by name and maybe server.
	`CREATE TABLE alert_mutes (
		cluster TEXT NOT NULL, name TEXT NOT NULL, server TEXT NOT NULL,
		until INTEGER, while_firing INTEGER NOT NULL, by_user TEXT NOT NULL, created INTEGER NOT NULL,
		PRIMARY KEY (cluster, name, server));`,
}

// Open opens (and creates or upgrades) the database. v encrypts cluster
// credentials; it may be nil when no clusters are stored.
func Open(path string, v *vault.Vault) (*Store, error) {
	// Create the file readable by the owner only; SQLite gives its WAL
	// and shared-memory files the same mode.
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err == nil {
		f.Close()
		_ = os.Chmod(path, 0o600)
	}
	// secure_delete overwrites what is deleted, such as replaced
	// credentials, instead of leaving it in free pages.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: writes are rare and small, and it avoids "database
	// is locked" between connections.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, vault: v, now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("preparing the database %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("the database was created by a newer version of k0s-monitor (schema %d)", v)
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func nullMS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ms(*t)
}

// ---------------------------------------------------------------------------
// Settings

// Setting returns a setting, or "" if it is not set.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// SetSealedSetting stores a secret setting, such as an API key, encrypted
// with the key that protects the clusters' credentials. An empty value
// removes it.
func (s *Store) SetSealedSetting(key string, value []byte) error {
	if len(value) == 0 {
		_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, key)
		return err
	}
	if s.vault == nil {
		return errors.New("no key to encrypt it; run k0s-monitor init")
	}
	sealed, err := s.vault.Seal(value)
	if err != nil {
		return err
	}
	return s.SetSetting(key, base64.StdEncoding.EncodeToString(sealed))
}

// SealedSetting returns a secret setting, decrypted; nil when not set.
func (s *Store) SealedSetting(key string) ([]byte, error) {
	v, err := s.Setting(key)
	if err != nil || v == "" {
		return nil, err
	}
	if s.vault == nil {
		return nil, errors.New("no key to decrypt it")
	}
	sealed, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	return s.vault.Open(sealed)
}

// ---------------------------------------------------------------------------
// Hidden alerts

// AlertMute hides a Prometheus alert in k0s-monitor: every alert of that
// name in the cluster, or only those about one server. Prometheus and its
// Alertmanager are never changed.
type AlertMute struct {
	Cluster string `json:"cluster"`
	Name    string `json:"name"`
	// Server is the node or controller; empty hides the name everywhere.
	Server string `json:"server,omitempty"`
	// Until ends it; nil means always, or while the alert fires.
	Until *time.Time `json:"until,omitempty"`
	// WhileFiring ends it once no such alert fires any more.
	WhileFiring bool      `json:"whileFiring,omitempty"`
	By          string    `json:"by"`
	Created     time.Time `json:"created"`
}

// SetAlertMute hides alerts, replacing a hiding of the same alerts.
func (s *Store) SetAlertMute(m AlertMute) error {
	if m.Created.IsZero() {
		m.Created = s.now()
	}
	_, err := s.db.Exec(`INSERT INTO alert_mutes (cluster, name, server, until, while_firing, by_user, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (cluster, name, server) DO UPDATE SET until = excluded.until,
			while_firing = excluded.while_firing, by_user = excluded.by_user, created = excluded.created`,
		m.Cluster, m.Name, m.Server, nullMS(m.Until), boolInt(m.WhileFiring), m.By, ms(m.Created))
	return err
}

// AlertMutes returns the cluster's hidden alerts, ended ones included.
func (s *Store) AlertMutes(cluster string) ([]AlertMute, error) {
	rows, err := s.db.Query(`SELECT name, server, until, while_firing, by_user, created FROM alert_mutes
		WHERE cluster = ? ORDER BY name, server`, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertMute
	for rows.Next() {
		m := AlertMute{Cluster: cluster}
		var until sql.NullInt64
		var firing int
		var created int64
		if err := rows.Scan(&m.Name, &m.Server, &until, &firing, &m.By, &created); err != nil {
			return nil, err
		}
		if until.Valid {
			t := fromMS(until.Int64)
			m.Until = &t
		}
		m.WhileFiring, m.Created = firing == 1, fromMS(created)
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteAlertMute shows hidden alerts again.
func (s *Store) DeleteAlertMute(cluster, name, server string) error {
	_, err := s.db.Exec(`DELETE FROM alert_mutes WHERE cluster = ? AND name = ? AND server = ?`, cluster, name, server)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Acknowledge and snooze (engine.Store)

// SetUserState acknowledges or snoozes a finding.
func (s *Store) SetUserState(cluster, id string, us engine.UserState) error {
	_, err := s.db.Exec(`INSERT INTO user_state (cluster, id, state, until, priority, updated, by_user)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (cluster, id) DO UPDATE SET state = excluded.state,
			until = excluded.until, priority = excluded.priority, updated = excluded.updated,
			by_user = excluded.by_user`,
		cluster, id, string(us.State), nullMS(us.Until), string(us.Priority), ms(s.now()), us.By)
	return err
}

// UserStates returns what people set on the cluster's findings.
func (s *Store) UserStates(cluster string) (map[string]engine.UserState, error) {
	rows, err := s.db.Query(`SELECT id, state, until, priority, by_user FROM user_state WHERE cluster = ?`, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]engine.UserState{}
	for rows.Next() {
		var id, state, prio, by string
		var until sql.NullInt64
		if err := rows.Scan(&id, &state, &until, &prio, &by); err != nil {
			return nil, err
		}
		us := engine.UserState{State: findings.State(state), Priority: findings.Priority(prio), By: by}
		if until.Valid {
			t := fromMS(until.Int64)
			us.Until = &t
		}
		out[id] = us
	}
	return out, rows.Err()
}

// ClearUserState reopens a finding.
func (s *Store) ClearUserState(cluster, id string) error {
	_, err := s.db.Exec(`DELETE FROM user_state WHERE cluster = ? AND id = ?`, cluster, id)
	return err
}

// ---------------------------------------------------------------------------
// History (engine.Store)

// RecordOpen records that a finding is open, or updates its open record.
func (s *Store) RecordOpen(f *findings.Finding) error {
	now := s.now()
	first := now
	if f.FirstSeen != nil {
		first = *f.FirstSeen
	}
	last := now
	if f.LastSeen != nil {
		last = *f.LastSeen
	}
	res, err := s.db.Exec(`UPDATE history SET last_seen = ?, priority = ?, title = ?, plain_title = ?
		WHERE cluster = ? AND id = ? AND resolved_at IS NULL`,
		ms(last), string(f.Priority), f.Title, f.Plain.Title, f.Cluster, f.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO history (cluster, id, rule, resource, title, plain_title,
		priority, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.Cluster, f.ID, f.RuleID, f.Resource.String(), f.Title, f.Plain.Title,
		string(f.Priority), ms(first), ms(last))
	return err
}

// RecordResolved closes a finding's open record.
func (s *Store) RecordResolved(cluster, id string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE history SET resolved_at = ?, last_seen = MAX(last_seen, ?)
		WHERE cluster = ? AND id = ? AND resolved_at IS NULL`, ms(at), ms(at), cluster, id)
	return err
}

// OpenFindings returns the first-seen time of the cluster's open findings.
func (s *Store) OpenFindings(cluster string) (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT id, first_seen FROM history WHERE cluster = ? AND resolved_at IS NULL`, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var first int64
		if err := rows.Scan(&id, &first); err != nil {
			return nil, err
		}
		out[id] = fromMS(first)
	}
	return out, rows.Err()
}

// Controllers returns the controllers last known for failover, in the
// order they were stored.
func (s *Store) Controllers(cluster string) ([]engine.KnownController, error) {
	rows, err := s.db.Query(`SELECT name, address FROM controllers WHERE cluster = ? ORDER BY rowid`, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []engine.KnownController
	for rows.Next() {
		var k engine.KnownController
		if err := rows.Scan(&k.Name, &k.Address); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetControllers replaces the controllers known for failover.
func (s *Store) SetControllers(cluster string, cs []engine.KnownController) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM controllers WHERE cluster = ?`, cluster); err != nil {
		tx.Rollback()
		return err
	}
	for _, k := range cs {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO controllers (cluster, address, name) VALUES (?, ?, ?)`, cluster, k.Address, k.Name); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Occurrence is one time a finding was open.
type Occurrence struct {
	FirstSeen  time.Time         `json:"firstSeen"`
	LastSeen   time.Time         `json:"lastSeen"`
	ResolvedAt *time.Time        `json:"resolvedAt,omitempty"`
	Priority   findings.Priority `json:"priority"`
	Title      string            `json:"title"`
}

// History returns the occurrences of a finding, newest first. It answers
// "has this happened before?".
func (s *Store) History(cluster, id string) ([]Occurrence, error) {
	rows, err := s.db.Query(`SELECT first_seen, last_seen, resolved_at, priority, title FROM history
		WHERE cluster = ? AND id = ? ORDER BY first_seen DESC LIMIT 50`, cluster, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Occurrence
	for rows.Next() {
		var first, last int64
		var resolved sql.NullInt64
		var o Occurrence
		var prio string
		if err := rows.Scan(&first, &last, &resolved, &prio, &o.Title); err != nil {
			return nil, err
		}
		o.FirstSeen, o.LastSeen, o.Priority = fromMS(first), fromMS(last), findings.Priority(prio)
		if resolved.Valid {
			t := fromMS(resolved.Int64)
			o.ResolvedAt = &t
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Notifications

// Notification is one entry of the bell.
type Notification struct {
	Seq       int64  `json:"seq"`
	Cluster   string `json:"cluster"`
	FindingID string `json:"findingId,omitempty"`
	// Kind is opened, worse, resolved, unreachable or summary.
	Kind       string            `json:"kind"`
	Priority   findings.Priority `json:"priority,omitempty"`
	Title      string            `json:"title"`
	PlainTitle string            `json:"plainTitle"`
	Created    time.Time         `json:"created"`
	Read       bool              `json:"read"`
}

// AddNotification stores a notification and returns it with its sequence
// number.
func (s *Store) AddNotification(n Notification) (Notification, error) {
	if n.Created.IsZero() {
		n.Created = s.now()
	}
	res, err := s.db.Exec(`INSERT INTO notifications (cluster, finding_id, kind, priority, title, plain_title, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, n.Cluster, n.FindingID, n.Kind, string(n.Priority), n.Title, n.PlainTitle, ms(n.Created))
	if err != nil {
		return n, err
	}
	n.Seq, err = res.LastInsertId()
	return n, err
}

// readUpTo is the last notification the user has read.
func (s *Store) readUpTo(user string) (int64, error) {
	var seq int64
	err := s.db.QueryRow(`SELECT seq FROM notification_reads WHERE user = ?`, user).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

// Notifications returns the newest notifications, read or not by the user,
// and how many the user hasn't read.
func (s *Store) Notifications(user string, limit int) ([]Notification, int, error) {
	upTo, err := s.readUpTo(user)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT seq, cluster, finding_id, kind, priority, title, plain_title, created
		FROM notifications ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var prio string
		var created int64
		if err := rows.Scan(&n.Seq, &n.Cluster, &n.FindingID, &n.Kind, &prio, &n.Title, &n.PlainTitle, &created); err != nil {
			return nil, 0, err
		}
		n.Priority, n.Created, n.Read = findings.Priority(prio), fromMS(created), n.Seq <= upTo
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var unread int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE seq > ?`, upTo).Scan(&unread)
	return out, unread, err
}

// MarkRead marks the user's notifications up to seq as read (all when seq
// is 0).
func (s *Store) MarkRead(user string, seq int64) error {
	if seq == 0 {
		if err := s.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM notifications`).Scan(&seq); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`INSERT INTO notification_reads (user, seq) VALUES (?, ?)
		ON CONFLICT (user) DO UPDATE SET seq = MAX(seq, excluded.seq)`, user, seq)
	return err
}

// ---------------------------------------------------------------------------
// Users

// User is an account of the web UI. Every user can do everything.
type User struct {
	Name       string     `json:"name"`
	Created    time.Time  `json:"created"`
	CreatedBy  string     `json:"createdBy,omitempty"`
	LastSignIn *time.Time `json:"lastSignIn,omitempty"`
}

// ErrUserExists is returned when adding a user whose name is taken.
var ErrUserExists = errors.New("a user with this name exists")

// ErrNoUser is returned for a user that doesn't exist.
var ErrNoUser = errors.New("no such user")

// ErrLastUser is returned when removing the only user.
var ErrLastUser = errors.New("the last user can't be removed")

// Users returns the users, sorted by name.
func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT name, created, created_by, last_sign_in FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&u.Name, &created, &u.CreatedBy, &last); err != nil {
			return nil, err
		}
		u.Created = fromMS(created)
		if last.Valid {
			t := fromMS(last.Int64)
			u.LastSignIn = &t
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserCount returns how many users there are; with none, sign-in is off.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// PasswordHash returns a user's password hash, or "" for no such user.
func (s *Store) PasswordHash(name string) (string, error) {
	var h string
	err := s.db.QueryRow(`SELECT hash FROM users WHERE name = ?`, name).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return h, err
}

// AddUser adds a user. The notifications so far count as read for them.
func (s *Store) AddUser(name, hash, by string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO users (name, hash, created, created_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (name) DO NOTHING`, name, hash, ms(s.now()), by)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserExists
	}
	if _, err := tx.Exec(`INSERT INTO notification_reads (user, seq)
		SELECT ?, COALESCE(MAX(seq), 0) FROM notifications WHERE true
		ON CONFLICT (user) DO UPDATE SET seq = excluded.seq`, name); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPassword changes a user's password.
func (s *Store) SetPassword(name, hash string) error {
	res, err := s.db.Exec(`UPDATE users SET hash = ? WHERE name = ?`, hash, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoUser
	}
	return nil
}

// DeleteUser removes a user, never the last one: two people removing each
// other at the same time leave one.
func (s *Store) DeleteUser(name string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE name = ? AND (SELECT COUNT(*) FROM users) > 1`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if h, _ := s.PasswordHash(name); h != "" {
			return ErrLastUser
		}
		return ErrNoUser
	}
	_, err = s.db.Exec(`DELETE FROM notification_reads WHERE user = ?`, name)
	return err
}

// RecordSignIn notes when a user last signed in.
func (s *Store) RecordSignIn(name string) error {
	_, err := s.db.Exec(`UPDATE users SET last_sign_in = ? WHERE name = ?`, ms(s.now()), name)
	return err
}

// ---------------------------------------------------------------------------
// Audit log

// AuditEntry is one recorded action.
type AuditEntry struct {
	Seq    int64     `json:"seq"`
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

// Audit records an action.
func (s *Store) Audit(user, ip, action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit (ts, user, ip, action, detail) VALUES (?, ?, ?, ?, ?)`,
		ms(s.now()), user, ip, action, detail)
	return err
}

// AuditLog returns the newest entries.
func (s *Store) AuditLog(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT seq, ts, user, ip, action, detail FROM audit ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&a.Seq, &ts, &a.User, &a.IP, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		a.Time = fromMS(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Clusters added in the UI

// StoredCluster is a cluster added in the UI.
type StoredCluster struct {
	Cluster config.Cluster
	// Account is "readonly" when k0s-monitor created its own read-only
	// account, or "uploaded" when the uploaded credentials are used.
	Account   string
	K0sctl    []byte
	K0sConfig []byte
	Created   time.Time
}

type clusterSpec struct {
	Context     string             `json:"context,omitempty"`
	Server      string             `json:"server,omitempty"`
	Proxy       string             `json:"proxy,omitempty"`
	Criticality string             `json:"criticality,omitempty"`
	Prometheus  *config.Prometheus `json:"prometheus,omitempty"`
	// K0sVersion is the k0s version the cluster should run, and
	// K0sVersionFrom where it came from.
	K0sVersion     string `json:"k0sVersion,omitempty"`
	K0sVersionFrom string `json:"k0sVersionFrom,omitempty"`
	// ReadTLSSecrets false turns off reading TLS Secrets.
	ReadTLSSecrets *bool `json:"readTLSSecrets,omitempty"`
}

// SaveCluster stores a cluster, encrypting its kubeconfig and files.
func (s *Store) SaveCluster(c StoredCluster) error {
	if s.vault == nil {
		return errors.New("no key to encrypt credentials; run k0s-monitor init")
	}
	if len(c.Cluster.KubeconfigData) == 0 {
		return errors.New("the cluster has no kubeconfig")
	}
	spec, _ := json.Marshal(clusterSpec{Context: c.Cluster.Context, Server: c.Cluster.Server, Proxy: c.Cluster.Proxy,
		Criticality: c.Cluster.Criticality, Prometheus: c.Cluster.Prometheus,
		K0sVersion: c.Cluster.K0sVersion, K0sVersionFrom: c.Cluster.K0sVersionFrom, ReadTLSSecrets: c.Cluster.ReadTLSSecrets})
	seal := func(b []byte) ([]byte, error) {
		if len(b) == 0 {
			return nil, nil
		}
		return s.vault.Seal(b)
	}
	kc, err := seal(c.Cluster.KubeconfigData)
	if err != nil {
		return err
	}
	k0sctl, err := seal(c.K0sctl)
	if err != nil {
		return err
	}
	k0s, err := seal(c.K0sConfig)
	if err != nil {
		return err
	}
	if c.Created.IsZero() {
		c.Created = s.now()
	}
	_, err = s.db.Exec(`INSERT INTO clusters (name, spec, kubeconfig, k0sctl, k0s_config, account, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET spec = excluded.spec, kubeconfig = excluded.kubeconfig,
			k0sctl = excluded.k0sctl, k0s_config = excluded.k0s_config, account = excluded.account`,
		c.Cluster.Name, string(spec), kc, k0sctl, k0s, c.Account, ms(c.Created))
	return err
}

// Clusters returns the clusters added in the UI, oldest first, with their
// credentials decrypted.
func (s *Store) Clusters() ([]StoredCluster, error) {
	rows, err := s.db.Query(`SELECT name, spec, kubeconfig, k0sctl, k0s_config, account, created FROM clusters ORDER BY created, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredCluster
	for rows.Next() {
		var name, specJSON, account string
		var kc, k0sctl, k0s []byte
		var created int64
		if err := rows.Scan(&name, &specJSON, &kc, &k0sctl, &k0s, &account, &created); err != nil {
			return nil, err
		}
		if s.vault == nil {
			return nil, errors.New("no key to decrypt the stored credentials")
		}
		var spec clusterSpec
		_ = json.Unmarshal([]byte(specJSON), &spec)
		open := func(b []byte) ([]byte, error) {
			if len(b) == 0 {
				return nil, nil
			}
			return s.vault.Open(b)
		}
		sc := StoredCluster{Account: account, Created: fromMS(created)}
		if sc.Cluster.KubeconfigData, err = open(kc); err != nil {
			return nil, fmt.Errorf("cluster %s: %w", name, err)
		}
		if sc.K0sctl, err = open(k0sctl); err != nil {
			return nil, fmt.Errorf("cluster %s: %w", name, err)
		}
		if sc.K0sConfig, err = open(k0s); err != nil {
			return nil, fmt.Errorf("cluster %s: %w", name, err)
		}
		sc.Cluster.Name = name
		sc.Cluster.Context = spec.Context
		sc.Cluster.Server = spec.Server
		sc.Cluster.Proxy = spec.Proxy
		sc.Cluster.Criticality = spec.Criticality
		sc.Cluster.Prometheus = spec.Prometheus
		sc.Cluster.K0sVersion, sc.Cluster.K0sVersionFrom = spec.K0sVersion, spec.K0sVersionFrom
		sc.Cluster.ReadTLSSecrets = spec.ReadTLSSecrets
		sc.Cluster.FromUI = true
		out = append(out, sc)
	}
	return out, rows.Err()
}

// SetClusterPrometheus changes where a stored cluster's metrics come from;
// nil finds them automatically.
func (s *Store) SetClusterPrometheus(name string, p *config.Prometheus) error {
	return s.updateSpec(name, func(spec *clusterSpec) { spec.Prometheus = p })
}

// SetClusterK0sVersion changes the k0s version a stored cluster should run;
// empty expects the version most controllers run.
func (s *Store) SetClusterK0sVersion(name, version, from string) error {
	return s.updateSpec(name, func(spec *clusterSpec) {
		spec.K0sVersion, spec.K0sVersionFrom = version, from
		if version == "" {
			spec.K0sVersionFrom = ""
		}
	})
}

// SetClusterTLSSecrets turns reading a cluster's TLS Secrets on or off.
func (s *Store) SetClusterTLSSecrets(name string, on bool) error {
	return s.updateSpec(name, func(spec *clusterSpec) {
		spec.ReadTLSSecrets = nil // on is the default
		if !on {
			spec.ReadTLSSecrets = &on
		}
	})
}

func (s *Store) updateSpec(name string, change func(*clusterSpec)) error {
	var specJSON string
	err := s.db.QueryRow(`SELECT spec FROM clusters WHERE name = ?`, name).Scan(&specJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("cluster %s was not added in the UI", name)
	}
	if err != nil {
		return err
	}
	var spec clusterSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return err
	}
	change(&spec)
	b, _ := json.Marshal(spec)
	_, err = s.db.Exec(`UPDATE clusters SET spec = ? WHERE name = ?`, string(b), name)
	return err
}

// DeleteCluster removes a cluster and everything recorded about it.
func (s *Store) DeleteCluster(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM clusters WHERE name = ?`,
		`DELETE FROM user_state WHERE cluster = ?`,
		`DELETE FROM history WHERE cluster = ?`,
		`DELETE FROM notifications WHERE cluster = ?`,
		`DELETE FROM controllers WHERE cluster = ?`,
	} {
		if _, err := tx.Exec(q, name); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------------
// Product packs

var _ pack.Store = (*Store)(nil)

// Packs returns the uploaded product packs, by name.
func (s *Store) Packs() ([]pack.Stored, error) {
	rows, err := s.db.Query(`SELECT name, data, uploaded_by, uploaded FROM packs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pack.Stored
	for rows.Next() {
		var p pack.Stored
		var at int64
		if err := rows.Scan(&p.Name, &p.Data, &p.By, &at); err != nil {
			return nil, err
		}
		p.At = fromMS(at)
		out = append(out, p)
	}
	return out, rows.Err()
}

// SavePack stores an uploaded pack, replacing one of the same name.
func (s *Store) SavePack(name string, data []byte, by string) error {
	_, err := s.db.Exec(`INSERT INTO packs (name, data, uploaded_by, uploaded) VALUES (?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET data = excluded.data, uploaded_by = excluded.uploaded_by, uploaded = excluded.uploaded`,
		name, data, by, ms(s.now()))
	return err
}

// DeletePack removes an uploaded pack.
func (s *Store) DeletePack(name string) error {
	_, err := s.db.Exec(`DELETE FROM packs WHERE name = ?`, name)
	return err
}

// ---------------------------------------------------------------------------
// Housekeeping

// Prune deletes resolved findings, notifications and audit entries older
// than Retention, and expired snoozes.
func (s *Store) Prune() error {
	cutoff := ms(s.now().Add(-Retention))
	var errs []string
	for _, q := range []string{
		`DELETE FROM history WHERE resolved_at IS NOT NULL AND resolved_at < ?`,
		`DELETE FROM notifications WHERE created < ?`,
		`DELETE FROM audit WHERE ts < ?`,
	} {
		if _, err := s.db.Exec(q, cutoff); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if _, err := s.db.Exec(`DELETE FROM user_state WHERE until IS NOT NULL AND until < ?`, ms(s.now())); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
