package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := WriteNewKey(path); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v", st.Mode().Perm())
	}
	if err := WriteNewKey(path); err == nil {
		t.Error("an existing key must never be replaced")
	}
	key, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := New(key)
	secret := []byte("users: [{name: admin, user: {token: abc}}]")
	sealed, err := v.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("token")) {
		t.Error("sealed data must not contain the plain text")
	}
	again, _ := v.Seal(secret)
	if bytes.Equal(sealed, again) {
		t.Error("each seal uses a new nonce")
	}
	got, err := v.Open(sealed)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open = %q, %v", got, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := v.Open(sealed); err == nil {
		t.Error("tampered data must be rejected")
	}

	other := make([]byte, KeySize)
	w, _ := New(other)
	if _, err := w.Open(again); err == nil {
		t.Error("another key must not open the data")
	}
}

func TestLoadKeyFromEnv(t *testing.T) {
	t.Setenv(KeyEnv, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if k, err := LoadKey("/does/not/exist"); err != nil || len(k) != KeySize {
		t.Errorf("env key: %v %v", k, err)
	}
	t.Setenv(KeyEnv, "short")
	if _, err := LoadKey("/does/not/exist"); err == nil {
		t.Error("a bad key must be rejected")
	}
}
