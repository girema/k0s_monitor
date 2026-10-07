// Package vault encrypts credentials at rest with AES-256-GCM. The key
// comes from a file created by `k0s-monitor init`, or from the
// K0S_MONITOR_KEY environment variable (base64).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KeyEnv names the environment variable that can hold the key.
const KeyEnv = "K0S_MONITOR_KEY"

// KeySize is the key length in bytes.
const KeySize = 32

// Vault seals and opens data with one key.
type Vault struct {
	aead cipher.AEAD
}

// New creates a vault from a 32-byte key.
func New(key []byte) (*Vault, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("the key must be %d bytes, not %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Seal encrypts data. The result starts with a random nonce.
func (v *Vault) Seal(data []byte) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return v.aead.Seal(nonce, nonce, data, nil), nil
}

// Open decrypts what Seal produced.
func (v *Vault) Open(sealed []byte) ([]byte, error) {
	n := v.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("encrypted data is too short")
	}
	out, err := v.aead.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		return nil, errors.New("encrypted data can't be read with this key")
	}
	return out, nil
}

// LoadKey reads the key from K0S_MONITOR_KEY or, if that is empty, from
// the file (base64, as written by WriteNewKey).
func LoadKey(path string) ([]byte, error) {
	src := "$" + KeyEnv
	text := os.Getenv(KeyEnv)
	if text == "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading the credentials key: %w", err)
		}
		text, src = string(data), path
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("%s must hold %d random bytes in base64", src, KeySize)
	}
	return key, nil
}

// WriteNewKey creates a random key file readable only by its owner. It
// fails if the file exists, so a key is never replaced by accident: data
// sealed with the old key would be lost.
func WriteNewKey(path string) error {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
