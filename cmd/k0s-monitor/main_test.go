package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k0s_monitor/internal/auth"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/store"
)

// deadCluster writes a config with one cluster whose API port is closed.
func deadCluster(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	dir := t.TempDir()
	kc := `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://` + addr + `"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {token: t}}]
`
	os.WriteFile(filepath.Join(dir, "cluster.config"), []byte(kc), 0o600)
	cfg := filepath.Join(dir, "k0s-monitor.yaml")
	os.WriteFile(cfg, []byte("clusters:\n- name: lab\n  kubeconfig: cluster.config\nscan: {connectTimeout: 2s}\n"), 0o600)
	return cfg
}

func TestScanUnreachableJSON(t *testing.T) {
	cfg := deadCluster(t)
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--config", cfg, "-o", "json", "--fail-on", "P1"}, &out, &errb)
	if code != exitProblems {
		t.Fatalf("exit code = %d, stderr: %s", code, errb.String())
	}
	var r struct {
		Clusters []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Error  struct {
				Kind string `json:"kind"`
				Hint string `json:"hint"`
			} `json:"error"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	c := r.Clusters[0]
	if c.Name != "lab" || c.Status != "unreachable" || c.Error.Kind != "refused" {
		t.Errorf("cluster = %+v", c)
	}
	if !strings.Contains(c.Error.Hint, "only works on the controller itself") {
		t.Errorf("hint should explain the loopback address: %q", c.Error.Hint)
	}
}

func TestScanFailOnNone(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--config", deadCluster(t)}, &out, &errb); code != exitOK {
		t.Errorf("without --fail-on the exit code is 0, got %d", code)
	}
	if !strings.Contains(out.String(), "lab") || !strings.Contains(out.String(), "cluster.unreachable") {
		t.Errorf("table output:\n%s", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"frobnicate"},
		{"scan", "--output", "xml", "--kubeconfig", "x"},
		{"scan", "--mode", "expert", "--kubeconfig", "x"},
		{"scan", "--fail-on", "P9", "--kubeconfig", "x"},
		{"scan", "--config", "/does/not/exist"},
		{"scan", "--config", "a", "--kubeconfig", "b"},
		{"scan", "--all", "--cluster", "a", "--kubeconfig", "x"},
		{"scan", "extra-arg"},
	}
	for _, args := range cases {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitUsage {
			t.Errorf("%v: exit code %d, want %d", args, code, exitUsage)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != exitOK || !strings.HasPrefix(out.String(), "k0s-monitor ") {
		t.Errorf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"scan", "-h"}, &out, &errb); code != exitOK {
		t.Errorf("scan -h: exit %d", code)
	}
}

func TestClusterName(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kc")
	os.WriteFile(kc, []byte("apiVersion: v1\nkind: Config\ncurrent-context: \"Admin@Edge Prod\"\n"), 0o600)
	if got := clusterName(kc, ""); got != "admin-edge-prod" {
		t.Errorf("from current-context: %q", got)
	}
	if got := clusterName(kc, "retail-us"); got != "retail-us" {
		t.Errorf("explicit context: %q", got)
	}
	if got := clusterName(filepath.Join(dir, "missing"), ""); got != "default" {
		t.Errorf("fallback: %q", got)
	}
}

func TestInitAndPasswd(t *testing.T) {
	dir := t.TempDir()
	etc, data, units := filepath.Join(dir, "etc"), filepath.Join(dir, "data"), filepath.Join(dir, "units")
	os.MkdirAll(units, 0o755)
	pw := filepath.Join(dir, "pw")
	os.WriteFile(pw, []byte("correct horse battery\n"), 0o600)
	args := []string{"init", "--config-dir", etc, "--data-dir", data, "--listen", "127.0.0.1:18444",
		"--user", "", "--systemd-dir", units, "--password-file", pw, "--san", "jump-01.lan", "--allow-from", "192.168.10.25,10.1.0.0/16"}
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != exitOK {
		t.Fatalf("init: %d %s", code, errb.String())
	}
	for name, mode := range map[string]os.FileMode{
		"config.yaml": 0o640, "ca.crt": 0o644, "ca.key": 0o600, "tls.crt": 0o644, "tls.key": 0o600, "secret.key": 0o600,
	} {
		st, err := os.Stat(filepath.Join(etc, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, want %v", name, st.Mode().Perm(), mode)
		}
	}
	if st, err := os.Stat(filepath.Join(data, "k0s-monitor.db")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("database: %v %v", st, err)
	}
	unit, _ := os.ReadFile(filepath.Join(units, "k0s-monitor.service"))
	if !strings.Contains(string(unit), "serve --config "+filepath.Join(etc, "config.yaml")) || !strings.Contains(string(unit), "ReadWritePaths="+data) {
		t.Errorf("unit:\n%s", unit)
	}
	if !strings.Contains(out.String(), "Trusted Root Certification Authorities") {
		t.Errorf("init explains how to trust ca.crt:\n%s", out.String())
	}
	for _, want := range []string{"CapabilityBoundingSet=\n", "SystemCallFilter=@system-service", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK", "UMask=0077"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("the unit lacks %q", want)
		}
	}
	if strings.Contains(string(unit), "AmbientCapabilities") {
		t.Error("port 18444 needs no capability")
	}
	if cfg, err := config.Load(filepath.Join(etc, "config.yaml")); err != nil || strings.Join(cfg.AllowFrom, ",") != "192.168.10.25,10.1.0.0/16" {
		t.Errorf("allowFrom from --allow-from: %v %v", cfg, err)
	}
	// A UI on port 443 gets the one capability it needs.
	low := filepath.Join(dir, "low.service")
	if err := writeUnit(low, "/usr/local/bin/k0s-monitor", "/etc/k0s-monitor/config.yaml", "/var/lib/k0s-monitor", "k0s-monitor", "0.0.0.0:443"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(low); !strings.Contains(string(b), "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n") {
		t.Errorf("port 443:\n%s", b)
	}
	if code := run([]string{"init", "--config-dir", filepath.Join(dir, "x"), "--allow-from", "not-an-address"}, &out, &errb); code != exitUsage {
		t.Error("a bad --allow-from is refused")
	}
	cert, _ := os.ReadFile(filepath.Join(etc, "tls.crt"))

	// A second run keeps everything.
	out.Reset()
	if code := run(args, &out, &errb); code != exitOK {
		t.Fatalf("second init: %d %s", code, errb.String())
	}
	again, _ := os.ReadFile(filepath.Join(etc, "tls.crt"))
	if !bytes.Equal(cert, again) || !strings.Contains(out.String(), "kept the users and their passwords") {
		t.Errorf("a second init must keep the certificate and the password:\n%s", out.String())
	}

	// passwd sets a new one.
	os.WriteFile(pw, []byte("another long password\n"), 0o600)
	out.Reset()
	if code := run([]string{"passwd", "--config", filepath.Join(etc, "config.yaml"), "--password-file", pw}, &out, &errb); code != exitOK {
		t.Fatalf("passwd: %d %s", code, errb.String())
	}
	// passwd --user adds a user with a new name.
	os.WriteFile(pw, []byte("annas long password\n"), 0o600)
	out.Reset()
	if code := run([]string{"passwd", "--config", filepath.Join(etc, "config.yaml"), "--user", "anna", "--password-file", pw}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "Added the user anna") {
		t.Fatalf("passwd --user anna: %d %s %s", code, out.String(), errb.String())
	}
	if code := run([]string{"passwd", "--config", filepath.Join(etc, "config.yaml"), "--user", "Anna Smith", "--password-file", pw}, &out, &errb); code != exitUsage {
		t.Error("a bad user name is refused")
	}
	os.WriteFile(pw, []byte("short\n"), 0o600)
	if code := run([]string{"passwd", "--config", filepath.Join(etc, "config.yaml"), "--password-file", pw}, &out, &errb); code != exitUsage {
		t.Error("a short password is refused")
	}
	st, err := store.Open(filepath.Join(data, "k0s-monitor.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	admin, _ := st.PasswordHash("admin")
	anna, _ := st.PasswordHash("anna")
	if !auth.VerifyPassword(admin, "another long password") || !auth.VerifyPassword(anna, "annas long password") {
		t.Error("each user has their own password")
	}
}

func TestServeRefusesNetworkWithoutPassword(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("listen: 0.0.0.0:18445\ndataDir: "+filepath.Join(dir, "data")+"\nclusters: []\n"), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"serve", "--config", cfg}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "k0s-monitor init") {
		t.Errorf("serving to the network without a password must be refused: %d %s", code, errb.String())
	}
}

func TestServiceCanRun(t *testing.T) {
	for _, p := range []string{"/root/src/k0s-monitor/bin/k0s-monitor", "/home/ops/k0s-monitor", "/run/user/0/k0s-monitor"} {
		if ok, why := serviceCanRun(p); ok || why == "" {
			t.Errorf("%s: ok %v, why %q", p, ok, why)
		}
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	bin := filepath.Join(dir, "k0s-monitor")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	if ok, why := serviceCanRun(bin); !ok && !strings.HasPrefix(why, "other users may not open") {
		t.Errorf("a world-executable binary: %s", why)
	}
	os.Chmod(bin, 0o700)
	if ok, why := serviceCanRun(bin); ok || why != "other users may not run it" {
		t.Errorf("a private binary: ok %v, why %q", ok, why)
	}

	dst := filepath.Join(dir, "sub", "k0s-monitor")
	os.Chmod(bin, 0o700)
	if err := installBinary(bin, dst); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dst); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("installed copy: %v %v", st, err)
	}
}
