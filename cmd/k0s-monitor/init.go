package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"golang.org/x/term"

	"k0s_monitor/internal/auth"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/store"
	"k0s_monitor/internal/tlsca"
	"k0s_monitor/internal/vault"
	"k0s_monitor/internal/version"
)

// PasswordEnv can hold the password for init and passwd, for automation.
const PasswordEnv = "K0S_MONITOR_PASSWORD"

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func versionString() string { return version.Version }

// ContainerEnv is set in the container image: there, init creates no
// system user and no systemd unit.
const ContainerEnv = "K0S_MONITOR_CONTAINER"

func runInit(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	container := os.Getenv(ContainerEnv) != ""
	defUser, defSystemd := "k0s-monitor", "/etc/systemd/system"
	if container {
		defUser, defSystemd = "", ""
	}
	var (
		configDir    = fs.String("config-dir", config.DefaultConfigDir, "directory for the configuration, certificates and key")
		dataDir      = fs.String("data-dir", config.DefaultDataDir, "directory for the database")
		listen       = fs.String("listen", config.DefaultListen, "address of the web UI")
		serviceUser  = fs.String("user", defUser, "system user that runs the service (created if missing; empty runs it as root)")
		systemdDir   = fs.String("systemd-dir", defSystemd, "where to write the systemd unit; empty skips it")
		binary       = fs.String("binary", "", "path of the k0s-monitor binary for the unit (default: this binary)")
		passwordFile = fs.String("password-file", "", "read the password from this file (\"-\" for standard input) instead of asking")
		renewCert    = fs.Bool("renew-cert", false, "issue a new server certificate, for example after adding --san")
		resetPass    = fs.Bool("reset-password", false, "set a new password even if one is set")
		sans         stringsFlag
		allowFrom    stringsFlag
	)
	fs.Var(&sans, "san", "extra host name or IP address for the certificate (repeatable)")
	fs.Var(&allowFrom, "allow-from", "address or CIDR range that may open the UI, for example your PC (repeatable, or comma-separated); only for a new configuration")
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: sudo k0s-monitor init [flags]

Set up the web UI on this machine. It is safe to run again: existing files are
kept unless a flag says otherwise. It creates:

  - the configuration file, a local certificate authority (ca.crt) and a
    certificate for the web UI, and the key that encrypts stored credentials;
  - the password of the "admin" account;
  - a system user and a systemd unit for the k0s-monitor service.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		fmt.Fprintf(stderr, "--listen %q: %v\n", *listen, err)
		return exitUsage
	}
	var allow []string
	for _, a := range allowFrom {
		for _, e := range strings.Split(a, ",") {
			if e = strings.TrimSpace(e); e == "" {
				continue
			}
			if _, err := config.ParseAllow(e); err != nil {
				fmt.Fprintf(stderr, "--allow-from %q: %v\n", e, err)
				return exitUsage
			}
			allow = append(allow, e)
		}
	}
	say := func(format string, a ...any) { fmt.Fprintf(stdout, format+"\n", a...) }
	fail := func(what string, err error) int {
		fmt.Fprintf(stderr, "%s: %v\n", what, err)
		return exitUsage
	}

	for _, d := range []string{*configDir, *dataDir, filepath.Join(*configDir, "packs")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fail("creating "+d, err)
		}
	}

	// Configuration file.
	cfgPath := filepath.Join(*configDir, configFile)
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := writeConfigTemplate(cfgPath, *listen, *configDir, *dataDir, allow); err != nil {
			return fail("writing "+cfgPath, err)
		}
		say("✓ wrote %s", cfgPath)
	} else {
		say("✓ kept %s", cfgPath)
		if len(allow) > 0 {
			say("! --allow-from only applies to a new configuration: set allowFrom in %s", cfgPath)
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fail("the configuration has a problem", err)
	}
	if len(cfg.AllowFrom) == 0 && !loopbackListen(cfg.Listen) {
		say("! anyone who can reach port %s may open the sign-in page. Limit it to your PCs with allowFrom in %s (or --allow-from on a new setup), or with a firewall.",
			portOf(cfg.Listen), cfgPath)
	}

	// Certificate authority and server certificate.
	names, ips := tlsca.Hosts(sans)
	now := time.Now()
	ca, err := tlsca.LoadCA(*configDir)
	newCA := false
	if err != nil {
		if ca, err = tlsca.NewCA(names[0], now, names, ips); err != nil {
			return fail("creating the certificate authority", err)
		}
		if err := ca.Save(*configDir); err != nil {
			return fail("saving the certificate authority", err)
		}
		newCA = true
		say("✓ created a certificate authority: %s", filepath.Join(*configDir, tlsca.CACertFile))
	}
	certPath := filepath.Join(*configDir, tlsca.CertFile)
	if newCA || *renewCert || tlsca.NeedsRenewal(certPath, now) {
		if err := ca.IssueFiles(*configDir, names, ips, now); err != nil {
			return fail("issuing the server certificate", err)
		}
		say("✓ issued the web UI certificate for %s", strings.Join(append(append([]string{}, names...), ipStrings(ips)...), ", "))
	} else {
		say("✓ kept the web UI certificate")
	}

	// Key for stored credentials.
	keyPath := filepath.Join(*configDir, keyFile)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if err := vault.WriteNewKey(keyPath); err != nil {
			return fail("creating the key", err)
		}
		say("✓ created the key that encrypts stored credentials: %s (back it up with the data directory)", keyPath)
	}

	// Password.
	key, err := vault.LoadKey(keyPath)
	if err != nil {
		return fail("reading the key", err)
	}
	v, _ := vault.New(key)
	st, err := store.Open(filepath.Join(*dataDir, dbFile), v)
	if err != nil {
		return fail("opening the database", err)
	}
	users, _ := st.UserCount()
	if users == 0 || *resetPass {
		pw, err := readNewPassword(*passwordFile, stdin, stdout)
		if err != nil {
			st.Close()
			return fail("password", err)
		}
		h, err := auth.HashPassword(pw)
		if err != nil {
			st.Close()
			return fail("password", err)
		}
		if _, err := setOrAddUser(st, auth.User, h, "init"); err != nil {
			st.Close()
			return fail("saving the password", err)
		}
		_ = st.Audit("root", "local", "password.set", "k0s-monitor init: "+auth.User)
		say("✓ set the password of the admin account")
	} else {
		say("✓ kept the users and their passwords (--reset-password sets admin's; sudo k0s-monitor passwd --user NAME sets anyone's)")
	}
	st.Close()

	// Service user and file ownership.
	if *serviceUser != "" && os.Geteuid() == 0 {
		u, err := ensureUser(*serviceUser, *dataDir)
		if err != nil {
			return fail("service user", err)
		}
		if err := ownFiles(u, *configDir, *dataDir); err != nil {
			return fail("setting file owners", err)
		}
		say("✓ the service runs as user %s", *serviceUser)
	} else if *serviceUser != "" {
		say("! not running as root: the service user and file owners were not set")
	}

	// systemd unit.
	if *systemdDir != "" {
		if _, err := os.Stat("/run/systemd/system"); err == nil || *systemdDir != "/etc/systemd/system" {
			bin := *binary
			if bin == "" {
				bin, _ = os.Executable()
				if real, err := filepath.EvalSymlinks(bin); err == nil {
					bin = real
				}
				// The service can't run a binary from a home directory
				// (ProtectHome) or one its user can't reach: install a copy
				// where it can.
				if ok, why := serviceCanRun(bin); !ok && os.Geteuid() == 0 {
					if err := installBinary(bin, installedBinary); err != nil {
						return fail("installing the binary", err)
					}
					say("✓ installed %s (the service can't run %s: %s)", installedBinary, bin, why)
					bin = installedBinary
				}
			}
			if ok, why := serviceCanRun(bin); !ok {
				say("! the service may not be able to run %s: %s. Copy it to %s and run init again.", bin, why, installedBinary)
			}
			unit := filepath.Join(*systemdDir, "k0s-monitor.service")
			if err := writeUnit(unit, bin, cfgPath, *dataDir, *serviceUser, cfg.Listen); err != nil {
				return fail("writing the systemd unit", err)
			}
			_ = exec.Command("systemctl", "daemon-reload").Run()
			say("✓ wrote %s", unit)
		}
	}

	host, _ := os.Hostname()
	if container {
		say(`
Next steps:
  1. Start k0s-monitor with the same volumes, and port %s published:
       docker run -d --name k0s-monitor --restart unless-stopped -p %s:%s \
         -v k0s-monitor-etc:%s -v k0s-monitor-data:%s IMAGE
  2. Trust the certificate once on your Windows PC: copy it out with
       docker cp k0s-monitor:%s ca.crt
     then double-click it on the PC, choose Install Certificate, then Local
     Machine, then "Trusted Root Certification Authorities".
  3. Open https://HOST:%s (a name given with --san) in Edge or Chrome, sign in,
     and add a cluster by uploading its cluster.config.

Use the volume names you gave this command. Product packs go in %s.`,
			portOf(*listen), portOf(*listen), portOf(*listen), *configDir, *dataDir,
			filepath.Join(*configDir, tlsca.CACertFile), portOf(*listen), filepath.Join(*configDir, "packs"))
		return exitOK
	}
	say(`
Next steps:
  1. Start the service, or restart it after an update:
       sudo systemctl enable k0s-monitor && sudo systemctl restart k0s-monitor
  2. Trust the certificate once on your Windows PC: copy
       %s
     to the PC, double-click it, choose Install Certificate, then Local Machine,
     then "Trusted Root Certification Authorities".
  3. Open https://%s in Edge or Chrome, sign in, and add a cluster
     by uploading its cluster.config.

If a firewall runs here, allow port %s from your LAN only. If the page doesn't
open, see why with: sudo systemctl status k0s-monitor; sudo journalctl -u k0s-monitor -n 50`,
		filepath.Join(*configDir, tlsca.CACertFile), displayAddr(*listen, host), portOf(*listen))
	return exitOK
}

func runPasswd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", filepath.Join(config.DefaultConfigDir, configFile), "configuration file")
	passwordFile := fs.String("password-file", "", "read the password from this file (\"-\" for standard input) instead of asking")
	name := fs.String("user", auth.User, "the user whose password to set; a new name adds the user")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if err := auth.CheckUserName(*name); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	dir := cfg.DataDir
	if dir == "" {
		dir = config.DefaultDataDir
	}
	st, err := store.Open(filepath.Join(dir, dbFile), nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	defer st.Close()
	pw, err := readNewPassword(*passwordFile, stdin, stdout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	added, err := setOrAddUser(st, *name, h, "root")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if added {
		_ = st.Audit("root", "local", "user.add", "k0s-monitor passwd: "+*name)
		fmt.Fprintf(stdout, "✓ Added the user %s. They can sign in now.\n", *name)
		return exitOK
	}
	_ = st.Audit("root", "local", "password.set", "k0s-monitor passwd: "+*name)
	fmt.Fprintf(stdout, "✓ The password of %s was changed. Browsers where %s is signed in stay signed in until they sign out or the service restarts; setting it in Settings instead signs them out at once.\n", *name, *name)
	return exitOK
}

// setOrAddUser sets a user's password, and adds the user if it is new.
func setOrAddUser(st *store.Store, name, hash, by string) (added bool, err error) {
	err = st.SetPassword(name, hash)
	if errors.Is(err, store.ErrNoUser) {
		return true, st.AddUser(name, hash, by)
	}
	return false, err
}

// readNewPassword takes the password from a file, the environment, or an
// interactive prompt (asked twice, not echoed).
func readNewPassword(file string, stdin io.Reader, stdout io.Writer) (string, error) {
	var pw string
	switch {
	case file == "-":
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading the password from standard input: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		pw = strings.TrimRight(strings.SplitN(string(data), "\n", 2)[0], "\r")
	case os.Getenv(PasswordEnv) != "":
		pw = os.Getenv(PasswordEnv)
	default:
		f, ok := stdin.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return "", fmt.Errorf("no terminal to ask for the password: use --password-file or $%s", PasswordEnv)
		}
		fmt.Fprintf(stdout, "Password for the web UI (at least %d characters): ", auth.MinPasswordLength)
		a, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stdout)
		if err != nil {
			return "", err
		}
		fmt.Fprint(stdout, "The same password again: ")
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stdout)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("the passwords are not the same")
		}
		pw = string(a)
	}
	return pw, auth.CheckPasswordStrength(pw)
}

var configTemplate = template.Must(template.New("").Parse(`# k0s-monitor configuration, written by "k0s-monitor init".
# Restart the service after changing it: sudo systemctl restart k0s-monitor

listen: {{.Listen}}
tls:
  certFile: {{.ConfigDir}}/tls.crt
  keyFile: {{.ConfigDir}}/tls.key
dataDir: {{.DataDir}}

# Only these addresses may open the UI, for example your Windows PC. Without
# it, anyone who can reach the port may open the sign-in page.
{{.Allow}}

ui:
  defaultMode: basic            # basic (plain words) or full (every detail)
  notify: [fix-now, fix-today]  # also: plan-ahead, suggestions

# Clusters are usually added in the UI. They can also be listed here (up to 5
# in total); these are shown as read-only in the UI.
# clusters:
# - name: edge-prod
#   kubeconfig: kubeconfigs/edge-prod.conf
clusters: []
`))

func writeConfigTemplate(path, listen, configDir, dataDir string, allow []string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	allowLine := "# allowFrom: [192.168.10.25]"
	if len(allow) > 0 {
		allowLine = "allowFrom: [" + strings.Join(allow, ", ") + "]"
	}
	err = configTemplate.Execute(f, map[string]string{"Listen": listen, "ConfigDir": configDir, "DataDir": dataDir, "Allow": allowLine})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

var unitTemplate = template.Must(template.New("").Parse(`[Unit]
Description=k0s-monitor: finds and explains problems in k0s clusters
After=network-online.target
Wants=network-online.target

[Service]
{{if .User}}User={{.User}}
Group={{.User}}
{{end}}ExecStart={{.Binary}} serve --config {{.Config}}
# Reads the product packs again.
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
MemoryMax=1G
NoNewPrivileges=yes
{{if .LowPort}}# The UI listens on a port below 1024: that one capability, nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
{{else}}CapabilityBoundingSet=
{{end}}ProtectSystem=strict
ReadWritePaths={{.DataDir}}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0077

[Install]
WantedBy=multi-user.target
`))

// installedBinary is where init installs the binary when the service
// can't run it from where it is.
const installedBinary = "/usr/local/bin/k0s-monitor"

// serviceCanRun reports whether the service, which runs as its own user
// with ProtectHome, can run the binary at path, and why not.
func serviceCanRun(path string) (bool, string) {
	path = filepath.Clean(path)
	for _, home := range []string{"/root", "/home", "/run/user"} {
		if path == home || strings.HasPrefix(path, home+"/") {
			return false, "systemd hides " + home + " from the service"
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, err.Error()
	}
	if st.Mode().Perm()&0o005 != 0o005 {
		return false, "other users may not run it"
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if d, err := os.Stat(dir); err != nil || d.Mode().Perm()&0o001 == 0 {
			return false, "other users may not open " + dir
		}
		if dir == "/" || dir == "." {
			return true, ""
		}
	}
}

// installBinary copies the binary to dst, replacing it atomically so a
// running service keeps its file.
func installBinary(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeUnit(path, binary, cfgPath, dataDir, serviceUser, listen string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	low := ""
	if p, err := strconv.Atoi(portOf(listen)); err == nil && p < 1024 {
		low = "yes"
	}
	err = unitTemplate.Execute(f, map[string]string{"Binary": binary, "Config": cfgPath, "DataDir": dataDir, "User": serviceUser, "LowPort": low})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ensureUser creates the system user if it does not exist.
func ensureUser(name, home string) (*user.User, error) {
	if u, err := user.Lookup(name); err == nil {
		return u, nil
	}
	shell := "/usr/sbin/nologin"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/false"
	}
	cmd := exec.Command("useradd", "--system", "--home-dir", home, "--no-create-home", "--shell", shell, name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("useradd: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return user.Lookup(name)
}

// ownFiles gives the service user what it needs, and nothing more: it
// reads the configuration, the certificate and the keys, and owns the data
// directory. The CA key stays readable by root only.
func ownFiles(u *user.User, configDir, dataDir string) error {
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	type f struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}
	files := []f{
		{configDir, 0, gid, 0o750},
		{filepath.Join(configDir, "packs"), 0, gid, 0o750},
		{filepath.Join(configDir, configFile), 0, gid, 0o640},
		{filepath.Join(configDir, tlsca.CACertFile), 0, 0, 0o644},
		{filepath.Join(configDir, tlsca.CAKeyFile), 0, 0, 0o600},
		{filepath.Join(configDir, tlsca.CertFile), 0, gid, 0o644},
		{filepath.Join(configDir, tlsca.KeyFile), uid, gid, 0o600},
		{filepath.Join(configDir, keyFile), uid, gid, 0o600},
		{dataDir, uid, gid, 0o750},
	}
	for _, x := range files {
		if _, err := os.Stat(x.path); err != nil {
			continue
		}
		if err := os.Chown(x.path, x.uid, x.gid); err != nil {
			return err
		}
		if err := os.Chmod(x.path, x.mode); err != nil {
			return err
		}
	}
	// Everything inside the data directory belongs to the service.
	return filepath.Walk(dataDir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func portOf(listen string) string {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return "8443"
	}
	return p
}
