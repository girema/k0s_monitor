package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/pack"
	"k0s_monitor/internal/store"
	"k0s_monitor/internal/tlsca"
	"k0s_monitor/internal/vault"
	"k0s_monitor/internal/web"
)

// Files inside the configuration directory.
const (
	configFile = "config.yaml"
	keyFile    = "secret.key"
	dbFile     = "k0s-monitor.db"
)

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath = fs.String("config", "", "configuration file (default "+filepath.Join(config.DefaultConfigDir, configFile)+" if it exists)")
		kubeconfig = fs.String("kubeconfig", "", "monitor the cluster of this kubeconfig without a configuration file (laptop mode)")
		kubeCtx    = fs.String("context", "", "kubeconfig context to use with --kubeconfig")
		listen     = fs.String("listen", "", "address of the web UI (default from the configuration, or 127.0.0.1:8443 in laptop mode)")
		dataDir    = fs.String("data-dir", "", "directory for the database (default from the configuration)")
		demo       = fs.String("demo", "", "")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: k0s-monitor serve [flags]

Run the web UI. On a jump host, "k0s-monitor init" prepares everything and the
k0s-monitor service runs this command. Without a configuration file it runs in
laptop mode: one cluster from --kubeconfig (or $KUBECONFIG), on 127.0.0.1 only,
without sign-in.

Flags:
`)
		fs.VisitAll(func(f *flag.Flag) {
			if f.Name != "demo" {
				fmt.Fprintf(stderr, "  --%s\n    \t%s\n", f.Name, f.Usage)
			}
		})
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitUsage
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, configDir, laptop, err := serveConfig(*configPath, *kubeconfig, *kubeCtx, *demo)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if cfg.DataDir == "" {
		cfg.DataDir = config.DefaultDataDir
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "data directory: %v\n", err)
		return exitUsage
	}

	// The key for stored credentials. In laptop mode one is created in the
	// data directory; on a jump host init creates it.
	var v *vault.Vault
	keyPath := filepath.Join(configDir, keyFile)
	if laptop {
		keyPath = filepath.Join(cfg.DataDir, keyFile)
		if _, err := os.Stat(keyPath); os.IsNotExist(err) && os.Getenv(vault.KeyEnv) == "" {
			_ = vault.WriteNewKey(keyPath)
		}
	}
	if key, err := vault.LoadKey(keyPath); err == nil {
		v, _ = vault.New(key)
	} else {
		log.Warn("adding clusters in the UI is off: no key to encrypt their credentials", "err", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, dbFile), v)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	defer st.Close()

	users, err := st.UserCount()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	noAuth := false
	if users == 0 {
		if !loopbackListen(cfg.Listen) {
			fmt.Fprintf(stderr, "No password is set, so the UI can only listen on 127.0.0.1.\n"+
				"Run \"sudo k0s-monitor init\" to set up sign-in, or use --listen 127.0.0.1:8443.\n")
			return exitUsage
		}
		noAuth = true
		log.Warn("sign-in is off: no password is set and the UI only listens on this computer")
	}
	if !noAuth && len(cfg.AllowFrom) == 0 && !loopbackListen(cfg.Listen) {
		log.Warn("anyone who can reach this address may open the sign-in page; limit it to your PCs with allowFrom in the configuration file", "listen", cfg.Listen)
	}

	cert, certExpires, err := serveCertificate(cfg, configDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Product packs: from the packs directory and uploads. SIGHUP reads
	// the directory again.
	packs := pack.NewRegistry(cfg.PacksDir, st)
	logPacks(log, packs.Load())

	var srv *web.Server
	now := demoNow(*demo)
	fleet := engine.NewFleet(ctx, engine.Options{
		Thresholds: cfg.Thresholds, Timeouts: cfg.Scan, Store: st, Connect: demoConnector(*demo), Now: now, Packs: packs,
		Metrics: demoMetrics(*demo, now), ControlPlane: demoControlPlane(*demo, now), CrashLogs: demoCrashLogs(*demo),
		OnEvent: func(ev engine.Event) {
			if srv != nil {
				srv.OnEvent(ev)
			}
		},
	})
	defer fleet.Stop()

	host, _ := os.Hostname()
	url := "https://" + displayAddr(cfg.Listen, host)
	srv, err = web.New(web.Options{
		Config: cfg, Fleet: fleet, Store: st, NoAuth: noAuth, Host: host, URL: url,
		CertExpires: certExpires, CanStoreClusters: v != nil, Logger: log, Now: now, Packs: packs,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	for _, c := range cfg.Clusters {
		if _, err := fleet.Add(c); err != nil {
			log.Error("cluster from the configuration not added", "cluster", c.Name, "err", err)
		}
	}
	if v != nil {
		stored, err := st.Clusters()
		if err != nil {
			log.Error("clusters added in the UI can't be read", "err", err)
		}
		for _, sc := range stored {
			if _, err := fleet.Add(sc.Cluster); err != nil {
				log.Error("cluster added in the UI not started", "cluster", sc.Cluster.Name, "err", err)
			}
		}
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("reading the product packs again (SIGHUP)")
			logPacks(log, packs.Load())
			for _, e := range fleet.Engines() {
				e.Refresh()
			}
		}
	}()

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "can't listen on %s: %v\n", cfg.Listen, err)
		return exitUsage
	}
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			_ = st.Prune()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- hs.ServeTLS(ln, "", "") }()
	fmt.Fprintf(stdout, "k0s-monitor %s: open %s\n", versionString(), url)
	log.Info("serving", "listen", cfg.Listen, "clusters", len(fleet.Engines()), "signIn", !noAuth)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(shutdown)
	return exitOK
}

// serveConfig finds the configuration: --config, the default file, or
// laptop mode built from a kubeconfig. It returns the configuration
// directory, where the key and certificates live.
func serveConfig(path, kubeconfig, kubeCtx, demo string) (*config.Config, string, bool, error) {
	if demo != "" {
		cfg, err := demoConfig(demo)
		return cfg, filepath.Dir(demo), true, err
	}
	if path == "" && kubeconfig == "" {
		def := filepath.Join(config.DefaultConfigDir, configFile)
		if _, err := os.Stat(def); err == nil {
			path = def
		}
	}
	if path != "" {
		if kubeconfig != "" {
			return nil, "", false, errors.New("use either --config or --kubeconfig, not both")
		}
		cfg, err := config.Load(path)
		if err != nil {
			return nil, "", false, err
		}
		return cfg, filepath.Dir(path), false, nil
	}
	// Laptop mode.
	cfg := config.Default()
	if err := config.ApplyServeDefaults(cfg); err != nil {
		return nil, "", false, err
	}
	cfg.Listen = "127.0.0.1:8443"
	if kubeconfig == "" {
		kubeconfig = defaultKubeconfig()
	}
	if kubeconfig != "" {
		cfg.Clusters = []config.Cluster{{Name: clusterName(kubeconfig, kubeCtx), Kubeconfig: kubeconfig, Context: kubeCtx}}
	}
	if home, err := os.UserHomeDir(); err == nil {
		cfg.DataDir = filepath.Join(home, ".local", "state", "k0s-monitor")
	}
	return cfg, "", true, cfg.Validate()
}

// serveCertificate loads the UI certificate: tls.certFile/keyFile, or
// tls.crt/tls.key from init, or an in-memory self-signed one for laptop mode.
func serveCertificate(cfg *config.Config, configDir string) (tls.Certificate, time.Time, error) {
	certFile, keyFile := cfg.TLS.CertFile, cfg.TLS.KeyFile
	if certFile == "" && configDir != "" {
		c, k := filepath.Join(configDir, tlsca.CertFile), filepath.Join(configDir, tlsca.KeyFile)
		if _, err := os.Stat(c); err == nil {
			certFile, keyFile = c, k
		}
	}
	if certFile == "" {
		if !loopbackListen(cfg.Listen) {
			return tls.Certificate{}, time.Time{}, errors.New("no TLS certificate: run \"sudo k0s-monitor init\", or set tls.certFile and tls.keyFile")
		}
		c, err := tlsca.SelfSigned(time.Now())
		return c, time.Time{}, err
	}
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, time.Time{}, fmt.Errorf("TLS certificate: %w", err)
	}
	var expires time.Time
	if x, err := tlsca.ReadCert(certFile); err == nil {
		expires = x.NotAfter
	}
	return c, expires, nil
}

func loopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// displayAddr is the address to print: the host name instead of 0.0.0.0.
func displayAddr(listen, host string) string {
	h, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if h == "" || h == "0.0.0.0" || h == "::" {
		h = host
	}
	return net.JoinHostPort(h, port)
}

// logPacks says which product packs are used, and which files aren't.
func logPacks(log *slog.Logger, s *pack.Set) {
	for _, p := range s.Problems {
		log.Error("product pack not used", "source", p.Source, "err", p.Err)
	}
	if len(s.Packs) > 0 {
		var names []string
		for _, p := range s.Packs {
			names = append(names, p.Name)
		}
		log.Info("product packs", "packs", strings.Join(names, ", "))
	}
}
