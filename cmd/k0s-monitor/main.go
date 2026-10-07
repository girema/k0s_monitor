// Command k0s-monitor finds, explains and prioritizes problems in k0s
// clusters. It never changes anything in the clusters.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/output"
	"k0s_monitor/internal/pack"
	"k0s_monitor/internal/version"
)

// Exit codes.
const (
	exitOK       = 0
	exitProblems = 1 // problems at or above --fail-on were found
	exitUsage    = 2 // bad flags or configuration
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// client-go logs retries and watch errors through klog; the scan
	// reports connection problems itself, so keep the terminal clean.
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)

	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], os.Stdin, stdout, stderr)
	case "passwd":
		return runPasswd(args[1:], os.Stdin, stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "k0s-monitor %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return exitOK
	case "help", "-h", "--help", "-help":
		usage(stdout)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprint(w, `k0s-monitor finds, explains and prioritizes problems in k0s clusters.
It only reads from the clusters and never changes them.

Usage:
  k0s-monitor init [flags]    set up the web UI on this machine (run once, as root)
  k0s-monitor serve [flags]   run the web UI (usually as the k0s-monitor service)
  k0s-monitor passwd [flags]  set a new password for the web UI
  k0s-monitor scan [flags]    scan clusters once and print the problems found
  k0s-monitor version         print the version

Run "k0s-monitor <command> -h" for the flags of a command.
`)
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath = fs.String("config", "", "configuration file with up to 5 clusters")
		kubeconfig = fs.String("kubeconfig", "", "kubeconfig of a single cluster to scan (default: $KUBECONFIG or ~/.kube/config)")
		kubeCtx    = fs.String("context", "", "kubeconfig context to use with --kubeconfig")
		all        = fs.Bool("all", false, "scan every cluster in the configuration (the default)")
		format     = fs.String("output", "table", "output format: table, json or markdown")
		mode       = fs.String("mode", "full", "wording: full (technical) or basic (plain language)")
		failOn     = fs.String("fail-on", "none", "exit with code 1 if a problem of this priority or higher is found: P1, P2, P3, P4 or none")
		verbose    = fs.Bool("v", false, "show evidence and the steps to fix each problem")
		timeout    = fs.Duration("timeout", 3*time.Minute, "overall time limit")
		noColor    = fs.Bool("no-color", false, "disable colors")
		packsDir   = fs.String("packs", "", "directory of product packs (default: packsDir of the configuration, or the packs directory next to it)")
		clusters   stringList
	)
	fs.StringVar(format, "o", "table", "shorthand for --output")
	fs.Var(&clusters, "cluster", "cluster to scan, by name from the configuration (repeatable)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: k0s-monitor scan [flags]\n\nScan clusters and print the problems found, most urgent first.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprint(stderr, "\nExit codes: 0 no problem at --fail-on level, 1 problems found at that level, 2 usage or configuration error.\n")
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
	if *all && len(clusters) > 0 {
		fmt.Fprintln(stderr, "use either --all or --cluster, not both")
		return exitUsage
	}

	outFmt, err := output.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	outMode, err := output.ParseMode(*mode)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	var threshold findings.Priority
	if !strings.EqualFold(*failOn, "none") {
		if threshold, err = findings.ParsePriority(*failOn); err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
	}

	cfg, err := loadConfig(*configPath, *kubeconfig, *kubeCtx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if len(cfg.Clusters) == 0 {
		fmt.Fprintln(stderr, "no clusters configured")
		return exitUsage
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	if *packsDir != "" {
		cfg.PacksDir = *packsDir
	}
	m := fleet.NewManager(cfg)
	if cfg.PacksDir != "" {
		set := pack.NewRegistry(cfg.PacksDir, nil).Load()
		for _, p := range set.Problems {
			fmt.Fprintf(stderr, "product pack %s not used: %s\n", p.Source, p.Err)
		}
		m.Packs = set
	}
	results, err := m.Scan(ctx, clusters)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	opts := output.Options{
		Format:  outFmt,
		Mode:    outMode,
		Verbose: *verbose,
		Color:   outFmt == output.Table && !*noColor && isTerminal(stdout),
		Now:     time.Now(),
	}
	if err := output.Render(stdout, results, opts); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if threshold != "" {
		if worst := fleet.Worst(results); worst != "" && worst.Rank() <= threshold.Rank() {
			return exitProblems
		}
	}
	return exitOK
}

// loadConfig reads the configuration file, or builds a one-cluster
// configuration from a kubeconfig.
func loadConfig(path, kubeconfig, kubeCtx string) (*config.Config, error) {
	if path != "" {
		if kubeconfig != "" {
			return nil, errors.New("use either --config or --kubeconfig, not both")
		}
		return config.Load(path)
	}
	if kubeconfig == "" {
		kubeconfig = defaultKubeconfig()
	}
	if kubeconfig == "" {
		return nil, errors.New("no cluster given: use --config, --kubeconfig, or set KUBECONFIG")
	}
	cfg := config.Default()
	cfg.Clusters = []config.Cluster{{
		Name:       clusterName(kubeconfig, kubeCtx),
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	}}
	return cfg, cfg.Validate()
}

func defaultKubeconfig() string {
	if env := os.Getenv("KUBECONFIG"); env != "" {
		for _, p := range filepath.SplitList(env) {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

var nameCleaner = regexp.MustCompile(`[^a-z0-9._-]+`)

// clusterName derives a display name from the kubeconfig context.
func clusterName(kubeconfig, kubeCtx string) string {
	name := kubeCtx
	if name == "" {
		if raw, err := clientcmd.LoadFromFile(kubeconfig); err == nil {
			name = raw.CurrentContext
		}
	}
	name = strings.Trim(nameCleaner.ReplaceAllString(strings.ToLower(name), "-"), "-._")
	if len(name) > 63 {
		name = strings.Trim(name[:63], "-._")
	}
	if name == "" {
		name = "default"
	}
	return name
}

func isTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
