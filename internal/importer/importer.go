// Package importer reads the files a person uploads or pastes on the Add
// cluster page (plan section 5.3). The type of each file is detected from
// its content: a kubeconfig (for example the product's cluster.config), a
// k0sctl cluster file or a k0s configuration. It points out problems that
// are cheaper to fix before connecting, such as a localhost server address
// or an expired client certificate.
package importer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"
)

// Limits for uploads.
const (
	MaxFiles    = 5
	MaxFileSize = 1 << 20
)

// FileType is what a file was recognized as.
type FileType string

const (
	TypeKubeconfig FileType = "kubeconfig"
	TypeK0sctl     FileType = "k0sctl"
	TypeK0sConfig  FileType = "k0s-config"
	TypeUnknown    FileType = "unknown"
)

// Input is one uploaded file or pasted text.
type Input struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// File describes one input after detection.
type File struct {
	Name    string   `json:"name"`
	Type    FileType `json:"type"`
	Summary string   `json:"summary"`
	Error   string   `json:"error,omitempty"`
}

// Note is a problem or hint found in the files.
type Note struct {
	// Level is error (the cluster can't be added like this), warning or info.
	Level string `json:"level"`
	Code  string `json:"code"`
	Plain string `json:"plain"`
	Hint  string `json:"hint,omitempty"`
}

// Context is one kubeconfig context.
type Context struct {
	Name     string `json:"name"`
	Cluster  string `json:"cluster"`
	User     string `json:"user"`
	Server   string `json:"server"`
	Loopback bool   `json:"loopback"`
	// Auth is client-certificate, token, basic or none.
	Auth        string     `json:"auth"`
	CertExpires *time.Time `json:"certExpires,omitempty"`
	CertSubject string     `json:"certSubject,omitempty"`
	Insecure    bool       `json:"insecure,omitempty"`
}

// Result is what the files say about the cluster.
type Result struct {
	Files    []File    `json:"files"`
	Contexts []Context `json:"contexts,omitempty"`
	// Current is the kubeconfig's current context.
	Current string `json:"current,omitempty"`
	// Name is a suggested name for the cluster.
	Name string `json:"name,omitempty"`
	// Servers are API server addresses to use instead of a loopback one,
	// best first, from k0sctl.yaml or k0s.yaml.
	Servers []string `json:"servers,omitempty"`
	// Controllers and Workers come from k0sctl.yaml.
	Controllers []string `json:"controllers,omitempty"`
	Workers     []string `json:"workers,omitempty"`
	K0sVersion  string   `json:"k0sVersion,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	Notes       []Note   `json:"notes,omitempty"`

	// Raw data, never sent to the browser.
	Kubeconfig []byte `json:"-"`
	K0sctl     []byte `json:"-"`
	K0sConfig  []byte `json:"-"`
	config     *clientcmdapi.Config
}

// HasKubeconfig reports whether a usable kubeconfig was found.
func (r *Result) HasKubeconfig() bool { return r.config != nil }

// Errors reports whether a note makes the cluster impossible to add.
func (r *Result) Errors() bool {
	for _, n := range r.Notes {
		if n.Level == "error" {
			return true
		}
	}
	return false
}

func (r *Result) note(level, code, plain, hint string) {
	r.Notes = append(r.Notes, Note{Level: level, Code: code, Plain: plain, Hint: hint})
}

// Detect reads the inputs. now is used for expiry checks.
func Detect(inputs []Input, now time.Time) (*Result, error) {
	if len(inputs) == 0 {
		return nil, errors.New("no file was given")
	}
	if len(inputs) > MaxFiles {
		return nil, fmt.Errorf("at most %d files at once", MaxFiles)
	}
	r := &Result{}
	var k0sctlDoc, k0sDoc map[string]any
	for i, in := range inputs {
		name := in.Name
		if name == "" {
			name = fmt.Sprintf("pasted text %d", i+1)
		}
		f := File{Name: name, Type: TypeUnknown}
		if len(in.Content) > MaxFileSize {
			f.Error = fmt.Sprintf("larger than %d KiB", MaxFileSize/1024)
			r.Files = append(r.Files, f)
			continue
		}
		doc, err := parseYAML(in.Content)
		if err != nil {
			f.Error = "not YAML or JSON: " + err.Error()
			r.Files = append(r.Files, f)
			continue
		}
		apiVersion, _ := doc["apiVersion"].(string)
		kind, _ := doc["kind"].(string)
		switch {
		case kind == "Config" && (apiVersion == "v1" || apiVersion == "") && doc["clusters"] != nil:
			f.Type = TypeKubeconfig
			if r.config != nil {
				f.Error = "a second kubeconfig; add one cluster at a time"
				break
			}
			if err := r.readKubeconfig([]byte(in.Content), now); err != nil {
				f.Error = err.Error()
				break
			}
			f.Summary = fmt.Sprintf("kubeconfig with %s", plural(len(r.Contexts), "context"))
		case strings.HasPrefix(apiVersion, "k0sctl.k0sproject.io/") && kind == "Cluster":
			f.Type = TypeK0sctl
			k0sctlDoc = doc
			r.K0sctl = []byte(in.Content)
		case strings.HasPrefix(apiVersion, "k0s.k0sproject.io/") && kind == "ClusterConfig":
			f.Type = TypeK0sConfig
			k0sDoc = doc
			r.K0sConfig = []byte(in.Content)
		default:
			f.Error = "not a kubeconfig, k0sctl.yaml or k0s.yaml"
			if kind != "" {
				f.Error = fmt.Sprintf("a %s %s, not a kubeconfig, k0sctl.yaml or k0s.yaml", apiVersion, kind)
			}
		}
		r.Files = append(r.Files, f)
	}
	if k0sctlDoc != nil {
		r.readK0sctl(k0sctlDoc)
		for i := range r.Files {
			if r.Files[i].Type == TypeK0sctl {
				r.Files[i].Summary = fmt.Sprintf("k0sctl cluster file: %s, %s%s", plural(len(r.Controllers), "controller"),
					plural(len(r.Workers), "worker"), ifStr(r.K0sVersion != "", ", k0s "+r.K0sVersion, ""))
			}
		}
	}
	if k0sDoc != nil {
		spec, _ := k0sDoc["spec"].(map[string]any)
		r.readAPI(spec)
		for i := range r.Files {
			if r.Files[i].Type == TypeK0sConfig {
				r.Files[i].Summary = "k0s configuration" + ifStr(len(r.SANs) > 0, fmt.Sprintf(", API SANs: %s", strings.Join(r.SANs, ", ")), "")
			}
		}
	}
	if r.config == nil {
		if k0sctlDoc != nil || k0sDoc != nil {
			r.note("error", "kubeconfig-missing", "These files have no credentials for the cluster.",
				"Add the kubeconfig too, for example the product's cluster.config, or run on a controller: sudo k0s kubeconfig admin")
		} else {
			r.note("error", "nothing-usable", "No kubeconfig was found in the files.",
				"Upload the cluster's kubeconfig, for example the product's cluster.config.")
		}
	}
	r.checkLoopback()
	r.suggestName()
	return r, nil
}

func parseYAML(s string) (map[string]any, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("empty")
	}
	return doc, nil
}

// readKubeconfig parses the kubeconfig and refuses what would make the jump
// host run commands or read its own files on behalf of an uploaded file.
func (r *Result) readKubeconfig(data []byte, now time.Time) error {
	cfg, err := clientcmd.Load(data)
	if err != nil {
		return fmt.Errorf("the kubeconfig can't be read: %w", err)
	}
	if len(cfg.Contexts) == 0 {
		return errors.New("the kubeconfig has no contexts")
	}
	for name, c := range cfg.Clusters {
		if c.CertificateAuthority != "" {
			return fmt.Errorf("cluster %q refers to a file (certificate-authority: %s); only embedded data (certificate-authority-data) can be uploaded", name, c.CertificateAuthority)
		}
	}
	for name, u := range cfg.AuthInfos {
		switch {
		case u.Exec != nil:
			return fmt.Errorf("user %q runs a command to get credentials (%s); k0s-monitor never runs commands from uploaded files. On a controller, create a kubeconfig with embedded credentials: sudo k0s kubeconfig admin", name, u.Exec.Command)
		case u.AuthProvider != nil:
			return fmt.Errorf("user %q uses an auth provider (%s), which is not supported; upload a kubeconfig with a token or a client certificate", name, u.AuthProvider.Name)
		case u.ClientCertificate != "" || u.ClientKey != "" || u.TokenFile != "":
			return fmt.Errorf("user %q refers to files on disk; only embedded data (client-certificate-data, client-key-data, token) can be uploaded", name)
		}
	}
	r.config = cfg
	r.Kubeconfig = data
	r.Current = cfg.CurrentContext
	var names []string
	for n := range cfg.Contexts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		kc := cfg.Contexts[n]
		ctx := Context{Name: n, Cluster: kc.Cluster, User: kc.AuthInfo, Auth: "none"}
		if cl := cfg.Clusters[kc.Cluster]; cl != nil {
			ctx.Server = cl.Server
			ctx.Loopback = isLoopbackURL(cl.Server)
			ctx.Insecure = cl.InsecureSkipTLSVerify
		}
		if u := cfg.AuthInfos[kc.AuthInfo]; u != nil {
			switch {
			case len(u.ClientCertificateData) > 0:
				ctx.Auth = "client-certificate"
				if c := firstCert(u.ClientCertificateData); c != nil {
					exp := c.NotAfter
					ctx.CertExpires = &exp
					ctx.CertSubject = c.Subject.CommonName
				}
			case u.Token != "":
				ctx.Auth = "token"
				if exp := jwtExpiry(u.Token); exp != nil {
					ctx.CertExpires = exp
				}
			case u.Username != "":
				ctx.Auth = "basic"
			}
		}
		r.Contexts = append(r.Contexts, ctx)
	}
	if r.Current == "" || cfg.Contexts[r.Current] == nil {
		r.Current = names[0]
	}
	for _, c := range r.Contexts {
		if c.Name != r.Current {
			continue
		}
		if c.CertExpires != nil {
			left := c.CertExpires.Sub(now)
			switch {
			case left <= 0:
				r.note("error", "credentials-expired", fmt.Sprintf("The credentials in this kubeconfig expired on %s.", c.CertExpires.UTC().Format("2006-01-02")),
					"Create a fresh kubeconfig on a controller (sudo k0s kubeconfig admin) and upload it.")
			case left < 30*24*time.Hour:
				r.note("warning", "credentials-expire-soon", fmt.Sprintf("The credentials in this kubeconfig expire on %s.", c.CertExpires.UTC().Format("2006-01-02")),
					"Choose the read-only account below: its token does not expire.")
			}
		}
		if c.Insecure {
			r.note("warning", "insecure", "The kubeconfig turns off the check of the server certificate (insecure-skip-tls-verify).",
				"The connection is encrypted, but the server's identity is not verified. Prefer a kubeconfig with certificate-authority-data.")
		}
		if c.Auth == "none" {
			r.note("error", "no-credentials", "The chosen context has no credentials.", "Upload a kubeconfig with a token or a client certificate.")
		}
	}
	return nil
}

func (r *Result) readK0sctl(doc map[string]any) {
	meta, _ := doc["metadata"].(map[string]any)
	if n, _ := meta["name"].(string); n != "" && r.Name == "" {
		r.Name = sanitize(n)
	}
	spec, _ := doc["spec"].(map[string]any)
	hosts, _ := spec["hosts"].([]any)
	for _, h := range hosts {
		hm, _ := h.(map[string]any)
		role, _ := hm["role"].(string)
		addr := ""
		if ssh, ok := hm["ssh"].(map[string]any); ok {
			addr, _ = ssh["address"].(string)
		}
		if addr == "" {
			if ws, ok := hm["winRM"].(map[string]any); ok {
				addr, _ = ws["address"].(string)
			}
		}
		if addr == "" {
			continue
		}
		switch role {
		case "controller", "controller+worker", "single":
			r.Controllers = append(r.Controllers, addr)
			if role != "controller" {
				r.Workers = append(r.Workers, addr)
			}
		case "worker":
			r.Workers = append(r.Workers, addr)
		}
	}
	k0s, _ := spec["k0s"].(map[string]any)
	r.K0sVersion, _ = k0s["version"].(string)
	if cfg, ok := k0s["config"].(map[string]any); ok {
		cs, _ := cfg["spec"].(map[string]any)
		r.readAPI(cs)
	}
	for _, c := range r.Controllers {
		r.addServer(c, 6443)
	}
}

// readAPI reads spec.api of a k0s configuration.
func (r *Result) readAPI(spec map[string]any) {
	api, _ := spec["api"].(map[string]any)
	if api == nil {
		return
	}
	port := 6443
	if p, ok := api["port"].(float64); ok && p > 0 {
		port = int(p)
	}
	if ext, _ := api["externalAddress"].(string); ext != "" {
		r.addServerFirst(ext, port)
	}
	if addr, _ := api["address"].(string); addr != "" {
		r.addServer(addr, port)
	}
	if sans, ok := api["sans"].([]any); ok {
		for _, s := range sans {
			if v, _ := s.(string); v != "" && !contains(r.SANs, v) {
				r.SANs = append(r.SANs, v)
			}
		}
	}
}

func (r *Result) addServer(host string, port int) {
	u := "https://" + net.JoinHostPort(host, fmt.Sprint(port))
	if !contains(r.Servers, u) && !isLoopbackURL(u) {
		r.Servers = append(r.Servers, u)
	}
}

func (r *Result) addServerFirst(host string, port int) {
	u := "https://" + net.JoinHostPort(host, fmt.Sprint(port))
	if isLoopbackURL(u) {
		return
	}
	out := []string{u}
	for _, s := range r.Servers {
		if s != u {
			out = append(out, s)
		}
	}
	r.Servers = out
}

// checkLoopback flags a server address that only works on the controller
// itself, which is typical when the kubeconfig was copied from there.
func (r *Result) checkLoopback() {
	for _, c := range r.Contexts {
		if c.Name != r.Current || !c.Loopback {
			continue
		}
		hint := "Enter the address of a controller or of the load balancer in front of them, as seen from this machine."
		if len(r.Servers) > 0 {
			hint = fmt.Sprintf("Use %s instead (from the uploaded files), or enter another address.", r.Servers[0])
		}
		r.note("warning", "loopback", fmt.Sprintf("The server address %s only works on the controller itself.", c.Server), hint)
	}
}

func (r *Result) suggestName() {
	if r.Name != "" {
		return
	}
	for _, c := range r.Contexts {
		if c.Name == r.Current {
			for _, cand := range []string{c.Cluster, c.Name} {
				if n := sanitize(cand); n != "" && n != "local" && n != "default" && n != "k0s" {
					r.Name = n
					return
				}
			}
		}
	}
	if r.Name == "" {
		r.Name = "k0s"
	}
}

// Context returns the chosen context, or the current one.
func (r *Result) Context(name string) (*Context, error) {
	if name == "" {
		name = r.Current
	}
	for i := range r.Contexts {
		if r.Contexts[i].Name == name {
			return &r.Contexts[i], nil
		}
	}
	return nil, fmt.Errorf("the kubeconfig has no context %q", name)
}

// Minify returns a kubeconfig with only the chosen context, its cluster and
// its user, so nothing unrelated is stored.
func (r *Result) Minify(context string) ([]byte, error) {
	if r.config == nil {
		return nil, errors.New("no kubeconfig")
	}
	ctx, err := r.Context(context)
	if err != nil {
		return nil, err
	}
	src := r.config
	out := clientcmdapi.NewConfig()
	out.Clusters[ctx.Cluster] = src.Clusters[ctx.Cluster]
	out.AuthInfos[ctx.User] = src.AuthInfos[ctx.User]
	out.Contexts[ctx.Name] = src.Contexts[ctx.Name]
	out.CurrentContext = ctx.Name
	return clientcmd.Write(*out)
}

// CAData returns the certificate authority of the chosen context's cluster.
func (r *Result) CAData(context string) []byte {
	ctx, err := r.Context(context)
	if err != nil || r.config == nil {
		return nil
	}
	if cl := r.config.Clusters[ctx.Cluster]; cl != nil {
		return cl.CertificateAuthorityData
	}
	return nil
}

func firstCert(data []byte) *x509.Certificate {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// jwtExpiry reads the exp claim of a JWT without verifying it.
func jwtExpiry(token string) *time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return nil
	}
	t := time.Unix(claims.Exp, 0).UTC()
	return &t
}

func isLoopbackURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var cleaner = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitize(s string) string {
	s = strings.Trim(cleaner.ReplaceAllString(strings.ToLower(s), "-"), "-._")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-._")
	}
	return s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return fmt.Sprintf("%d %ss", n, w)
}

func ifStr(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
