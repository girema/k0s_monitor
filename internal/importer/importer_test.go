package importer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func clientCert(t *testing.T, notAfter time.Time) (certB64, keyB64 string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	enc := base64.StdEncoding.EncodeToString
	return enc(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), enc(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

// kubeconfig is what `k0s kubeconfig admin` prints on a controller.
func kubeconfig(t *testing.T, server string, notAfter time.Time) string {
	cert, key := clientCert(t, notAfter)
	return `apiVersion: v1
clusters:
- cluster:
    server: ` + server + `
    certificate-authority-data: ` + cert + `
  name: local
contexts:
- context:
    cluster: local
    namespace: default
    user: user
  name: Default
current-context: Default
kind: Config
preferences: {}
users:
- name: user
  user:
    client-certificate-data: ` + cert + `
    client-key-data: ` + key + `
`
}

const k0sctl = `apiVersion: k0sctl.k0sproject.io/v1beta1
kind: Cluster
metadata:
  name: Edge-Prod
spec:
  hosts:
  - role: controller
    ssh: {address: 10.0.10.11, user: root}
  - role: controller
    ssh: {address: 10.0.10.12, user: root}
  - role: worker
    ssh: {address: 10.0.10.21, user: root}
  - role: worker
    ssh: {address: 10.0.10.22, user: root}
  k0s:
    version: v1.36.4+k0s.1
    config:
      spec:
        api:
          externalAddress: api.edge-prod.lan
          sans: [10.0.10.11, 10.0.10.12, api.edge-prod.lan]
`

const k0sYAML = `apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
metadata: {name: k0s}
spec:
  api:
    address: 10.0.10.11
    port: 6443
    sans: [10.0.10.11]
`

func TestKubeconfigWithLocalhostAndK0sctl(t *testing.T) {
	r, err := Detect([]Input{
		{Name: "cluster.config", Content: kubeconfig(t, "https://localhost:6443", now.Add(365*24*time.Hour))},
		{Name: "k0sctl.yaml", Content: k0sctl},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Files[0].Type != TypeKubeconfig || r.Files[1].Type != TypeK0sctl || r.Errors() {
		t.Fatalf("files = %+v notes = %+v", r.Files, r.Notes)
	}
	if r.Files[1].Summary != "k0sctl cluster file: 2 controllers, 2 workers, k0s v1.36.4+k0s.1" {
		t.Errorf("summary = %q", r.Files[1].Summary)
	}
	if r.Name != "edge-prod" {
		t.Errorf("name = %q", r.Name)
	}
	want := []string{"https://api.edge-prod.lan:6443", "https://10.0.10.11:6443", "https://10.0.10.12:6443"}
	if strings.Join(r.Servers, " ") != strings.Join(want, " ") {
		t.Errorf("servers = %v", r.Servers)
	}
	var loop *Note
	for i := range r.Notes {
		if r.Notes[i].Code == "loopback" {
			loop = &r.Notes[i]
		}
	}
	if loop == nil || !strings.Contains(loop.Hint, "https://api.edge-prod.lan:6443") {
		t.Errorf("the localhost address is flagged with the fix: %+v", r.Notes)
	}
	ctx, _ := r.Context("")
	if ctx.Name != "Default" || ctx.Auth != "client-certificate" || ctx.CertSubject != "admin" || !ctx.Loopback {
		t.Errorf("context = %+v", ctx)
	}
}

func TestK0sConfigAlone(t *testing.T) {
	r, err := Detect([]Input{{Content: k0sYAML}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Files[0].Type != TypeK0sConfig || r.Files[0].Name != "pasted text 1" || !r.Errors() {
		t.Fatalf("result = %+v", r)
	}
	if r.Notes[0].Code != "kubeconfig-missing" || r.Servers[0] != "https://10.0.10.11:6443" {
		t.Errorf("notes = %+v servers = %v", r.Notes, r.Servers)
	}
}

func TestRefusedKubeconfigs(t *testing.T) {
	cases := map[string]string{
		"exec": `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://10.0.0.1:6443"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {exec: {apiVersion: client.authentication.k8s.io/v1, command: /bin/sh, args: [-c, "curl evil"]}}}]
`,
		"token file": `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://10.0.0.1:6443"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {tokenFile: /etc/k0s-monitor/secret.key}}]
`,
		"CA file": `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://10.0.0.1:6443", certificate-authority: /etc/shadow}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {token: abc}}]
`,
	}
	for name, kc := range cases {
		r, err := Detect([]Input{{Name: name, Content: kc}}, now)
		if err != nil {
			t.Fatal(err)
		}
		if r.Files[0].Error == "" || r.HasKubeconfig() {
			t.Errorf("%s: must be refused, got %+v", name, r.Files[0])
		}
	}
}

func TestExpiredCredentials(t *testing.T) {
	r, _ := Detect([]Input{{Content: kubeconfig(t, "https://10.0.10.11:6443", now.Add(-time.Hour))}}, now)
	if !r.Errors() || r.Notes[0].Code != "credentials-expired" {
		t.Errorf("notes = %+v", r.Notes)
	}
	r, _ = Detect([]Input{{Content: kubeconfig(t, "https://10.0.10.11:6443", now.Add(10*24*time.Hour))}}, now)
	if r.Errors() || r.Notes[0].Code != "credentials-expire-soon" {
		t.Errorf("notes = %+v", r.Notes)
	}
}

func TestExpiredJWT(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1700000000}`))
	kc := `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://10.0.0.1:6443"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {token: "eyJhbGciOiJSUzI1NiJ9.` + payload + `.sig"}}]
`
	r, _ := Detect([]Input{{Content: kc}}, now)
	if !r.Errors() || r.Notes[0].Code != "credentials-expired" {
		t.Errorf("notes = %+v", r.Notes)
	}
}

func TestUnknownAndBadFiles(t *testing.T) {
	r, err := Detect([]Input{{Name: "notes.txt", Content: "::: not yaml"}, {Name: "deploy.yaml", Content: "apiVersion: apps/v1\nkind: Deployment\n"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Files[0].Error == "" || !strings.Contains(r.Files[1].Error, "apps/v1 Deployment") || !r.Errors() {
		t.Errorf("files = %+v", r.Files)
	}
	if _, err := Detect(nil, now); err == nil {
		t.Error("no input is an error")
	}
	many := make([]Input, MaxFiles+1)
	if _, err := Detect(many, now); err == nil {
		t.Error("too many files is an error")
	}
}

func TestMinify(t *testing.T) {
	kc := kubeconfig(t, "https://10.0.10.11:6443", now.Add(time.Hour*24*365))
	kc = strings.Replace(kc, "contexts:\n", "contexts:\n- context: {cluster: local, user: user}\n  name: other\n", 1)
	r, _ := Detect([]Input{{Content: kc}}, now)
	if len(r.Contexts) != 2 {
		t.Fatalf("contexts = %+v", r.Contexts)
	}
	out, err := r.Minify("Default")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(out)
	if err != nil || len(cfg.Contexts) != 1 || cfg.CurrentContext != "Default" || len(cfg.AuthInfos["user"].ClientKeyData) == 0 {
		t.Errorf("minified = %+v %v", cfg, err)
	}
	if _, err := r.Minify("nope"); err == nil {
		t.Error("an unknown context is an error")
	}
}
