package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/snapshot"
)

// The Secrets pages list a namespace's Secrets and show one: its keys and
// their sizes, what uses it, and, when showing values is turned on in
// Settings, each value on request. Reading Secrets needs the cluster's
// optional Secrets role, the one the certificate check uses. Each value
// shown is recorded in the audit log. Values never appear in pages, lists
// or other answers of the API: only in the answer to a request for that
// one value.

const (
	// settingSecretValues is "on" while Secret values may be shown.
	settingSecretValues = "secrets.showValues"
	// maxValueBytes is the largest value shown.
	maxValueBytes = 64 << 10
)

// secretValuesOn reports whether Secret values may be shown.
func (s *Server) secretValuesOn() bool {
	v, _ := s.o.Store.Setting(settingSecretValues)
	return v == "on"
}

// setSecretValues turns showing Secret values on or off, for everyone.
func (s *Server) setSecretValues(r *http.Request, on bool) error {
	if err := s.o.Store.SetSetting(settingSecretValues, ifStr(on, "on", "")); err != nil {
		return err
	}
	s.audit(r, "settings.change", ifStr(on, "Secret values: shown on request", "Secret values: never shown"))
	return nil
}

// hiddenSecret says why k0s-monitor never shows a Secret's values, or "".
func hiddenSecret(t corev1.SecretType) string {
	switch t {
	case corev1.SecretTypeServiceAccountToken:
		return "It holds a service account token: a credential to the cluster itself, like k0s-monitor's own. k0s-monitor never shows these."
	case corev1.SecretTypeBootstrapToken:
		return "It holds a bootstrap token, which lets machines join the cluster. k0s-monitor never shows these."
	}
	return ""
}

// secretTypes explain the usual Secret types.
var secretTypes = map[corev1.SecretType]string{
	corev1.SecretTypeOpaque:              "any keys and values",
	corev1.SecretTypeTLS:                 "a TLS certificate and its private key",
	corev1.SecretTypeDockerConfigJson:    "credentials for image registries",
	corev1.SecretTypeDockercfg:           "credentials for image registries (old format)",
	corev1.SecretTypeBasicAuth:           "a user name and password",
	corev1.SecretTypeSSHAuth:             "an SSH private key",
	corev1.SecretTypeServiceAccountToken: "a service account token",
	corev1.SecretTypeBootstrapToken:      "a bootstrap token, for machines to join the cluster",
	"helm.sh/release.v1":                 "a Helm release: the chart's settings and objects, compressed",
}

const secretsNotAllowed = "k0s-monitor's account may not read Secrets in this cluster. The cluster's Connection page has the commands that allow it."

// secretsConn returns the connection to read a cluster's Secrets, or why
// they can't be read, with the HTTP status that goes with it.
func secretsConn(e *engine.Engine) (*cluster.Conn, string, int) {
	if !e.Cluster().TLSSecretsOn() {
		return nil, "k0s-monitor doesn't read Secrets in this cluster: it is turned off on the cluster's Connection page, or with readTLSSecrets in the configuration file.", http.StatusForbidden
	}
	// Only once the access review said so, as for the certificate check.
	switch st := e.State(); {
	case st.Info == nil || st.Info.TLSSecrets == "":
		return nil, "k0s-monitor hasn't checked yet whether it may read Secrets in this cluster. Try again in a minute.", http.StatusServiceUnavailable
	case st.Info.TLSSecrets == "not allowed":
		return nil, secretsNotAllowed, http.StatusForbidden
	case st.Info.TLSSecrets != "ok":
		return nil, "Whether k0s-monitor may read Secrets in this cluster " + st.Info.TLSSecrets + ".", http.StatusServiceUnavailable
	}
	conn := e.Conn()
	if conn == nil {
		return nil, "The cluster can't be reached right now.", http.StatusServiceUnavailable
	}
	return conn, "", 0
}

// secretsReadable reports whether a cluster's Secrets can be read: what
// links to the Secrets pages.
func secretsReadable(e *engine.Engine) bool {
	st := e.State()
	return e.Cluster().TLSSecretsOn() && st.Info != nil && st.Info.TLSSecrets == "ok"
}

// readError words an error of the API server.
func readError(err error) (string, int) {
	switch {
	case apierrors.IsForbidden(err):
		return secretsNotAllowed, http.StatusForbidden
	case apierrors.IsNotFound(err):
		return "This Secret doesn't exist (any more).", http.StatusNotFound
	case errors.Is(err, context.DeadlineExceeded):
		return "The cluster didn't answer in time.", http.StatusGatewayTimeout
	}
	return "The Secret can't be read: " + err.Error(), http.StatusBadGateway
}

// ---------------------------------------------------------------------------
// What uses a Secret

// secretUse is how a pod uses a Secret.
type secretUse struct {
	Secret string
	// Key is the key it reads; empty when it reads them all.
	Key      string
	How      string
	Optional bool
}

// podSecretUses lists what a pod takes from Secrets: environment
// variables, files and image pull credentials.
func podSecretUses(p *corev1.Pod) []secretUse {
	var out []secretUse
	opt := func(b *bool) bool { return b != nil && *b }
	mounts := map[string][]string{}
	containers := append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...)
	for _, c := range containers {
		for _, m := range c.VolumeMounts {
			mounts[m.Name] = append(mounts[m.Name], m.MountPath+" in "+c.Name)
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				r := e.ValueFrom.SecretKeyRef
				out = append(out, secretUse{Secret: r.Name, Key: r.Key, How: "env " + e.Name + " in " + c.Name, Optional: opt(r.Optional)})
			}
		}
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				how := "every key as env in " + c.Name
				if ef.Prefix != "" {
					how = "every key as env " + ef.Prefix + "… in " + c.Name
				}
				out = append(out, secretUse{Secret: ef.SecretRef.Name, How: how, Optional: opt(ef.SecretRef.Optional)})
			}
		}
	}
	files := func(v corev1.Volume, name string, items []corev1.KeyToPath, optional *bool) {
		where := strings.Join(mounts[v.Name], ", ")
		if where == "" {
			where = "volume " + v.Name + " (not mounted)"
		}
		if len(items) == 0 {
			out = append(out, secretUse{Secret: name, How: "files in " + where, Optional: opt(optional)})
		}
		for _, it := range items {
			out = append(out, secretUse{Secret: name, Key: it.Key, How: "file " + it.Path + " in " + where, Optional: opt(optional)})
		}
	}
	for _, v := range p.Spec.Volumes {
		switch {
		case v.Secret != nil:
			files(v, v.Secret.SecretName, v.Secret.Items, v.Secret.Optional)
		case v.Projected != nil:
			for _, src := range v.Projected.Sources {
				if src.Secret != nil {
					files(v, src.Secret.Name, src.Secret.Items, src.Secret.Optional)
				}
			}
		}
	}
	for _, ips := range p.Spec.ImagePullSecrets {
		out = append(out, secretUse{Secret: ips.Name, How: "credentials to pull its images"})
	}
	return out
}

// secretUser is a workload or Ingress that uses a Secret, and how.
type secretUser struct {
	Name, Link string
	How        []string
	uses       []secretUse
}

// workloadLink links a workload on the Apps page, or a bare pod's page.
func workloadLink(clusterName string, w snapshot.Workload) string {
	c := url.PathEscape(clusterName)
	if w.Kind == "Pod" {
		return "/c/" + c + "/pods/" + url.PathEscape(w.Namespace) + "/" + url.PathEscape(w.Name)
	}
	return "/c/" + c + "/apps?ns=" + url.QueryEscape(w.Namespace) + "&q=" + url.QueryEscape(w.Name) + "#app-" + shortKind(w.Kind) + "-" + w.Namespace + "-" + w.Name
}

// secretUsers maps "namespace/secret" to what uses it, in the snapshot:
// workloads, by their running pods, and the TLS of Ingresses.
func secretUsers(clusterName string, snap *snapshot.Snapshot) map[string][]*secretUser {
	out := map[string][]*secretUser{}
	if snap == nil {
		return out
	}
	byName := map[string]*secretUser{}
	user := func(ns, secret, name, link string) *secretUser {
		k := ns + "/" + secret + "/" + name
		if u := byName[k]; u != nil {
			return u
		}
		u := &secretUser{Name: name, Link: link}
		byName[k] = u
		out[ns+"/"+secret] = append(out[ns+"/"+secret], u)
		return u
	}
	add := func(u *secretUser, use secretUse) {
		for _, h := range u.How {
			if h == use.How {
				return
			}
		}
		u.How = append(u.How, use.How)
		u.uses = append(u.uses, use)
	}
	for _, p := range snap.Pods {
		if snapshot.IsPodTerminal(p) {
			continue
		}
		w := snap.WorkloadOf(p)
		for _, use := range podSecretUses(p) {
			add(user(p.Namespace, use.Secret, w.Kind+" "+w.Name, workloadLink(clusterName, w)), use)
		}
	}
	for _, ing := range snap.Ingresses {
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue
			}
			how := "TLS certificate"
			if len(t.Hosts) > 0 {
				how += " for " + strings.Join(t.Hosts, ", ")
			}
			add(user(ing.Namespace, t.SecretName, "Ingress "+ing.Name, ""), secretUse{Secret: t.SecretName, How: how})
		}
	}
	for _, us := range out {
		sort.Slice(us, func(i, j int) bool { return us[i].Name < us[j].Name })
	}
	return out
}

// ---------------------------------------------------------------------------
// The list

// secretMeta is what the list shows of a Secret: never its values.
type secretMeta struct {
	Namespace, Name string
	Type            corev1.SecretType
	Keys            int
	Created         time.Time
}

// listSecrets lists the Secrets of a namespace ("" for all) without their
// values: as a table, which the API server fills in without sending them.
func listSecrets(ctx context.Context, conn *cluster.Conn, ns string) ([]secretMeta, error) {
	rc, ok := conn.Client.CoreV1().RESTClient().(*rest.RESTClient)
	if !ok || rc == nil {
		// A fake client (the demo, tests) serves no tables.
		list, err := conn.Client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		out := make([]secretMeta, 0, len(list.Items))
		for _, sec := range list.Items {
			out = append(out, secretMeta{Namespace: sec.Namespace, Name: sec.Name, Type: sec.Type, Keys: len(sec.Data), Created: sec.CreationTimestamp.Time})
		}
		return out, nil
	}
	raw, err := rc.Get().Namespace(ns).Resource("secrets").
		Param("includeObject", "Metadata").
		SetHeader("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io").
		Do(ctx).Raw()
	if err != nil {
		return nil, err
	}
	var t metav1.Table
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("the list of Secrets can't be read: %w", err)
	}
	col := map[string]int{}
	for i, c := range t.ColumnDefinitions {
		col[c.Name] = i
	}
	cell := func(row metav1.TableRow, name string) any {
		if i, ok := col[name]; ok && i < len(row.Cells) {
			return row.Cells[i]
		}
		return nil
	}
	out := make([]secretMeta, 0, len(t.Rows))
	for _, row := range t.Rows {
		var m metav1.PartialObjectMetadata
		if err := json.Unmarshal(row.Object.Raw, &m); err != nil {
			continue
		}
		sm := secretMeta{Namespace: m.Namespace, Name: m.Name, Created: m.CreationTimestamp.Time}
		if v, ok := cell(row, "Type").(string); ok {
			sm.Type = corev1.SecretType(v)
		}
		if v, ok := cell(row, "Data").(float64); ok {
			sm.Keys = int(v)
		}
		out = append(out, sm)
	}
	return out, nil
}

type secretRow struct {
	Namespace, Name, Type string
	Keys                  int
	Age                   string
	Link                  string
	Users                 []backend
	Search                string
	Hidden                bool
}

type secretsData struct {
	Cluster    string
	Namespace  string
	Query      string
	Namespaces []string
	Rows       []secretRow
	Error      string
	ValuesOn   bool
	Shown      int
	// AppsLink and ServicesLink are the Apps page's other tabs.
	AppsLink, ServicesLink string
}

func secretLink(clusterName, ns, name string) string {
	return "/c/" + url.PathEscape(clusterName) + "/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(name)
}

func (s *Server) secretsPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	v := r.URL.Query()
	q := appsQuery{Query: strings.TrimSpace(v.Get("q")), Namespace: v.Get("ns")}
	d := secretsData{Cluster: e.Name(), Namespace: q.Namespace, Query: q.Query, ValuesOn: s.secretValuesOn(),
		AppsLink: "/c/" + url.PathEscape(e.Name()) + "/apps" + q.link(""), ServicesLink: "/c/" + url.PathEscape(e.Name()) + "/apps" + q.link("services")}
	status := http.StatusOK
	if conn, msg, code := secretsConn(e); conn == nil {
		d.Error, status = msg, code
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		list, err := listSecrets(ctx, conn, q.Namespace)
		cancel()
		if err != nil {
			d.Error, status = readError(err)
		}
		users := secretUsers(e.Name(), st.Snapshot)
		words := strings.Fields(strings.ToLower(q.Query))
		for _, m := range list {
			row := secretRow{Namespace: m.Namespace, Name: m.Name, Type: string(m.Type), Keys: m.Keys, Age: "—", Link: secretLink(e.Name(), m.Namespace, m.Name)}
			if !m.Created.IsZero() {
				row.Age = ago(s.now().Sub(m.Created))
			}
			var names []string
			for _, u := range users[m.Namespace+"/"+m.Name] {
				row.Users = append(row.Users, backend{Name: u.Name, Link: u.Link})
				names = append(names, u.Name)
			}
			row.Search = strings.ToLower(strings.Join(append([]string{m.Namespace, m.Name, string(m.Type)}, names...), " "))
			row.Hidden = !matches(row.Search, words)
			if !row.Hidden {
				d.Shown++
			}
			d.Rows = append(d.Rows, row)
		}
		sort.SliceStable(d.Rows, func(i, j int) bool {
			if d.Rows[i].Namespace != d.Rows[j].Namespace {
				return d.Rows[i].Namespace < d.Rows[j].Namespace
			}
			return d.Rows[i].Name < d.Rows[j].Name
		})
	}
	seen := map[string]bool{}
	if snap := st.Snapshot; snap != nil {
		for _, n := range snap.Namespaces {
			seen[n.Name] = true
		}
	}
	for _, row := range d.Rows {
		seen[row.Namespace] = true
	}
	for ns := range seen {
		d.Namespaces = append(d.Namespaces, ns)
	}
	sort.Strings(d.Namespaces)
	s.render(w, r, "secrets", &page{Title: "Secrets · " + e.Name(), Nav: "apps", Cluster: &nav, Data: d, Status: status})
}

// ---------------------------------------------------------------------------
// One Secret

type secretKey struct {
	Name   string
	Size   string
	Binary bool
	// UsedAs says what reads this key.
	UsedAs []string
}

type secretData struct {
	Cluster, Namespace, Name string
	Type, TypeText           string
	Created                  time.Time
	Labels, Annotations      []string
	Keys                     []secretKey
	Cert                     *snapshot.TLSCert
	Users                    []*secretUser
	// Missing are keys something needs that the Secret doesn't have.
	Missing []string
	// Hidden says why its values are never shown.
	Hidden   string
	ValuesOn bool
	Error    string
	Reveal   string
	ListLink string
}

// annotationText shows an annotation, except the one that holds a copy of
// the whole Secret.
func annotationText(k, v string) string {
	if k == corev1.LastAppliedConfigAnnotation {
		return k + ": (not shown: it holds a copy of the values)"
	}
	return k + ": " + truncateText(v, 200)
}

func truncateText(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// isText reports whether a value reads as text.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func byteSize(n int) string {
	if n < 1024 {
		return plural(n, "byte")
	}
	return bytesIEC(float64(n))
}

func (s *Server) secretPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	d := secretData{Cluster: e.Name(), Namespace: ns, Name: name, ValuesOn: s.secretValuesOn(),
		Reveal:   "/api/v1/clusters/" + url.PathEscape(e.Name()) + "/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(name) + "/reveal",
		ListLink: "/c/" + url.PathEscape(e.Name()) + "/secrets?ns=" + url.QueryEscape(ns)}
	d.Users = secretUsers(e.Name(), st.Snapshot)[ns+"/"+name]
	status := http.StatusOK
	var sec *corev1.Secret
	if conn, msg, code := secretsConn(e); conn == nil {
		d.Error, status = msg, code
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		got, err := conn.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		cancel()
		if err != nil {
			d.Error, status = readError(err)
			if status == http.StatusNotFound && len(d.Users) == 0 {
				s.notFound(w, r, fmt.Sprintf("The Secret %s/%s doesn't exist (any more).", ns, name))
				return
			}
			if status == http.StatusNotFound {
				d.Error = "This Secret doesn't exist, but the apps below need it: their pods can't start until it is created."
			}
		} else {
			sec = got
		}
	}
	if sec != nil {
		d.Type, d.TypeText, d.Hidden = string(sec.Type), secretTypes[sec.Type], hiddenSecret(sec.Type)
		d.Created = sec.CreationTimestamp.Time
		for k, v := range sec.Labels {
			d.Labels = append(d.Labels, k+"="+v)
		}
		for k, v := range sec.Annotations {
			d.Annotations = append(d.Annotations, annotationText(k, v))
		}
		sort.Strings(d.Labels)
		sort.Strings(d.Annotations)
		for k, v := range sec.Data {
			d.Keys = append(d.Keys, secretKey{Name: k, Size: byteSize(len(v)), Binary: !isText(v)})
		}
		sort.Slice(d.Keys, func(i, j int) bool { return d.Keys[i].Name < d.Keys[j].Name })
		if sec.Type == corev1.SecretTypeTLS {
			c := snapshot.TLSCertOf(sec)
			d.Cert = &c
		}
	}
	keyIdx := map[string]int{}
	for i, k := range d.Keys {
		keyIdx[k.Name] = i
	}
	for _, u := range d.Users {
		for _, use := range u.uses {
			if use.Key == "" {
				continue
			}
			if i, ok := keyIdx[use.Key]; ok {
				d.Keys[i].UsedAs = append(d.Keys[i].UsedAs, u.Name+": "+use.How)
			} else if sec != nil && !use.Optional {
				d.Missing = append(d.Missing, fmt.Sprintf("%s needs the key %s (%s), which this Secret doesn't have.", u.Name, use.Key, use.How))
			}
		}
	}
	s.render(w, r, "secret", &page{Title: name + " · Secrets · " + e.Name(), Nav: "apps", Cluster: &nav, Data: d, Status: status})
}

// ---------------------------------------------------------------------------
// Showing a value

type revealRequest struct {
	Key string `json:"key"`
}

type revealResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	// Base64 is true when the value isn't text and is sent as base64.
	Base64 bool `json:"base64"`
	Size   int  `json:"size"`
}

// apiSecretReveal shows one value of a Secret, and records it in the audit
// log.
func (s *Server) apiSecretReveal(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	var req revealRequest
	if err := readJSON(r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.secretValuesOn() {
		writeJSON(w, http.StatusForbidden, apiError{Error: "showing Secret values is turned off", Hint: "It can be turned on in Settings."})
		return
	}
	conn, msg, status := secretsConn(e)
	if conn == nil {
		writeError(w, status, msg)
		return
	}
	ns, name := r.PathValue("ns"), r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	sec, err := conn.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	cancel()
	if err != nil {
		msg, status := readError(err)
		writeError(w, status, msg)
		return
	}
	if why := hiddenSecret(sec.Type); why != "" {
		writeError(w, http.StatusForbidden, why)
		return
	}
	v, ok := sec.Data[req.Key]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("the Secret has no key %q", req.Key))
		return
	}
	if len(v) > maxValueBytes {
		writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: fmt.Sprintf("the value has %s; k0s-monitor shows values up to 64 KiB", byteSize(len(v))),
			Hint: fmt.Sprintf("kubectl -n %s get secret %s -o jsonpath='{.data.%s}' | base64 -d", ns, name, strings.ReplaceAll(req.Key, ".", `\.`))})
		return
	}
	// Every value shown is recorded; if it can't be, it isn't shown.
	user := sessionOf(r).User
	if err := s.o.Store.Audit(user, clientIP(r), "secret.reveal", fmt.Sprintf("%s: %s/%s key %s", e.Name(), ns, name, req.Key)); err != nil {
		s.log.Error("writing the audit log", "err", err)
		writeError(w, http.StatusInternalServerError, "the audit log can't be written, so the value isn't shown")
		return
	}
	resp := revealResponse{Key: req.Key, Size: len(v)}
	if isText(v) {
		resp.Value = string(v)
	} else {
		resp.Value, resp.Base64 = base64.StdEncoding.EncodeToString(v), true
	}
	writeJSON(w, http.StatusOK, resp)
}

// secretValuesForm turns showing Secret values on or off, on the Settings
// page.
func (s *Server) secretValuesForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	on := r.PostFormValue("on") == "1"
	if err := s.setSecretValues(r, on); err != nil {
		s.renderSettings(w, r, "", "Could not save: "+err.Error())
		return
	}
	s.renderSettings(w, r, ifStr(on, "Secret values can now be shown, one at a time, on the page of each Secret.", "Secret values are no longer shown."), "")
}
