package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/testutil"
)

const dbPassword = "s3cr3t-db-pass"

// secretsEnv is a cluster whose account may read Secrets, with a pod that
// uses one.
func secretsEnv(t *testing.T) *testEnv {
	t.Helper()
	objs := testutil.Objects(t, "../rules/testdata/crashloop.yaml")
	optional := true
	objs = append(objs,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "db-credentials", Namespace: "shop", CreationTimestamp: metav1.NewTime(fixedNow.Add(-72 * 3600e9)),
			Labels:      map[string]string{"app": "api"},
			Annotations: map[string]string{corev1.LastAppliedConfigAnnotation: `{"data":{"password":"` + dbPassword + `"}}`, "owner": "team-shop"}},
			Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"password": []byte(dbPassword), "user": []byte("shop")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "blob", Namespace: "shop"}, Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"key.bin": {0xff, 0x00, 0x01}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "k0s-monitor-token", Namespace: "kube-system"}, Type: corev1.SecretTypeServiceAccountToken,
			Data: map[string][]byte{"token": []byte("eyJhbGciOiJSUzI1NiJ9.cluster-credential")}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "shop/api:1.4",
					Env: []corev1.EnvVar{
						{Name: "DB_PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db-credentials"}, Key: "password"}}},
						{Name: "API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db-credentials"}, Key: "apikey"}}},
						{Name: "FEATURE", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db-credentials"}, Key: "feature", Optional: &optional}}},
					},
					VolumeMounts: []corev1.VolumeMount{{Name: "blob", MountPath: "/etc/blob"}}}},
				Volumes:          []corev1.Volume{{Name: "blob", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "blob"}}}},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	)
	client := fake.NewClientset(objs...)
	client.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).DeepCopy()
		r.Status.Allowed = true
		return true, r, nil
	})
	env := newEnvFor(t, client, nil)
	env.waitFor(func(e *engine.Engine) bool { return secretsReadable(e) && e.State().Snapshot != nil })
	env.login()
	return env
}

func (env *testEnv) reveal(ns, name, key string) (int, map[string]any) {
	env.t.Helper()
	resp := env.do("POST", "/api/v1/clusters/edge-prod/secrets/"+ns+"/"+name+"/reveal", strings.NewReader(`{"key":"`+key+`"}`),
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": env.csrf})
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		env.t.Errorf("reveal answers must not be cached: %q", cc)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp.StatusCode, out
}

func TestSecretPages(t *testing.T) {
	env := secretsEnv(t)

	resp := env.do("GET", "/c/edge-prod/secrets?ns=shop", nil, nil)
	list := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	mustContain(t, list, "db-credentials", "/c/edge-prod/secrets/shop/db-credentials", "Pod api", "showing them is turned off")
	if strings.Contains(list, dbPassword) || strings.Contains(list, "k0s-monitor-token") {
		t.Error("the list shows no values, and only the namespace asked for")
	}

	resp = env.do("GET", "/c/edge-prod/secrets/shop/db-credentials?mode=full", nil, nil)
	page := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("secret page: %d %s", resp.StatusCode, page)
	}
	mustContain(t, page, "password", "user", "14 bytes", "Pod api: env DB_PASSWORD in api", "app=api", "owner: team-shop",
		"last-applied-configuration: (not shown: it holds a copy of the values)",
		"Pod api needs the key apikey (env API_KEY in api), which this Secret doesn&#39;t have.", "Showing them is turned off")
	if strings.Contains(page, dbPassword) {
		t.Error("the page never holds a value, not even in the last-applied annotation")
	}
	if strings.Contains(page, "key feature") {
		t.Error("an optional key that is missing isn't a problem")
	}
	if strings.Contains(page, "data-show") {
		t.Error("no Show buttons while showing values is off")
	}
	if !strings.Contains(page, `id="secretPage" data-no-refresh`) {
		t.Error("live refresh would replace the page, and the values shown with it")
	}

	// The pod page lists the Secrets it uses, with links.
	resp = env.do("GET", "/c/edge-prod/pods/shop/api?mode=full", nil, nil)
	mustContain(t, readBody(t, resp), `href="/c/edge-prod/secrets/shop/db-credentials"`, "key password as env DB_PASSWORD in api",
		"key feature as env FEATURE in api (optional)", "files in /etc/blob in api", "credentials to pull its images")

	// Off: nothing is shown.
	if code, out := env.reveal("shop", "db-credentials", "password"); code != http.StatusForbidden || out["value"] != nil {
		t.Errorf("off: %d %v", code, out)
	}
	resp = env.do("POST", "/settings/secrets", strings.NewReader("on=1&csrf="+env.csrf),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	mustContain(t, readBody(t, resp), "can now be shown")
	if !env.srv.secretValuesOn() {
		t.Fatal("the setting didn't turn on")
	}

	// On: shown on request, without asking for the password again.
	code, out := env.reveal("shop", "db-credentials", "password")
	if code != 200 || out["value"] != dbPassword || out["base64"] != false {
		t.Errorf("reveal: %d %v", code, out)
	}
	code, out = env.reveal("shop", "blob", "key.bin")
	if code != 200 || out["value"] != "/wAB" || out["base64"] != true {
		t.Errorf("binary: %d %v", code, out)
	}
	if code, out := env.reveal("kube-system", "k0s-monitor-token", "token"); code != http.StatusForbidden || out["value"] != nil {
		t.Errorf("service account tokens are never shown: %d %v", code, out)
	}
	if code, _ := env.reveal("shop", "db-credentials", "nope"); code != http.StatusNotFound {
		t.Errorf("unknown key: %d", code)
	}
	if code, _ := env.reveal("shop", "gone", "password"); code != http.StatusNotFound {
		t.Errorf("unknown Secret: %d", code)
	}

	// Without the CSRF token, nothing.
	resp = env.do("POST", "/api/v1/clusters/edge-prod/secrets/shop/db-credentials/reveal", strings.NewReader(`{"key":"password"}`),
		map[string]string{"Content-Type": "application/json"})
	if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || strings.Contains(body, dbPassword) {
		t.Errorf("no CSRF token: %d", resp.StatusCode)
	}

	// Each value shown is in the audit log, and the setting.
	log, _ := env.st.AuditLog(20)
	var actions []string
	for _, a := range log {
		actions = append(actions, a.Action+" "+a.Detail)
	}
	all := strings.Join(actions, "\n")
	mustContain(t, all, "secret.reveal edge-prod: shop/db-credentials key password", "secret.reveal edge-prod: shop/blob key key.bin",
		"settings.change Secret values: shown on request")
	if strings.Count(all, "secret.reveal") != 2 {
		t.Errorf("only values shown are logged:\n%s", all)
	}

	// With values on, the page has Show buttons, still no values.
	page = readBody(t, env.do("GET", "/c/edge-prod/secrets/shop/db-credentials", nil, nil))
	if !strings.Contains(page, "data-show") || !strings.Contains(page, "data-show-all") || strings.Contains(page, dbPassword) {
		t.Error("Show buttons, but no values, on the page")
	}
	page = readBody(t, env.do("GET", "/c/edge-prod/secrets/kube-system/k0s-monitor-token", nil, nil))
	if !strings.Contains(page, "never shows these") || strings.Contains(page, "data-show") || strings.Contains(page, "cluster-credential") {
		t.Error("a service account token's page offers no values")
	}

	// A Secret that is missing but needed says who needs it.
	resp = env.do("GET", "/c/edge-prod/secrets/shop/registry", nil, nil)
	if body := readBody(t, resp); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "the apps below need it") {
		t.Errorf("missing Secret: %d", resp.StatusCode)
	}

	// Turning it off again works through the API too.
	resp = env.do("PATCH", "/api/v1/settings", strings.NewReader(`{"secretValues":false}`),
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": env.csrf})
	if body := readBody(t, resp); resp.StatusCode != 200 || !strings.Contains(body, `"secretValues": false`) {
		t.Errorf("patch: %d %s", resp.StatusCode, body)
	}
	if code, _ := env.reveal("shop", "db-credentials", "password"); code != http.StatusForbidden {
		t.Errorf("off again: %d", code)
	}
}

func TestSecretsNotReadable(t *testing.T) {
	client := fake.NewClientset(testutil.Objects(t, "../rules/testdata/crashloop.yaml")...)
	client.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, a.(k8stesting.CreateAction).GetObject(), nil // not allowed
	})
	env := newEnvFor(t, client, nil)
	env.waitFor(func(e *engine.Engine) bool {
		return e.State().Info != nil && e.State().Info.TLSSecrets == "not allowed"
	})
	env.login()
	if err := env.srv.setSecretValues(httptest.NewRequest("POST", "/settings/secrets", nil), true); err != nil {
		t.Fatal(err)
	}
	resp := env.do("GET", "/c/edge-prod/secrets", nil, nil)
	if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "may not read Secrets") {
		t.Errorf("not allowed: %d", resp.StatusCode)
	}
	if code, _ := env.reveal("shop", "db-credentials", "password"); code != http.StatusForbidden {
		t.Errorf("reveal without the permission: %d", code)
	}
	resp = env.do("GET", "/c/edge-prod/apps?mode=full", nil, nil)
	if strings.Contains(readBody(t, resp), "/c/edge-prod/secrets") {
		t.Error("the Apps page links the Secrets only when they can be read")
	}
}

func TestPodSecretUses(t *testing.T) {
	p := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", EnvFrom: []corev1.EnvFromSource{{Prefix: "DB_", SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}}}}}},
		Containers:     []corev1.Container{{Name: "web", VolumeMounts: []corev1.VolumeMount{{Name: "tls", MountPath: "/tls"}, {Name: "all", MountPath: "/all"}}}},
		Volumes: []corev1.Volume{
			{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "web-tls", Items: []corev1.KeyToPath{{Key: "tls.crt", Path: "cert.pem"}}}}},
			{Name: "all", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "extra"}}}}}}},
			{Name: "unused", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "spare"}}},
		},
	}}
	var got []string
	for _, u := range podSecretUses(p) {
		got = append(got, u.Secret+"|"+u.Key+"|"+u.How)
	}
	want := []string{
		"db||every key as env DB_… in init",
		"web-tls|tls.crt|file cert.pem in /tls in web",
		"extra||files in /all in web",
		"spare||files in volume unused (not mounted)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("uses:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
