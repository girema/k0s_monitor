package web

import (
	"strings"
	"testing"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/snapshot"
)

func TestAddonsAndConfig(t *testing.T) {
	st := stateOf(t, "k0s-addons.yaml")
	d := k0sOf(st, config.DefaultThresholds(), fixedNow)
	if !d.AddonsRead || len(d.Addons) != 4 {
		t.Fatalf("addons %+v", d.Addons)
	}
	// Failed first, then the rest.
	if d.Addons[0].Icon != "crit" || d.Addons[len(d.Addons)-1].Name != "metrics" || d.Addons[len(d.Addons)-1].Status != "installed, revision 1" {
		t.Errorf("order or status: %+v", d.Addons)
	}
	for _, a := range d.Addons {
		if a.Name == "ingress" && (a.Status != "update to 4.11.0 failed; 4.10.0 runs" || a.Top == nil) {
			t.Errorf("ingress: %+v", a)
		}
	}

	// Settings explained, profiles listed, from the ClusterConfig object.
	if d.Config.From != "the cluster (dynamic configuration)" || d.Config.Uploaded {
		t.Errorf("from %q", d.Config.From)
	}
	setting := func(name string) configSetting {
		for _, s := range d.Config.Settings {
			if s.Name == name {
				return s
			}
		}
		return configSetting{}
	}
	if s := setting("Network driver"); s.Value != "kuberouter" || !strings.Contains(s.Means, "k0s's default") {
		t.Errorf("network driver %+v", s)
	}
	if s := setting("Node-local load balancing"); s.Value != "on" || !strings.Contains(s.Means, "keeps working when a controller is down") {
		t.Errorf("NLLB %+v", s)
	}
	if s := setting("kube-proxy"); s.Value != "on" || !strings.HasPrefix(s.Means, "On:") {
		t.Errorf("kube-proxy %+v", s)
	}
	if s := setting("Helm add-ons"); s.Value != "broken" {
		t.Errorf("add-ons setting %+v", s)
	}
	if len(d.Config.Profiles) != 1 || d.Config.Profiles[0].Name != "big-logs" {
		t.Fatalf("profiles %+v", d.Config.Profiles)
	}
	got := map[string]configSetting{}
	for _, s := range d.Config.Profiles[0].Settings {
		got[s.Name] = s
	}
	if got["maxPods"].Value != "150" || got["containerLogMaxSize"].Means == "" || got["evictionHard"].Value != "memory.available=500Mi, nodefs.available=10%" {
		t.Errorf("profile settings %+v", got)
	}

	basic, full := renderPage(t, "k0s", d)
	for _, page := range []string{basic, full} {
		for _, secret := range []string{"hunter2", "Sup3rSecret", "repoPass1"} {
			if strings.Contains(page, secret) {
				t.Errorf("%q shows on the page", secret)
			}
		}
	}
	mustContain(t, full, "Add-ons (Helm charts)", "example/nothing 1.0.0", "not installed: failed", "password: ••••••", "Cluster configuration",
		"Worker profiles", "containerLogMaxSize", "The whole configuration")
	mustContain(t, basic, "Extra parts installed with the cluster", "not installed: it failed", "update failed; the previous version runs")
	if strings.Contains(basic, "Cluster configuration") || strings.Contains(basic, "password:") {
		t.Error("Basic mode shows no configuration or values")
	}

	// With the uploaded file too: the differences, within what the cluster
	// publishes (not api or storage).
	uploaded, err := snapshot.ParseClusterConfig([]byte(`apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  api: {externalAddress: k8s.example.com}
  storage: {type: etcd}
  network: {provider: kuberouter, podCIDR: 10.200.0.0/16, nodeLocalLoadBalancing: {enabled: true}}
  workerProfiles:
  - name: big-logs
    values: {containerLogMaxSize: 50Mi, maxPods: 110}
`), "the k0s.yaml uploaded with the cluster")
	if err != nil {
		t.Fatal(err)
	}
	cv := configOf(st, uploaded)
	var diffs []string
	for _, df := range cv.Diffs {
		diffs = append(diffs, df.Path+": "+df.Uploaded+" → "+df.Cluster)
	}
	want := "network.podCIDR: 10.200.0.0/16 → 10.244.0.0/16\nworkerProfiles[0].values.maxPods: 110 → 150"
	if strings.Join(diffs, "\n") != want || cv.DiffWith != "k0s.yaml uploaded with the cluster" {
		t.Errorf("diffs:\n%s\nwant:\n%s", strings.Join(diffs, "\n"), want)
	}

	// Without dynamic configuration, the uploaded file, said so.
	st.Snapshot.ControlPlane.Config = nil
	cv = configOf(st, uploaded)
	if !cv.Uploaded || cv.From != "the k0s.yaml uploaded with the cluster" || len(cv.Diffs) != 0 {
		t.Errorf("uploaded only: %+v", cv)
	}
	d.Config = configOf(st, nil)
	_, full = renderPage(t, "k0s", d)
	mustContain(t, full, "only with dynamic configuration", "sudo cat /etc/k0s/k0s.yaml")
}
