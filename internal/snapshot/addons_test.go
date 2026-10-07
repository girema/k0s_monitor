package snapshot

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The Chart and ClusterConfig documents in testdata are what k0s
// v1.36.4+k0s.1 serves for a configuration with a Helm chart whose
// repository doesn't exist, and a worker profile.

func TestParseCharts(t *testing.T) {
	data, err := os.ReadFile("testdata/k0s-charts.json")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ParseCharts(data)
	if err != nil || len(cs) != 1 {
		t.Fatalf("charts %v, %v", cs, err)
	}
	c := cs[0]
	if c.Addon() != "broken" || c.Namespace != "kube-system" || c.Release != "broken" || c.TargetNamespace != "default" ||
		c.ChartName != "example/nothing" || c.Version != "1.0.0" || c.Repository != "https://charts.example.invalid" {
		t.Errorf("chart %+v", c)
	}
	if !c.Failed() || !strings.Contains(c.Error, `"repo" is not a valid chart repository or cannot be reached`) || c.Installed != "" {
		t.Errorf("error %q, installed %q", c.Error, c.Installed)
	}
	if want := time.Date(2026, 10, 5, 6, 45, 42, 722778603, time.UTC); !c.Updated.Equal(want) {
		t.Errorf("updated %v, want %v", c.Updated, want)
	}
	if strings.Contains(c.Values, "hunter2") || !strings.Contains(c.Values, "password: ••••••") || !strings.Contains(c.Values, "replicas: 2") {
		t.Errorf("values %q", c.Values)
	}
}

func TestMaskedValues(t *testing.T) {
	cs, err := ParseCharts([]byte(`{"kind":"Chart","metadata":{"name":"k0s-addon-chart-db"},"spec":{"values":` +
		`"auth:\n  rootPassword: s3cret\n  enabled: true\nreplicas: 3\nurl: postgres://app:pw123@db:5432/app\ntls:\n  key: |\n    -----BEGIN PRIVATE KEY-----\n    abc\n    -----END PRIVATE KEY-----\nnote: hello\n"}}`))
	if err != nil {
		t.Fatal(err)
	}
	v := cs[0].Values
	for _, secret := range []string{"s3cret", "pw123", "BEGIN PRIVATE KEY"} {
		if strings.Contains(v, secret) {
			t.Errorf("%q shows in %q", secret, v)
		}
	}
	for _, kept := range []string{"enabled: true", "replicas: 3", "note: hello", "postgres://app:••••••@db:5432/app"} {
		if !strings.Contains(v, kept) {
			t.Errorf("%q is missing from %q", kept, v)
		}
	}
	cs, _ = ParseCharts([]byte(`{"kind":"Chart","metadata":{"name":"x"},"spec":{"values":"a: [unclosed"}}`))
	if !cs[0].ValuesUnreadable || cs[0].Values != "" {
		t.Errorf("values that aren't YAML aren't shown: %+v", cs[0])
	}
}

func TestParseClusterConfig(t *testing.T) {
	data, err := os.ReadFile("testdata/k0s-clusterconfig.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseClusterConfig(data, "cluster")
	if err != nil {
		t.Fatal(err)
	}
	if c.Get("network", "provider") != "custom" || c.Get("network", "podCIDR") != "10.244.0.0/16" || c.Get("network", "kubeProxy", "disabled") != true {
		t.Errorf("network %v", c.Get("network"))
	}
	profiles, _ := c.Get("workerProfiles").([]any)
	if len(profiles) != 1 || profiles[0].(map[string]any)["name"] != "big-logs" {
		t.Errorf("profiles %v", profiles)
	}
	charts, _ := c.Get("extensions", "helm", "charts").([]any)
	if v := charts[0].(map[string]any)["values"].(string); strings.Contains(v, "hunter2") || !strings.Contains(v, "replicas: 2") {
		t.Errorf("chart values %q", v)
	}

	// The k0s configuration inside a k0sctl.yaml.
	k0sctl := `apiVersion: k0sctl.k0sproject.io/v1beta1
kind: Cluster
spec:
  k0s:
    version: v1.36.4+k0s.1
    config:
      apiVersion: k0s.k0sproject.io/v1beta1
      kind: ClusterConfig
      spec:
        api: {externalAddress: k8s.example.com, sans: [10.0.0.10]}
        storage: {type: etcd}
        network: {provider: calico}
`
	c, err = ParseClusterConfig([]byte(k0sctl), "k0sctl.yaml")
	if err != nil || c.Get("network", "provider") != "calico" || c.Get("api", "externalAddress") != "k8s.example.com" {
		t.Errorf("k0sctl.yaml: %v %v", c, err)
	}
	if _, err := ParseClusterConfig([]byte("kind: Cluster\nspec: {}"), "k0sctl.yaml"); err == nil {
		t.Error("a k0sctl.yaml without a k0s configuration")
	}
}
