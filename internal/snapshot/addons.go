package snapshot

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"k0s_monitor/internal/remedy"
)

// ChartPrefix starts the names of the Chart objects k0s makes for the Helm
// charts of its configuration (spec.extensions.helm.charts).
const ChartPrefix = "k0s-addon-chart-"

// Chart is a Helm add-on that k0s installs: a Chart object
// (helm.k0sproject.io). Values that look secret are masked as it is read,
// and its annotations, which hold a copy of the values, are not kept.
type Chart struct {
	// Name and Namespace are the Chart object's.
	Name, Namespace string
	// Release is the Helm release, installed in TargetNamespace.
	Release, TargetNamespace string
	ChartName                string
	// Version is the chart version asked for; Installed the one installed,
	// if any, with its AppVersion and Revision.
	Version    string
	Installed  string
	AppVersion string
	Revision   int64
	Repository string
	// Values are the chart's values, masked. ValuesUnreadable says they
	// aren't YAML, so none of them are kept.
	Values           string
	ValuesUnreadable bool
	// Error is why k0s couldn't install or update it, as k0s reports it.
	Error    string
	Updated  time.Time
	Created  time.Time
	Deleting bool
}

// Addon is the name the k0s configuration gives the chart: "ingress".
func (c Chart) Addon() string { return strings.TrimPrefix(c.Name, ChartPrefix) }

// Failed reports whether k0s couldn't install or update it.
func (c Chart) Failed() bool { return c.Error != "" }

type chartDoc struct {
	Metadata struct {
		Name              string       `json:"name"`
		Namespace         string       `json:"namespace"`
		CreationTimestamp metav1.Time  `json:"creationTimestamp"`
		DeletionTimestamp *metav1.Time `json:"deletionTimestamp"`
	} `json:"metadata"`
	Spec struct {
		ChartName   string `json:"chartName"`
		ReleaseName string `json:"releaseName"`
		Version     string `json:"version"`
		Values      string `json:"values"`
		Namespace   string `json:"namespace"`
		Repository  *struct {
			URL string `json:"url"`
		} `json:"repository"`
	} `json:"spec"`
	Status struct {
		ReleaseName string `json:"releaseName"`
		Version     string `json:"version"`
		AppVersion  string `json:"appVersion"`
		Revision    int64  `json:"revision"`
		Namespace   string `json:"namespace"`
		Error       string `json:"error"`
		Updated     string `json:"updated"`
	} `json:"status"`
}

// ParseCharts reads Chart objects as the API serves them: a list or one.
func ParseCharts(data []byte) ([]Chart, error) {
	var list struct {
		Kind  string     `json:"kind"`
		Items []chartDoc `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if list.Kind == "Chart" {
		var one chartDoc
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, err
		}
		list.Items = []chartDoc{one}
	}
	out := make([]Chart, 0, len(list.Items))
	for _, d := range list.Items {
		c := Chart{
			Name: d.Metadata.Name, Namespace: d.Metadata.Namespace, Created: d.Metadata.CreationTimestamp.Time,
			Deleting: d.Metadata.DeletionTimestamp != nil,
			Release:  d.Spec.ReleaseName, TargetNamespace: d.Spec.Namespace, ChartName: d.Spec.ChartName, Version: d.Spec.Version,
			Installed: d.Status.Version, AppVersion: d.Status.AppVersion, Revision: d.Status.Revision,
			Error: strings.TrimSpace(d.Status.Error), Updated: parseGoTime(d.Status.Updated),
		}
		if c.Release == "" {
			c.Release = d.Status.ReleaseName
		}
		if c.TargetNamespace == "" {
			c.TargetNamespace = d.Status.Namespace
		}
		if d.Spec.Repository != nil {
			c.Repository = remedy.MaskValue("", d.Spec.Repository.URL)
		}
		if strings.TrimSpace(d.Spec.Values) != "" {
			if v, ok := remedy.MaskYAML(d.Spec.Values); ok {
				c.Values = v
			} else {
				c.ValuesUnreadable = true
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// parseGoTime reads a time as Go prints it, which k0s uses in Chart
// statuses: "2026-10-05 06:40:35.383947919 +0000 UTC m=+40.589489112".
func parseGoTime(s string) time.Time {
	if i := strings.Index(s, " m="); i > 0 {
		s = s[:i]
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999 -0700 MST", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ClusterConfig is k0s's cluster-wide configuration (spec of a
// ClusterConfig), with secret-looking values masked, the values of its Helm
// charts included.
type ClusterConfig struct {
	// From says where it was read: the cluster's ClusterConfig object, which
	// k0s keeps with dynamic configuration, or an uploaded file.
	From string
	Spec map[string]any
}

// ParseClusterConfig reads a ClusterConfig (JSON or YAML), or the k0s
// configuration inside a k0sctl.yaml (spec.k0s.config).
func ParseClusterConfig(data []byte, from string) (*ClusterConfig, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if kind, _ := doc["kind"].(string); kind == "Cluster" {
		// k0sctl.yaml
		k0s, _ := dig(doc, "spec", "k0s", "config").(map[string]any)
		if k0s == nil {
			return nil, fmt.Errorf("the k0sctl.yaml has no k0s configuration (spec.k0s.config)")
		}
		doc = k0s
	}
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return nil, fmt.Errorf("no spec")
	}
	// Chart values are YAML inside a text: mask them as YAML.
	if charts, ok := dig(spec, "extensions", "helm", "charts").([]any); ok {
		for _, c := range charts {
			if m, ok := c.(map[string]any); ok {
				if v, ok := m["values"].(string); ok {
					if masked, ok := remedy.MaskYAML(v); ok {
						m["values"] = masked
					} else {
						m["values"] = remedy.Mask
					}
				}
			}
		}
	}
	remedy.MaskTree(spec, false)
	return &ClusterConfig{From: from, Spec: spec}, nil
}

// Get returns the value at a path of keys, or nil.
func (c *ClusterConfig) Get(path ...string) any {
	if c == nil {
		return nil
	}
	return dig(c.Spec, path...)
}

func dig(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}
