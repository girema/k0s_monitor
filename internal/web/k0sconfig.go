package web

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/store"
)

// The k0s page's Add-ons and Cluster configuration views, read-only: the
// Helm charts k0s installs, and its configuration with the settings
// explained. Values that look secret are masked as they are read.

type addonView struct {
	Name, Chart, Version, Installed, AppVersion string
	Namespace, Release, Repository              string
	Revision                                    int64
	Status, Plain, Icon, Mark                   string
	Error                                       string
	Updated                                     time.Time
	Values                                      string
	ValuesUnreadable                            bool
	Top                                         *findings.Finding
}

// addonsOf lists the Helm add-ons, failed ones first.
func addonsOf(st *engine.State) (out []addonView, read bool) {
	snap := st.Snapshot
	if snap == nil || snap.ControlPlane == nil {
		return nil, false
	}
	top := map[string]*findings.Finding{}
	for _, f := range st.Findings {
		if f.RuleID == "k0s.chart-failed" {
			top[f.Resource.Name] = f
		}
	}
	for _, c := range snap.ControlPlane.Charts {
		v := addonView{Name: c.Addon(), Chart: c.ChartName, Version: c.Version, Installed: c.Installed, AppVersion: c.AppVersion,
			Namespace: c.TargetNamespace, Release: c.Release, Repository: c.Repository, Revision: c.Revision,
			Error: c.Error, Updated: c.Updated, Values: c.Values, ValuesUnreadable: c.ValuesUnreadable, Top: top[c.Name]}
		switch {
		case c.Deleting:
			v.Status, v.Plain, v.Icon, v.Mark = "being removed", "being removed", "info", "…"
		case c.Failed() && c.Installed != "":
			v.Status, v.Plain, v.Icon, v.Mark = fmt.Sprintf("update to %s failed; %s runs", c.Version, c.Installed), "update failed; the previous version runs", "warn", "▲"
		case c.Failed():
			v.Status, v.Plain, v.Icon, v.Mark = "not installed: failed", "not installed: it failed", "crit", "✕"
		case c.Installed == "":
			v.Status, v.Plain, v.Icon, v.Mark = "not installed yet", "being installed", "info", "…"
		case c.Version != "" && c.Installed != c.Version:
			v.Status, v.Plain, v.Icon, v.Mark = fmt.Sprintf("installed %s, updating to %s", c.Installed, c.Version), "being updated", "info", "…"
		default:
			v.Status, v.Plain, v.Icon, v.Mark = fmt.Sprintf("installed, revision %d", c.Revision), "installed", "good", "✓"
		}
		out = append(out, v)
	}
	rank := map[string]int{"crit": 0, "warn": 1, "info": 2, "good": 3}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Icon] != rank[out[j].Icon] {
			return rank[out[i].Icon] < rank[out[j].Icon]
		}
		return out[i].Name < out[j].Name
	})
	return out, snap.ControlPlane.ChartsRead || len(out) > 0
}

// configSetting is one setting, with what it means.
type configSetting struct {
	Name, Value, Means string
}

type profileView struct {
	Name     string
	Settings []configSetting
}

// configDiff is a setting the uploaded file has that the cluster's
// configuration doesn't have the same way.
type configDiff struct {
	Path, Uploaded, Cluster string
}

type configView struct {
	// From names the source; empty when there is none.
	From     string
	Settings []configSetting
	Profiles []profileView
	// YAML is the whole configuration, masked.
	YAML string
	// Diffs compare the cluster's configuration with the uploaded file,
	// when there are both; DiffWith names the file.
	Diffs    []configDiff
	DiffWith string
	// Uploaded says only the uploaded file is shown: the cluster doesn't
	// publish its own.
	Uploaded bool
}

// uploadedConfig reads the k0s configuration uploaded with a cluster added
// in the UI: its k0s.yaml, else the one in its k0sctl.yaml.
func uploadedConfig(st *store.Store, name string) *snapshot.ClusterConfig {
	stored, err := st.Clusters()
	if err != nil {
		return nil
	}
	for _, sc := range stored {
		if sc.Cluster.Name != name {
			continue
		}
		if len(sc.K0sConfig) > 0 {
			if c, err := snapshot.ParseClusterConfig(sc.K0sConfig, "the k0s.yaml uploaded with the cluster"); err == nil {
				return c
			}
		}
		if len(sc.K0sctl) > 0 {
			if c, err := snapshot.ParseClusterConfig(sc.K0sctl, "the k0sctl.yaml uploaded with the cluster"); err == nil {
				return c
			}
		}
	}
	return nil
}

// configOf explains the cluster's configuration: its ClusterConfig object
// (dynamic configuration), else the uploaded file.
func configOf(st *engine.State, uploaded *snapshot.ClusterConfig) configView {
	var live *snapshot.ClusterConfig
	if snap := st.Snapshot; snap != nil && snap.ControlPlane != nil {
		live = snap.ControlPlane.Config
	}
	c := live
	if c == nil {
		c = uploaded
	}
	if c == nil {
		return configView{}
	}
	v := configView{From: c.From, Uploaded: live == nil}
	v.Settings = explainSettings(c)
	if profiles, ok := c.Get("workerProfiles").([]any); ok {
		for _, p := range profiles {
			m, _ := p.(map[string]any)
			name, _ := m["name"].(string)
			values, _ := m["values"].(map[string]any)
			v.Profiles = append(v.Profiles, profileView{Name: name, Settings: explainKubelet(values)})
		}
	}
	if b, err := yaml.Marshal(c.Spec); err == nil {
		v.YAML = string(b)
	}
	if live != nil && uploaded != nil {
		v.Diffs, v.DiffWith = configDiffs(live, uploaded), strings.TrimPrefix(uploaded.From, "the ")
	}
	return v
}

// settingMeanings explain the cluster-wide settings, by path.
var settingMeanings = []struct {
	path  []string
	name  string
	means func(v any) string
}{
	{[]string{"api", "externalAddress"}, "API address", fixed("The address clients and workers use for the API server, usually a load balancer in front of the controllers.")},
	{[]string{"api", "address"}, "API listens on", fixed("The controller's own address for the API server.")},
	{[]string{"api", "sans"}, "Certificate names", fixed("Other names and addresses the API server's certificate is valid for.")},
	{[]string{"storage", "type"}, "Storage", func(v any) string {
		if v == "kine" {
			return "kine: the cluster's state is kept in a database such as SQLite or PostgreSQL instead of etcd."
		}
		return "etcd on the controllers keeps the cluster's state."
	}},
	{[]string{"network", "provider"}, "Network driver", func(v any) string {
		switch v {
		case "kuberouter":
			return "kube-router, k0s's default: it connects the pods and applies network policies."
		case "calico":
			return "Calico, installed by k0s."
		case "custom":
			return "A network driver installed separately, not by k0s: k0s doesn't manage or update it."
		}
		return ""
	}},
	{[]string{"network", "podCIDR"}, "Pod addresses", fixed("Pods get addresses from this range; each node gets a part of it.")},
	{[]string{"network", "serviceCIDR"}, "Service addresses", fixed("Services get addresses from this range. The cluster's DNS has the tenth one.")},
	{[]string{"network", "clusterDomain"}, "Cluster domain", fixed("Services are found as <service>.<namespace>.svc under this domain.")},
	{[]string{"network", "kubeProxy", "disabled"}, "kube-proxy", func(v any) string { // shown as on or off, below
		if v == true {
			return "Off: the network driver routes traffic to Services itself."
		}
		return "On: it routes traffic to Services on each node."
	}},
	{[]string{"network", "kubeProxy", "mode"}, "kube-proxy mode", fixed("How kube-proxy routes traffic: iptables, ipvs or nftables.")},
	{[]string{"network", "nodeLocalLoadBalancing", "enabled"}, "Node-local load balancing", func(v any) string {
		if v == true {
			return "On: each worker reaches the controllers through a load balancer of its own, so it keeps working when a controller is down."
		}
		return "Off: workers reach the controllers through the API address."
	}},
	{[]string{"network", "dualStack", "enabled"}, "IPv4 and IPv6", fixed("Whether pods and Services get both kinds of addresses.")},
	{[]string{"images", "repository"}, "Image registry", fixed("k0s's own images come from this registry instead of the internet, as in networks without internet access.")},
	{[]string{"images", "default_pull_policy"}, "Image pulls", fixed("When k0s's own images are downloaded again.")},
	{[]string{"extensions", "storage", "type"}, "Storage extension", fixed("A storage provider k0s installs, which gives the cluster a StorageClass.")},
	{[]string{"telemetry", "enabled"}, "Telemetry", fixed("Whether k0s sends anonymous usage statistics to its makers.")},
	{[]string{"featureGates"}, "Feature gates", fixed("Kubernetes features turned on or off.")},
}

func fixed(s string) func(any) string { return func(any) string { return s } }

func explainSettings(c *snapshot.ClusterConfig) []configSetting {
	var out []configSetting
	for _, m := range settingMeanings {
		v := c.Get(m.path...)
		if v == nil {
			continue
		}
		value := valueText(v)
		if m.name == "kube-proxy" { // the setting says whether it is disabled
			value = map[bool]string{true: "off", false: "on"}[v == true]
		}
		out = append(out, configSetting{Name: m.name, Value: value, Means: m.means(v)})
	}
	if charts, ok := c.Get("extensions", "helm", "charts").([]any); ok && len(charts) > 0 {
		var names []string
		for _, ch := range charts {
			if m, ok := ch.(map[string]any); ok {
				if n, ok := m["name"].(string); ok {
					names = append(names, n)
				}
			}
		}
		out = append(out, configSetting{Name: "Helm add-ons", Value: strings.Join(names, ", "), Means: "Charts k0s installs with the cluster; their state is under Add-ons."})
	}
	return out
}

// kubeletMeanings explain the kubelet settings worker profiles often set.
var kubeletMeanings = map[string]string{
	"containerLogMaxSize":         "A container's log is rotated when it reaches this size.",
	"containerLogMaxFiles":        "How many rotated log files are kept per container.",
	"evictionHard":                "Pods are evicted at once when free memory or disk falls below these.",
	"evictionSoft":                "Pods are evicted when free memory or disk stays below these for the grace period.",
	"evictionSoftGracePeriod":     "How long the soft thresholds may be crossed before pods are evicted.",
	"maxPods":                     "The most pods a node runs.",
	"kubeReserved":                "Memory and CPU kept for Kubernetes' own services on each node.",
	"systemReserved":              "Memory and CPU kept for the operating system on each node.",
	"imageGCHighThresholdPercent": "Unused images are removed when the image disk is this full (percent).",
	"imageGCLowThresholdPercent":  "…until it is this full again (percent).",
	"cpuManagerPolicy":            "How CPUs are given to containers: none (shared) or static (dedicated).",
	"memoryManagerPolicy":         "How memory is given to containers.",
	"topologyManagerPolicy":       "How CPUs, memory and devices are placed together.",
	"failSwapOn":                  "Whether the kubelet refuses to run with swap on.",
	"failCgroupV1":                "Whether the kubelet refuses to run on cgroup v1 hosts.",
	"serializeImagePulls":         "Whether images are downloaded one at a time.",
	"podPidsLimit":                "The most processes a pod may run.",
	"shutdownGracePeriod":         "How long a node waits for its pods when it shuts down.",
}

func explainKubelet(values map[string]any) []configSetting {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]configSetting, 0, len(keys))
	for _, k := range keys {
		out = append(out, configSetting{Name: k, Value: valueText(values[k]), Means: kubeletMeanings[k]})
	}
	return out
}

// valueText shows a setting's value on one line.
func valueText(v any) string {
	switch t := v.(type) {
	case nil:
		return "—"
	case string:
		return t
	case bool:
		return map[bool]string{true: "on", false: "off"}[t]
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+valueText(t[k]))
		}
		return strings.Join(parts, ", ")
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, valueText(x))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(v)
}

// configDiffs compares the settings of the uploaded file with the
// cluster's, within the sections the cluster publishes (with dynamic
// configuration, k0s doesn't publish node-local ones such as api and
// storage).
func configDiffs(live, uploaded *snapshot.ClusterConfig) []configDiff {
	lv, uv := map[string]string{}, map[string]string{}
	flatten("", live.Spec, lv)
	flatten("", uploaded.Spec, uv)
	var out []configDiff
	for path, u := range uv {
		section := strings.SplitN(strings.SplitN(path, ".", 2)[0], "[", 2)[0]
		if _, ok := live.Spec[section]; !ok {
			continue
		}
		if l, ok := lv[path]; !ok || l != u {
			if !ok {
				l = "not set"
			}
			out = append(out, configDiff{Path: path, Uploaded: u, Cluster: l})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// flatten lists a configuration's settings by path; items of lists of
// maps by their index ("workerProfiles[0].values.maxPods"), so settings k0s
// adds to an item by default don't count as a difference.
func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, x, out)
		}
	case []any:
		maps := len(t) > 0
		for _, x := range t {
			if _, ok := x.(map[string]any); !ok {
				maps = false
			}
		}
		if !maps {
			out[prefix] = valueText(v)
			return
		}
		for i, x := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), x, out)
		}
	default:
		out[prefix] = valueText(v)
	}
}
