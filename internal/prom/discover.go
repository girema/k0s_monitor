package prom

import (
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// wellKnown are the Service names of common Prometheus installations, best
// first: the Prometheus Operator's own Service, kube-prometheus,
// kube-prometheus-stack and the prometheus Helm chart.
var wellKnown = []string{
	"prometheus-operated",
	"prometheus-k8s",
	"kube-prometheus-stack-prometheus",
	"prometheus-kube-prometheus-prometheus",
	"prometheus-server",
	"prometheus",
}

// victoriaMetrics are the Services of VictoriaMetrics installations that
// answer the Prometheus query API, by name prefix: the operator's VMSingle
// and VMCluster, and the Helm charts. vmselect serves it under a path.
var victoriaMetrics = []struct {
	prefix, path string
	score        int
}{
	{"vmsingle-", "", 90},
	{"victoria-metrics-single", "", 88},
	{"vmselect-", "select/0/prometheus", 84},
	{"victoria-metrics-cluster-vmselect", "select/0/prometheus", 82},
}

// notPrometheus are parts of the Prometheus and VictoriaMetrics ecosystems
// that don't answer queries.
var notPrometheus = []string{
	"alertmanager", "node-exporter", "pushgateway", "adapter", "operator",
	"blackbox", "kube-state-metrics", "thanos", "grafana", "exporter",
	"vmagent", "vminsert", "vmstorage", "vmalert",
}

// Discover ranks the Services that look like a Prometheus server, best
// first. The first one that answers is used.
func Discover(services []*corev1.Service) []Target {
	type cand struct {
		t     Target
		score int
	}
	var cs []cand
	for _, svc := range services {
		score := 0
		name := svc.Name
		if isOther(name) {
			continue
		}
		path := ""
		for i, n := range wellKnown {
			if name == n {
				score = 100 - i
			}
		}
		for _, vm := range victoriaMetrics {
			if score == 0 && strings.HasPrefix(name, vm.prefix) {
				score, path = vm.score, vm.path
			}
		}
		if svc.Labels["app.kubernetes.io/name"] == "prometheus" || svc.Labels["app"] == "prometheus" ||
			svc.Labels["operated-prometheus"] == "true" {
			score += 50
		}
		switch svc.Labels["app.kubernetes.io/name"] {
		case "vmsingle", "victoria-metrics-single":
			score += 50
		case "vmselect":
			score, path = score+50, "select/0/prometheus"
		}
		// Whatever it is called, VictoriaMetrics serves queries on its own
		// ports: 8428 for a single node, 8481 for a cluster's vmselect.
		for _, p := range svc.Spec.Ports {
			switch {
			case score == 0 && p.Port == 8428:
				score = 60
			case score == 0 && p.Port == 8481:
				score, path = 55, "select/0/prometheus"
			}
		}
		if score == 0 && strings.Contains(name, "prometheus") {
			score = 10
		}
		if score == 0 {
			continue
		}
		port, scheme, ok := serverPort(svc)
		if !ok {
			continue
		}
		cs = append(cs, cand{Target{Namespace: svc.Namespace, Service: name, Scheme: scheme, Port: port, Path: path}, score})
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].score != cs[j].score {
			return cs[i].score > cs[j].score
		}
		return cs[i].t.Namespace+"/"+cs[i].t.Service < cs[j].t.Namespace+"/"+cs[j].t.Service
	})
	out := make([]Target, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.t)
	}
	return out
}

func isOther(name string) bool {
	for _, n := range notPrometheus {
		if strings.Contains(name, n) {
			return true
		}
	}
	return false
}

// serverPort picks the port Prometheus serves its API on.
func serverPort(svc *corev1.Service) (port, scheme string, ok bool) {
	if len(svc.Spec.Ports) == 0 {
		return "", "", false
	}
	best := -1
	rank := func(p corev1.ServicePort) int {
		switch {
		case p.Name == "web" || p.Name == "http-web":
			return 4
		case p.Port == 9090 || p.Port == 8428 || p.Port == 8481:
			return 3
		case p.Name == "http" || p.Name == "https":
			return 2
		case p.Name == "reloader-web" || p.Name == "grpc":
			return -1
		}
		return 0
	}
	for i, p := range svc.Spec.Ports {
		if r := rank(p); r >= 0 && (best < 0 || r > rank(svc.Spec.Ports[best])) {
			best = i
		}
	}
	if best < 0 {
		return "", "", false
	}
	p := svc.Spec.Ports[best]
	scheme = "http"
	if p.Name == "https" || strings.HasPrefix(p.Name, "https-") || p.Port == 443 {
		scheme = "https"
	}
	return strconv.Itoa(int(p.Port)), scheme, true
}
