package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

// FromYAMLFile builds a snapshot from a multi-document YAML file, for tests.
// Every kind counts as collected.
func FromYAMLFile(cluster, path string, now time.Time) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromYAML(cluster, data, now)
}

// FromYAML builds a snapshot from multi-document YAML.
func FromYAML(cluster string, data []byte, now time.Time) (*Snapshot, error) {
	s := &Snapshot{Cluster: cluster, Now: now, Available: map[Kind]bool{}}
	for _, k := range AllKinds {
		s.Available[k] = true
	}
	// Fixtures without a Metrics document have no metrics, as a cluster
	// without Prometheus data; the rules that need them find nothing.
	s.Available[KindMetrics] = true
	s.Available[KindControlPlane] = true
	s.Available[KindTLSSecret] = true
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	deserializer := scheme.Codecs.UniversalDeserializer()
	var plans []*Plan
	var charts []Chart
	var config *ClusterConfig
	for i := 0; ; i++ {
		var raw runtime.RawExtension
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}
		if bytes.Contains(raw.Raw, []byte("k0s-monitor.io/v1")) && bytes.Contains(raw.Raw, []byte(`"Metrics"`)) {
			js, err := utilyaml.ToJSON(raw.Raw)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			m, err := parseMetricsDoc(js, now)
			if err != nil {
				return nil, fmt.Errorf("document %d (Metrics): %w", i, err)
			}
			s.Metrics = m
			continue
		}
		if bytes.Contains(raw.Raw, []byte("k0s-monitor.io/v1")) && bytes.Contains(raw.Raw, []byte(`"ControlPlane"`)) {
			js, err := utilyaml.ToJSON(raw.Raw)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			if err := parseControlPlaneDoc(js, now, s); err != nil {
				return nil, fmt.Errorf("document %d (ControlPlane): %w", i, err)
			}
			continue
		}
		if bytes.Contains(raw.Raw, []byte("k0s-monitor.io/v1")) && bytes.Contains(raw.Raw, []byte(`"CrashLogs"`)) {
			js, err := utilyaml.ToJSON(raw.Raw)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			if err := parseCrashLogsDoc(js, now, s); err != nil {
				return nil, fmt.Errorf("document %d (CrashLogs): %w", i, err)
			}
			continue
		}
		if bytes.Contains(raw.Raw, []byte("autopilot.k0sproject.io")) && bytes.Contains(raw.Raw, []byte(`"Plan"`)) {
			js, err := utilyaml.ToJSON(raw.Raw)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			ps, err := ParsePlans(js)
			if err != nil {
				return nil, fmt.Errorf("document %d (Plan): %w", i, err)
			}
			plans = append(plans, ps...)
			continue
		}
		if bytes.Contains(raw.Raw, []byte("helm.k0sproject.io")) && bytes.Contains(raw.Raw, []byte("Chart")) {
			js, err := utilyaml.ToJSON(raw.Raw)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			cs, err := ParseCharts(js)
			if err != nil {
				return nil, fmt.Errorf("document %d (Chart): %w", i, err)
			}
			charts = append(charts, cs...)
			continue
		}
		if bytes.Contains(raw.Raw, []byte("k0s.k0sproject.io")) && bytes.Contains(raw.Raw, []byte("ClusterConfig")) {
			c, err := ParseClusterConfig(raw.Raw, "the cluster (dynamic configuration)")
			if err != nil {
				return nil, fmt.Errorf("document %d (ClusterConfig): %w", i, err)
			}
			config = c
			continue
		}
		if bytes.Contains(raw.Raw, []byte("apiregistration.k8s.io")) {
			js, err := utilyaml.ToJSON(raw.Raw)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			as, err := ParseAPIServices(js)
			if err != nil {
				return nil, fmt.Errorf("document %d: %w", i, err)
			}
			s.APIServices = append(s.APIServices, as...)
			continue
		}
		obj, _, err := deserializer.Decode(raw.Raw, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		if err := s.add(obj, i); err != nil {
			return nil, err
		}
	}
	// Autopilot plans, Helm add-ons and the ClusterConfig come with the
	// controllers' view, as k0s-monitor reads them.
	if len(plans) > 0 || len(charts) > 0 || config != nil {
		if s.ControlPlane == nil {
			s.ControlPlane = &ControlPlane{At: now, EtcdDBBytes: Missing, EtcdQuotaBytes: DefaultEtcdQuota}
		}
		s.ControlPlane.Plans = plans
		s.ControlPlane.Charts, s.ControlPlane.ChartsRead = charts, len(charts) > 0
		s.ControlPlane.Config = config
	}
	return New(s), nil
}

func (s *Snapshot) add(obj runtime.Object, i int) error {
	// Give every object a UID so indexes keyed by UID work in fixtures.
	uid := func(u *types.UID, name string) {
		if *u == "" {
			*u = types.UID(fmt.Sprintf("uid-%d-%s", i, name))
		}
	}
	switch o := obj.(type) {
	case *corev1.Pod:
		uid(&o.UID, o.Name)
		s.Pods = append(s.Pods, o)
	case *corev1.Node:
		uid(&o.UID, o.Name)
		s.Nodes = append(s.Nodes, o)
	case *corev1.Service:
		s.Services = append(s.Services, o)
	case *discoveryv1.EndpointSlice:
		s.EndpointSlices = append(s.EndpointSlices, o)
	case *networkingv1.Ingress:
		s.Ingresses = append(s.Ingresses, o)
	case *corev1.PersistentVolumeClaim:
		uid(&o.UID, o.Name)
		s.PVCs = append(s.PVCs, o)
	case *storagev1.StorageClass:
		s.StorageClasses = append(s.StorageClasses, o)
	case *corev1.Event:
		uid(&o.UID, o.Name)
		s.Events = append(s.Events, o)
	case *corev1.Namespace:
		s.Namespaces = append(s.Namespaces, o)
	case *appsv1.Deployment:
		uid(&o.UID, o.Name)
		s.Deployments = append(s.Deployments, o)
	case *appsv1.ReplicaSet:
		uid(&o.UID, o.Name)
		s.ReplicaSets = append(s.ReplicaSets, o)
	case *appsv1.StatefulSet:
		s.StatefulSets = append(s.StatefulSets, o)
	case *appsv1.DaemonSet:
		s.DaemonSets = append(s.DaemonSets, o)
	case *batchv1.Job:
		s.Jobs = append(s.Jobs, o)
	case *coordinationv1.Lease:
		s.Leases = append(s.Leases, o)
	case *batchv1.CronJob:
		uid(&o.UID, o.Name)
		s.CronJobs = append(s.CronJobs, o)
	case *admissionv1.ValidatingWebhookConfiguration:
		s.ValidatingWHs = append(s.ValidatingWHs, o)
	case *admissionv1.MutatingWebhookConfiguration:
		s.MutatingWHs = append(s.MutatingWHs, o)
	case *corev1.PersistentVolume:
		s.PVs = append(s.PVs, o)
	case *autoscalingv2.HorizontalPodAutoscaler:
		s.HPAs = append(s.HPAs, o)
	case *corev1.ResourceQuota:
		s.Quotas = append(s.Quotas, o)
	case *policyv1.PodDisruptionBudget:
		s.PDBs = append(s.PDBs, o)
	case *corev1.Secret:
		if o.Type == corev1.SecretTypeTLS {
			s.TLSCerts = append(s.TLSCerts, TLSCertOf(OnlyTLSCert(o)))
		}
	default:
		return fmt.Errorf("document %d: unsupported kind %T", i, obj)
	}
	return nil
}
