package cluster

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"

	"k0s_monitor/internal/snapshot"
)

// Info is what the probe learned about a cluster.
type Info struct {
	Server string `json:"server"`
	// Fallback is set while Server is another controller than the
	// kubeconfig's, which doesn't answer.
	Fallback   *Fallback `json:"fallback,omitempty"`
	Version    string    `json:"version"`
	K0s        bool      `json:"k0s"`
	K0sGroups  []string  `json:"k0sGroups,omitempty"`
	MetricsAPI bool      `json:"metricsApi"`
	// Unreadable lists resource kinds the credentials can't list, with the
	// reason. Rules that need them are skipped.
	Unreadable map[string]string `json:"unreadable,omitempty"`
	Nodes      int               `json:"nodes"`
	Pods       int               `json:"pods"`
	// Prometheus says whether metrics could be read, and from where.
	Prometheus *PrometheusStatus `json:"prometheus,omitempty"`
	// TLSSecrets says whether the certificates in TLS Secrets can be read:
	// "ok", "not allowed" (the optional permission isn't granted), "off"
	// (turned off for the cluster), or why not.
	TLSSecrets string `json:"tlsSecrets,omitempty"`
}

// PrometheusStatus describes the metrics source of a cluster.
type PrometheusStatus struct {
	// State is ok, not-found, forbidden, error or disabled.
	State string `json:"state"`
	// Target is where Prometheus was found or configured.
	Target string `json:"target,omitempty"`
	// Message explains a problem in plain words.
	Message string `json:"message,omitempty"`
	// Hint is what to do about it, for example commands that grant the
	// read-only account access.
	Hint string `json:"hint,omitempty"`
	// Nodes with node-exporter data, out of NodesTotal.
	NodeExporter int `json:"nodeExporter"`
	NodesTotal   int `json:"nodesTotal"`
	// Which other data exists.
	KubeletVolumes bool `json:"kubeletVolumes"`
	CAdvisor       bool `json:"cadvisor"`
	Timex          bool `json:"timex"`
	// Unmapped node-exporter instances that match no node.
	Unmapped []string `json:"unmapped,omitempty"`
	// Fallbacks says what came from the metrics API or the kubelets
	// instead, and FallbackHint how to get more.
	Fallbacks    []string  `json:"fallbacks,omitempty"`
	FallbackHint string    `json:"fallbackHint,omitempty"`
	At           time.Time `json:"at"`
}

// Probe detects k0s, optional APIs, and which resource kinds can be read.
// It returns the kinds that can be collected.
func Probe(ctx context.Context, c *Conn, v *version.Info) (*Info, map[snapshot.Kind]bool) {
	info := &Info{Server: c.Server, Fallback: c.Fallback, Unreadable: map[string]string{}}
	if v != nil {
		info.Version = v.GitVersion
		info.K0s = strings.Contains(v.GitVersion, "+k0s")
	}
	if groups, err := c.Client.Discovery().ServerGroups(); err == nil {
		for _, g := range groups.Groups {
			switch {
			case strings.HasSuffix(g.Name, "k0sproject.io"):
				info.K0sGroups = append(info.K0sGroups, g.Name)
			case g.Name == "metrics.k8s.io":
				info.MetricsAPI = true
			}
		}
		sort.Strings(info.K0sGroups)
		if len(info.K0sGroups) > 0 {
			info.K0s = true
		}
	}

	allowed := map[snapshot.Kind]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, k := range snapshot.AllKinds {
		wg.Add(1)
		go func(k snapshot.Kind) {
			defer wg.Done()
			err := canList(ctx, c.Client, k)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				allowed[k] = true
				return
			}
			switch {
			case errors.Is(err, errNoRawClient):
				// Only fake clients lack one; nothing to tell the user.
			case apierrors.IsForbidden(err):
				info.Unreadable[string(k)] = "not allowed"
			case apierrors.IsNotFound(err):
				info.Unreadable[string(k)] = "not served by this cluster"
			default:
				info.Unreadable[string(k)] = err.Error()
			}
		}(k)
	}
	wg.Wait()
	if len(info.Unreadable) == 0 {
		info.Unreadable = nil
	}
	info.TLSSecrets = tlsSecretsAccess(ctx, c.Client)
	if info.TLSSecrets == "ok" {
		allowed[snapshot.KindTLSSecret] = true
	}
	return info, allowed
}

// TLSSecretsOff stops reading TLS Secrets for a cluster that turned it off.
func TLSSecretsOff(info *Info, allowed map[snapshot.Kind]bool) {
	delete(allowed, snapshot.KindTLSSecret)
	info.TLSSecrets = "off"
}

// tlsSecretsAccess asks whether Secrets may be listed and watched in every
// namespace, without listing one: that would fetch a private key.
func tlsSecretsAccess(ctx context.Context, cs kubernetes.Interface) string {
	for _, verb := range []string{"list", "watch"} {
		res, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authzv1.SelfSubjectAccessReview{
			Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Resource: "secrets"}},
		}, metav1.CreateOptions{})
		switch {
		case err != nil:
			return "can't be checked: " + err.Error()
		case !res.Status.Allowed:
			return "not allowed"
		}
	}
	return "ok"
}

// errNoRawClient means the client can't make raw requests, which only
// happens with fake clients in tests.
var errNoRawClient = errors.New("no REST client")

// canList lists one object of the kind, which checks both the permission
// and that the API is served.
func canList(ctx context.Context, cs kubernetes.Interface, k snapshot.Kind) error {
	opts := metav1.ListOptions{Limit: 1}
	var err error
	switch k {
	case snapshot.KindPod:
		_, err = cs.CoreV1().Pods("").List(ctx, opts)
	case snapshot.KindNode:
		_, err = cs.CoreV1().Nodes().List(ctx, opts)
	case snapshot.KindService:
		_, err = cs.CoreV1().Services("").List(ctx, opts)
	case snapshot.KindEndpointSlice:
		_, err = cs.DiscoveryV1().EndpointSlices("").List(ctx, opts)
	case snapshot.KindIngress:
		_, err = cs.NetworkingV1().Ingresses("").List(ctx, opts)
	case snapshot.KindPVC:
		_, err = cs.CoreV1().PersistentVolumeClaims("").List(ctx, opts)
	case snapshot.KindStorageClass:
		_, err = cs.StorageV1().StorageClasses().List(ctx, opts)
	case snapshot.KindEvent:
		opts.FieldSelector = "type=Warning"
		_, err = cs.CoreV1().Events("").List(ctx, opts)
	case snapshot.KindNamespace:
		_, err = cs.CoreV1().Namespaces().List(ctx, opts)
	case snapshot.KindDeployment:
		_, err = cs.AppsV1().Deployments("").List(ctx, opts)
	case snapshot.KindReplicaSet:
		_, err = cs.AppsV1().ReplicaSets("").List(ctx, opts)
	case snapshot.KindStatefulSet:
		_, err = cs.AppsV1().StatefulSets("").List(ctx, opts)
	case snapshot.KindDaemonSet:
		_, err = cs.AppsV1().DaemonSets("").List(ctx, opts)
	case snapshot.KindJob:
		_, err = cs.BatchV1().Jobs("").List(ctx, opts)
	case snapshot.KindLease:
		_, err = cs.CoordinationV1().Leases(snapshot.NodeLeaseNamespace).List(ctx, opts)
	case snapshot.KindCronJob:
		_, err = cs.BatchV1().CronJobs("").List(ctx, opts)
	case snapshot.KindPV:
		_, err = cs.CoreV1().PersistentVolumes().List(ctx, opts)
	case snapshot.KindHPA:
		_, err = cs.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, opts)
	case snapshot.KindQuota:
		_, err = cs.CoreV1().ResourceQuotas("").List(ctx, opts)
	case snapshot.KindPDB:
		_, err = cs.PolicyV1().PodDisruptionBudgets("").List(ctx, opts)
	case snapshot.KindValidatingWH:
		_, err = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, opts)
	case snapshot.KindMutatingWH:
		_, err = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, opts)
	case snapshot.KindAPIService:
		rc := cs.Discovery().RESTClient()
		if rc == nil || reflect.ValueOf(rc).IsNil() {
			return errNoRawClient
		}
		err = rc.Get().AbsPath("/apis/apiregistration.k8s.io/v1/apiservices").Param("limit", "1").Do(ctx).Error()
	}
	return err
}
