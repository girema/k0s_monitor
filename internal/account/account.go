// Package account creates k0s-monitor's own read-only account in a cluster
// (plan sections 5.3 and 13): a ServiceAccount, a ClusterRole with read
// access, its binding, and a token. The uploaded admin credentials are used
// once for this and then discarded. This is the only time k0s-monitor
// writes to a cluster, and only when the person chooses it.
package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Names of the objects.
const (
	Namespace  = "kube-system"
	Name       = "k0s-monitor"
	RoleName   = "k0s-monitor:reader"
	SecretName = "k0s-monitor-token"
)

// RemoveCommands undo what Create did. Like every command k0s-monitor
// shows, they use the kubectl that ships with k0s.
const RemoveCommands = "k0s kubectl delete clusterrolebinding k0s-monitor:reader\n" +
	"k0s kubectl delete clusterrole k0s-monitor:reader\n" +
	"k0s kubectl delete rolebinding,role -A -l app.kubernetes.io/managed-by=k0s-monitor\n" +
	"k0s kubectl delete clusterrolebinding,clusterrole " + KubeletStatsRoleName + " --ignore-not-found\n" +
	"k0s kubectl delete clusterrolebinding,clusterrole " + TLSSecretsRoleName + " --ignore-not-found\n" +
	"k0s kubectl -n kube-system delete secret k0s-monitor-token serviceaccount k0s-monitor"

var read = []string{"get", "list", "watch"}

// Rules are the read-only permissions (plan section 13). There is no access
// to Secrets: reading TLS certificates is a separate, optional role.
func Rules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Verbs: read, Resources: []string{
			"pods", "nodes", "services", "endpoints", "events", "namespaces", "persistentvolumeclaims",
			"persistentvolumes", "replicationcontrollers", "resourcequotas", "limitranges", "serviceaccounts"}},
		{APIGroups: []string{""}, Verbs: []string{"get"}, Resources: []string{"pods/log"}},
		{APIGroups: []string{"apps"}, Verbs: read, Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"}},
		{APIGroups: []string{"batch"}, Verbs: read, Resources: []string{"jobs", "cronjobs"}},
		{APIGroups: []string{"networking.k8s.io"}, Verbs: read, Resources: []string{"ingresses", "ingressclasses", "networkpolicies"}},
		{APIGroups: []string{"discovery.k8s.io"}, Verbs: read, Resources: []string{"endpointslices"}},
		{APIGroups: []string{"storage.k8s.io"}, Verbs: read, Resources: []string{"storageclasses", "volumeattachments", "csidrivers", "csinodes"}},
		{APIGroups: []string{"policy"}, Verbs: read, Resources: []string{"poddisruptionbudgets"}},
		{APIGroups: []string{"autoscaling"}, Verbs: read, Resources: []string{"horizontalpodautoscalers"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Verbs: read, Resources: []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}},
		{APIGroups: []string{"apiregistration.k8s.io"}, Verbs: read, Resources: []string{"apiservices"}},
		{APIGroups: []string{"coordination.k8s.io"}, Verbs: read, Resources: []string{"leases"}},
		{APIGroups: []string{"metrics.k8s.io"}, Verbs: []string{"get", "list"}, Resources: []string{"pods", "nodes"}},
		{APIGroups: []string{"helm.k0sproject.io", "autopilot.k0sproject.io", "k0s.k0sproject.io", "etcd.k0sproject.io"}, Verbs: read, Resources: []string{"*"}},
		{NonResourceURLs: []string{"/readyz", "/readyz/*", "/livez", "/livez/*", "/healthz", "/version", "/metrics"}, Verbs: []string{"get"}},
	}
}

var labels = map[string]string{"app.kubernetes.io/name": "k0s-monitor", "app.kubernetes.io/managed-by": "k0s-monitor"}

var annotations = map[string]string{"k0s-monitor.io/purpose": "Read-only access for k0s-monitor. Delete the k0s-monitor ServiceAccount, token Secret, ClusterRole and ClusterRoleBinding to revoke it."}

func meta(name, ns string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels, Annotations: annotations}
}

func objects() (*corev1.ServiceAccount, *rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.Secret) {
	sa := &corev1.ServiceAccount{ObjectMeta: meta(Name, Namespace)}
	role := &rbacv1.ClusterRole{ObjectMeta: meta(RoleName, ""), Rules: Rules()}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: meta(RoleName, ""),
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: RoleName},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: Name, Namespace: Namespace}}}
	secret := &corev1.Secret{ObjectMeta: meta(SecretName, Namespace), Type: corev1.SecretTypeServiceAccountToken}
	secret.Annotations = map[string]string{corev1.ServiceAccountNameKey: Name, "k0s-monitor.io/purpose": annotations["k0s-monitor.io/purpose"]}
	return sa, role, binding, secret
}

// Result is the new account.
type Result struct {
	// Kubeconfig uses only the new token.
	Kubeconfig []byte
	// Changed lists what was created or updated.
	Changed []string
}

// Options for Create.
type Options struct {
	// Server is the API server address to put in the new kubeconfig.
	Server string
	// CAData is the certificate authority that verified Server. If empty,
	// the one from the token Secret is used.
	CAData []byte
	// ClusterName names the cluster in the new kubeconfig.
	ClusterName string
	// Wait bounds how long to wait for the token.
	Wait time.Duration
	// PrometheusNamespace and PrometheusProxyName, when set, let the
	// account read that one Prometheus Service through the API server's
	// service proxy. ProxyName is scheme:name:port.
	PrometheusNamespace string
	PrometheusProxyName string
	// TLSSecrets adds the role that reads Secrets, for the expiry of apps'
	// TLS certificates.
	TLSSecrets bool
}

// TLSSecretsRoleName names the optional ClusterRole and binding that let
// the account read Secrets: for the certificates in TLS Secrets, and for
// the Secrets pages. Kubernetes can't limit this to TLS Secrets: the
// account can read every Secret. k0s-monitor itself watches only TLS
// Secrets and keeps only their public certificate; it reads another Secret
// only when someone opens it, and shows its values only when that is
// turned on in Settings.
const TLSSecretsRoleName = "k0s-monitor:secrets"

// TLSSecretsCommands grant it to an existing account.
const TLSSecretsCommands = "k0s kubectl create clusterrole " + TLSSecretsRoleName + " --verb=get,list,watch --resource=secrets\n" +
	"k0s kubectl create clusterrolebinding " + TLSSecretsRoleName + " --clusterrole=" + TLSSecretsRoleName + " --serviceaccount=kube-system:k0s-monitor"

// tlsSecretsObjects are the optional ClusterRole and binding for TLS
// Secrets.
func tlsSecretsObjects() (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding) {
	role := &rbacv1.ClusterRole{ObjectMeta: meta(TLSSecretsRoleName, ""), Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Verbs: read, Resources: []string{"secrets"}},
	}}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: meta(TLSSecretsRoleName, ""),
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: TLSSecretsRoleName},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: Name, Namespace: Namespace}}}
	return role, binding
}

// KubeletStatsRoleName names the optional ClusterRole and binding that let
// the account read the kubelets' stats through the API server, for volume
// usage without Prometheus.
const KubeletStatsRoleName = "k0s-monitor:kubelet-stats"

// KubeletStatsCommands grant it. The permission, get nodes/proxy, reaches
// the whole kubelet API, so it is separate and never created by default.
const KubeletStatsCommands = "k0s kubectl create clusterrole " + KubeletStatsRoleName + " --verb=get --resource=nodes/proxy\n" +
	"k0s kubectl create clusterrolebinding " + KubeletStatsRoleName + " --clusterrole=" + KubeletStatsRoleName + " --serviceaccount=kube-system:k0s-monitor"

// PrometheusRoleName names the Role and RoleBinding that let the account
// read Prometheus.
const PrometheusRoleName = "k0s-monitor:prometheus"

// prometheusObjects are the Role and RoleBinding for Prometheus access.
func prometheusObjects(ns, proxyName string) (*rbacv1.Role, *rbacv1.RoleBinding) {
	role := &rbacv1.Role{ObjectMeta: meta(PrometheusRoleName, ns), Rules: []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"services/proxy"}, Verbs: []string{"get"}, ResourceNames: []string{proxyName},
	}}}
	binding := &rbacv1.RoleBinding{ObjectMeta: meta(PrometheusRoleName, ns),
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: PrometheusRoleName},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: Name, Namespace: Namespace}}}
	return role, binding
}

// Create makes (or updates) the account with an admin client.
func Create(ctx context.Context, cs kubernetes.Interface, o Options) (*Result, error) {
	if o.Wait == 0 {
		o.Wait = 30 * time.Second
	}
	// A server-side dry run first: nothing changes if anything would fail.
	if err := apply(ctx, cs, true, nil, o); err != nil {
		return nil, fmt.Errorf("dry run: %w", err)
	}
	res := &Result{}
	if err := apply(ctx, cs, false, res, o); err != nil {
		return nil, err
	}

	token, ca, err := waitForToken(ctx, cs, o.Wait)
	if err != nil {
		return nil, err
	}
	if len(o.CAData) > 0 {
		ca = o.CAData
	}
	name := o.ClusterName
	if name == "" {
		name = "cluster"
	}
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[name] = &clientcmdapi.Cluster{Server: o.Server, CertificateAuthorityData: ca}
	cfg.AuthInfos[Name] = &clientcmdapi.AuthInfo{Token: token}
	ctxName := Name + "@" + name
	cfg.Contexts[ctxName] = &clientcmdapi.Context{Cluster: name, AuthInfo: Name}
	cfg.CurrentContext = ctxName
	res.Kubeconfig, err = clientcmd.Write(*cfg)
	return res, err
}

// applyClusterRole creates a ClusterRole and its binding to the account, or
// updates them when they exist.
func applyClusterRole(ctx context.Context, cs kubernetes.Interface, co metav1.CreateOptions, uo metav1.UpdateOptions,
	changed func(string), role *rbacv1.ClusterRole, binding *rbacv1.ClusterRoleBinding) error {
	name := role.Name
	if _, err := cs.RbacV1().ClusterRoles().Create(ctx, role, co); err == nil {
		changed("created ClusterRole " + name)
	} else if apierrors.IsAlreadyExists(err) {
		cur, err := cs.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return explain("the ClusterRole "+name, err)
		}
		cur.Rules = role.Rules
		cur.Labels = labels
		if _, err := cs.RbacV1().ClusterRoles().Update(ctx, cur, uo); err != nil {
			return explain("the ClusterRole "+name, err)
		}
		changed("updated ClusterRole " + name)
	} else {
		return explain("the ClusterRole "+name, err)
	}

	if _, err := cs.RbacV1().ClusterRoleBindings().Create(ctx, binding, co); err == nil {
		changed("created ClusterRoleBinding " + name)
	} else if apierrors.IsAlreadyExists(err) {
		cur, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return explain("the ClusterRoleBinding "+name, err)
		}
		if cur.RoleRef != binding.RoleRef {
			return fmt.Errorf("a ClusterRoleBinding %s exists and points to %s %s; delete it and try again", name, cur.RoleRef.Kind, cur.RoleRef.Name)
		}
		cur.Subjects = binding.Subjects
		if _, err := cs.RbacV1().ClusterRoleBindings().Update(ctx, cur, uo); err != nil {
			return explain("the ClusterRoleBinding "+name, err)
		}
		changed("updated ClusterRoleBinding " + name)
	} else {
		return explain("the ClusterRoleBinding "+name, err)
	}
	return nil
}

// apply creates each object, or updates it when it exists.
func apply(ctx context.Context, cs kubernetes.Interface, dryRun bool, res *Result, o Options) error {
	var co metav1.CreateOptions
	var uo metav1.UpdateOptions
	if dryRun {
		co.DryRun = []string{metav1.DryRunAll}
		uo.DryRun = []string{metav1.DryRunAll}
	}
	changed := func(what string) {
		if res != nil {
			res.Changed = append(res.Changed, what)
		}
	}
	sa, role, binding, secret := objects()

	if _, err := cs.CoreV1().ServiceAccounts(Namespace).Create(ctx, sa, co); err == nil {
		changed("created ServiceAccount " + Namespace + "/" + Name)
	} else if !apierrors.IsAlreadyExists(err) {
		return explain("the ServiceAccount", err)
	}
	if err := applyClusterRole(ctx, cs, co, uo, changed, role, binding); err != nil {
		return err
	}
	if o.TLSSecrets {
		trole, tbinding := tlsSecretsObjects()
		if err := applyClusterRole(ctx, cs, co, uo, changed, trole, tbinding); err != nil {
			return err
		}
	}

	if _, err := cs.CoreV1().Secrets(Namespace).Create(ctx, secret, co); err == nil {
		changed("created token Secret " + Namespace + "/" + SecretName)
	} else if !apierrors.IsAlreadyExists(err) {
		return explain("the token Secret", err)
	}

	if o.PrometheusNamespace == "" || o.PrometheusProxyName == "" {
		return nil
	}
	ns := o.PrometheusNamespace
	prole, pbinding := prometheusObjects(ns, o.PrometheusProxyName)
	if _, err := cs.RbacV1().Roles(ns).Create(ctx, prole, co); err == nil {
		changed("created Role " + ns + "/" + PrometheusRoleName)
	} else if apierrors.IsAlreadyExists(err) {
		cur, err := cs.RbacV1().Roles(ns).Get(ctx, PrometheusRoleName, metav1.GetOptions{})
		if err != nil {
			return explain("the Prometheus Role", err)
		}
		cur.Rules, cur.Labels = prole.Rules, labels
		if _, err := cs.RbacV1().Roles(ns).Update(ctx, cur, uo); err != nil {
			return explain("the Prometheus Role", err)
		}
		changed("updated Role " + ns + "/" + PrometheusRoleName)
	} else {
		return explain("the Prometheus Role", err)
	}
	if _, err := cs.RbacV1().RoleBindings(ns).Create(ctx, pbinding, co); err == nil {
		changed("created RoleBinding " + ns + "/" + PrometheusRoleName)
	} else if !apierrors.IsAlreadyExists(err) {
		return explain("the Prometheus RoleBinding", err)
	}
	return nil
}

func waitForToken(ctx context.Context, cs kubernetes.Interface, wait time.Duration) (string, []byte, error) {
	deadline := time.Now().Add(wait)
	for {
		s, err := cs.CoreV1().Secrets(Namespace).Get(ctx, SecretName, metav1.GetOptions{})
		if err == nil && len(s.Data[corev1.ServiceAccountTokenKey]) > 0 {
			return string(s.Data[corev1.ServiceAccountTokenKey]), s.Data[corev1.ServiceAccountRootCAKey], nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return "", nil, explain("the token", err)
			}
			return "", nil, errors.New("the cluster did not fill in the token within the time limit; is the kube-controller-manager running?")
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func explain(what string, err error) error {
	if apierrors.IsForbidden(err) {
		return fmt.Errorf("the uploaded credentials may not create %s; use an admin kubeconfig or keep the uploaded credentials", what)
	}
	return fmt.Errorf("creating %s: %w", what, err)
}
