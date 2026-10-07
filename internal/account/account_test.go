package account

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
)

// honorDryRun makes the fake client skip dry-run writes, as an API server
// does.
func honorDryRun(cs *fake.Clientset) {
	cs.PrependReactor("create", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca := a.(k8stesting.CreateActionImpl)
		if len(ca.GetCreateOptions().DryRun) > 0 {
			return true, ca.GetObject(), nil
		}
		return false, nil, nil
	})
	cs.PrependReactor("update", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ua := a.(k8stesting.UpdateActionImpl)
		if len(ua.GetUpdateOptions().DryRun) > 0 {
			return true, ua.GetObject(), nil
		}
		return false, nil, nil
	})
}

// tokenController fills in the token like kube-controller-manager does.
func tokenController(cs *fake.Clientset) {
	cs.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj, err := cs.Tracker().Get(a.GetResource(), a.GetNamespace(), a.(k8stesting.GetAction).GetName())
		if err != nil {
			return true, nil, err
		}
		s := obj.(*corev1.Secret).DeepCopy()
		s.Data = map[string][]byte{"token": []byte("sa-token"), "ca.crt": []byte("secret-ca")}
		return true, s, nil
	})
}

func TestCreate(t *testing.T) {
	cs := fake.NewClientset()
	honorDryRun(cs)
	tokenController(cs)
	res, err := Create(context.Background(), cs, Options{Server: "https://10.0.10.11:6443", CAData: []byte("admin-ca"), ClusterName: "edge-prod", Wait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changed) != 4 {
		t.Errorf("changed = %v", res.Changed)
	}
	cfg, err := clientcmd.Load(res.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx := cfg.Contexts[cfg.CurrentContext]
	if cfg.AuthInfos[ctx.AuthInfo].Token != "sa-token" || cfg.Clusters[ctx.Cluster].Server != "https://10.0.10.11:6443" ||
		string(cfg.Clusters[ctx.Cluster].CertificateAuthorityData) != "admin-ca" {
		t.Errorf("kubeconfig = %s", res.Kubeconfig)
	}
	if strings.Contains(string(res.Kubeconfig), "client-key") {
		t.Error("the new kubeconfig carries only the token")
	}
	role, err := cs.RbacV1().ClusterRoles().Get(context.Background(), RoleName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range role.Rules {
		for _, res := range r.Resources {
			if res == "secrets" || res == "*" && len(r.APIGroups) > 0 && r.APIGroups[0] == "" {
				t.Errorf("the role must not read secrets: %+v", r)
			}
		}
		for _, v := range r.Verbs {
			if v != "get" && v != "list" && v != "watch" {
				t.Errorf("the role must be read-only: %+v", r)
			}
		}
	}

	// Running it again updates instead of failing.
	res, err = Create(context.Background(), cs, Options{Server: "https://10.0.10.11:6443", Wait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Changed, ";") != "updated ClusterRole k0s-monitor:reader;updated ClusterRoleBinding k0s-monitor:reader" {
		t.Errorf("second run = %v", res.Changed)
	}
	cfg, _ = clientcmd.Load(res.Kubeconfig)
	if string(cfg.Clusters[cfg.Contexts[cfg.CurrentContext].Cluster].CertificateAuthorityData) != "secret-ca" {
		t.Error("without a CA from the kubeconfig, the Secret's CA is used")
	}
}

func TestDryRunFirst(t *testing.T) {
	cs := fake.NewClientset()
	var dry, real int
	cs.PrependReactor("create", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca := a.(k8stesting.CreateActionImpl)
		if len(ca.GetCreateOptions().DryRun) > 0 {
			dry++
			return true, ca.GetObject(), nil
		}
		real++
		return false, nil, nil
	})
	tokenController(cs)
	if _, err := Create(context.Background(), cs, Options{Server: "https://x:6443", Wait: time.Second}); err != nil {
		t.Fatal(err)
	}
	if dry != 4 || real != 4 {
		t.Errorf("dry runs %d, real creates %d", dry, real)
	}
}

func TestForbidden(t *testing.T) {
	cs := fake.NewClientset()
	honorDryRun(cs)
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errForbidden()
	})
	_, err := Create(context.Background(), cs, Options{Server: "https://x:6443", Wait: time.Second})
	if err == nil || !strings.Contains(err.Error(), "may not create") {
		t.Errorf("err = %v", err)
	}
	if list, _ := cs.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{}); len(list.Items) != 0 {
		t.Error("when the dry run fails, nothing is created")
	}
}

func TestBindingToAnotherRole(t *testing.T) {
	cs := fake.NewClientset(&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: RoleName},
		RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}})
	honorDryRun(cs)
	tokenController(cs)
	if _, err := Create(context.Background(), cs, Options{Server: "https://x:6443", Wait: time.Second}); err == nil {
		t.Error("an existing binding to another role must not be reused")
	}
}

func errForbidden() error {
	return apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, Name, nil)
}

func TestCreateGrantsPrometheus(t *testing.T) {
	cs := fake.NewClientset()
	honorDryRun(cs)
	tokenController(cs)
	res, err := Create(context.Background(), cs, Options{Server: "https://x:6443", Wait: time.Second,
		PrometheusNamespace: "monitoring", PrometheusProxyName: "http:prometheus-k8s:9090"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := cs.RbacV1().Roles("monitoring").Get(context.Background(), PrometheusRoleName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r := role.Rules[0]
	if len(role.Rules) != 1 || r.Resources[0] != "services/proxy" || r.Verbs[0] != "get" || r.ResourceNames[0] != "http:prometheus-k8s:9090" {
		t.Errorf("rules = %+v", role.Rules)
	}
	rb, err := cs.RbacV1().RoleBindings("monitoring").Get(context.Background(), PrometheusRoleName, metav1.GetOptions{})
	if err != nil || rb.Subjects[0].Name != Name || rb.Subjects[0].Namespace != Namespace {
		t.Errorf("binding = %+v, %v", rb, err)
	}
	if !strings.Contains(strings.Join(res.Changed, "; "), "created Role monitoring/k0s-monitor:prometheus") {
		t.Errorf("changed = %v", res.Changed)
	}
	if !strings.Contains(RemoveCommands, "delete rolebinding,role -A -l app.kubernetes.io/managed-by=k0s-monitor") {
		t.Errorf("remove commands miss the Prometheus Role")
	}
	if !strings.Contains(RemoveCommands, "delete clusterrolebinding,clusterrole k0s-monitor:kubelet-stats --ignore-not-found") {
		t.Errorf("remove commands miss the optional kubelet stats role")
	}
}

func TestCreateWithTLSSecrets(t *testing.T) {
	cs := fake.NewClientset()
	honorDryRun(cs)
	tokenController(cs)
	res, err := Create(context.Background(), cs, Options{Server: "https://10.0.10.11:6443", Wait: time.Second, TLSSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Changed, ";"), "created ClusterRole k0s-monitor:secrets;created ClusterRoleBinding k0s-monitor:secrets") {
		t.Errorf("changed = %v", res.Changed)
	}
	role, err := cs.RbacV1().ClusterRoles().Get(context.Background(), TLSSecretsRoleName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(role.Rules) != 1 || strings.Join(role.Rules[0].Resources, ",") != "secrets" || strings.Join(role.Rules[0].Verbs, ",") != "get,list,watch" {
		t.Errorf("rules = %+v", role.Rules)
	}
	b, err := cs.RbacV1().ClusterRoleBindings().Get(context.Background(), TLSSecretsRoleName, metav1.GetOptions{})
	if err != nil || b.Subjects[0].Name != Name || b.RoleRef.Name != TLSSecretsRoleName {
		t.Errorf("binding = %+v, %v", b, err)
	}
	// The main role still reads no Secrets.
	main, _ := cs.RbacV1().ClusterRoles().Get(context.Background(), RoleName, metav1.GetOptions{})
	for _, r := range main.Rules {
		for _, res := range r.Resources {
			if res == "secrets" {
				t.Errorf("the reader role reads secrets: %+v", r)
			}
		}
	}
	if !strings.Contains(RemoveCommands, TLSSecretsRoleName) || !strings.Contains(TLSSecretsCommands, "--verb=get,list,watch --resource=secrets") {
		t.Error("commands")
	}
}
