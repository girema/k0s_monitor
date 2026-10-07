package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/config"
)

// accountForm is the cluster setting for the credentials k0s-monitor uses.
type accountForm struct {
	// Uploaded is true while k0s-monitor uses the credentials uploaded with
	// the cluster, which are often an admin's.
	Uploaded bool
	Notice   string
	OK       bool
}

// clusterAccountForm replaces a cluster's uploaded credentials with
// k0s-monitor's own read-only account: they create it once and are then
// deleted from this machine, as when the cluster is added with it.
func (s *Server) clusterAccountForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	c := e.Cluster()
	fail := func(status int, msg string) {
		s.renderClusterSettings(w, r, e, settingsForms{account: &accountForm{Uploaded: true, Notice: msg}}, status)
	}
	if !c.FromUI {
		fail(http.StatusBadRequest, "This cluster comes from the configuration file: its kubeconfig is set there.")
		return
	}
	stored, err := s.o.Store.Clusters()
	if err != nil {
		fail(http.StatusInternalServerError, "The stored cluster can't be read: "+err.Error())
		return
	}
	i := -1
	for j, sc := range stored {
		if sc.Cluster.Name == c.Name {
			i = j
		}
	}
	if i < 0 || stored[i].Account != "uploaded" {
		fail(http.StatusBadRequest, "This cluster already uses k0s-monitor's read-only account.")
		return
	}
	server, caData, err := kubeconfigServer(c)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	res, err := s.createAccount(ctx, c, account.Options{Server: server, CAData: caData, ClusterName: c.Name, TLSSecrets: r.PostFormValue("tlsSecrets") == "on"})
	if err != nil {
		fail(http.StatusBadRequest, "The read-only account could not be created with the uploaded credentials: "+err.Error())
		return
	}
	ro := c
	ro.KubeconfigData, ro.Server = res.Kubeconfig, ""
	if err := s.verifyAccess(ctx, ro); err != nil {
		fail(http.StatusBadRequest, "The new read-only account can't sign in: "+err.Error()+". The uploaded credentials are still used.")
		return
	}
	sc := stored[i]
	sc.Cluster, sc.Account = ro, "readonly"
	if err := s.o.Store.SaveCluster(sc); err != nil {
		fail(http.StatusInternalServerError, "Saving the new account failed: "+err.Error()+". The uploaded credentials are still used.")
		return
	}
	if _, err := s.o.Fleet.Replace(ro); err != nil {
		fail(http.StatusInternalServerError, "Saved, but the cluster could not be restarted: "+err.Error())
		return
	}
	detail := c.Name + ": uploaded credentials replaced by the read-only account"
	if len(res.Changed) > 0 {
		detail += "; " + strings.Join(res.Changed, ", ")
	}
	s.audit(r, "cluster.account", detail)
	http.Redirect(w, r, "/c/"+url.PathEscape(c.Name)+"/settings?saved=account#account", http.StatusSeeOther)
}

// kubeconfigServer is the API server address a cluster is reached at, and
// the certificate authority its kubeconfig trusts for it.
func kubeconfigServer(c config.Cluster) (string, []byte, error) {
	kc, err := clientcmd.Load(c.KubeconfigData)
	if err != nil {
		return "", nil, errors.New("the stored kubeconfig can't be read: " + err.Error())
	}
	name := c.Context
	if name == "" {
		name = kc.CurrentContext
	}
	ctx := kc.Contexts[name]
	if ctx == nil {
		return "", nil, errors.New("the stored kubeconfig has no context " + name)
	}
	cl := kc.Clusters[ctx.Cluster]
	if cl == nil {
		return "", nil, errors.New("the stored kubeconfig has no cluster " + ctx.Cluster)
	}
	server := cl.Server
	if c.Server != "" {
		server = c.Server
	}
	return server, cl.CertificateAuthorityData, nil
}
