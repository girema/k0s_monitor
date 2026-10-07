// Package cluster connects to one cluster: it builds the client from a
// kubeconfig, checks that the API server answers, explains connection
// failures and probes what the cluster offers.
package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k0s_monitor/internal/config"
	kmversion "k0s_monitor/internal/version"
)

// Conn is a configured client for one cluster. Creating it does not touch
// the network; call Ping to check that the cluster answers.
type Conn struct {
	Name   string
	Server string
	Config *rest.Config
	Client kubernetes.Interface
	// Fallback is set when Server is another controller, used because the
	// kubeconfig's server doesn't answer.
	Fallback *Fallback

	// ping overrides how the API server is contacted (tests only).
	ping func(ctx context.Context) (*version.Info, error)
}

// InClusterName is a name every API server certificate k0s makes is valid
// for, whatever address the controller is reached at.
const InClusterName = "kubernetes.default.svc"

// Fallback says that a connection goes to another controller because the
// kubeconfig's server doesn't answer.
type Fallback struct {
	// Server is the kubeconfig's server.
	Server string `json:"server"`
	// Error says why it isn't used.
	Error *ConnError `json:"error"`
	// Controller names the controller used instead; Conn.Server is its
	// address.
	Controller string `json:"controller"`
	// ServerIsController says that the kubeconfig's server is one
	// controller's own address rather than a shared one (a load balancer).
	ServerIsController bool      `json:"serverIsController,omitempty"`
	Since              time.Time `json:"since"`
}

// Address is a server URL's host:port.
func Address(server string) string {
	host, port := hostPort(server)
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// NewForClient wraps an existing client, for tests and embedding. The
// cluster is considered reachable and reports the given version.
func NewForClient(name, server string, client kubernetes.Interface, v *version.Info) *Conn {
	return &Conn{Name: name, Server: server, Client: client,
		ping: func(context.Context) (*version.Info, error) { return v, nil }}
}

// NewForClientWithPing is NewForClient with a custom health check, so tests
// can make the cluster unreachable and bring it back.
func NewForClientWithPing(name, server string, client kubernetes.Interface, ping func(ctx context.Context) (*version.Info, error)) *Conn {
	return &Conn{Name: name, Server: server, Client: client, ping: ping}
}

// Connector creates connections. Tests replace it with fakes.
type Connector func(c config.Cluster, connectTimeout time.Duration) (*Conn, error)

// Connect builds a client from the cluster's kubeconfig.
func Connect(c config.Cluster, connectTimeout time.Duration) (*Conn, error) {
	rc, err := RESTConfig(c)
	if err != nil {
		return nil, err
	}
	rc.UserAgent = "k0s-monitor/" + kmversion.Version
	rc.QPS = 20
	rc.Burst = 40
	if c.Proxy != "" {
		u, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, &ConnError{Kind: KindConfig, Err: err, Plain: "The proxy URL is invalid: " + c.Proxy}
		}
		rc.Proxy = http.ProxyURL(u)
	}
	if c.ServerName != "" {
		// Another controller gets the credentials only once its certificate
		// proves it is one of this cluster's API servers.
		if rc.Insecure {
			return nil, &ConnError{Kind: KindConfig, Server: rc.Host,
				Plain: "The kubeconfig doesn't check the server's certificate, so k0s-monitor doesn't send its credentials to another address."}
		}
		rc.TLSClientConfig.ServerName = c.ServerName
	}
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	rc.Dial = dialer.DialContext
	client, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, &ConnError{Kind: KindConfig, Err: err, Plain: "The client can't be created: " + err.Error()}
	}
	return &Conn{Name: c.Name, Server: rc.Host, Config: rc, Client: client}, nil
}

// Ping asks the API server for its version. It returns a *ConnError that
// explains the failure in plain words.
// RESTConfig loads the cluster's kubeconfig, from its file or from the data
// of a cluster added in the UI, and applies the server override.
func RESTConfig(c config.Cluster) (*rest.Config, error) {
	var cc clientcmd.ClientConfig
	overrides := &clientcmd.ConfigOverrides{CurrentContext: c.Context}
	if len(c.KubeconfigData) > 0 {
		raw, err := clientcmd.Load(c.KubeconfigData)
		if err != nil {
			return nil, &ConnError{Kind: KindConfig, Err: err,
				Plain: "The stored kubeconfig can't be read: " + err.Error(),
				Hint:  "Add the cluster again by uploading its file."}
		}
		cc = clientcmd.NewNonInteractiveClientConfig(*raw, c.Context, overrides, nil)
	} else {
		if _, err := os.Stat(c.Kubeconfig); err != nil {
			return nil, &ConnError{Kind: KindConfig, Err: err,
				Plain: fmt.Sprintf("The kubeconfig file %s can't be read.", c.Kubeconfig),
				Hint:  "Check the path in the configuration, or add the cluster again by uploading its file."}
		}
		rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: c.Kubeconfig}
		cc = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	}
	rc, err := cc.ClientConfig()
	if err != nil {
		return nil, &ConnError{Kind: KindConfig, Err: err,
			Plain: "The kubeconfig can't be used: " + err.Error(),
			Hint:  "Check that the file is a complete kubeconfig and that the context exists."}
	}
	rc = rest.CopyConfig(rc)
	if c.Server != "" {
		rc.Host = c.Server
	}
	return rc, nil
}

func (c *Conn) Ping(ctx context.Context) (*version.Info, error) {
	if c.ping != nil {
		return c.ping(ctx)
	}
	raw, err := c.Client.Discovery().RESTClient().Get().AbsPath("/version").Do(ctx).Raw()
	if err != nil {
		return nil, Classify(err, c.Server, c.proxyURL())
	}
	var info version.Info
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, &ConnError{Kind: KindOther, Server: c.Server, Err: err,
			Plain: "The server answered, but not like a Kubernetes API server.",
			Hint:  "Check that the kubeconfig points at the k0s API (port 6443)."}
	}
	return &info, nil
}

func (c *Conn) proxyURL() string {
	if c.Config == nil || c.Config.Proxy == nil {
		return ""
	}
	req, err := http.NewRequest(http.MethodGet, c.Server, nil)
	if err != nil {
		return ""
	}
	u, err := c.Config.Proxy(req)
	if err != nil || u == nil {
		return ""
	}
	return u.Redacted()
}
