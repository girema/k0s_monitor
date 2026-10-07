package web

import (
	"net/http"
	"strings"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/pack"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/store"
)

// The guide for adding a node (plan section 10.2): the commands to run,
// with the k0s version the product ships. k0s-monitor never creates join
// tokens itself: a token is a credential to the cluster. A product pack can
// replace the guide with the product's own procedure.

type portRow struct {
	Port, Proto, Between, Why string
}

type addNodeData struct {
	State *engine.State
	// Version is the k0s version to install, and VersionFrom where it
	// comes from; empty when unknown.
	Version, VersionFrom string
	// Controller is where to create the token: a controller's name, or
	// "a controller".
	Controller string
	// Controllers is how many there are, when known.
	Controllers int
	Network     string
	Ports       []portRow
	// Profiles are the worker profiles of the k0s configuration.
	Profiles []string
	// K0sctl is true when the cluster came with a k0sctl.yaml.
	K0sctl bool
	// Pack is a product pack's own procedure, from PackName.
	Pack     *pack.AddNode
	PackName string
	// Guide holds the steps: the built-in ones, or the pack's.
	Guide *findings.Finding
	// Builtin are the built-in steps, shown under a pack's in Full mode.
	Builtin *findings.Finding
	// GetK0s is the line that installs the version from the internet, when
	// the version is known exactly.
	GetK0s string
}

// builtinSteps are the steps k0s's documentation gives for adding a worker,
// with this cluster's version, controller and profiles.
func builtinSteps(d *addNodeData) []findings.Step {
	version := "the same k0s version as the controllers"
	if d.Version != "" {
		version = "k0s " + d.Version
	}
	install := "sudo k0s install worker --token-file ./worker-token"
	if len(d.Profiles) > 0 {
		install += " --profile " + d.Profiles[0]
	}
	return []findings.Step{
		{Text: "Create a join token for a worker, valid for one hour. It lets a machine join the cluster: treat it like a password, and copy it only over SSH",
			Plain:   "Create a key that lets the new server join, valid for one hour. Treat it like a password: don't send it by email or chat",
			Command: "sudo k0s token create --role=worker --expiry=1h > worker-token", Host: d.Controller},
		{Text: "Install " + version + " on the new server: copy the program from the controller, which runs that version, and check it",
			Plain:   "Put the same k0s program on the new server: copy it from the controller, and check its version",
			Command: "scp " + hostOrPlaceholder(d.Controller) + ":/usr/local/bin/k0s .\nsudo install -m 755 k0s /usr/local/bin/k0s\nk0s version", Host: "the new server"},
		{Text: "Copy worker-token to the new server, then install k0s there as a worker service and start it",
			Plain:   "Copy the key to the new server, then install and start k0s there",
			Command: install + "\nsudo k0s start\nsudo k0s status", Host: "the new server"},
		{Text: "Watch it join: it becomes Ready within a few minutes, and shows on the Servers page",
			Plain:   "Wait a few minutes: the new server appears on the Servers page, working",
			Command: findings.K0sKubectl("kubectl get nodes -o wide")},
		{Text: "Delete the token on both machines. An unused token expires after an hour; one can be withdrawn sooner by its ID",
			Plain:   "Delete the key on both machines",
			Command: "shred -u worker-token\nsudo k0s token list --role=worker\nsudo k0s token invalidate <ID>", Host: "both machines"},
	}
}

func hostOrPlaceholder(controller string) string {
	if controller == "" || controller == "a controller" {
		return "CONTROLLER"
	}
	return controller
}

// networkOf names the cluster's network provider: from the k0s
// configuration, else from the DaemonSets k0s runs.
func networkOf(s *snapshot.Snapshot, cfg *snapshot.ClusterConfig) string {
	if p, ok := cfg.Get("network", "provider").(string); ok && p != "" {
		return p
	}
	if s != nil {
		for _, ds := range s.DaemonSets {
			if ds.Namespace != "kube-system" {
				continue
			}
			switch ds.Name {
			case "kube-router":
				return "kuberouter"
			case "calico-node":
				return "calico"
			}
		}
	}
	return ""
}

// workerPorts are the connections a new worker needs (k0s documentation,
// "networking").
func workerPorts(network string) []portRow {
	ports := []portRow{
		{"6443", "TCP", "new server → controllers", "the Kubernetes API"},
		{"8132", "TCP", "new server → controllers", "konnectivity: logs, exec and metrics through the controllers"},
	}
	switch network {
	case "kuberouter":
		ports = append(ports, portRow{"179", "TCP", "between all servers", "kube-router (BGP), the pod network"})
	case "calico":
		ports = append(ports, portRow{"4789", "UDP", "between all servers", "Calico (VXLAN), the pod network"})
	default:
		ports = append(ports, portRow{"", "", "between all servers", "what the cluster's network provider needs"})
	}
	return ports
}

func uploadedK0sctl(st *store.Store, name string) bool {
	stored, err := st.Clusters()
	if err != nil {
		return false
	}
	for _, sc := range stored {
		if sc.Cluster.Name == name {
			return len(sc.K0sctl) > 0
		}
	}
	return false
}

func (s *Server) addNodePage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	d := addNodeData{State: st, Controller: "a controller"}
	snap := st.Snapshot
	var cfg *snapshot.ClusterConfig
	if snap != nil {
		if v, from, ok := snap.ExpectedVersion(); ok {
			d.Version, d.VersionFrom = v.Raw, from
		}
		if cp := snap.ControlPlane; cp != nil {
			cfg = cp.Config
			d.Controllers = len(cp.Controllers)
			for _, c := range cp.Controllers {
				if c.Reached && c.Name != "" {
					d.Controller = c.Name
					break
				}
			}
		}
	}
	if e.Cluster().FromUI {
		if cfg == nil {
			cfg = uploadedConfig(s.o.Store, e.Name())
		}
		d.K0sctl = uploadedK0sctl(s.o.Store, e.Name())
	}
	d.Network = networkOf(snap, cfg)
	d.Ports = workerPorts(d.Network)
	if ps, ok := cfg.Get("workerProfiles").([]any); ok {
		for _, p := range ps {
			if m, ok := p.(map[string]any); ok {
				if name, ok := m["name"].(string); ok && name != "" {
					d.Profiles = append(d.Profiles, name)
				}
			}
		}
	}
	if strings.Contains(d.Version, "+k0s.") {
		d.GetK0s = "curl -sSLf https://get.k0s.sh | sudo K0S_VERSION=" + d.Version + " sh"
	}
	d.Builtin = &findings.Finding{Remedy: findings.Remedy{Steps: builtinSteps(&d)}}
	d.Guide = d.Builtin
	if a, name := s.o.Packs.Current().AddNode(e.Name()); a != nil {
		d.Pack, d.PackName = a, name
		d.Guide = &findings.Finding{}
		for _, st := range a.Steps {
			cmd := st.Command
			if st.Host == "" {
				cmd = findings.K0sKubectl(cmd)
			}
			d.Guide.AddStep(findings.Step{Text: st.Text, Plain: st.Plain, Command: cmd, Host: st.Host, Pack: name})
		}
		for _, doc := range a.Docs {
			d.Guide.Docs = append(d.Guide.Docs, findings.Doc{Title: doc.Title, URL: doc.URL, Pack: name})
		}
	}
	nav := navOf(st)
	s.render(w, r, "addnode", &page{Title: "Add a server · " + e.Name(), Nav: "servers", Cluster: &nav, Data: d})
}
