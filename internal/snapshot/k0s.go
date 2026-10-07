package snapshot

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// k0s versions

// IsK0s reports whether the cluster runs k0s: its kubelets say so in their
// version (v1.36.4+k0s).
func (s *Snapshot) IsK0s() bool {
	for _, n := range s.Nodes {
		if strings.Contains(n.Status.NodeInfo.KubeletVersion, "+k0s") {
			return true
		}
	}
	return false
}

// K0sVersion is a k0s version such as v1.36.4+k0s.1: the Kubernetes version
// it ships and k0s's own build number. Kubelets report only the first part
// (v1.36.4+k0s), so Build may be empty.
type K0sVersion struct {
	Major, Minor, Patch int
	Build               string
	Raw                 string
}

// ParseK0sVersion reads v1.36.4+k0s.1, v1.36.4+k0s or 1.36.4.
func ParseK0sVersion(s string) (K0sVersion, bool) {
	v := K0sVersion{Raw: strings.TrimSpace(s)}
	core, meta, _ := strings.Cut(strings.TrimPrefix(v.Raw, "v"), "+")
	core, _, _ = strings.Cut(core, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, false
	}
	var err error
	for i, p := range []*int{&v.Major, &v.Minor, &v.Patch} {
		if *p, err = strconv.Atoi(parts[i]); err != nil {
			return v, false
		}
	}
	if b, ok := strings.CutPrefix(meta, "k0s."); ok {
		v.Build = b
	}
	return v, true
}

// Kubernetes is the Kubernetes part, like v1.36.4.
func (v K0sVersion) Kubernetes() string { return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Matches says whether two versions are the same: the same Kubernetes
// version, and the same k0s build when both are known.
func (v K0sVersion) Matches(o K0sVersion) bool {
	if v.Major != o.Major || v.Minor != o.Minor || v.Patch != o.Patch {
		return false
	}
	return v.Build == "" || o.Build == "" || v.Build == o.Build
}

// ExpectedK0s is the k0s version a cluster should run, and where that
// comes from: the configuration file, the uploaded k0sctl.yaml, or set in
// k0s-monitor. Without one, the version most controllers run is expected.
type ExpectedK0s struct {
	Version string
	From    string
}

// ExpectedOf is the expected version set for a cluster, or nil. A version
// without a source comes from the configuration file.
func ExpectedOf(version, from string) *ExpectedK0s {
	if version == "" {
		return nil
	}
	if from == "" {
		from = "the configuration file"
	}
	return &ExpectedK0s{Version: version, From: from}
}

// NodeVersion is the k0s version one node or controller runs.
type NodeVersion struct {
	Name string
	// Controller is true for controllers, including those that also run
	// workloads.
	Controller bool
	Version    K0sVersion
}

// K0sVersions lists the version of every controller (from k0s's ControlNode
// objects, else its API server) and every other node (its kubelet), by
// name. Nodes that don't report a version are left out.
func (s *Snapshot) K0sVersions() []NodeVersion {
	var out []NodeVersion
	seen := map[string]bool{}
	if cp := s.ControlPlane; cp != nil {
		for _, c := range cp.Controllers {
			raw := c.K0sVersion
			if raw == "" {
				raw = c.Version
			}
			v, ok := ParseK0sVersion(raw)
			if !ok {
				continue
			}
			out = append(out, NodeVersion{Name: c.Label(), Controller: true, Version: v})
			seen[c.Label()] = true
		}
	}
	for _, n := range s.Nodes {
		if seen[n.Name] {
			continue
		}
		v, ok := ParseK0sVersion(n.Status.NodeInfo.KubeletVersion)
		if !ok {
			continue
		}
		out = append(out, NodeVersion{Name: n.Name, Controller: n.Labels["node.k0sproject.io/role"] == "control-plane", Version: v})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Controller != out[j].Controller {
			return out[i].Controller
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ExpectedVersion is the version the cluster should run: the configured
// one, else the one most controllers run (the newest on a tie), else the
// one most nodes run. ok is false when nothing is known.
func (s *Snapshot) ExpectedVersion() (v K0sVersion, from string, ok bool) {
	if e := s.ExpectedK0s; e != nil && e.Version != "" {
		if v, ok := ParseK0sVersion(e.Version); ok {
			return v, e.From, true
		}
	}
	all := s.K0sVersions()
	pick := func(controllers bool) (K0sVersion, bool) {
		count := map[string]int{}
		byRaw := map[string]K0sVersion{}
		for _, nv := range all {
			if controllers && !nv.Controller {
				continue
			}
			count[nv.Version.Raw]++
			byRaw[nv.Version.Raw] = nv.Version
		}
		best, found := K0sVersion{}, false
		for raw, n := range count {
			cand := byRaw[raw]
			if !found || n > count[best.Raw] || n == count[best.Raw] && newer(cand, best) {
				best, found = cand, true
			}
		}
		return best, found
	}
	if v, ok := pick(true); ok {
		return v, "the version most controllers run", true
	}
	if v, ok := pick(false); ok {
		return v, "the version most nodes run", true
	}
	return K0sVersion{}, "", false
}

func newer(a, b K0sVersion) bool {
	if a.Major != b.Major {
		return a.Major > b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor > b.Minor
	}
	if a.Patch != b.Patch {
		return a.Patch > b.Patch
	}
	return a.Build > b.Build
}

// ---------------------------------------------------------------------------
// Autopilot plans

// Plan states, as k0s's Autopilot sets them.
const (
	PlanSchedulable       = "Schedulable"
	PlanSchedulableWait   = "SchedulableWait"
	PlanCompleted         = "Completed"
	PlanWarning           = "Warning"
	PlanIncompleteTargets = "IncompleteTargets"
	PlanRestricted        = "Restricted"
	PlanApplyFailed       = "ApplyFailed"

	SignalPending         = "SignalPending"
	SignalSent            = "SignalSent"
	SignalCompleted       = "SignalCompleted"
	SignalMissingNode     = "SignalMissingNode"
	SignalMissingPlatform = "SignalMissingPlatform"
	SignalApplyFailed     = "SignalApplyFailed"
)

// Plan is an Autopilot plan (autopilot.k0sproject.io/v1beta2): how k0s
// updates itself, node by node. Products may deliver their updates this way.
type Plan struct {
	Name     string
	Created  time.Time
	State    string
	Commands []PlanCommand
}

// PlanCommand is one step of a plan: an update to a k0s version, or an
// airgap bundle.
type PlanCommand struct {
	// Kind is "k0s update" or "airgap update".
	Kind        string
	Version     string
	State       string
	Description string
	Targets     []PlanTarget
}

// PlanTarget is one node of a command, and how far it got.
type PlanTarget struct {
	Name       string
	Controller bool
	State      string
	Updated    time.Time
}

// Running says whether the plan is still being carried out.
func (p *Plan) Running() bool {
	switch p.State {
	case "", PlanSchedulable, PlanSchedulableWait:
		return true
	}
	return false
}

// Version is the k0s version the plan updates to, when it says.
func (p *Plan) Version() string {
	for _, c := range p.Commands {
		if c.Version != "" {
			return c.Version
		}
	}
	return ""
}

// Targets lists every node of every command.
func (p *Plan) Targets() []PlanTarget {
	var out []PlanTarget
	for _, c := range p.Commands {
		out = append(out, c.Targets...)
	}
	return out
}

// UpdateRunning says whether an Autopilot plan is being carried out.
func (s *Snapshot) UpdateRunning() bool {
	if s.ControlPlane == nil {
		return false
	}
	for _, p := range s.ControlPlane.Plans {
		if p.Running() {
			return true
		}
	}
	return false
}

type planTargetsDoc struct {
	Controllers []planTargetStatusDoc `json:"controllers"`
	Workers     []planTargetStatusDoc `json:"workers"`
}

type planTargetStatusDoc struct {
	Name                 string      `json:"name"`
	State                string      `json:"state"`
	LastUpdatedTimestamp metav1.Time `json:"lastUpdatedTimestamp"`
}

type planDoc struct {
	Kind     string            `json:"kind"`
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		Commands []struct {
			K0sUpdate *struct {
				Version string `json:"version"`
			} `json:"k0supdate"`
			AirgapUpdate *struct {
				Version string `json:"version"`
			} `json:"airgapupdate"`
		} `json:"commands"`
	} `json:"spec"`
	Status struct {
		State    string `json:"state"`
		Commands []struct {
			ID           int             `json:"id"`
			State        string          `json:"state"`
			Description  string          `json:"description"`
			K0sUpdate    *planTargetsDoc `json:"k0supdate"`
			AirgapUpdate *planTargetsDoc `json:"airgapupdate"`
		} `json:"commands"`
	} `json:"status"`
}

// ParsePlans reads a PlanList, or a single Plan, as JSON.
func ParsePlans(data []byte) ([]*Plan, error) {
	var list struct {
		Kind  string    `json:"kind"`
		Items []planDoc `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if list.Kind == "Plan" {
		var one planDoc
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, err
		}
		list.Items = []planDoc{one}
	}
	var out []*Plan
	for _, it := range list.Items {
		p := &Plan{Name: it.Metadata.Name, Created: it.Metadata.CreationTimestamp.Time, State: it.Status.State}
		for i, c := range it.Spec.Commands {
			pc := PlanCommand{Kind: "k0s update"}
			switch {
			case c.K0sUpdate != nil:
				pc.Version = c.K0sUpdate.Version
			case c.AirgapUpdate != nil:
				pc.Kind, pc.Version = "airgap update", c.AirgapUpdate.Version
			}
			for _, st := range it.Status.Commands {
				if st.ID != i {
					continue
				}
				pc.State, pc.Description = st.State, st.Description
				for _, t := range []*planTargetsDoc{st.K0sUpdate, st.AirgapUpdate} {
					if t == nil {
						continue
					}
					for _, c := range t.Controllers {
						pc.Targets = append(pc.Targets, PlanTarget{Name: c.Name, Controller: true, State: c.State, Updated: c.LastUpdatedTimestamp.Time})
					}
					for _, w := range t.Workers {
						pc.Targets = append(pc.Targets, PlanTarget{Name: w.Name, State: w.State, Updated: w.LastUpdatedTimestamp.Time})
					}
				}
			}
			p.Commands = append(p.Commands, pc)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// PlanStateText says in words how far a plan got.
func PlanStateText(s string) string {
	switch s {
	case "":
		return "not started"
	case PlanSchedulable, PlanSchedulableWait:
		return "running"
	case PlanCompleted:
		return "completed"
	case PlanApplyFailed:
		return "failed"
	case PlanIncompleteTargets:
		return "nodes missing"
	case PlanWarning:
		return "refused"
	case PlanRestricted:
		return "not allowed"
	}
	return s
}

// TargetStateText says in words how far one node of a plan got.
func TargetStateText(s string) string {
	switch s {
	case SignalPending:
		return "waiting"
	case SignalSent:
		return "updating"
	case SignalCompleted:
		return "updated"
	case SignalMissingNode:
		return "not found"
	case SignalMissingPlatform:
		return "no download for its platform"
	case SignalApplyFailed:
		return "failed"
	}
	return s
}

// SignalDataAnnotation is where Autopilot keeps a node's part of an update,
// on its Node (workers) or ControlNode (controllers).
const SignalDataAnnotation = "k0sproject.io/autopilot-signal-data"

// UpdateSignal is a node's own view of an update: what it is doing, and
// where it downloads the new version from.
type UpdateSignal struct {
	Status string
	URL    string
}

// ParseUpdateSignal reads a node's signal annotation; ok is false without
// one.
func ParseUpdateSignal(annotations map[string]string) (UpdateSignal, bool) {
	raw, found := annotations[SignalDataAnnotation]
	if !found {
		return UpdateSignal{}, false
	}
	var doc struct {
		Command struct {
			K0sUpdate *struct {
				URL string `json:"url"`
			} `json:"k0supdate"`
			AirgapUpdate *struct {
				URL string `json:"url"`
			} `json:"airgapupdate"`
		} `json:"command"`
		Status struct {
			Status string `json:"status"`
		} `json:"status"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return UpdateSignal{}, false
	}
	sig := UpdateSignal{Status: doc.Status.Status}
	switch {
	case doc.Command.K0sUpdate != nil:
		sig.URL = doc.Command.K0sUpdate.URL
	case doc.Command.AirgapUpdate != nil:
		sig.URL = doc.Command.AirgapUpdate.URL
	}
	return sig, true
}

// UpdateSignalOf is a plan target's own view of the update: from its
// ControlNode for a controller, from its Node for a worker.
func (s *Snapshot) UpdateSignalOf(t PlanTarget) (UpdateSignal, bool) {
	if t.Controller {
		if c := s.ControlPlane.Controller(t.Name); c != nil && c.UpdateSignal != nil {
			return *c.UpdateSignal, true
		}
		return UpdateSignal{}, false
	}
	if n := s.Node(t.Name); n != nil {
		return ParseUpdateSignal(n.Annotations)
	}
	return UpdateSignal{}, false
}

// SignalStatusText says in words what a node is doing in an update.
func SignalStatusText(s string) string {
	switch s {
	case "Downloading":
		return "downloading the new version"
	case "FailedDownload":
		return "the download failed"
	case "Cordoning":
		return "moving its workloads away"
	case "ApplyingUpdate":
		return "installing the new version"
	case "Restart":
		return "restarting k0s"
	case "UnCordoning":
		return "taking workloads again"
	case "Completed":
		return "done"
	case "Failed":
		return "failed"
	}
	return s
}
