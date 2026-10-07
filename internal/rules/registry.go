// Package rules contains the detectors. Each rule reads a snapshot and
// returns findings; rules never talk to the cluster.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// Rule is one detector.
type Rule struct {
	// ID is the stable rule name, for example "pod.crashloop".
	ID string
	// Code is the short catalog code from the plan, for example "W01".
	Code     string
	Category findings.Category
	// Needs lists the resource kinds the rule reads. The rule is skipped
	// when one of them could not be collected.
	Needs []snapshot.Kind
	Eval  func(*Context) []*findings.Finding
}

// Context is what a rule gets to work with.
type Context struct {
	S *snapshot.Snapshot
	T config.Thresholds
}

// Skipped explains why a rule did not run.
type Skipped struct {
	RuleID string `json:"ruleId"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// All returns the rules shipped in this build, in catalog order.
func All() []Rule {
	return []Rule{
		crashLoopRule,
		oomKilledRule,
		imagePullRule,
		configErrorRule,
		runErrorRule,
		unschedulableRule,
		stuckCreatingRule,
		stuckTerminatingRule,
		notReadyRule,
		probeKillsRule,
		evictedRule,
		deploymentUnavailableRule,
		statefulSetUnavailableRule,
		daemonSetUnavailableRule,
		jobFailedRule,
		cronJobFailingRule,
		cronJobMissedRule,
		hpaMaxedRule,
		hpaNoMetricsRule,
		quotaExhaustedRule,
		containerNearLimitRule,
		nodeNotReadyRule,
		nodePressureRule,
		npdConditionRule,
		nodeNetworkUnavailableRule,
		nodeDiskRule,
		nodeInodesRule,
		nodeSaturationRule,
		nodeOvercommitRule,
		nodeCordonedLongRule,
		nodePodsNearMaxRule,
		cpuStealRule,
		ioWaitRule,
		clockSkewRule,
		serviceDownRule,
		kernelErrorsRule,
		rebootRule,
		swapRule,
		hostDiskRule,
		volumeUsageRule,
		volumeForecastRule,
		pvcPendingRule,
		pvReleasedRule,
		mountFailureRule,
		noDefaultClassRule,
		resizeStuckRule,
		serviceNoEndpointsRule,
		selectorMismatchRule,
		ingressBackendMissingRule,
		dnsUnhealthyRule,
		cniUnhealthyRule,
		konnectivityDownRule,
		kubeProxyUnhealthyRule,
		lbPendingRule,
		tlsCertExpiryRule,
		apiServerReadyRule,
		etcdHealthRule,
		controllersCountRule,
		certExpiryRule,
		updateStuckRule,
		versionDriftRule,
		webhookBlockingRule,
		apiServiceUnavailableRule,
		namespaceStuckRule,
		warningSpikeRule,
		endpointTLSNameRule,
		endpointFallbackRule,
		noLimitsRule,
		noProbesRule,
		latestTagRule,
		pdbBlocksDrainRule,
		privilegedRule,
		finishedPodsRule,
		k0sControlPlaneTargetsRule,
		chartFailedRule,
	}
}

// Evaluate runs every rule whose data is available.
func Evaluate(s *snapshot.Snapshot, t config.Thresholds) ([]*findings.Finding, []Skipped) {
	return EvaluateRules(All(), s, t)
}

// EvaluateRules runs the given rules.
func EvaluateRules(rs []Rule, s *snapshot.Snapshot, t config.Thresholds) ([]*findings.Finding, []Skipped) {
	ctx := &Context{S: s, T: t}
	var out []*findings.Finding
	var skipped []Skipped
	for _, r := range rs {
		var missing []string
		for _, k := range r.Needs {
			if !s.Has(k) {
				missing = append(missing, string(k))
			}
		}
		if len(missing) > 0 {
			reason := "cannot read " + strings.Join(missing, ", ")
			if len(missing) == 1 && missing[0] == string(snapshot.KindMetrics) {
				reason = "needs metrics from Prometheus, which are not available"
			}
			if len(missing) == 1 && missing[0] == string(snapshot.KindTLSSecret) {
				reason = "needs to read TLS Secrets, which the account may not or is turned off"
			}
			skipped = append(skipped, Skipped{RuleID: r.ID, Code: r.Code, Reason: reason})
			continue
		}
		for _, f := range r.Eval(ctx) {
			f.RuleID = r.ID
			if f.Category == "" {
				// The rule's, unless it chose another for this finding.
				f.Category = r.Category
			}
			f.ID = findings.Fingerprint(f.Cluster, f.RuleID, f.Resource)
			out = append(out, f)
		}
	}
	explainRollouts(ctx, out)
	for _, f := range out {
		f.UseK0sKubectl()
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, skipped
}

// newFinding starts a finding. Evaluate fills in the rule ID, the category
// and the fingerprint.
func (c *Context) newFinding(sev findings.Severity, res findings.ObjectRef) *findings.Finding {
	return findings.New(c.S.Cluster, "", "", sev, res)
}

func workloadRef(w snapshot.Workload) findings.ObjectRef {
	return findings.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
}

// k0sManaged are the kube-system components k0s deploys and keeps in
// place itself: changing them by hand (for example a rollout undo) is
// undone by k0s, so fixes go through k0s or a product update.
var k0sManaged = map[string]bool{
	"coredns": true, "metrics-server": true, "kube-router": true, "calico-node": true,
	"calico-kube-controllers": true, "konnectivity-agent": true, "kube-proxy": true,
}

func isK0sManaged(w snapshot.Workload) bool {
	return w.Namespace == "kube-system" && k0sManaged[w.Name]
}

// kubectlTarget is how kubectl names a workload, for example "deploy/api".
func kubectlTarget(w snapshot.Workload) string {
	switch w.Kind {
	case "Deployment":
		return "deploy/" + w.Name
	case "StatefulSet":
		return "sts/" + w.Name
	case "DaemonSet":
		return "ds/" + w.Name
	case "ReplicaSet":
		return "rs/" + w.Name
	case "CronJob":
		return "cronjob/" + w.Name
	case "Job":
		return "job/" + w.Name
	}
	return "pod/" + w.Name
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
