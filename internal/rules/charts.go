package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// C07 k0s.chart-failed

var chartFailedRule = Rule{
	ID: "k0s.chart-failed", Code: "C07", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane},
	Eval:  evalChartFailed,
}

// chartCause explains one way k0s fails to install a Helm add-on, by the
// error k0s reports in the Chart's status.
type chartCause struct {
	kind  string
	match *regexp.Regexp
	// short completes "k0s couldn't install it: …".
	short string
	// cause and plain explain it; %[1]s is the repository, %[2]s the chart,
	// %[3]s its version, %[4]s the namespace it installs into.
	cause, plain string
	// todo is what to do, in Basic mode; %[1]s is the repository's host.
	todo string
}

// fill puts the arguments into a text that has %[n]s places, and leaves
// other texts alone.
func fill(text string, args ...any) string {
	if !strings.Contains(text, "%[") {
		return text
	}
	return fmt.Sprintf(text, args...)
}

// chartCauses are tried in order.
var chartCauses = []chartCause{
	{
		kind:  "stuck",
		match: regexp.MustCompile(`(?i)another operation .*in progress|pending-(install|upgrade|rollback)`),
		short: "a previous install or update of it is stuck",
		cause: "Helm left the release in a pending state after an install or update was interrupted, for example when a controller restarted. k0s retries, and Helm refuses while that state remains.",
		plain: "an earlier attempt to install it was interrupted and left it half done",
		todo:  "Send the report to your support team: the half-done installation must be cleaned up.",
	},
	{
		kind:  "repository",
		match: regexp.MustCompile(`(?i)not a valid chart repository|cannot be reached|no such host|i/o timeout|connection refused|network is unreachable|x509|certificate signed by unknown|tls: |can't add repository|failed to fetch .*index\.yaml`),
		short: "its chart repository can't be reached",
		cause: "The controllers download the chart from its repository (%[1]s) and couldn't reach it. In a network without internet access, the controllers need a proxy, or the repository must be one they can reach; a certificate error means the controllers don't trust the repository's certificate.",
		plain: "the servers can't download it from %[1]s",
		todo:  "Check with your network team that the cluster's control servers can reach %[1]s, or send the report to your support team.",
	},
	{
		kind:  "version",
		match: regexp.MustCompile(`(?i)no chart version found|no chart name found|chart ".*" (version ".*" )?not found|failed to download|404 not found`),
		short: "the chart or its version isn't in the repository",
		cause: "The repository doesn't have chart %[2]s in version %[3]s: the version was removed from the repository, or the name or version is mistyped in the k0s configuration.",
		plain: "the version it asks for isn't available",
		todo:  "Send the report to your support team: the product's configuration asks for a version that isn't available.",
	},
	{
		kind:  "conflict",
		match: regexp.MustCompile(`(?i)already exists|invalid ownership metadata|cannot be imported into the current release`),
		short: "objects it would create already exist",
		cause: "Objects the chart creates already exist in the cluster and belong to something else, for example an earlier installation made by hand: Helm won't take them over.",
		plain: "parts of it were already installed some other way",
		todo:  "Send the report to your support team: the earlier installation must be removed first.",
	},
	{
		kind:  "values",
		match: regexp.MustCompile(`(?i)yaml|template:|execution error|values don't meet|schema|unknown field|parse error`),
		short: "its values don't fit the chart",
		cause: "The chart rejected the values of the k0s configuration, often after its version changed and the values didn't.",
		plain: "its settings don't fit the version being installed",
		todo:  "Send the report to your support team: the add-on's settings must be corrected.",
	},
	{
		kind:  "timeout",
		match: regexp.MustCompile(`(?i)timed out|context deadline exceeded|timeout`),
		short: "it didn't become ready in time",
		cause: "Helm waited for the chart's pods and they didn't become ready before the timeout. Why they aren't ready shows in the namespace %[4]s, usually as its own problems.",
		plain: "its parts didn't start in time",
		todo:  "Look at the other problems with the cluster first: they usually say why it didn't start.",
	},
}

var defaultChartCause = chartCause{
	kind:  "other",
	short: "k0s couldn't install it",
	cause: "k0s's Helm controller reported the error above. It retries regularly.",
	plain: "the installation failed",
	todo:  "Send the report to your support team.",
}

func evalChartFailed(c *Context) []*findings.Finding {
	cp := c.S.ControlPlane
	if cp == nil {
		return nil
	}
	var out []*findings.Finding
	for _, ch := range cp.Charts {
		if !ch.Failed() || ch.Deleting {
			continue
		}
		cause := defaultChartCause
		for _, k := range chartCauses {
			if k.match.MatchString(ch.Error) {
				cause = k
				break
			}
		}
		repo := ch.Repository
		if repo == "" {
			repo = "its repository"
		}
		repoHost := repo
		if u, err := url.Parse(ch.Repository); err == nil && u.Host != "" {
			repoHost = u.Host
		}
		todo := fill(cause.todo, repoHost)

		sev := findings.High
		if ch.Installed != "" {
			sev = findings.Medium // the installed version keeps running
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Chart", Namespace: ch.Namespace, Name: ch.Name})
		f.System = true
		name := ch.Addon()
		f.Title = fmt.Sprintf("Add-on %s: %s", name, cause.short)
		if ch.Installed != "" {
			f.Summary = fmt.Sprintf("k0s couldn't update its Helm add-on %s (chart %s) to version %s: %s. Version %s stays installed.", name, ch.ChartName, ch.Version, cause.short, ch.Installed)
		} else {
			f.Summary = fmt.Sprintf("k0s couldn't install its Helm add-on %s (chart %s %s): %s. What it provides is missing from the cluster.", name, ch.ChartName, ch.Version, cause.short)
		}
		f.AddFact("Error", truncate(ch.Error, 400))
		f.AddFact("Chart", strings.TrimSpace(ch.ChartName+" "+ch.Version))
		f.AddFact("Repository", ch.Repository)
		f.AddFact("Installs into", ch.TargetNamespace)
		if ch.Installed != "" {
			f.AddFact("Installed", fmt.Sprintf("%s (revision %d)", ch.Installed, ch.Revision))
		} else {
			f.AddFact("Installed", "no")
		}
		if !ch.Updated.IsZero() {
			f.AddFact("Last attempt", ago(c.S.Now.Sub(ch.Updated))+" ago")
		}
		f.Remedy.LikelyCause = fill(cause.cause, repo, ch.ChartName, ch.Version, ch.TargetNamespace)

		f.AddStep(findings.Step{
			Text:    "See the add-on's state as k0s reports it",
			Command: fmt.Sprintf("kubectl -n %s get chart %s -o jsonpath='{.status}{\"\\n\"}'", ch.Namespace, ch.Name),
		})
		switch cause.kind {
		case "stuck":
			f.AddStep(findings.Step{
				Text:    "See the release's history: the last one is pending. With Helm, roll back to the last good revision (or, if it was never installed, uninstall it); k0s then installs it again",
				Command: fmt.Sprintf("kubectl -n %s get secrets -l owner=helm,name=%s\nhelm -n %s history %s\nhelm -n %s rollback %s", ch.TargetNamespace, ch.Release, ch.TargetNamespace, ch.Release, ch.TargetNamespace, ch.Release),
			})
		case "repository":
			f.AddStep(findings.Step{
				Text:    "Check that the controller reaches the repository, and through which proxy k0s goes",
				Command: fmt.Sprintf("curl -sSI %s/index.yaml | head -n 1\nsudo systemctl show k0scontroller -p Environment", strings.TrimSuffix(ch.Repository, "/")),
				Host:    "a controller",
			})
		case "timeout":
			f.AddStep(findings.Step{
				Text:    "See the add-on's pods, and why they aren't ready",
				Command: fmt.Sprintf("kubectl -n %s get pods\nkubectl -n %s get events --sort-by=.lastTimestamp | tail -n 20", ch.TargetNamespace, ch.TargetNamespace),
			})
		}
		f.AddStep(findings.Step{
			Text:    "See what k0s logged about it (the controller that leads installs add-ons)",
			Command: fmt.Sprintf("sudo journalctl -u k0scontroller --since '1 hour ago' --no-pager | grep -i 'chart=.*%s' | tail -n 20", ch.Name),
			Host:    "each controller",
		})
		f.AddStep(findings.Step{
			Text:  "The add-on's chart, version and values are part of the k0s configuration (spec.extensions.helm): when they must change, that comes with a product update",
			Plain: todo,
		})

		plainWhat := fill(cause.plain, repoHost)
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The add-on %s couldn't be installed", name),
			WhatHappened: fmt.Sprintf("k0s installs %s with the cluster, and it failed: %s.", name, plainWhat),
			Why:          "Whatever it provides is missing from the cluster.",
			WhatToDo:     todo,
		}
		if ch.Installed != "" {
			f.Plain.Title = fmt.Sprintf("The add-on %s couldn't be updated", name)
			f.Plain.WhatHappened = fmt.Sprintf("k0s tried to update %s, and it failed: %s.", name, plainWhat)
			f.Plain.Why = "The previous version keeps running, so nothing is broken yet."
		}
		out = append(out, f)
	}
	return out
}
