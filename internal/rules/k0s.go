package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// Control plane health from asking each controller (plan section 7.6).
// Controllers run as host processes, so the fix steps run on the
// controller host: k0s's unit there is k0scontroller.

// failingGrace keeps a controller that is starting or restarting from
// being reported: its checks fail for a few seconds while it starts.
const failingGrace = time.Minute

// staleLease is how long a stopped controller counts as down before it is
// more likely removed: k0s keeps a removed controller's lease.
const staleLease = 7 * 24 * time.Hour

func controllerRef(c *snapshot.Controller) findings.ObjectRef {
	return findings.ObjectRef{Kind: "Controller", Name: c.Label()}
}

// settled says whether a controller's failure has lasted past the grace.
func settled(c *Context, ctl *snapshot.Controller) bool {
	return ctl.FailingSince.IsZero() || c.S.Now.Sub(ctl.FailingSince) >= failingGrace
}

func checkList(cs []snapshot.Check) string {
	var out []string
	for _, ch := range cs {
		s := ch.Name
		if ch.Message != "" && ch.Message != "reason withheld" {
			s += " (" + ch.Message + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// hostSteps are the usual first steps on a controller host.
func hostSteps(f *findings.Finding, host string) {
	f.AddStep(findings.Step{Text: "See k0s's own view on the controller", Plain: "On the controller, see what k0s says about itself",
		Command: "sudo k0s status\nsudo k0s kubectl get --raw '/readyz?verbose'", Host: host})
	f.AddStep(findings.Step{Text: "Read the controller's recent errors", Plain: "Read its recent errors",
		Command: "sudo journalctl -u k0scontroller -n 200 --no-pager | grep -iE 'error|fail'", Host: host})
}

// ---------------------------------------------------------------------------
// C01 apiserver.readyz

var apiServerReadyRule = Rule{
	ID: "apiserver.readyz", Code: "C01", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane},
	Eval:  evalAPIServerReady,
}

// notEtcd leaves out the etcd checks: C02 reports those.
func notEtcd(cs []snapshot.Check) []snapshot.Check {
	var out []snapshot.Check
	for _, ch := range cs {
		if !strings.HasPrefix(ch.Name, "etcd") {
			out = append(out, ch)
		}
	}
	return out
}

func evalAPIServerReady(c *Context) []*findings.Finding {
	cp := c.S.ControlPlane
	if cp == nil {
		return nil
	}
	reached, bad := 0, 0
	for _, ctl := range cp.Controllers {
		if ctl.Reached {
			reached++
			if len(notEtcd(ctl.Failing)) > 0 || len(notEtcd(ctl.LiveFailing)) > 0 {
				bad++
			}
		}
	}
	var out []*findings.Finding
	for _, ctl := range cp.Controllers {
		failing, live := notEtcd(ctl.Failing), notEtcd(ctl.LiveFailing)
		if !ctl.Reached || (len(failing) == 0 && len(live) == 0) || !settled(c, ctl) {
			continue
		}
		sev := findings.High
		all := bad == reached
		if all {
			sev = findings.Critical
		}
		f := c.newFinding(sev, controllerRef(ctl))
		f.System = true
		f.Impact.ClusterWide = all
		if !ctl.FailingSince.IsZero() {
			since := ctl.FailingSince
			f.Since = &since
		}
		if ctl.Name != "" {
			f.Links.Nodes = []string{ctl.Name}
		}
		f.AddFact("Controller", ctl.Label()+" ("+ctl.Address+")")
		f.AddFact("readyz failing", checkList(failing))
		f.AddFact("livez failing", checkList(live))
		f.AddFact("Controllers answering", fmt.Sprintf("%d of %d are ready", reached-bad, reached))
		f.AddFact("Version", ctl.Version)
		names := strings.Join(snapshotNames(failing, live), ", ")
		f.Title = fmt.Sprintf("API server on %s not ready: %s", ctl.Label(), names)
		scope := "Requests that reach this controller may fail; the other controllers serve the rest."
		if all {
			scope = "No controller is fully ready: changes to the cluster may fail."
		}
		f.Summary = fmt.Sprintf("The API server on controller %s fails its health checks (%s). %s", ctl.Label(), names, scope)
		f.Remedy.LikelyCause = readyzCause(failing, live)
		hostSteps(f, ctl.Label())
		f.AddStep(findings.Step{Text: "If it stays unhealthy, restart k0s on that controller (one controller at a time)", Plain: "If it doesn't recover, restart k0s on that controller",
			Command: "sudo systemctl restart k0scontroller", Host: ctl.Label()})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The control plane on %s isn't healthy", ctl.Label()),
			WhatHappened: fmt.Sprintf("The cluster's API on %s reports that some of its parts (%s) don't work.", ctl.Label(), names),
			Why:          plainScope(all),
			WhatToDo:     "It often recovers by itself within a minute. If it doesn't, restart k0s on that server (steps below), or send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

func snapshotNames(lists ...[]snapshot.Check) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, ch := range l {
			if !seen[ch.Name] {
				seen[ch.Name] = true
				out = append(out, ch.Name)
			}
		}
	}
	return out
}

func plainScope(all bool) string {
	if all {
		return "No server of the cluster's control plane is fully working, so changes to the cluster may fail."
	}
	return "The other control plane servers still work, so the cluster keeps running."
}

// readyzCause explains the usual failing checks.
func readyzCause(failing, live []snapshot.Check) string {
	for _, ch := range append(append([]snapshot.Check{}, failing...), live...) {
		switch {
		case ch.Name == "shutdown":
			return "The API server is shutting down, for example because k0s on the controller is stopping or restarting."
		case strings.HasPrefix(ch.Name, "poststarthook/"), strings.HasPrefix(ch.Name, "informer-sync"):
			return "The API server hasn't finished starting. If it stays like this, it can't finish a startup step; the controller's log says which."
		case strings.HasPrefix(ch.Name, "kms-providers"):
			return "The API server can't reach its encryption provider."
		}
	}
	return "A part of the API server fails; the controller's log says why."
}

// ---------------------------------------------------------------------------
// C02 etcd.health

var etcdHealthRule = Rule{
	ID: "etcd.health", Code: "C02", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane},
	Eval:  evalEtcdHealth,
}

func evalEtcdHealth(c *Context) []*findings.Finding {
	cp := c.S.ControlPlane
	if cp == nil {
		return nil
	}
	var out []*findings.Finding
	reached, bad := 0, 0
	for _, ctl := range cp.Controllers {
		if ctl.Reached {
			reached++
			if ctl.EtcdFailing() {
				bad++
			}
		}
	}
	for _, ctl := range cp.Controllers {
		if !ctl.Reached || !ctl.EtcdFailing() || !settled(c, ctl) {
			continue
		}
		all := bad == reached
		sev := findings.High
		if all {
			sev = findings.Critical
		}
		var etcd []snapshot.Check
		for _, ch := range ctl.Failing {
			if strings.HasPrefix(ch.Name, "etcd") {
				etcd = append(etcd, ch)
			}
		}
		f := c.newFinding(sev, controllerRef(ctl))
		f.System = true
		f.Impact.ClusterWide = all
		if !ctl.FailingSince.IsZero() {
			since := ctl.FailingSince
			f.Since = &since
		}
		f.AddFact("Controller", ctl.Label()+" ("+ctl.Address+")")
		f.AddFact("Failing checks", checkList(etcd))
		f.AddFact("Controllers with etcd", fmt.Sprintf("%d of %d answer", reached-bad, reached))
		f.Title = fmt.Sprintf("etcd not ready for the API server on %s", ctl.Label())
		f.Summary = fmt.Sprintf("The API server on %s can't use etcd, the cluster's database (%s).", ctl.Label(), checkList(etcd))
		if all {
			f.Summary += " No controller can: the cluster can't store changes."
		}
		f.Remedy.LikelyCause = "The local etcd member is down or can't reach the others, often because too few controllers run (etcd needs a majority), a disk is full or slow, or the clocks differ."
		f.AddStep(findings.Step{Text: "See the etcd members from a running controller", Plain: "See the database's members",
			Command: "sudo k0s etcd member-list", Host: ctl.Label()})
		f.AddStep(findings.Step{Text: "Read etcd's errors in the controller's log", Plain: "Read the database's errors",
			Command: "sudo journalctl -u k0scontroller -n 300 --no-pager | grep -i etcd | grep -iE 'error|fail|timeout'", Host: ctl.Label()})
		f.AddStep(findings.Step{Text: "Check the disk that holds the database", Plain: "Check the disk space on that server",
			Command: "df -h /var/lib/k0s/etcd", Host: ctl.Label()})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The cluster's database doesn't answer on %s", ctl.Label()),
			WhatHappened: "The cluster keeps everything in a database (etcd), and its copy on this server doesn't work.",
			Why:          plainScope(all),
			WhatToDo:     "Check that all control plane servers run and have free disk space (steps below). Send the report to your support team if it doesn't recover.",
		}
		out = append(out, f)
	}
	if f := etcdSize(c, cp); f != nil {
		out = append(out, f)
	}
	return out
}

func etcdSize(c *Context, cp *snapshot.ControlPlane) *findings.Finding {
	if !snapshot.Known(cp.EtcdDBBytes) || cp.EtcdQuotaBytes <= 0 {
		return nil
	}
	share := cp.EtcdDBBytes / cp.EtcdQuotaBytes * 100
	l := c.T.EtcdQuotaPercent
	var sev findings.Severity
	switch {
	case l.Critical > 0 && share >= l.Critical:
		sev = findings.Critical
	case l.High > 0 && share >= l.High:
		sev = findings.High
	case l.Warn > 0 && share >= l.Warn:
		sev = findings.Medium
	default:
		return nil
	}
	f := c.newFinding(sev, findings.ObjectRef{Kind: "Etcd", Name: "database"})
	f.System = true
	f.Impact.ClusterWide = true
	f.AddFact("Size", fmt.Sprintf("%s of %s (%.0f%%)", bytesIEC(cp.EtcdDBBytes), bytesIEC(cp.EtcdQuotaBytes), share))
	if cp.EtcdQuotaBytes == snapshot.DefaultEtcdQuota {
		f.AddFact("Quota", "etcd's default of 2 GiB (k0s keeps it unless its configuration sets quota-backend-bytes)")
	}
	var top []string
	for i, o := range cp.Objects {
		if i == 5 {
			break
		}
		top = append(top, fmt.Sprintf("%s %.0f", o.Resource, o.Count))
	}
	f.AddFact("Most objects", strings.Join(top, ", "))
	f.Title = fmt.Sprintf("etcd database %.0f%% of its quota (%s of %s)", share, bytesIEC(cp.EtcdDBBytes), bytesIEC(cp.EtcdQuotaBytes))
	f.Summary = "When the etcd database reaches its quota, etcd refuses writes: nothing in the cluster can be created or changed until space is freed and the database defragmented."
	f.Remedy.LikelyCause = "Many objects of one kind, for example events, old ReplicaSets, or ConfigMaps and Secrets kept for every Helm release."
	if len(cp.Objects) > 0 {
		f.Remedy.LikelyCause = fmt.Sprintf("%s has the most objects (%.0f).", cp.Objects[0].Resource, cp.Objects[0].Count)
	}
	f.AddStep(findings.Step{Text: "See which resources hold the most objects", Plain: "See what fills the database",
		Command: "kubectl get --raw /metrics | grep -E '^apiserver_(storage|resource)_objects' | sort -k2 -n | tail -n 10"})
	f.AddStep(findings.Step{Text: "Delete what isn't needed (old ReplicaSets: lower revisionHistoryLimit; Helm releases: fewer kept revisions). The file only shrinks after a defragmentation, which support can do.",
		Plain: "Remove what isn't needed; support can then shrink the database"})
	f.Plain = findings.PlainText{
		Title:        fmt.Sprintf("The cluster's database is %.0f%% full", share),
		WhatHappened: fmt.Sprintf("The cluster's database (etcd) uses %s of the %s it may use.", bytesPlain(cp.EtcdDBBytes), bytesPlain(cp.EtcdQuotaBytes)),
		Why:          "When it is full, nothing in the cluster can be created or changed.",
		WhatToDo:     "Send the report to your support team: they can see what fills it and shrink it.",
	}
	return f
}

// ---------------------------------------------------------------------------
// C03 controllers.count

var controllersCountRule = Rule{
	ID: "controllers.count", Code: "C03", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindLease},
	Eval:  evalControllersCount,
}

func evalControllersCount(c *Context) []*findings.Finding {
	leases := c.S.ControllerLeases()
	if len(leases) == 0 {
		return nil // one controller that can't be joined: k0s keeps no leases
	}
	alive, expected := 0, 0
	for _, l := range leases {
		if l.Alive {
			alive++
		}
		if l.Alive || c.S.Now.Sub(l.Renewed) < staleLease {
			expected++
		}
	}
	var out []*findings.Finding
	for _, l := range leases {
		if l.Alive || l.Renewed.IsZero() || c.S.Now.Sub(l.Renewed) < failingGrace {
			continue
		}
		down := c.S.Now.Sub(l.Renewed)
		stale := down >= staleLease
		sev := findings.High
		if stale {
			sev = findings.Low
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Controller", Name: l.Name})
		f.System = true
		f.Impact.ClusterWide = !stale
		since := l.Renewed
		f.Since = &since
		f.Links.Nodes = []string{l.Name}
		f.AddFact("Last seen", ago(down)+" ago (its lease k0s-ctrl-"+l.Name+" in kube-node-lease)")
		f.AddFact("Controllers running", fmt.Sprintf("%d of %d", alive, expected))
		if ctl := c.S.ControlPlane.Controller(l.Name); ctl != nil && ctl.Error != "" {
			f.AddFact("Asking it directly", ctl.Error)
		}
		quorum := ""
		if !stale && expected >= 3 && alive*2 <= expected {
			quorum = " etcd needs more than half of the controllers: with this few, the cluster can't store changes."
		}
		if stale {
			f.Title = fmt.Sprintf("Controller %s stopped %s ago", l.Name, ago(down))
			f.Summary = fmt.Sprintf("Controller %s hasn't run for %s. If it was removed on purpose, its lease is left over and can be deleted; otherwise it is still down.", l.Name, ago(down))
			f.Remedy.LikelyCause = "k0s keeps the lease of a controller that was removed from the cluster."
			f.AddStep(findings.Step{Text: "If the controller was removed, delete its left-over lease", Plain: "If that server was removed on purpose, clean up after it",
				Command: fmt.Sprintf("kubectl -n kube-node-lease delete lease k0s-ctrl-%s", l.Name)})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The control plane server %s has been off for %s", l.Name, agoPlain(down)),
				WhatHappened: fmt.Sprintf("%s used to be one of the cluster's control plane servers and hasn't run for %s.", l.Name, agoPlain(down)),
				Why:          "Either it was removed on purpose and left a note behind, or it is still down.",
				WhatToDo:     "If it was removed on purpose, clean up (step below). Otherwise start it again.",
			}
		} else {
			f.Title = fmt.Sprintf("Controller %s not running (%d of %d controllers run)", l.Name, alive, expected)
			f.Summary = fmt.Sprintf("Controller %s stopped renewing its lease %s ago, so k0s counts it as down: %d of %d controllers run.%s", l.Name, ago(down), alive, expected, quorum)
			f.Remedy.LikelyCause = "k0s on that controller stopped or crashed, or the host is down or cut off from the other controllers."
			f.AddStep(findings.Step{Text: "Check whether k0s runs on the controller", Plain: "On that server, check whether k0s runs",
				Command: "sudo systemctl status k0scontroller --no-pager\nsudo k0s status", Host: l.Name})
			f.AddStep(findings.Step{Text: "Read why it stopped", Plain: "Read why it stopped",
				Command: "sudo journalctl -u k0scontroller -n 200 --no-pager", Host: l.Name})
			f.AddStep(findings.Step{Text: "Start it again", Plain: "Start it again",
				Command: "sudo systemctl start k0scontroller", Host: l.Name})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The control plane server %s is down", l.Name),
				WhatHappened: fmt.Sprintf("%d of the cluster's %d control plane servers run; %s stopped %s ago.", alive, expected, l.Name, agoPlain(down)),
				Why:          "The others keep the cluster working, but it can't lose another one without trouble." + quorum,
				WhatToDo:     "Start k0s on that server again (steps below), or send the report to your support team.",
			}
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// C04 cert.expiry

var certExpiryRule = Rule{
	ID: "cert.expiry", Code: "C04", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane},
	Eval:  evalCertExpiry,
}

func certSeverity(c *Context, left time.Duration) (findings.Severity, bool) {
	l := c.T.CertExpiresWithin
	switch {
	case left <= 0 || (l.Critical > 0 && left <= l.Critical.D()):
		return findings.Critical, true
	case l.High > 0 && left <= l.High.D():
		return findings.High, true
	case l.Warn > 0 && left <= l.Warn.D():
		return findings.Medium, true
	}
	return findings.Info, false
}

func whenPlain(left time.Duration) string {
	if left <= 0 {
		return "has expired"
	}
	return "expires in " + agoPlain(left)
}

func evalCertExpiry(c *Context) []*findings.Finding {
	cp := c.S.ControlPlane
	if cp == nil {
		return nil
	}
	var out []*findings.Finding
	for _, ctl := range cp.Controllers {
		if ctl.Cert == nil {
			continue
		}
		left := ctl.Cert.NotAfter.Sub(c.S.Now)
		sev, ok := certSeverity(c, left)
		if !ok {
			continue
		}
		f := c.newFinding(sev, controllerRef(ctl))
		f.System = true
		f.Impact.ClusterWide = true
		breach := max(left, time.Minute)
		f.Impact.BreachIn = breach
		f.AddFact("Certificate", "the API server's serving certificate on "+ctl.Label()+" ("+ctl.Address+")")
		f.AddFact("Valid until", ctl.Cert.NotAfter.UTC().Format("2006-01-02 15:04 UTC"))
		when := "expires in " + ago(left)
		if left <= 0 {
			when = "expired " + ago(-left) + " ago"
		}
		f.Title = fmt.Sprintf("API server certificate on %s %s", ctl.Label(), when)
		f.Summary = fmt.Sprintf("The API server certificate of controller %s %s. After that, clients refuse to connect to it: k0s kubectl, the nodes and k0s-monitor.", ctl.Label(), when)
		f.Remedy.LikelyCause = "k0s's certificates last a year by default, and the controller hasn't restarted since this one was made. k0s makes new certificates each time the controller starts."
		f.AddStep(findings.Step{Text: "See the certificate's end date on the controller", Plain: "On that server, see when the certificate ends",
			Command: "sudo openssl x509 -noout -enddate -in /var/lib/k0s/pki/server.crt", Host: ctl.Label()})
		f.AddStep(findings.Step{Text: "Restart k0s on the controller: it makes new certificates as it starts. With several controllers, restart one at a time.",
			Plain: "Restart k0s on that server: it renews its certificates as it starts", Command: "sudo systemctl restart k0scontroller", Host: ctl.Label()})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("A security certificate on %s %s", ctl.Label(), whenPlain(left)),
			WhatHappened: fmt.Sprintf("The certificate that proves the identity of the cluster's API on %s %s.", ctl.Label(), whenPlain(left)),
			Why:          "Without a valid certificate, the servers and tools can't talk to the cluster any more.",
			WhatToDo:     "Restart k0s on that server before then (steps below): it renews its certificates as it starts.",
		}
		out = append(out, f)
	}
	if cp.ClientCertNotAfter != nil {
		left := cp.ClientCertNotAfter.Sub(c.S.Now)
		if sev, ok := certSeverity(c, left); ok {
			f := c.newFinding(sev, findings.ObjectRef{Kind: "Kubeconfig", Name: "k0s-monitor"})
			f.System = true
			f.Impact.BreachIn = max(left, time.Minute)
			f.AddFact("Certificate", "the client certificate in the kubeconfig k0s-monitor uses for this cluster")
			f.AddFact("Valid until", cp.ClientCertNotAfter.UTC().Format("2006-01-02 15:04 UTC"))
			f.Title = fmt.Sprintf("k0s-monitor's client certificate for this cluster %s", strings.Replace(whenPlain(left), "expires in", "expires in about", 1))
			f.Summary = "k0s-monitor signs in to this cluster with the client certificate of the kubeconfig it was given. When it expires, k0s-monitor can't read the cluster any more."
			f.Remedy.LikelyCause = "Kubeconfigs made by k0s carry a certificate that lasts a year."
			f.AddStep(findings.Step{Text: "Add the cluster again and let k0s-monitor create its read-only account: it signs in with a token that doesn't expire. Or upload a new kubeconfig:",
				Plain:   "Add the cluster again with a new kubeconfig, or let k0s-monitor create its own read-only account",
				Command: "sudo k0s kubeconfig admin > cluster.config", Host: "a controller"})
			f.Plain = findings.PlainText{
				Title:        "k0s-monitor's access to this cluster " + whenPlain(left),
				WhatHappened: "The certificate k0s-monitor signs in with " + whenPlain(left) + ".",
				Why:          "After that, k0s-monitor can't watch this cluster.",
				WhatToDo:     "Add the cluster again and keep \"Create a read-only account\" selected: that access doesn't expire.",
			}
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// F02 endpoint.tls-name

var endpointTLSNameRule = Rule{
	ID: "endpoint.tls-name", Code: "F02", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane},
	Eval:  evalEndpointTLSName,
}

func evalEndpointTLSName(c *Context) []*findings.Finding {
	cp := c.S.ControlPlane
	// With one controller's own address, requests never reach the others
	// through it; with a shared address (a load balancer, a DNS name),
	// they do.
	if cp == nil || cp.Server == "" || cp.ServerIsController() {
		return nil
	}
	var out []*findings.Finding
	for _, ctl := range cp.Controllers {
		if ctl.Cert == nil || ctl.Cert.CoversServer {
			continue
		}
		f := c.newFinding(findings.Medium, controllerRef(ctl))
		f.System = true
		names := append([]string{}, ctl.Cert.Names...)
		sort.Strings(names)
		f.AddFact("Address clients use", cp.Server)
		f.AddFact("Names in its certificate", strings.Join(names, ", "))
		f.Title = fmt.Sprintf("Certificate on %s doesn't include %s", ctl.Label(), cp.Server)
		f.Summary = fmt.Sprintf("Clients reach the cluster at %s, but the API server certificate on %s isn't valid for that address. Requests that land on this controller, for example through a load balancer, fail with an x509 certificate error.", cp.Server, ctl.Label())
		f.Remedy.LikelyCause = fmt.Sprintf("The address %s isn't in spec.api.sans (or spec.api.externalAddress) of the k0s configuration on %s.", cp.Server, ctl.Label())
		f.AddStep(findings.Step{Text: "See the names its certificate is valid for", Plain: "See which addresses its certificate covers",
			Command: fmt.Sprintf("openssl s_client -connect %s </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName", ctl.Address)})
		f.AddStep(findings.Step{Text: fmt.Sprintf("Add %s to spec.api.sans in the k0s configuration, then restart k0s on the controller so it makes a new certificate. The k0s configuration comes with your product, so this is a product update.", cp.Server),
			Plain: "The address must be added to the cluster's configuration, which comes with your product: send the report to your support team"})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The certificate on %s doesn't match the cluster's address", ctl.Label()),
			WhatHappened: fmt.Sprintf("Tools reach the cluster at %s, but the certificate of %s doesn't include that address.", cp.Server, ctl.Label()),
			Why:          "Requests that end up on that server are refused as insecure.",
			WhatToDo:     "Send the report to your support team: the address must be added to the cluster's configuration.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// F03 endpoint.fallback

var endpointFallbackRule = Rule{
	ID: "endpoint.fallback", Code: "F03", Category: findings.ControlPlane,
	Eval: evalEndpointFallback,
}

// evalEndpointFallback reports that k0s-monitor reads the cluster through
// another controller because the kubeconfig's server doesn't answer. When
// that server is one controller's own address, the controller's own
// problem (C01, C03) says what is wrong and this is only a note; when it is
// a shared address, nothing else reports that everyone using it is cut off.
func evalEndpointFallback(c *Context) []*findings.Finding {
	fb := c.S.Fallback
	if fb == nil {
		return nil
	}
	cp := c.S.ControlPlane
	isController := fb.ServerIsController || cp.ServerIsController()
	via := fb.Controller
	if via != fb.Address {
		via += " (" + fb.Address + ")"
	}
	host := fb.Server
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.HasSuffix(host, "]") {
		host = strings.Trim(host[:i], "[]")
	}
	why := "."
	if e := strings.TrimSpace(fb.Error); e != "" {
		why = ": " + strings.TrimSuffix(e, ".") + "."
	}
	sev := findings.High
	if isController {
		sev = findings.Low
	}
	f := c.newFinding(sev, findings.ObjectRef{Kind: "Endpoint", Name: fb.Server})
	f.System = true
	f.Impact.ClusterWide = !isController
	since := fb.Since
	f.Since = &since
	f.AddFact("Kubeconfig's server", fb.Server)
	f.AddFact("Why it isn't used", fb.Error)
	f.AddFact("Used instead", via)
	f.AddFact("Going back", "as soon as "+fb.Server+" answers again for a minute")
	if isController {
		f.Title = fmt.Sprintf("Kubeconfig's controller %s doesn't answer; k0s-monitor uses %s", fb.Server, fb.Controller)
		f.Summary = fmt.Sprintf("The kubeconfig's server %s is one controller's own address, and it doesn't answer%s k0s-monitor reads the cluster through %s meanwhile. Tools that use %s can't reach the cluster until it is back.", fb.Server, why, via, fb.Server)
		f.Remedy.LikelyCause = "k0s on that controller is stopped, or its host is down; the controller's own problem says more."
		f.AddStep(findings.Step{Text: "Check k0s on that controller", Plain: "On that server, check whether k0s runs",
			Command: "sudo systemctl status k0scontroller --no-pager\nsudo k0s status", Host: host})
		f.AddStep(findings.Step{Text: "If that controller was removed for good, add the cluster again with a kubeconfig that uses another controller's address, or better a load balancer's:",
			Plain: "If that server was removed on purpose, add the cluster again with a new cluster.config", Command: "sudo k0s kubeconfig admin > cluster.config", Host: "a running controller"})
		f.Plain = findings.PlainText{
			Title:        "k0s-monitor switched to another control plane server",
			WhatHappened: fmt.Sprintf("The server named in the cluster's configuration file (%s) doesn't answer, so k0s-monitor watches the cluster through %s instead.", host, fb.Controller),
			Why:          "Monitoring goes on as before. Tools that use that one server can't reach the cluster until it is back.",
			WhatToDo:     "Nothing, if that server is being fixed. If it was removed on purpose, add the cluster again with a new cluster.config.",
		}
		return []*findings.Finding{f}
	}
	f.Title = fmt.Sprintf("Cluster address %s doesn't answer; the controllers do", fb.Server)
	f.Summary = fmt.Sprintf("Clients reach the cluster at %s, a load balancer or a name shared by the controllers, and it doesn't answer%s The controllers run: k0s-monitor reads the cluster through %s. kubectl, pipelines and anything else that uses %s, including the worker nodes when k0s's externalAddress points there, can't reach the cluster.", fb.Server, why, via, fb.Server)
	f.Remedy.LikelyCause = "The load balancer in front of the controllers is down or has no healthy backends, or the name points at an address that doesn't answer."
	f.AddStep(findings.Step{Text: "Check the address from this host, without credentials", Plain: "Check whether the address answers",
		Command: fmt.Sprintf("curl -sk --max-time 5 https://%s/healthz; echo", fb.Server)})
	f.AddStep(findings.Step{Text: "Check the load balancer: its backends are the controllers on port 6443 (and 8132 and 9443, which k0s's workers and joining controllers use)",
		Plain: "Ask your network team to check the load balancer in front of the cluster"})
	f.Plain = findings.PlainText{
		Title:        "The cluster's address doesn't answer",
		WhatHappened: fmt.Sprintf("Tools and servers reach the cluster at %s, and that address doesn't answer. The cluster's control plane runs: k0s-monitor watches it through one of its servers directly.", host),
		Why:          "Anything that uses that address can't reach the cluster, possibly including the cluster's own servers.",
		WhatToDo:     "Tell your network team or support team: the load balancer or name in front of the cluster doesn't work.",
	}
	return []*findings.Finding{f}
}
