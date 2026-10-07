package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// X09 tls.cert-expiry

var tlsCertExpiryRule = Rule{
	ID: "tls.cert-expiry", Code: "X09", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindTLSSecret, snapshot.KindPod, snapshot.KindIngress},
	Eval:  evalTLSCertExpiry,
}

// certManagerWarn is when a certificate that cert-manager renews is
// reported: it renews a third of the lifetime before the end (30 days for
// 90-day certificates), so by now the renewal has failed.
const certManagerWarn = 14 * 24 * time.Hour

// certUse is what uses a TLS Secret.
type certUse struct {
	ingresses []string
	hosts     []string
	workloads []snapshot.Workload
}

// certUses maps "namespace/secret" to what uses it: the TLS of Ingresses,
// and pods that mount it.
func certUses(s *snapshot.Snapshot) map[string]*certUse {
	uses := map[string]*certUse{}
	use := func(ns, name string) *certUse {
		k := ns + "/" + name
		if uses[k] == nil {
			uses[k] = &certUse{}
		}
		return uses[k]
	}
	for _, ing := range s.Ingresses {
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue // the controller's default certificate
			}
			u := use(ing.Namespace, t.SecretName)
			u.ingresses = append(u.ingresses, ing.Name)
			u.hosts = append(u.hosts, t.Hosts...)
		}
	}
	for _, p := range s.Pods {
		if snapshot.IsPodTerminal(p) || p.DeletionTimestamp != nil {
			continue
		}
		var names []string
		for _, v := range p.Spec.Volumes {
			switch {
			case v.Secret != nil:
				names = append(names, v.Secret.SecretName)
			case v.Projected != nil:
				for _, src := range v.Projected.Sources {
					if src.Secret != nil {
						names = append(names, src.Secret.Name)
					}
				}
			}
		}
		for _, n := range names {
			u := use(p.Namespace, n)
			w := s.WorkloadOf(p)
			known := false
			for _, o := range u.workloads {
				known = known || o == w
			}
			if !known {
				u.workloads = append(u.workloads, w)
			}
		}
	}
	return uses
}

// dateText is how dates read: "2026-10-02 14:00 UTC".
func dateText(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// plainDate is how dates read in Basic mode: "2 October 2026".
func plainDate(t time.Time) string { return t.UTC().Format("2 January 2006") }

func evalTLSCertExpiry(c *Context) []*findings.Finding {
	uses := certUses(c.S)
	lv := c.T.AppCertExpiresWithin
	var out []*findings.Finding
	for _, cert := range c.S.TLSCerts {
		u := uses[cert.Namespace+"/"+cert.Secret]
		if u == nil || cert.Error != "" || cert.NotAfter.IsZero() {
			continue // not in use, or nothing to read
		}
		left := cert.NotAfter.Sub(c.S.Now)
		warn := lv.Warn.D()
		if cert.CertManager != "" && warn > certManagerWarn {
			warn = certManagerWarn
		}
		sev := findings.Medium
		switch {
		case left <= 0:
			sev = findings.Critical
		case left <= lv.Critical.D():
			sev = findings.High
		case left <= warn:
		default:
			continue
		}

		f := c.newFinding(sev, findings.ObjectRef{Kind: "Secret", Namespace: cert.Namespace, Name: cert.Secret})
		f.Impact.Exposed = len(u.ingresses) > 0
		name := cert.Secret
		if names := cert.Names(); len(names) > 0 {
			name = names[0]
		}
		when := "expires in " + ago(left)
		plainWhen := "expires in " + agoPlainFuture(left)
		if left <= 0 {
			when = "expired " + ago(-left) + " ago"
			plainWhen = "has expired"
		}
		f.Title = fmt.Sprintf("Certificate for %s %s (Secret %s/%s)", name, when, cert.Namespace, cert.Secret)

		var users []string
		for _, i := range u.ingresses {
			users = append(users, "Ingress "+i)
		}
		for _, w := range u.workloads {
			users = append(users, kubectlTarget(w))
		}
		sort.Strings(users)
		f.Summary = fmt.Sprintf("The TLS certificate in Secret %s/%s, used by %s, is valid until %s. After that, browsers and clients refuse to connect.",
			cert.Namespace, cert.Secret, strings.Join(users, ", "), dateText(cert.NotAfter))
		if left <= 0 {
			f.Summary = fmt.Sprintf("The TLS certificate in Secret %s/%s, used by %s, expired on %s: browsers and clients refuse to connect, or warn.",
				cert.Namespace, cert.Secret, strings.Join(users, ", "), dateText(cert.NotAfter))
		}
		f.AddFact("Valid until", dateText(cert.NotAfter))
		f.AddFact("Names", strings.Join(firstN(cert.Names(), 6), ", "))
		f.AddFact("Issuer", cert.Issuer)
		f.AddFact("Used by", strings.Join(users, ", "))
		var uncovered []string
		for _, h := range u.hosts {
			if !cert.Covers(h) {
				uncovered = append(uncovered, h)
			}
		}
		f.AddFact("Hosts not in it", strings.Join(uncovered, ", "))
		for _, w := range u.workloads {
			f.Links.Workloads = append(f.Links.Workloads, workloadRef(w))
		}

		ns, secret := cert.Namespace, cert.Secret
		f.AddStep(findings.Step{
			Text:    "See the certificate that is in the Secret now: on the Secret's page (Full mode: follow the Secret above), or with kubectl",
			Command: fmt.Sprintf("kubectl -n %s get secret %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -subject -issuer -enddate -ext subjectAltName", ns, secret),
		})
		if cert.CertManager != "" {
			f.AddFact("Renewed by", "cert-manager Certificate "+cert.CertManager)
			f.Remedy.LikelyCause = "cert-manager should have renewed it by now: by default it renews a third of the lifetime before the end. " +
				"Its Certificate, CertificateRequests and ACME orders say why it didn't; often the issuer can't reach its CA or ACME server, or the ACME challenge doesn't reach the cluster."
			f.AddStep(findings.Step{
				Text:    "See why cert-manager doesn't renew it",
				Plain:   "The automatic renewal failed: send the report to your support team.",
				Command: fmt.Sprintf("kubectl -n %s describe certificate %s\nkubectl -n %s get certificaterequests,orders.acme.cert-manager.io,challenges.acme.cert-manager.io", ns, cert.CertManager, ns),
			})
		} else {
			f.AddFact("Renewed by", "nothing in the cluster: renewed by hand")
			f.Remedy.LikelyCause = "Nothing in the cluster renews it: it was put in by hand or by a tool outside the cluster, and must be renewed the same way."
			f.AddStep(findings.Step{
				Text:    "Get the renewed certificate and its key from whoever issues them, then replace the Secret's contents",
				Plain:   "Whoever manages this certificate should renew it.",
				Command: fmt.Sprintf("kubectl -n %s create secret tls %s --cert=renewed.crt --key=renewed.key --dry-run=client -o yaml | kubectl apply -f -", ns, secret),
			})
		}
		if len(u.workloads) > 0 {
			var restarts []string
			for _, w := range u.workloads {
				if w.Kind != "Pod" {
					restarts = append(restarts, fmt.Sprintf("kubectl -n %s rollout restart %s", ns, kubectlTarget(w)))
				}
			}
			if len(restarts) > 0 {
				f.AddStep(findings.Step{
					Text:    "Apps that read the certificate only when they start need a restart once it is renewed",
					Command: strings.Join(restarts, "\n"),
				})
			}
		}

		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The security certificate for %s %s", name, plainWhen),
			WhatHappened: fmt.Sprintf("It is valid until %s. After that, browsers and apps refuse to connect to %s.", plainDate(cert.NotAfter), name),
		}
		if left <= 0 {
			f.Plain.WhatHappened = fmt.Sprintf("Since %s, browsers and apps refuse to connect to %s, or show a security warning.", plainDate(cert.NotAfter), name)
		}
		if cert.CertManager != "" {
			f.Plain.Why = "It should renew itself automatically, but that didn't happen."
			f.Plain.WhatToDo = "Send the report to your support team: the automatic renewal needs fixing."
		} else {
			f.Plain.Why = "Certificates are valid for a limited time, and nothing renews this one automatically."
			f.Plain.WhatToDo = fmt.Sprintf("Whoever manages the certificate for %s should renew it before %s.", name, plainDate(cert.NotAfter))
			if left <= 0 {
				f.Plain.WhatToDo = fmt.Sprintf("Whoever manages the certificate for %s should renew it now.", name)
			}
		}
		out = append(out, f)
	}
	return out
}

// agoPlainFuture words a time left in Basic mode: "5 days", "3 hours".
func agoPlainFuture(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return "less than 2 hours"
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
}
