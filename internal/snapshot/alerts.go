package snapshot

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Alert is an alert that fires in the cluster's Prometheus (or vmalert).
// k0s-monitor shows it and links it to the problems it is about; it never
// changes or silences it.
type Alert struct {
	Name     string
	Severity string
	// Labels are the alert's labels, without alertname.
	Labels map[string]string
	// Summary and Description are the usual annotations; Runbook is
	// runbook_url. All may be empty: the ALERTS series has none.
	Summary, Description, Runbook string
	// Since is when it became active; zero when unknown.
	Since time.Time
}

// ID identifies the alert: its name and labels.
func (a Alert) ID() string {
	keys := make([]string, 0, len(a.Labels))
	for k := range a.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha1.New()
	h.Write([]byte(a.Name))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k + "=" + a.Labels[k]))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Text is the alert's own explanation: its summary, else its description.
func (a Alert) Text() string {
	if a.Summary != "" {
		return a.Summary
	}
	return a.Description
}

// SeverityRank orders severities: critical first, then warning, info and
// anything else.
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical", "page", "error", "high":
		return 0
	case "warning", "warn", "medium":
		return 1
	case "info", "low":
		return 2
	}
	return 3
}

// SortAlerts orders alerts by severity, then name and labels.
func SortAlerts(as []Alert) {
	sort.SliceStable(as, func(i, j int) bool {
		if ri, rj := SeverityRank(as[i].Severity), SeverityRank(as[j].Severity); ri != rj {
			return ri < rj
		}
		if as[i].Name != as[j].Name {
			return as[i].Name < as[j].Name
		}
		return as[i].ID() < as[j].ID()
	})
}

// heartbeatAlerts always fire on purpose, to show that alerting works.
var heartbeatAlerts = map[string]bool{"Watchdog": true, "InfoInhibitor": true, "DeadMansSwitch": true}

// IsHeartbeat reports whether an alert fires on purpose all the time, or
// is only meant to inhibit others (severity none): these are left out.
func IsHeartbeat(name, severity string) bool {
	return heartbeatAlerts[name] || strings.EqualFold(severity, "none")
}
