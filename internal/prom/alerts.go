package prom

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

// Alert is an alert as Prometheus's alerts API reports it.
type Alert struct {
	Labels      map[string]string
	Annotations map[string]string
	// State is "firing" or "pending".
	State string
	// ActiveAt is when the alert's condition started; zero when unknown.
	ActiveAt time.Time
}

// Alerts returns the active alerts, firing and pending, from the alerts
// API. VictoriaMetrics answers it only when it knows its vmalert
// (-vmalert.proxyURL); FiringAlerts reads the ALERTS series instead.
func (c *Client) Alerts(ctx context.Context) ([]Alert, error) {
	b, err := c.get(ctx, "api/v1/alerts", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		Status    string `json:"status"`
		ErrorType string `json:"errorType"`
		Error     string `json:"error"`
		Data      struct {
			Alerts []struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
				State       string            `json:"state"`
				ActiveAt    *time.Time        `json:"activeAt"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, notAPI(b, err)
	}
	if r.Status != "success" {
		return nil, apiError(response{ErrorType: r.ErrorType, Error: r.Error})
	}
	out := make([]Alert, 0, len(r.Data.Alerts))
	for _, a := range r.Data.Alerts {
		al := Alert{Labels: a.Labels, Annotations: a.Annotations, State: a.State}
		if a.ActiveAt != nil && a.ActiveAt.Year() > 1 {
			al.ActiveAt = a.ActiveAt.UTC()
		}
		out = append(out, al)
	}
	return out, nil
}

// FiringAlerts reads the firing alerts from the ALERTS series, which
// Prometheus and vmalert write. It has no annotations; ALERTS_FOR_STATE,
// when present, says since when an alert is active.
func (c *Client) FiringAlerts(ctx context.Context, at time.Time) ([]Alert, error) {
	ss, err := c.Query(ctx, `ALERTS{alertstate="firing"}`, at)
	if err != nil {
		return nil, err
	}
	since := map[string]time.Time{}
	if fs, err := c.Query(ctx, `ALERTS_FOR_STATE`, at); err == nil {
		for _, s := range fs {
			since[labelKey(s.Labels, "")] = time.Unix(int64(s.Value), 0).UTC()
		}
	}
	out := make([]Alert, 0, len(ss))
	for _, s := range ss {
		labels := map[string]string{}
		for k, v := range s.Labels {
			if k != "alertstate" && k != "__name__" {
				labels[k] = v
			}
		}
		out = append(out, Alert{Labels: labels, State: "firing", ActiveAt: since[labelKey(s.Labels, "alertstate")]})
	}
	return out, nil
}

// labelKey identifies a series by its labels, without __name__ and skip.
func labelKey(labels map[string]string, skip string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if k != "__name__" && k != skip {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b []byte
	for _, k := range keys {
		b = strconv.AppendQuote(append(b, k...), labels[k])
		b = append(b, ',')
	}
	return string(b)
}
