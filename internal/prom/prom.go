// Package prom reads from a cluster's Prometheus (plan section 6.1). It
// queries through the API server's service proxy by default, so it needs
// no network access beyond port 6443, or a configured URL. It never
// writes to Prometheus.
package prom

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
)

// Target is where a Prometheus answers.
type Target struct {
	// Through the API server's service proxy.
	Namespace string `json:"namespace,omitempty"`
	Service   string `json:"service,omitempty"`
	Scheme    string `json:"scheme,omitempty"` // http or https
	Port      string `json:"port,omitempty"`   // number or name
	// Path is where the query API lives under the Service, for example
	// "select/0/prometheus" for a VictoriaMetrics vmselect.
	Path string `json:"path,omitempty"`

	// Or directly, for a Prometheus or VictoriaMetrics outside the cluster.
	URL string `json:"url,omitempty"`
}

// String names the target the way people read it.
func (t Target) String() string {
	if t.URL != "" {
		return t.URL
	}
	path := ""
	if t.Path != "" {
		path = "/" + t.Path
	}
	return fmt.Sprintf("%s/%s:%s%s (service proxy)", t.Namespace, t.Service, t.Port, path)
}

// ProxyName is the service name segment of the proxy path, which is also
// what an RBAC rule with resourceNames must list.
func (t Target) ProxyName() string {
	return t.Scheme + ":" + t.Service + ":" + t.Port
}

// Auth holds credentials for a direct URL.
type Auth struct {
	Username    string
	Password    string
	BearerToken string
	CAFile      string
}

// Client runs PromQL queries.
type Client struct {
	Target Target
	get    func(ctx context.Context, path string, params map[string]string) ([]byte, error)
}

// NewProxy queries a Prometheus Service through the API server.
func NewProxy(cs kubernetes.Interface, t Target) *Client {
	return &Client{Target: t, get: func(ctx context.Context, path string, params map[string]string) ([]byte, error) {
		if t.Path != "" {
			path = strings.Trim(t.Path, "/") + "/" + path
		}
		b, err := cs.CoreV1().Services(t.Namespace).ProxyGet(t.Scheme, t.Service, t.Port, path, params).DoRaw(ctx)
		if err != nil && len(b) > 0 {
			// Prometheus's own error body says more than the status.
			if perr := parseError(b); perr != nil {
				return nil, perr
			}
		}
		return b, err
	}}
}

// NewURL queries a Prometheus at a URL.
func NewURL(t Target, a Auth) (*Client, error) {
	base, err := url.Parse(strings.TrimSuffix(t.URL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("prometheus url %q is not a valid URL", t.URL)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s has no PEM certificate", a.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return &Client{Target: t, get: func(ctx context.Context, path string, params map[string]string) ([]byte, error) {
		u := *base
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + path
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		switch {
		case a.BearerToken != "":
			req.Header.Set("Authorization", "Bearer "+a.BearerToken)
		case a.Username != "":
			req.SetBasicAuth(a.Username, a.Password)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			if perr := parseError(b); perr != nil {
				return nil, perr
			}
			return nil, fmt.Errorf("prometheus answered %s", resp.Status)
		}
		return b, nil
	}}, nil
}

// NewFunc builds a client from a request function, for tests.
func NewFunc(t Target, get func(ctx context.Context, path string, params map[string]string) ([]byte, error)) *Client {
	return &Client{Target: t, get: get}
}

// Sample is one series' value at one time.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Series is one series over time.
type Series struct {
	Labels map[string]string
	Points []Point
}

// Point is one value at one time.
type Point struct {
	T time.Time
	V float64
}

// Query runs an instant query.
func (c *Client) Query(ctx context.Context, q string, at time.Time) ([]Sample, error) {
	params := map[string]string{"query": q}
	if !at.IsZero() {
		params["time"] = formatTime(at)
	}
	b, err := c.get(ctx, "api/v1/query", params)
	if err != nil {
		return nil, err
	}
	var r response
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, notAPI(b, err)
	}
	if r.Status != "success" {
		return nil, apiError(r)
	}
	var out []Sample
	switch r.Data.ResultType {
	case "vector":
		var vs []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		}
		if err := json.Unmarshal(r.Data.Result, &vs); err != nil {
			return nil, err
		}
		for _, v := range vs {
			f, ok := parseValue(v.Value[1])
			if !ok {
				continue
			}
			out = append(out, Sample{Labels: v.Metric, Value: f})
		}
	case "scalar":
		var v [2]any
		if err := json.Unmarshal(r.Data.Result, &v); err != nil {
			return nil, err
		}
		if f, ok := parseValue(v[1]); ok {
			out = append(out, Sample{Labels: map[string]string{}, Value: f})
		}
	default:
		return nil, fmt.Errorf("unexpected result type %q for an instant query", r.Data.ResultType)
	}
	return out, nil
}

// QueryRange runs a range query.
func (c *Client) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error) {
	b, err := c.get(ctx, "api/v1/query_range", map[string]string{
		"query": q, "start": formatTime(start), "end": formatTime(end),
		"step": strconv.FormatFloat(step.Seconds(), 'f', -1, 64),
	})
	if err != nil {
		return nil, err
	}
	var r response
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, notAPI(b, err)
	}
	if r.Status != "success" {
		return nil, apiError(r)
	}
	if r.Data.ResultType != "matrix" {
		return nil, fmt.Errorf("unexpected result type %q for a range query", r.Data.ResultType)
	}
	var ms []struct {
		Metric map[string]string `json:"metric"`
		Values [][2]any          `json:"values"`
	}
	if err := json.Unmarshal(r.Data.Result, &ms); err != nil {
		return nil, err
	}
	var out []Series
	for _, m := range ms {
		s := Series{Labels: m.Metric}
		for _, v := range m.Values {
			ts, ok1 := v[0].(float64)
			f, ok2 := parseValue(v[1])
			if !ok1 || !ok2 {
				continue
			}
			s.Points = append(s.Points, Point{T: time.Unix(0, int64(ts*1e9)).UTC(), V: f})
		}
		sort.Slice(s.Points, func(i, j int) bool { return s.Points[i].T.Before(s.Points[j].T) })
		out = append(out, s)
	}
	return out, nil
}

type response struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

// Error is an error Prometheus reported about a query.
type Error struct {
	Type, Message string
}

func (e *Error) Error() string { return "prometheus: " + e.Type + ": " + e.Message }

func apiError(r response) error {
	if r.Error == "" {
		return errors.New("prometheus: the query failed without a message")
	}
	return &Error{Type: r.ErrorType, Message: r.Error}
}

// NotQueryAPIError means the address answers, but not with the Prometheus
// query API: for example it is an exporter, which Prometheus or
// VictoriaMetrics collects from.
type NotQueryAPIError struct {
	// What completes "<address> ...", for example "is node-exporter".
	What string
	// Exporter is true when it serves metrics to be collected.
	Exporter bool
}

func (e *NotQueryAPIError) Error() string { return "the address " + e.What }

// notAPI explains an answer that isn't Prometheus JSON.
func notAPI(b []byte, err error) error {
	head := strings.ToLower(string(b[:min(len(b), 8192)]))
	switch {
	case strings.Contains(head, "node exporter") || strings.Contains(head, "node_exporter"):
		return &NotQueryAPIError{What: "is node-exporter: it exposes a server's metrics, but doesn't store them or answer queries", Exporter: true}
	case strings.Contains(head, "# help ") || strings.Contains(head, "# type "):
		return &NotQueryAPIError{What: "is an exporter's metrics page, not a query API", Exporter: true}
	case strings.Contains(head, "<html") || strings.Contains(head, "<!doctype"):
		return &NotQueryAPIError{What: "answers with a web page, not the Prometheus query API"}
	}
	return fmt.Errorf("the answer is not Prometheus JSON: %w", err)
}

func parseError(b []byte) error {
	var r response
	if json.Unmarshal(b, &r) != nil || r.Status != "error" {
		return nil
	}
	return apiError(r)
}

func parseValue(v any) (float64, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func formatTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', 3, 64)
}
