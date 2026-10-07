package snapshot

import (
	"encoding/json"
	"sort"
	"time"
)

type apiServiceJSON struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Service *struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"service"`
	} `json:"spec"`
	Status struct {
		Conditions []struct {
			Type               string    `json:"type"`
			Status             string    `json:"status"`
			Reason             string    `json:"reason"`
			Message            string    `json:"message"`
			LastTransitionTime time.Time `json:"lastTransitionTime"`
		} `json:"conditions"`
	} `json:"status"`
}

type apiServiceListJSON struct {
	Kind  string           `json:"kind"`
	Items []apiServiceJSON `json:"items"`
}

// ParseAPIServices reads an APIServiceList, or a single APIService, as JSON.
func ParseAPIServices(data []byte) ([]APIService, error) {
	var list apiServiceListJSON
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	items := list.Items
	if list.Kind == "APIService" {
		var one apiServiceJSON
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, err
		}
		items = []apiServiceJSON{one}
	}
	var out []APIService
	for _, it := range items {
		a := APIService{Name: it.Metadata.Name, Available: true}
		if sv := it.Spec.Service; sv != nil {
			a.Service = sv.Namespace + "/" + sv.Name
		}
		for _, c := range it.Status.Conditions {
			if c.Type == "Available" {
				a.Available = c.Status == "True"
				a.Reason, a.Message, a.Since = c.Reason, c.Message, c.LastTransitionTime
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
