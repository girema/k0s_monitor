package snapshot

import (
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// CordonedAtAnnotation carries the time a node was cordoned on the cached
// copy of the node. It is set by KeepCordonTime and never written to the
// cluster.
const CordonedAtAnnotation = "k0s-monitor.io/cordoned-at"

// KeepCordonTime records when a cordoned node was cordoned, from its
// managed fields, before they are dropped to save memory. The API has no
// other record of that time.
func KeepCordonTime(n *corev1.Node) {
	if !n.Spec.Unschedulable {
		return
	}
	if t, ok := cordonTimeFromManagedFields(n); ok {
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		n.Annotations[CordonedAtAnnotation] = t.UTC().Format(time.RFC3339)
	}
}

// CordonedSince returns when a cordoned node was cordoned, if known.
func CordonedSince(n *corev1.Node) (time.Time, bool) {
	if !n.Spec.Unschedulable {
		return time.Time{}, false
	}
	if v := n.Annotations[CordonedAtAnnotation]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, true
		}
	}
	return cordonTimeFromManagedFields(n)
}

// cordonTimeFromManagedFields finds the newest managed-fields entry that
// owns spec.unschedulable, which is when the node was last cordoned.
func cordonTimeFromManagedFields(n *corev1.Node) (time.Time, bool) {
	var best time.Time
	for _, mf := range n.ManagedFields {
		if mf.FieldsV1 == nil || mf.Time == nil {
			continue
		}
		var fields struct {
			Spec map[string]json.RawMessage `json:"f:spec"`
		}
		if err := json.Unmarshal(mf.FieldsV1.Raw, &fields); err != nil {
			continue
		}
		if _, ok := fields.Spec["f:unschedulable"]; ok && mf.Time.After(best) {
			best = mf.Time.Time
		}
	}
	return best, !best.IsZero()
}
