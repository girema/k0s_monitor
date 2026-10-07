package fleet

import (
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/findings"
)

// UnreachableRuleID is the fleet-level rule F01.
const UnreachableRuleID = cluster.UnreachableRuleID

// Unreachable builds the F01 finding for a cluster that could not be reached.
func Unreachable(name string, ce *cluster.ConnError) *findings.Finding {
	return cluster.Unreachable(name, ce)
}
