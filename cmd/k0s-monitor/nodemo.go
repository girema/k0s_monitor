//go:build !demo

package main

import (
	"errors"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
)

func demoConfig(string) (*config.Config, error) {
	return nil, errors.New("this build has no demo mode (build with -tags demo)")
}

func demoConnector(string) cluster.Connector { return nil }

func demoNow(string) func() time.Time { return nil }

func demoMetrics(string, func() time.Time) func(*cluster.Conn) engine.MetricsSource { return nil }

func demoControlPlane(string, func() time.Time) func(*cluster.Conn) engine.ControlPlaneSource {
	return nil
}

func demoCrashLogs(string) func(*cluster.Conn) engine.CrashLogSource { return nil }
