// Package version holds build information, set at link time:
//
//	go build -ldflags "-X k0s_monitor/internal/version.Version=v0.1.0"
package version

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
