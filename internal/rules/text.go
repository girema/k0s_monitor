package rules

import (
	"fmt"
	"time"

	"k0s_monitor/internal/remedy"
)

// ago renders a duration the way people say it: "45 s", "12 min", "3 h", "2 days".
func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "0 s"
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// agoPlain is the Basic-mode variant: "12 minutes", "3 hours".
func agoPlain(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < 2*time.Minute:
		return "1 minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 2*time.Hour:
		return "1 hour"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// exitCodeMeaning explains a container exit code in plain words.
func exitCodeMeaning(code int32, reason string) string { return remedy.ExitCode(code, reason).Plain }
