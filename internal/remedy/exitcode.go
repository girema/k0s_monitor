package remedy

import "fmt"

// Exit explains how a container ended.
type Exit struct {
	// Plain finishes the sentence "The last time, …" (Basic mode).
	Plain string
	// Technical says what the code means (Full mode).
	Technical string
}

var signals = map[int32]string{1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
	9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM"}

// ExitCode explains an exit code and the reason Kubernetes gives for it.
func ExitCode(code int32, reason string) Exit {
	sig := func(what string) string {
		s := code - 128
		name := signals[s]
		if name == "" {
			name = fmt.Sprintf("signal %d", s)
		}
		return fmt.Sprintf("%d = 128 + %d (%s): %s", code, s, name, what)
	}
	switch {
	case reason == "OOMKilled":
		return Exit{"it used more memory than it is allowed to",
			fmt.Sprintf("%d, OOMKilled: the kernel killed it at the container's memory limit", code)}
	case reason == "ContainerCannotRun" || reason == "StartError":
		return Exit{"it could not be started",
			fmt.Sprintf("%d, %s: the container runtime couldn't start the process; the message says why", code, reason)}
	case code == 0:
		return Exit{"it finished on purpose, but it is configured to keep running, so check its command",
			"0: it ended normally; a container that must keep running shouldn't end, so its command probably runs once and stops"}
	case code == 1:
		return Exit{"the app reported an error and stopped", "1: a general error the app reported; its log says which"}
	case code == 2:
		return Exit{"the app was started with wrong arguments or reported a usage error",
			"2: a usage error, usually wrong arguments or options"}
	case code == 125:
		return Exit{"it could not be started", "125: the container runtime failed to run it"}
	case code == 126:
		return Exit{"its start command is not executable", "126: the command exists but can't be executed (permissions, or not a program)"}
	case code == 127:
		return Exit{"its start command was not found in the image", "127: the command was not found in the image"}
	case code == 128+2:
		return Exit{"it was interrupted", sig("interrupted")}
	case code == 128+6:
		return Exit{"it aborted itself after an internal error", sig("it aborted itself, often after a failed assertion or an uncaught C++ exception")}
	case code == 128+9:
		return Exit{"it was killed (out of memory, or a failed liveness probe)",
			sig("killed, by the kernel at the memory limit (the reason is then OOMKilled) or by the kubelet after the grace period, for example after a failed liveness probe")}
	case code == 128+11:
		return Exit{"it crashed with a segmentation fault", sig("a segmentation fault, a crash in native code")}
	case code == 128+15:
		return Exit{"it was asked to stop (SIGTERM)", sig("asked to stop, by Kubernetes (a failed liveness probe, an eviction, a rollout) or by itself")}
	case code == 255:
		return Exit{"the app reported an error and stopped", "255: it exited with -1, often after an unhandled error"}
	case code > 128 && code < 160:
		return Exit{fmt.Sprintf("it was stopped by signal %d", code-128), sig("stopped by a signal")}
	}
	return Exit{fmt.Sprintf("it stopped with exit code %d", code), fmt.Sprintf("%d: the app's own exit code; its log or documentation says what it means", code)}
}
