package findings

import "strings"

// Kubectl is how commands call kubectl: k0s ships it as "k0s kubectl".
const Kubectl = "k0s kubectl"

// K0sKubectl rewrites each kubectl call in a shell command to k0s kubectl:
// at the start of a line, after a pipe, ";", "&&", "(" or "$(", and as
// the command xargs runs. Calls already written as k0s kubectl are left.
func K0sKubectl(cmd string) string {
	const word = "kubectl "
	var b strings.Builder
	rest := cmd
	for {
		i := strings.Index(rest, word)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		before := b.String() + rest[:i]
		b.WriteString(rest[:i])
		if commandPosition(before) {
			b.WriteString("k0s ")
		}
		b.WriteString(word)
		rest = rest[i+len(word):]
	}
}

// commandPosition reports whether what follows text starts a command.
func commandPosition(text string) bool {
	if strings.HasSuffix(text, "k0s ") {
		return false
	}
	t := strings.TrimRight(text, " \t")
	if t == "" || strings.HasSuffix(t, "\n") {
		return true
	}
	for _, sep := range []string{"|", ";", "&", "("} {
		if strings.HasSuffix(t, sep) {
			return true
		}
	}
	if len(t) == len(text) {
		return false // kubectl inside a word, such as "mykubectl "
	}
	for _, xargs := range []string{"xargs", "xargs -n 1", "xargs -r"} {
		if strings.HasSuffix(t, xargs) {
			return true
		}
	}
	return false
}

// UseK0sKubectl rewrites the commands of a finding's steps.
func (f *Finding) UseK0sKubectl() {
	for i := range f.Remedy.Steps {
		f.Remedy.Steps[i].Command = K0sKubectl(f.Remedy.Steps[i].Command)
	}
}
