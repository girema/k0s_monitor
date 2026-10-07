package remedy

import (
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// Mask replaces a hidden value.
const Mask = "••••••"

var secretName = regexp.MustCompile(`(?i)(pass|secret|token|key|credential|private|auth|cert|signature|salt)`)

// SecretLike reports whether a name, such as an environment variable's,
// looks like it holds a secret.
func SecretLike(name string) bool { return secretName.MatchString(name) }

// MaskValue hides a value if its name looks secret, and passwords in URLs.
func MaskValue(name, value string) string {
	if value == "" {
		return value
	}
	if SecretLike(name) {
		return Mask
	}
	return urlUser.ReplaceAllString(value, "${1}"+Mask+"${3}")
}

// MaskYAML hides, in a YAML document such as a Helm chart's values, the
// text under keys that look secret, private keys anywhere, and passwords in
// URLs. Numbers and switches stay: they hold no secrets. ok is false when
// the text isn't YAML; then nothing of it may be shown.
func MaskYAML(text string) (masked string, ok bool) {
	var doc any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return "", false
	}
	if doc == nil {
		return "", true
	}
	out, err := yaml.Marshal(MaskTree(doc, false))
	if err != nil {
		return "", false
	}
	return string(out), true
}

// MaskTree is MaskYAML for a parsed document; hide masks every text in it.
func MaskTree(v any, hide bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = MaskTree(x, hide || SecretLike(k))
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = MaskTree(x, hide)
		}
		return t
	case string:
		switch {
		case t == "":
			return t
		case hide, strings.Contains(t, "PRIVATE KEY"):
			return Mask
		}
		return MaskValue("", t)
	}
	return v
}
