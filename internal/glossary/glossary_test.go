package glossary

import (
	"regexp"
	"strings"
	"testing"
)

var tag = regexp.MustCompile(`<[^>]+>`)

// visible drops the tooltips and tags: what the text reads as.
func visible(h string) string {
	h = regexp.MustCompile(`<span class="gtip"[^>]*>.*?</span></span>`).ReplaceAllString(h, "")
	return tag.ReplaceAllString(h, "")
}

func TestAnnotate(t *testing.T) {
	in := `The pod web-1 on server worker-1 can't reach the API server: pods restart. See pod/web-1 & node-exporter <b>`
	out := string(Annotate(in))
	// The text reads the same, escaped.
	if got := visible(out); got != `The pod web-1 on server worker-1 can&#39;t reach the API server: pods restart. See pod/web-1 &amp; node-exporter &lt;b&gt;` {
		t.Errorf("text changed: %s", got)
	}
	// Terms marked once each: pod, server (node), API server; not "pods"
	// again, nor names like pod/web-1 or node-exporter.
	var marked []string
	for _, m := range regexp.MustCompile(`class="term"[^>]*>([^<]+)<`).FindAllStringSubmatch(out, -1) {
		marked = append(marked, m[1])
	}
	if strings.Join(marked, ",") != "pod,server,API server" {
		t.Errorf("marked %v", marked)
	}
	if !strings.Contains(out, `<b>node</b> A machine`) || !strings.Contains(out, `role="tooltip"`) {
		t.Errorf("tooltip: %s", out)
	}
	// Each tooltip has its own id, referenced by its term.
	ids := regexp.MustCompile(`aria-describedby="(gt\d+)"`).FindAllStringSubmatch(out, -1)
	for _, id := range ids {
		if !strings.Contains(out, `id="`+id[1]+`"`) {
			t.Errorf("no tooltip %s", id[1])
		}
	}
	// A marker explains a term once over several texts.
	mk := NewMarker()
	if a, b := string(mk.Mark("the node is down")), string(mk.Mark("move the pods off the node")); !strings.Contains(a, `class="term"`) ||
		strings.Count(b, `class="term"`) != 1 || !strings.Contains(b, ">pods<") {
		t.Errorf("marker: %s | %s", a, b)
	}
	if Annotate("") != "" || Annotate("nothing here") != "nothing here" {
		t.Error("text without terms changes")
	}
}

func TestTerms(t *testing.T) {
	seen := map[string]string{}
	for _, term := range Terms {
		if term.Text == "" || !strings.HasSuffix(term.Text, ".") {
			t.Errorf("%s: text %q", term.Name, term.Text)
		}
		for _, w := range append([]string{term.Name}, term.Also...) {
			k := strings.ToLower(w)
			if other, dup := seen[k]; dup {
				t.Errorf("%q names both %s and %s", w, other, term.Name)
			}
			seen[k] = term.Name
		}
	}
	if Lookup("App Parts").Name != "pod" || Lookup("nope") != nil {
		t.Error("lookup")
	}
	if Anchor(Lookup("API server")) != "t-api-server" {
		t.Error("anchor")
	}
}
