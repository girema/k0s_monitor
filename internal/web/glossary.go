package web

import (
	"net/http"
	"strings"

	"k0s_monitor/internal/glossary"
)

type glossaryTerm struct {
	Anchor, Name, Text string
	Also               []string
	// From names the product pack that explains it.
	From string
}

type glossaryLetter struct{ Letter, Anchor string }

type glossaryData struct {
	Terms   []glossaryTerm
	Letters []glossaryLetter
}

func glossaryOf() glossaryData {
	var d glossaryData
	for _, t := range glossary.Sorted() {
		a := glossary.Anchor(&t)
		var also []string
		for _, w := range t.Also {
			// Plurals go without saying.
			if l, n := strings.ToLower(w), strings.ToLower(t.Name); l != n+"s" && l != n+"es" {
				also = append(also, w)
			}
		}
		d.Terms = append(d.Terms, glossaryTerm{Anchor: a, Name: t.Name, Text: t.Text, Also: also, From: t.From})
		letter := strings.ToUpper(string([]rune(t.Name)[:1]))
		if n := len(d.Letters); n == 0 || d.Letters[n-1].Letter != letter {
			d.Letters = append(d.Letters, glossaryLetter{Letter: letter, Anchor: a})
		}
	}
	return d
}

func (s *Server) glossaryPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "glossary", &page{Title: "Glossary", Nav: "glossary", Data: glossaryOf()})
}
