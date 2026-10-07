package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"k0s_monitor/internal/pack"
)

// Product packs (plan section 10.6): listed, uploaded and removed in
// Settings, and through the API.

type packRow struct {
	Name, Version, Description string
	// Source says where it comes from; Uploaded is true for uploads,
	// which can be removed here.
	Source   string
	Uploaded bool
	// For lists the clusters it applies to.
	For  []string
	Adds string
	// K0sVersion and Support are what it sets.
	K0sVersion string
	Support    string
	// QueryErrors are queries Prometheus refused, by cluster.
	QueryErrors []string
}

type packsData struct {
	On       bool
	Dir      string
	Packs    []packRow
	Problems []pack.Problem
}

func (s *Server) packsData() packsData {
	d := packsData{On: s.o.Packs != nil, Dir: s.o.Packs.Dir()}
	set := s.o.Packs.Current()
	if set == nil {
		return d
	}
	d.Problems = set.Problems
	clusters := s.o.Fleet.Engines()
	for _, l := range set.Packs {
		row := packRow{Name: l.Name, Version: l.Version, Description: l.Description, K0sVersion: l.K0sVersion, Support: l.Support.Contact()}
		if l.File != "" {
			row.Source = l.File
		} else {
			row.Uploaded = true
			row.Source = fmt.Sprintf("uploaded by %s, %s", l.UploadedBy, stamp(l.Uploaded))
		}
		var on []string
		for _, e := range clusters {
			if l.AppliesTo(e.Name()) {
				on = append(on, e.Name())
			}
		}
		switch {
		case len(l.Clusters) == 0:
			row.For = []string{"every cluster"}
		case len(on) == 0:
			row.For = []string{strings.Join(l.Clusters, ", ") + " (none of the clusters here)"}
		default:
			row.For = on
		}
		var adds []string
		for _, c := range []struct {
			n    int
			word string
		}{{len(l.Checks), "check"}, {len(l.Apps), "app name"}, {len(l.Guides), "guide"}, {len(l.Glossary), "glossary word"}} {
			if c.n > 0 {
				adds = append(adds, plural(c.n, c.word))
			}
		}
		if l.AddNode != nil {
			adds = append(adds, "the add-node guide")
		}
		row.Adds = strings.Join(adds, ", ")
		for _, e := range clusters {
			if !l.AppliesTo(e.Name()) {
				continue
			}
			snap := e.State().Snapshot
			if snap == nil || snap.Metrics == nil {
				continue
			}
			for _, ch := range l.Checks {
				if msg, ok := snap.Metrics.QueryErrors[strings.TrimSpace(ch.Query)]; ok && ch.Kind == pack.KindQuery {
					row.QueryErrors = append(row.QueryErrors, fmt.Sprintf("%s in %s: %s", ch.ID, e.Name(), msg))
				}
			}
		}
		sort.Strings(row.QueryErrors)
		d.Packs = append(d.Packs, row)
	}
	return d
}

// reloadPacks reads the packs again and has every cluster evaluated with
// them.
func (s *Server) reloadPacks() *pack.Set {
	set := s.o.Packs.Load()
	for _, e := range s.o.Fleet.Engines() {
		e.Refresh()
	}
	return set
}

var errPacksOff = errors.New("product packs are off")

// savePack checks and stores an uploaded pack.
func (s *Server) savePack(r *http.Request, data []byte) (*pack.Pack, error) {
	if s.o.Packs == nil {
		return nil, errPacksOff
	}
	p, err := pack.Parse(data)
	if err != nil {
		return nil, err
	}
	if l := s.o.Packs.Current().Get(p.Name); l != nil && l.File != "" {
		return nil, fmt.Errorf("a pack named %s comes from %s: change that file instead, or give this one another name", p.Name, l.File)
	}
	if err := s.o.Store.SavePack(p.Name, data, sessionUser(r)); err != nil {
		return nil, err
	}
	set := s.reloadPacks()
	for _, pr := range set.Problems {
		if pr.Source == "uploaded pack "+p.Name {
			return nil, errors.New(pr.Err)
		}
	}
	s.audit(r, "pack.upload", fmt.Sprintf("%s %s", p.Name, p.Version))
	return p, nil
}

func (s *Server) removePack(r *http.Request, name string) error {
	if s.o.Packs == nil {
		return errPacksOff
	}
	l := s.o.Packs.Current().Get(name)
	if l == nil {
		return fmt.Errorf("there is no pack named %q", name)
	}
	if l.File == "" {
		if err := s.o.Store.DeletePack(name); err != nil {
			return err
		}
		s.reloadPacks()
		s.audit(r, "pack.remove", name)
		return nil
	}
	return fmt.Errorf("the pack %s comes from %s: remove that file, then read the packs again", name, l.File)
}

// limitBody caps a request's body before the handler (and its sign-in
// check) reads it.
func limitBody(n int64, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		h(w, r)
	}
}

const packUploadLimit = pack.MaxSize + 64<<10

func (s *Server) packUploadForm(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("pack")
	if err != nil {
		s.renderSettings(w, r, "", "Choose a pack file (.yaml) to upload.")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, pack.MaxSize+1))
	if err != nil {
		s.renderSettings(w, r, "", "The file can't be read: "+err.Error())
		return
	}
	p, err := s.savePack(r, data)
	if err != nil {
		s.renderSettings(w, r, "", "The pack wasn't added: "+err.Error())
		return
	}
	s.renderSettings(w, r, fmt.Sprintf("The pack %s is in use. The clusters are checked with it now.", p.Name), "")
}

func (s *Server) packRemoveForm(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.removePack(r, name); err != nil {
		s.renderSettings(w, r, "", err.Error())
		return
	}
	s.renderSettings(w, r, fmt.Sprintf("The pack %s was removed.", name), "")
}

func (s *Server) packReloadForm(w http.ResponseWriter, r *http.Request) {
	if s.o.Packs == nil {
		s.renderSettings(w, r, "", errPacksOff.Error())
		return
	}
	set := s.reloadPacks()
	s.audit(r, "pack.reload", fmt.Sprintf("%d packs, %d not used", len(set.Packs), len(set.Problems)))
	msg := fmt.Sprintf("The packs were read again: %s in use.", plural(len(set.Packs), "pack"))
	if len(set.Problems) > 0 {
		msg += fmt.Sprintf(" %s can't be used: see below.", plural(len(set.Problems), "file"))
	}
	s.renderSettings(w, r, msg, "")
}

// packFile downloads a pack as it was written, or the example pack.
func (s *Server) packFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.PathValue("file"), ".yaml")
	data := pack.Example
	if name != "example" {
		l := s.o.Packs.Current().Get(name)
		if l == nil {
			http.Error(w, "There is no such pack.", http.StatusNotFound)
			return
		}
		data = l.Data
	}
	h := w.Header()
	h.Set("Content-Type", "application/yaml; charset=utf-8")
	h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".yaml"))
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

type apiPack struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Description string   `json:"description,omitempty"`
	File        string   `json:"file,omitempty"`
	UploadedBy  string   `json:"uploadedBy,omitempty"`
	Clusters    []string `json:"clusters,omitempty"`
	Checks      []string `json:"checks,omitempty"`
}

func (s *Server) apiPacks(w http.ResponseWriter, _ *http.Request) {
	type resp struct {
		Packs    []apiPack      `json:"packs"`
		Problems []pack.Problem `json:"problems,omitempty"`
	}
	out := resp{Packs: []apiPack{}}
	if set := s.o.Packs.Current(); set != nil {
		out.Problems = set.Problems
		for _, l := range set.Packs {
			a := apiPack{Name: l.Name, Version: l.Version, Description: l.Description, File: l.File, UploadedBy: l.UploadedBy, Clusters: l.Clusters}
			for _, c := range l.Checks {
				a.Checks = append(a.Checks, l.RuleID(c.ID))
			}
			out.Packs = append(out.Packs, a)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// apiUploadPack takes a pack file as the request body.
func (s *Server) apiUploadPack(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "the pack is too large")
		return
	}
	p, err := s.savePack(r, data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, apiPack{Name: p.Name, Version: p.Version, Description: p.Description, Clusters: p.Clusters})
}

func (s *Server) apiRemovePack(w http.ResponseWriter, r *http.Request) {
	if err := s.removePack(r, r.PathValue("name")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
