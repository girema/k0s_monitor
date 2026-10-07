package web

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"k0s_monitor/internal/auth"
	"k0s_monitor/internal/store"
)

// Users: every user can do everything, including managing the other users.
// Removing a user or setting their password ends their sessions at once.

type userRow struct {
	Name       string
	Me         bool
	SignedIn   int // live sessions
	LastSignIn string
	Created    string
}

func (s *Server) userRows(me string) []userRow {
	us, err := s.o.Store.Users()
	if err != nil {
		return nil
	}
	live := s.sessions.SignedIn()
	var out []userRow
	for _, u := range us {
		r := userRow{Name: u.Name, Me: u.Name == me, SignedIn: live[u.Name], LastSignIn: "never", Created: stamp(u.Created)}
		if u.CreatedBy != "" {
			r.Created += " by " + u.CreatedBy
		}
		if u.LastSignIn != nil {
			if d := s.now().Sub(*u.LastSignIn); d < time.Minute {
				r.LastSignIn = "just now"
			} else {
				r.LastSignIn = ago(d) + " ago"
			}
		}
		out = append(out, r)
	}
	return out
}

// errUsers is an error the user can act on (a 400, not a 500).
type errUsers struct{ msg string }

func (e errUsers) Error() string { return e.msg }

func (s *Server) addUser(r *http.Request, name, password string) error {
	if s.o.NoAuth {
		return errUsers{"sign-in is off in this mode, so there are no users"}
	}
	if err := auth.CheckUserName(name); err != nil {
		return errUsers{err.Error()}
	}
	hash, err := s.hashPassword(r, password)
	if err != nil {
		return errUsers{err.Error()}
	}
	if err := s.o.Store.AddUser(name, hash, sessionOf(r).User); err != nil {
		if errors.Is(err, store.ErrUserExists) {
			return errUsers{fmt.Sprintf("there is a user named %s already", name)}
		}
		return err
	}
	s.audit(r, "user.add", name)
	return nil
}

// setUserPassword sets another user's password, without their current one,
// and signs them out everywhere. Users change their own password with the
// current one (changePassword).
func (s *Server) setUserPassword(r *http.Request, name, password string) error {
	if s.o.NoAuth {
		return errUsers{"sign-in is off in this mode, so there are no users"}
	}
	if name == sessionOf(r).User {
		return errUsers{"change your own password with your current one, under Change your password"}
	}
	hash, err := s.hashPassword(r, password)
	if err != nil {
		return errUsers{err.Error()}
	}
	if err := s.o.Store.SetPassword(name, hash); err != nil {
		if errors.Is(err, store.ErrNoUser) {
			return errUsers{fmt.Sprintf("there is no user named %s", name)}
		}
		return err
	}
	s.sessions.DeleteUser(name, "")
	s.audit(r, "user.password", name)
	return nil
}

func (s *Server) removeUser(r *http.Request, name string) error {
	if s.o.NoAuth {
		return errUsers{"sign-in is off in this mode, so there are no users"}
	}
	if name == sessionOf(r).User {
		return errUsers{"you can't remove yourself; another user can"}
	}
	if err := s.o.Store.DeleteUser(name); err != nil {
		switch {
		case errors.Is(err, store.ErrNoUser):
			return errUsers{fmt.Sprintf("there is no user named %s", name)}
		case errors.Is(err, store.ErrLastUser):
			return errUsers{"the last user can't be removed"}
		}
		return err
	}
	s.sessions.DeleteUser(name, "")
	s.audit(r, "user.remove", name)
	return nil
}

// ---------------------------------------------------------------------------
// Settings forms

func (s *Server) userForm(w http.ResponseWriter, r *http.Request, done func() (string, error)) {
	msg, err := done()
	if err != nil {
		s.renderSettings(w, r, "", upperFirst(err.Error())+".")
		return
	}
	s.renderSettings(w, r, msg, "")
}

func (s *Server) addUserForm(w http.ResponseWriter, r *http.Request) {
	s.userForm(w, r, func() (string, error) {
		name := r.PostFormValue("name")
		if r.PostFormValue("password") != r.PostFormValue("confirm") {
			return "", errUsers{"the passwords are not the same"}
		}
		if err := s.addUser(r, name, r.PostFormValue("password")); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s was added. Give them the password; they can change it under Settings.", name), nil
	})
}

func (s *Server) userPasswordForm(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.userForm(w, r, func() (string, error) {
		if r.PostFormValue("password") != r.PostFormValue("confirm") {
			return "", errUsers{"the passwords are not the same"}
		}
		if err := s.setUserPassword(r, name, r.PostFormValue("password")); err != nil {
			return "", err
		}
		return fmt.Sprintf("The password of %s was set, and %s was signed out everywhere.", name, name), nil
	})
}

func (s *Server) removeUserForm(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.userForm(w, r, func() (string, error) {
		if err := s.removeUser(r, name); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s was removed and signed out everywhere.", name), nil
	})
}

// ---------------------------------------------------------------------------
// API

type apiUser struct {
	Name       string     `json:"name"`
	SignedIn   int        `json:"signedIn"`
	Created    time.Time  `json:"created"`
	CreatedBy  string     `json:"createdBy,omitempty"`
	LastSignIn *time.Time `json:"lastSignIn,omitempty"`
}

func (s *Server) apiUsers(w http.ResponseWriter, _ *http.Request) {
	us, err := s.o.Store.Users()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	live := s.sessions.SignedIn()
	out := []apiUser{}
	for _, u := range us {
		out = append(out, apiUser{Name: u.Name, SignedIn: live[u.Name], Created: u.Created, CreatedBy: u.CreatedBy, LastSignIn: u.LastSignIn})
	}
	writeJSON(w, http.StatusOK, out)
}

type userRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func writeUserError(w http.ResponseWriter, err error) {
	var ue errUsers
	if errors.As(err, &ue) {
		writeError(w, http.StatusBadRequest, ue.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func (s *Server) apiAddUser(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if err := readJSON(r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.addUser(r, req.Name, req.Password); err != nil {
		writeUserError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) apiUserPassword(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if err := readJSON(r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.setUserPassword(r, r.PathValue("name"), req.Password); err != nil {
		writeUserError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiRemoveUser(w http.ResponseWriter, r *http.Request) {
	if err := s.removeUser(r, r.PathValue("name")); err != nil {
		writeUserError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
