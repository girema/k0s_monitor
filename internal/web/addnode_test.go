package web

import (
	"html"
	"strings"
	"testing"
)

func TestAddNodeGuide(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	resp := env.do("GET", "/c/edge-prod/servers?mode=basic", nil, nil)
	mustContain(t, readBody(t, resp), `href="/c/edge-prod/servers/add">Add a server`)

	resp = env.do("GET", "/c/edge-prod/servers/add?mode=full", nil, nil)
	body := html.UnescapeString(readBody(t, resp))
	// The controllers' version (this fake cluster reports none), the token
	// command on a controller, the install on the new server, and the
	// ports; never a token itself.
	mustContain(t, body, "Join a worker", "the controllers' k0s version", "Install the same k0s version as the controllers", "sudo k0s token create --role=worker --expiry=1h > worker-token",
		"sudo k0s install worker --token-file ./worker-token", "k0s kubectl get nodes -o wide", "6443/TCP", "8132/TCP",
		"shred -u worker-token", "Adding a controller", "--role=controller")
	resp = env.do("GET", "/c/edge-prod/servers/add?mode=basic", nil, nil)
	body = readBody(t, resp)
	mustContain(t, body, "Add a server", "Create a key that lets the new server join", "What the new server needs")
	if strings.Contains(body, "Adding a controller") {
		t.Error("Basic mode shows how to add a controller")
	}
}

func TestAddNodeFromPack(t *testing.T) {
	env := newPackEnv(t)
	resp := env.do("GET", "/c/edge-prod/servers/add?mode=basic", nil, nil)
	body := readBody(t, resp)
	mustContain(t, body, "How your product adds a server", "from the product pack shop", "Servers for the Shop are added with the Shop installer",
		"sudo shop-installer add-node --cluster shop-prod", "Shop installer: adding a server")
	if strings.Contains(body, "k0s token create") {
		t.Error("Basic mode shows the k0s commands next to the pack's procedure")
	}
	// The pack's version is the one to install.
	resp = env.do("GET", "/c/edge-prod/servers/add?mode=full", nil, nil)
	mustContain(t, html.UnescapeString(readBody(t, resp)), "The k0s commands, for reference", "k0s v1.36.4+k0s.1", "Install k0s v1.36.4+k0s.1 on the new server")
}
