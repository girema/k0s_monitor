package web

import (
	"encoding/json"
	"sync"
)

// message is one server-sent event.
type message struct {
	Event   string
	Cluster string
	Data    []byte
	// User, when set, is the only user whose browsers get it.
	User string
}

// hub fans messages out to the browsers that follow the SSE stream.
type hub struct {
	mu   sync.Mutex
	subs map[chan message]string // the user of each browser
}

func newHub() *hub { return &hub{subs: map[chan message]string{}} }

func (h *hub) subscribe(user string) chan message {
	ch := make(chan message, 64)
	h.mu.Lock()
	h.subs[ch] = user
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan message) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// publish sends to every subscriber. A browser that can't keep up misses
// messages rather than slowing down the engines; the page refreshes from
// the latest state anyway.
func (h *hub) publish(event, cluster string, v any) {
	h.send(message{Event: event, Cluster: cluster}, v)
}

// publishTo sends to one user's browsers only.
func (h *hub) publishTo(user, event string, v any) {
	h.send(message{Event: event, User: user}, v)
}

func (h *hub) send(m message, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	m.Data = data
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch, user := range h.subs {
		if m.User != "" && m.User != user {
			continue
		}
		select {
		case ch <- m:
		default:
		}
	}
}

func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
