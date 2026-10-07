package report

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ipv4 = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b`)
	// ipv6 matches the full form and forms with "::"; net.ParseIP then
	// decides, so times like 12:34:56 and MAC addresses never match.
	ipv6 = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){0,7}:(?::?[0-9a-f]{1,4}){0,7}`)
)

// ipMasker replaces IP addresses with names that stay the same across the
// report: the same address is ip-3 in every file, so relations stay
// visible. Loopback and unspecified addresses are kept: they say nothing
// about the network.
type ipMasker struct {
	names map[string]string
	v4    int
	v6    int
}

func newIPMasker() *ipMasker { return &ipMasker{names: map[string]string{}} }

// IPMasker replaces IP addresses with names that stay the same across the
// texts it masks (ip-1, ip-2, …).
type IPMasker struct{ m *ipMasker }

// NewIPMasker returns a masker with no names given yet.
func NewIPMasker() *IPMasker { return &IPMasker{m: newIPMasker()} }

// Mask replaces the IP addresses in s.
func (m *IPMasker) Mask(s string) string { return m.m.mask(s) }

func (m *ipMasker) mask(s string) string {
	s = m.replace(s, ipv4, false)
	if strings.Contains(s, ":") {
		s = m.replace(s, ipv6, true)
	}
	return s
}

func (m *ipMasker) replace(s string, re *regexp.Regexp, v6 bool) string {
	locs := re.FindAllStringIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		addr := s[l[0]:l[1]]
		if !m.standalone(s, l[0], l[1], v6) {
			continue
		}
		ip := net.ParseIP(addr)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		b.WriteString(s[last:l[0]])
		b.WriteString(m.name(ip.String(), v6))
		last = l[1]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// standalone says the match isn't part of a longer word or number, such as
// the version 1.2.3.4.5 or an identifier like Foo::Bar.
func (m *ipMasker) standalone(s string, start, end int, v6 bool) bool {
	if start > 0 {
		c := s[start-1]
		if isWord(c) || c == '.' || (v6 && c == ':') {
			return false
		}
	}
	if end < len(s) {
		c := s[end]
		if isWord(c) || (c == '.' && end+1 < len(s) && s[end+1] >= '0' && s[end+1] <= '9') {
			return false
		}
	}
	return end-start > 2
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func (m *ipMasker) name(addr string, v6 bool) string {
	if n, ok := m.names[addr]; ok {
		return n
	}
	var n string
	if v6 {
		m.v6++
		n = fmt.Sprintf("ip6-%d", m.v6)
	} else {
		m.v4++
		n = fmt.Sprintf("ip-%d", m.v4)
	}
	m.names[addr] = n
	return n
}

// count is how many different addresses were replaced.
func (m *ipMasker) count() int { return len(m.names) }
