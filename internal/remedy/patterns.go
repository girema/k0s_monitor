// Package remedy explains why things fail: known messages in logs, exit
// codes, and what a rollout changed (plan section 8.4).
package remedy

import (
	"regexp"
	"strings"
)

// Pattern is a known log message: what it means and what to check.
// Texts may name the pattern's captured parts as {name}, or {name|words}
// with words for when the part wasn't captured.
type Pattern struct {
	ID string
	// Title is a short technical summary, Cause the likely cause and Hint
	// what to check (Full mode).
	Title, Cause, Hint string
	// Plain says what happened and PlainHint what to do (Basic mode).
	Plain, PlainHint string
	res              []*regexp.Regexp
	// fallback patterns only count when no other one matches.
	fallback bool
}

// Match is a pattern found in a log: the last line it matched, and how
// many lines did.
type Match struct {
	ID    string            `json:"id"`
	Line  string            `json:"line"`
	Vars  map[string]string `json:"vars,omitempty"`
	Count int               `json:"count"`
}

// Pattern returns the matched pattern.
func (m Match) Pattern() *Pattern { return Lookup(m.ID) }

// Title, Cause, Hint, Plain and PlainHint are the pattern's texts with the
// captured parts filled in.
func (m Match) Title() string     { return fill(m.Pattern().Title, m.Vars) }
func (m Match) Cause() string     { return fill(m.Pattern().Cause, m.Vars) }
func (m Match) Hint() string      { return fill(m.Pattern().Hint, m.Vars) }
func (m Match) Plain() string     { return fill(m.Pattern().Plain, m.Vars) }
func (m Match) PlainHint() string { return fill(m.Pattern().PlainHint, m.Vars) }

// Var returns a captured part, or "".
func (m Match) Var(name string) string { return m.Vars[name] }

var placeholder = regexp.MustCompile(`\{(\w+)(?:\|([^}]*))?\}`)

func fill(text string, vars map[string]string) string {
	return placeholder.ReplaceAllStringFunc(text, func(p string) string {
		sub := placeholder.FindStringSubmatch(p)
		if v := vars[sub[1]]; v != "" {
			return v
		}
		return sub[2]
	})
}

func res(exprs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(exprs))
	for i, e := range exprs {
		out[i] = regexp.MustCompile(e)
	}
	return out
}

// Patterns are checked in this order: the specific ones first.
var Patterns = []*Pattern{
	{
		ID:    "go-nil-pointer",
		Title: "Go panic: nil pointer dereference",
		Cause: "A bug in the program: it used a value that was never set, often a setting that is missing or a connection that failed without being checked.",
		Hint:  "The stack trace after the panic names the function. Check the app's settings and the services it needs first.",
		Plain: "The program crashed because of an error in the program itself.", PlainHint: "Send the report to your support team: it contains the error.",
		res: res(`invalid memory address or nil pointer dereference`),
	},
	{
		ID:    "java-oom",
		Title: "Java out of memory ({kind})",
		Cause: "The Java heap is too small for the work, or the app keeps memory it no longer needs. This is the heap limit inside the JVM, not the container's memory limit.",
		Hint:  "Raise the heap (-Xmx, or -XX:MaxRAMPercentage) together with the container's memory limit, or find what fills it.",
		Plain: "The app ran out of memory.", PlainHint: "It needs more memory. This is set in the app's configuration, which comes with your product: send the report to your support team.",
		res: res(`java\.lang\.OutOfMemoryError: (?P<kind>[^\r\n]+)`),
	},
	{
		ID:    "node-oom",
		Title: "Node.js out of memory",
		Cause: "The JavaScript heap reached its limit.",
		Hint:  "Raise --max-old-space-size together with the container's memory limit, or find what fills it.",
		Plain: "The app ran out of memory.", PlainHint: "It needs more memory. This is set in the app's configuration, which comes with your product: send the report to your support team.",
		res: res(`JavaScript heap out of memory`),
	},
	{
		ID:    "alloc-failed",
		Title: "Memory allocation failed",
		Cause: "The program couldn't get memory: the container's memory limit or the node is exhausted.",
		Hint:  "Compare the container's memory use with its limit (Full mode, Workloads).",
		Plain: "The app couldn't get the memory it needs.", PlainHint: "It needs more memory, or the server it runs on is full. Send the report to your support team.",
		res: res(`std::bad_alloc`, `Cannot allocate memory`, `^MemoryError\b`),
	},
	{
		ID:    "db-auth",
		Title: "Database refused the password of {user|the app}",
		Cause: "The user name or password the app uses doesn't match the database's: a changed Secret, or a database created earlier with another password (for example on a volume that was kept).",
		Hint:  "Compare the password in the app's Secret with the one the database was created with.",
		Plain: "The database doesn't accept the app's password.", PlainHint: "The app's password and the database's differ. Send the report to your support team.",
		res: res(`password authentication failed for user "(?P<user>[^"]+)"`,
			`Access denied for user '(?P<user>[^']+)'`,
			`Login failed for user '(?P<user>[^']+)'`,
			`NOAUTH Authentication required`, `WRONGPASS invalid username-password`,
			`MongoServerError: Authentication failed`, `SCRAM authentication failed`),
	},
	{
		ID:    "db-missing",
		Title: "Database {db} doesn't exist",
		Cause: "The app connects to a database that was never created, or to the wrong server.",
		Hint:  "Check the database name in the app's settings, and that the database server's first-start setup ran.",
		Plain: "The database the app expects isn't there.", PlainHint: "Send the report to your support team.",
		res: res(`database "(?P<db>[^"]+)" does not exist`, `Unknown database '(?P<db>[^']+)'`),
	},
	{
		ID:    "migration",
		Title: "Database migration failed",
		Cause: "The database schema upgrade at start-up failed, often because an earlier upgrade was interrupted. The app refuses to start until it is fixed.",
		Hint:  "The lines before this one name the failing migration. Don't delete data: a failed migration usually needs a manual fix.",
		Plain: "The app couldn't upgrade its database, so it doesn't start.", PlainHint: "Send the report to your support team; don't delete any data.",
		res: res(`(?i)\bmigrations? (?:\S+ )?(?:failed|error)`, `(?i)failed to (?:apply|run) migrations?`,
			`Dirty database version`, `FlywayException`, `LiquibaseException`),
	},
	{
		ID:    "k8s-forbidden",
		Title: "Kubernetes API: {sa} may not {verb} {resource}",
		Cause: "The app talks to the Kubernetes API, and its service account lacks a permission (RBAC).",
		Hint:  "Grant the permission with a Role or ClusterRole bound to {sa}. The app's installation usually brings it.",
		Plain: "The app isn't allowed to read something from the cluster it needs.", PlainHint: "A permission is missing from the app's installation. Send the report to your support team.",
		res: res(`is forbidden: User "system:serviceaccount:(?P<sa>[^"]+)" cannot (?P<verb>\w+) resource "(?P<resource>[^"]+)"`),
	},
	{
		ID:    "tls-mismatch",
		Title: "TLS and plain HTTP mixed up",
		Cause: "One side speaks TLS and the other plain HTTP: an https:// address for a plain port, or the reverse.",
		Hint:  "Check the scheme and port in the address the app connects to.",
		Plain: "The app and the service it connects to don't agree on encryption.", PlainHint: "The address in the app's settings probably has the wrong scheme or port. Send the report to your support team.",
		res: res(`server gave HTTP response to HTTPS client`, `first record does not look like a TLS handshake`,
			`WRONG_VERSION_NUMBER`, `wrong version number`),
	},
	{
		ID:    "tls-unknown-ca",
		Title: "TLS certificate not trusted",
		Cause: "The server's certificate is signed by a certificate authority the app doesn't trust, usually a private CA missing from the app's trust store.",
		Hint:  "Add the CA to the app's trust store (a mounted CA bundle), or connect with the name the certificate is for.",
		Plain: "The app doesn't trust the security certificate of a service it connects to.", PlainHint: "Send the report to your support team.",
		res: res(`x509: certificate signed by unknown authority`, `unable to find valid certification path`,
			`CERTIFICATE_VERIFY_FAILED`, `self[- ]signed certificate in certificate chain`, `unable to get local issuer certificate`),
	},
	{
		ID:    "tls-expired",
		Title: "TLS certificate expired",
		Cause: "A certificate the app uses or checks has expired.",
		Hint:  "Renew it; the line says which server or file.",
		Plain: "A security certificate has expired.", PlainHint: "It must be renewed. Send the report to your support team.",
		res: res(`x509: certificate has expired`, `certificate has expired`, `CertificateExpiredException`),
	},
	{
		ID:    "tls-name",
		Title: "TLS certificate doesn't match {host|the address}",
		Cause: "The app connects to {host|an address} that isn't one of the names in the server's certificate.",
		Hint:  "Connect with a name the certificate lists, or reissue the certificate with this one.",
		Plain: "A security certificate doesn't match the address the app uses.", PlainHint: "Send the report to your support team.",
		res: res(`x509: certificate is valid for .+?, not (?P<host>[^\s,]+)`, `Hostname (?P<host>\S+) not verified`,
			`doesn't match any of the subject alternative names`, `Hostname mismatch`),
	},
	{
		ID:    "conn-refused",
		Title: "Connection refused by {target|a service}",
		Cause: "Nothing listens at {target|the address the app connects to}: the service it depends on isn't running or not ready yet, or the address or port is wrong.",
		Hint:  "Check that the Service behind {target|it} has ready endpoints, and that the port is right.",
		Plain: "The app can't reach {target|another service} it needs: the connection is refused.", PlainHint: "Check that the service it depends on runs, for example its database. If it does, the address in the app's settings may be wrong.",
		res: res(`dial tcp (?P<target>[^\s:]+:\d+): connect: connection refused`,
			`connect ECONNREFUSED (?P<target>\S+:\d+)`,
			`connection to server at "(?P<target>[^"]+)".*Connection refused`,
			`(?i)connection refused`, `ConnectionRefusedError`, `ECONNREFUSED`),
	},
	{
		ID:    "dns",
		Title: "Name not found: {host|a host name}",
		Cause: "The name {host|the app uses} doesn't resolve: no Service of that name exists in the namespace, it is misspelled, or the cluster's DNS doesn't work.",
		Hint:  "A Service in another namespace needs name.namespace. Check the name, and that CoreDNS runs.",
		Plain: "The app looks for {host|another service} by name and can't find it.", PlainHint: "The name in the app's settings may be wrong, or the service it needs is missing.",
		res: res(`lookup (?P<host>[^\s:]+)(?: on \S+)?: no such host`, `UnknownHostException: (?P<host>[^\s:]+)`,
			`getaddrinfo (?:ENOTFOUND|EAI_AGAIN) (?P<host>\S+)`, `host not found in upstream "(?P<host>[^"]+)"`,
			`Name or service not known`, `Temporary failure in name resolution`, `nodename nor servname provided`),
	},
	{
		ID:    "no-route",
		Title: "No route to {target|a service}",
		Cause: "The network has no path there: a NetworkPolicy, a network problem on the node, or an address outside the cluster that can't be reached.",
		Hint:  "Check the NetworkPolicies of the namespace, and whether other pods on that node reach it.",
		Plain: "The app can't reach {target|another service}: the network has no way there.", PlainHint: "Send the report to your support team.",
		res: res(`dial tcp (?P<target>[^\s:]+:\d+): connect: no route to host`, `(?i)no route to host`,
			`(?i)network is unreachable`, `EHOSTUNREACH`, `ENETUNREACH`),
	},
	{
		ID:    "timeout",
		Title: "Timed out connecting to {target|a service}",
		Cause: "No answer: a NetworkPolicy or firewall drops the traffic, the target is overloaded, or its address is wrong.",
		Hint:  "Check the address, the NetworkPolicies of both namespaces, and whether the target answers from another pod.",
		Plain: "The app waits for an answer from {target|another service} and gets none.", PlainHint: "Check that the service it depends on runs. Otherwise send the report to your support team.",
		res: res(`dial tcp (?P<target>[^\s:]+:\d+): i/o timeout`, `(?i)connect(?:ion)? timed out`, `\bi/o timeout`,
			`context deadline exceeded`, `ETIMEDOUT`, `SocketTimeoutException`, `(?i)read timed out`),
	},
	{
		ID:    "conn-reset",
		Title: "Connection reset",
		Cause: "The other side closed the connection: it crashed or restarted, a proxy cut it, or TLS and plain HTTP are mixed up.",
		Hint:  "Check the logs of the service it connects to at the same time.",
		Plain: "A service the app talks to breaks off the connection.", PlainHint: "Check that the service it depends on runs normally.",
		res: res(`connection reset by peer`, `ECONNRESET`, `Connection reset`),
	},
	{
		ID:    "perm-denied",
		Title: "Permission denied: {path|a file}",
		Cause: "The container's user may not open {path|a file}: a volume owned by another user (often after runAsUser or fsGroup changed), or files from an image built for another user.",
		Hint:  "Set securityContext.fsGroup or runAsUser to match the files' owner, or fix the owner on the volume.",
		Plain: "The app isn't allowed to open {path|one of its files}.", PlainHint: "The permissions of its storage need fixing. Send the report to your support team.",
		res: res(`open (?P<path>/\S+): permission denied`, `mkdir (?P<path>/\S+): permission denied`,
			`EACCES: permission denied, \w+ '(?P<path>[^']+)'`, `PermissionError: \[Errno 13\] Permission denied: '(?P<path>[^']+)'`,
			`could not open file "(?P<path>[^"]+)": Permission denied`, `Permission denied: '(?P<path>[^']+)'`,
			`data directory "(?P<path>[^"]+)" has wrong ownership`),
	},
	{
		ID:    "read-only-fs",
		Title: "Read-only file system",
		Cause: "The app writes where it may not: readOnlyRootFilesystem is set, or a volume is mounted read-only.",
		Hint:  "Mount a writable emptyDir at the path it writes to, or make the volume writable.",
		Plain: "The app tries to write where it isn't allowed to.", PlainHint: "Send the report to your support team.",
		res: res(`(?i)read-only file system`, `EROFS`),
	},
	{
		ID:    "disk-full",
		Title: "No space left on device",
		Cause: "The volume or the node's disk it writes to is full.",
		Hint:  "See the Storage page for the volume, or the Nodes & VMs page for the node's disk.",
		Plain: "The disk the app writes to is full.", PlainHint: "See the Storage page. Freeing space or a larger volume fixes it.",
		res: res(`(?i)no space left on device`, `ENOSPC`, `could not extend file`),
	},
	{
		ID:    "no-such-file",
		Title: "File not found: {path|a file}",
		Cause: "{path|A file the app needs} doesn't exist in the container: a ConfigMap or Secret isn't mounted there, a key is missing, or a volume is missing.",
		Hint:  "Compare the path with the pod's volume mounts, and the ConfigMap or Secret keys.",
		Plain: "A file the app needs is missing.", PlainHint: "A configuration file is probably missing. Send the report to your support team.",
		res: res(`open (?P<path>/\S+): no such file or directory`, `FileNotFoundError: \[Errno 2\] No such file or directory: '(?P<path>[^']+)'`,
			`ENOENT: no such file or directory, \w+ '(?P<path>[^']+)'`, `java\.io\.FileNotFoundException: (?P<path>\S+)`),
	},
	{
		ID:    "addr-in-use",
		Title: "Address already in use",
		Cause: "Two processes want the same port: two containers of the pod, a sidecar, or a pod on the host network colliding with the node.",
		Hint:  "Check the ports of the pod's containers, and hostNetwork.",
		Plain: "Two programs want to use the same network port.", PlainHint: "Send the report to your support team.",
		res: res(`bind: address already in use`, `EADDRINUSE`, `Address already in use`),
	},
	{
		ID:    "too-many-files",
		Title: "Too many open files",
		Cause: "The process reached its open-file limit: it leaks connections or files, or the limit is low.",
		Hint:  "Check the app's connection handling; raise the limit only if the load really needs it.",
		Plain: "The app has too many files and connections open at once.", PlainHint: "Send the report to your support team.",
		res: res(`(?i)too many open files`, `EMFILE`),
	},
	{
		ID:    "exec-format",
		Title: "Image built for another CPU",
		Cause: "The image doesn't match the node's CPU architecture, for example an arm64 image on an amd64 node.",
		Hint:  "Use a multi-architecture image, or one built for this node's architecture.",
		Plain: "The app was built for a different kind of server.", PlainHint: "Send the report to your support team.",
		res: res(`exec format error`),
	},
	{
		ID:    "exec-not-found",
		Title: "Command not found: {cmd|the start command}",
		Cause: "The container's command or a script it runs isn't in the image, or has Windows line endings.",
		Hint:  "Compare the command and args with what the image contains.",
		Plain: "The app's start command isn't in its image.", PlainHint: "The image or its settings are wrong. Send the report to your support team.",
		res: res(`exec: "(?P<cmd>[^"]+)": executable file not found`, `/bin/\w*sh: (?:\d+: )?(?P<cmd>\S+): not found`,
			`exec (?P<cmd>\S+): no such file or directory`),
	},
	{
		ID:    "code-missing",
		Title: "Code missing from the image: {mod}",
		Cause: "The image lacks a module or class the app loads: a broken build, or the wrong image tag.",
		Hint:  "Check the image tag against the app's release.",
		Plain: "Part of the app is missing from its image.", PlainHint: "The wrong version may be installed. Send the report to your support team.",
		res: res(`ModuleNotFoundError: No module named '(?P<mod>[^']+)'`, `Cannot find module '(?P<mod>[^']+)'`,
			`ClassNotFoundException: (?P<mod>\S+)`, `NoClassDefFoundError: (?P<mod>\S+)`),
	},
	{
		ID:    "missing-setting",
		Title: "Setting {name} is missing",
		Cause: "The app needs the setting {name}, usually an environment variable from a ConfigMap or Secret, and it isn't there.",
		Hint:  "Add {name} to the container's env, or the key to the ConfigMap or Secret it comes from.",
		Plain: "A setting the app needs ({name}) is missing.", PlainHint: "Whoever installs or updates the app must add the setting {name}: send them the report for support.",
		res: res(`(?i)(?:environment variable|env var(?:iable)?)\s+["'\x60]?(?P<name>[A-Z][A-Z0-9_]{2,})["'\x60]?\s+(?:is\s+)?(?:not set|required|missing|must be set|empty)`,
			`\b(?P<name>[A-Z][A-Z0-9]*_[A-Z0-9_]+) (?:environment variable )?(?:is )?(?:not set|required|must be set|missing)\b`,
			`KeyError: '(?P<name>[A-Z][A-Z0-9_]{2,})'`),
	},
	{
		ID:    "config-syntax",
		Title: "Configuration can't be read",
		Cause: "A configuration file, usually from a ConfigMap, has a syntax error or a value of the wrong type.",
		Hint:  "The line names the file or position; compare it with the ConfigMap it comes from.",
		Plain: "The app's configuration has a mistake in it.", PlainHint: "Send the report to your support team.",
		res: res(`yaml: line \d+: `, `json: cannot unmarshal`, `invalid character '.' looking for`,
			`(?i)(?:error|failed to) (?:load|pars|read)(?:e|ing)? (?:the )?config(?:uration)?`, `nginx: \[emerg\]`),
	},
	{
		ID:    "spring-failed",
		Title: "Spring Boot application failed to start",
		Cause: "The lines after APPLICATION FAILED TO START name the setting or dependency that is wrong.",
		Hint:  "Read the Description and Action lines that follow in the log.",
		Plain: "The app found a problem in its settings and didn't start.", PlainHint: "Send the report to your support team.",
		res: res(`APPLICATION FAILED TO START`),
	},
	{
		ID:    "segfault",
		Title: "Segmentation fault",
		Cause: "The program crashed in native code: a bug, a library that doesn't match, or memory corruption.",
		Hint:  "Check whether the image changed; the crash is inside the program.",
		Plain: "The program crashed because of an error in the program itself.", PlainHint: "Send the report to your support team.",
		res: res(`Segmentation fault`, `SIGSEGV`, `segfault at`),
	},
	{
		ID:    "go-panic",
		Title: "Go panic: {msg}",
		Cause: "The program stopped on an error it didn't handle.",
		Hint:  "The stack trace after the panic names the function.",
		Plain: "The program crashed because of an error it didn't expect.", PlainHint: "Send the report to your support team: it contains the error.",
		res: res(`(?:^|\s)panic: (?P<msg>.+)$`),
	},
	{
		ID:    "exception",
		Title: "{exc}: {msg}",
		Cause: "The app stopped on an error it didn't handle; the message says what failed.",
		Hint:  "The lines around it in the log say where.",
		Plain: "The app stopped because of an error.", PlainHint: "Send the report to your support team: it contains the error.",
		res:      res(`(?:^|\s)(?P<exc>(?:[\w$]+\.)*\w*(?:Error|Exception)): (?P<msg>\S.*)$`),
		fallback: true,
	},
}

var byID = func() map[string]*Pattern {
	m := map[string]*Pattern{}
	for _, p := range Patterns {
		m[p.ID] = p
	}
	return m
}()

// Lookup returns a pattern by its ID; an unknown ID gets an empty one.
func Lookup(id string) *Pattern {
	if p := byID[id]; p != nil {
		return p
	}
	return &Pattern{ID: id}
}

// maxMatches is how many different patterns Find reports.
const maxMatches = 3

// Find returns the known patterns in a log, most specific first. Each
// comes with the last line its most specific expression matched (secrets
// masked), and how many lines matched it.
func Find(log string) []Match {
	lines := strings.Split(log, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	var out []Match
	for _, p := range Patterns {
		if p.fallback && len(out) > 0 {
			continue
		}
		count := 0
		for _, line := range lines {
			for _, re := range p.res {
				if re.MatchString(line) {
					count++
					break
				}
			}
		}
		if count == 0 {
			continue
		}
		m := Match{ID: p.ID, Count: count}
	search:
		for _, re := range p.res {
			for i := len(lines) - 1; i >= 0; i-- {
				sub := re.FindStringSubmatch(lines[i])
				if sub == nil {
					continue
				}
				m.Line = Redact(lines[i])
				for j, name := range re.SubexpNames() {
					if name != "" && sub[j] != "" {
						if m.Vars == nil {
							m.Vars = map[string]string{}
						}
						m.Vars[name] = Redact(truncate(strings.TrimSpace(sub[j]), 120))
					}
				}
				break search
			}
		}
		out = append(out, m)
		if len(out) == maxMatches {
			break
		}
	}
	return out
}

var (
	// secretPair is "name=value" or "name: value" where the name holds a
	// secret word, also inside a longer name such as DB_PASSWORD.
	secretPair = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?)[A-Za-z0-9_.-]*)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&<({\["'][^\s,;&"']*)`)
	bearer     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	urlUser    = regexp.MustCompile(`(://[^:/@\s]+:)([^@\s]+)(@)`)
	privateKey = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
	jwt        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	awsKey     = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
)

// Redact masks what looks like a password, token or key in a log line,
// and shortens it.
func Redact(line string) string {
	return truncate(RedactText(line), 300)
}

// RedactText masks what looks like a password, token or key in a text of
// any length, such as a log or `kubectl describe` output: values of
// secret-looking names, bearer and basic credentials, passwords in URLs,
// private keys, JSON web tokens and cloud access keys.
func RedactText(text string) string {
	text = privateKey.ReplaceAllString(text, "-----BEGIN ${1}----- "+Mask+" (private key hidden)")
	text = secretPair.ReplaceAllStringFunc(text, maskPair)
	text = bearer.ReplaceAllString(text, "${1} "+Mask)
	text = urlUser.ReplaceAllString(text, "${1}"+Mask+"${3}")
	text = jwt.ReplaceAllString(text, Mask)
	return awsKey.ReplaceAllString(text, Mask)
}

// referenceSuffixes end names that refer to a secret rather than hold one:
// SecretName: app-tls, tokenFile=/var/run/token, passwordRef.
var referenceSuffixes = []string{"name", "names", "ref", "file", "path", "seconds", "secrets"}

func maskPair(m string) string {
	sub := secretPair.FindStringSubmatch(m)
	if sub == nil {
		return m
	}
	key := strings.ToLower(sub[1])
	for _, s := range referenceSuffixes {
		if strings.HasSuffix(key, s) {
			return m
		}
	}
	return sub[1] + sub[2] + Mask
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ErrorLine matches log lines that look like errors.
var ErrorLine = regexp.MustCompile(`(?i)(fatal|panic|error|exception|traceback|failed|failure|refused|denied|forbidden|unauthori[sz]ed|not found|no such|timeout|timed out|killed|out of memory|cannot|can't|unable)`)

// ErrorLines returns the last n lines of a log that look like errors, in
// the order they appeared, with secrets masked.
func ErrorLines(log string, n int) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" || !ErrorLine.MatchString(l) {
			continue
		}
		out = append(out, l)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	for i := range out {
		out[i] = Redact(out[i])
	}
	return out
}
