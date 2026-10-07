package remedy

import (
	"strings"
	"testing"
)

func TestPatterns(t *testing.T) {
	for _, c := range []struct {
		line, id string
		vars     map[string]string
		title    string
	}{
		{`panic: runtime error: invalid memory address or nil pointer dereference`, "go-nil-pointer", nil, "Go panic: nil pointer dereference"},
		{`panic: config: missing listen address`, "go-panic", map[string]string{"msg": "config: missing listen address"}, "Go panic: config: missing listen address"},
		{`Exception in thread "main" java.lang.OutOfMemoryError: Java heap space`, "java-oom", map[string]string{"kind": "Java heap space"}, "Java out of memory (Java heap space)"},
		{`FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory`, "node-oom", nil, ""},
		{`terminate called after throwing an instance of 'std::bad_alloc'`, "alloc-failed", nil, ""},
		{`FATAL:  password authentication failed for user "shop"`, "db-auth", map[string]string{"user": "shop"}, "Database refused the password of shop"},
		{`ERROR 1045 (28000): Access denied for user 'app'@'10.244.0.12' (using password: YES)`, "db-auth", map[string]string{"user": "app"}, ""},
		{`(error) NOAUTH Authentication required.`, "db-auth", nil, ""},
		{`FATAL:  database "orders" does not exist`, "db-missing", map[string]string{"db": "orders"}, "Database orders doesn't exist"},
		{`error: Dirty database version 17. Fix and force version.`, "migration", nil, ""},
		{`org.flywaydb.core.api.FlywayException: Validate failed: Migrations have failed validation`, "migration", nil, ""},
		{`E0927 pods is forbidden: User "system:serviceaccount:shop:api" cannot list resource "pods" in API group "" in the namespace "shop"`,
			"k8s-forbidden", map[string]string{"sa": "shop:api", "verb": "list", "resource": "pods"}, "Kubernetes API: shop:api may not list pods"},
		{`Get "https://payments:8443/health": http: server gave HTTP response to HTTPS client`, "tls-mismatch", nil, ""},
		{`Post "https://vault.lan/v1/auth": x509: certificate signed by unknown authority`, "tls-unknown-ca", nil, "TLS certificate not trusted"},
		{`ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed`, "tls-unknown-ca", nil, ""},
		{`x509: certificate has expired or is not yet valid: current time 2026-09-27T14:00:00Z is after 2026-09-01T00:00:00Z`, "tls-expired", nil, ""},
		{`x509: certificate is valid for db.internal, db, not postgres.shop.svc`, "tls-name", map[string]string{"host": "postgres.shop.svc"}, "TLS certificate doesn't match postgres.shop.svc"},
		{`failed to connect to database: dial tcp 10.96.14.2:5432: connect: connection refused`, "conn-refused", map[string]string{"target": "10.96.14.2:5432"}, "Connection refused by 10.96.14.2:5432"},
		{`Error: connect ECONNREFUSED 10.96.0.20:6379`, "conn-refused", map[string]string{"target": "10.96.0.20:6379"}, ""},
		{`psycopg2.OperationalError: connection to server at "postgres" (10.96.14.2), port 5432 failed: Connection refused`, "conn-refused", map[string]string{"target": "postgres"}, ""},
		{`java.net.ConnectException: Connection refused (Connection refused)`, "conn-refused", nil, "Connection refused by a service"},
		{`dial tcp: lookup postgresql on 10.96.0.10:53: no such host`, "dns", map[string]string{"host": "postgresql"}, "Name not found: postgresql"},
		{`java.net.UnknownHostException: kafka-0.kafka`, "dns", map[string]string{"host": "kafka-0.kafka"}, ""},
		{`nginx: [emerg] host not found in upstream "backend" in /etc/nginx/conf.d/default.conf:12`, "dns", map[string]string{"host": "backend"}, ""},
		{`socket.gaierror: [Errno -3] Temporary failure in name resolution`, "dns", nil, "Name not found: a host name"},
		{`dial tcp 10.0.3.7:443: connect: no route to host`, "no-route", map[string]string{"target": "10.0.3.7:443"}, ""},
		{`dial tcp 10.96.3.1:9092: i/o timeout`, "timeout", map[string]string{"target": "10.96.3.1:9092"}, "Timed out connecting to 10.96.3.1:9092"},
		{`read tcp 10.244.1.5:48210->10.96.0.20:6379: read: connection reset by peer`, "conn-reset", nil, ""},
		{`open /data/app.db: permission denied`, "perm-denied", map[string]string{"path": "/data/app.db"}, "Permission denied: /data/app.db"},
		{`initdb: error: could not change permissions of directory "/var/lib/postgresql/data": Operation not permitted`, "", nil, ""},
		{`FATAL:  data directory "/var/lib/postgresql/data" has wrong ownership`, "perm-denied", map[string]string{"path": "/var/lib/postgresql/data"}, ""},
		{`Error: EACCES: permission denied, mkdir '/app/cache'`, "perm-denied", map[string]string{"path": "/app/cache"}, ""},
		{`mkdir /tmp/uploads: read-only file system`, "read-only-fs", nil, ""},
		{`write /var/log/app.log: no space left on device`, "disk-full", nil, ""},
		{`open /etc/app/config.yaml: no such file or directory`, "no-such-file", map[string]string{"path": "/etc/app/config.yaml"}, "File not found: /etc/app/config.yaml"},
		{`listen tcp :8080: bind: address already in use`, "addr-in-use", nil, ""},
		{`accept tcp [::]:8080: accept4: too many open files`, "too-many-files", nil, ""},
		{`exec /app/server: exec format error`, "exec-format", nil, "Image built for another CPU"},
		{`/bin/sh: 1: ./start.sh: not found`, "exec-not-found", map[string]string{"cmd": "./start.sh"}, ""},
		{`ModuleNotFoundError: No module named 'psycopg2'`, "code-missing", map[string]string{"mod": "psycopg2"}, "Code missing from the image: psycopg2"},
		{`Error: Cannot find module '/app/dist/main.js'`, "code-missing", map[string]string{"mod": "/app/dist/main.js"}, ""},
		{`config error: environment variable DATABASE_URL is not set`, "missing-setting", map[string]string{"name": "DATABASE_URL"}, "Setting DATABASE_URL is missing"},
		{`fatal: SMTP_HOST is required`, "missing-setting", map[string]string{"name": "SMTP_HOST"}, ""},
		{`KeyError: 'REDIS_URL'`, "missing-setting", map[string]string{"name": "REDIS_URL"}, ""},
		{`TLS is required for this listener`, "", nil, ""},
		{`error parsing config: yaml: line 12: did not find expected key`, "config-syntax", nil, ""},
		{`***************************`, "", nil, ""},
		{`APPLICATION FAILED TO START`, "spring-failed", nil, ""},
		{`Segmentation fault (core dumped)`, "segfault", nil, ""},
		{`ValueError: invalid literal for int() with base 10: 'abc'`, "exception", map[string]string{"exc": "ValueError", "msg": "invalid literal for int() with base 10: 'abc'"}, ""},
		{`2026-09-27 level=info msg="listening on :8080"`, "", nil, ""},
	} {
		ms := Find(c.line)
		if c.id == "" {
			if len(ms) != 0 {
				t.Errorf("%q: matched %s, want nothing", c.line, ms[0].ID)
			}
			continue
		}
		if len(ms) == 0 || ms[0].ID != c.id {
			t.Errorf("%q: got %+v, want %s", c.line, ms, c.id)
			continue
		}
		for k, v := range c.vars {
			if ms[0].Var(k) != v {
				t.Errorf("%q: %s = %q, want %q", c.line, k, ms[0].Var(k), v)
			}
		}
		if c.title != "" && ms[0].Title() != c.title {
			t.Errorf("%q: title %q, want %q", c.line, ms[0].Title(), c.title)
		}
		p := ms[0].Pattern()
		if p.Title == "" || p.Cause == "" || p.Hint == "" || p.Plain == "" || p.PlainHint == "" {
			t.Errorf("pattern %s lacks a text", p.ID)
		}
	}
}

func TestFindInALog(t *testing.T) {
	log := `2026-09-27T13:58:01Z starting shop-api v2.4.1
2026-09-27T13:58:01Z connecting to postgres:5432
2026-09-27T13:58:02Z ERROR db: dial tcp 10.96.14.2:5432: connect: connection refused
2026-09-27T13:58:04Z ERROR db: dial tcp 10.96.14.2:5432: connect: connection refused
2026-09-27T13:58:06Z retry failed: Connection refused
2026-09-27T13:58:06Z panic: giving up after 3 attempts: connection refused
goroutine 1 [running]:
main.main()`
	ms := Find(log)
	if len(ms) != 2 || ms[0].ID != "conn-refused" || ms[1].ID != "go-panic" {
		t.Fatalf("matches = %+v", ms)
	}
	// The most specific expression's last match gives the address.
	if ms[0].Var("target") != "10.96.14.2:5432" || ms[0].Count != 4 || !strings.Contains(ms[0].Line, "13:58:04Z") {
		t.Errorf("conn-refused = %+v", ms[0])
	}
	// The catch-all only counts when nothing else matched.
	if ms := Find("RuntimeError: boom\ndial tcp 1.2.3.4:80: connect: connection refused"); len(ms) != 1 || ms[0].ID != "conn-refused" {
		t.Errorf("fallback with a specific match: %+v", ms)
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		`connecting with password=hunter22 to db`:                `connecting with password=` + Mask + ` to db`,
		`{"apiKey": "sk-123456", "user": "x"}`:                   `{"apiKey": ` + Mask + `, "user": "x"}`,
		`Authorization: Bearer eyJhbGciOiJIUzI1NiIs.abc`:         `Authorization: Bearer ` + Mask,
		`dial postgres://shop:s3cret@postgres:5432/shop failed`:  `dial postgres://shop:` + Mask + `@postgres:5432/shop failed`,
		`FATAL:  password authentication failed for user "shop"`: `FATAL:  password authentication failed for user "shop"`,
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	if ms := Find(`failed: dial tcp 10.0.0.5:5432 with token=abcdef123: connect: connection refused`); len(ms) != 1 || strings.Contains(ms[0].Line, "abcdef123") {
		t.Errorf("the matched line keeps a token: %+v", ms)
	}
}

func TestRedactText(t *testing.T) {
	in := `start DB_PASSWORD=hunter2 api_key: "k-123" token=abc
Authorization: Bearer abcdefghijklmnop
url postgres://app:Sup3rSecret@db:5432/pay
jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl
aws AKIAABCDEFGHIJKLMNOP
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA
-----END RSA PRIVATE KEY-----
SecretName: app-tls
tokenFile=/var/run/secrets/token
DB_PASSWORD:  <set to the key 'password' in secret 'db'>
TokenExpirationSeconds: 3607
echo "token=abcd1234zz"`
	out := RedactText(in)
	for _, leak := range []string{"hunter2", "k-123", "token=abc", "abcdefghijklmnop", "Sup3rSecret", "eyJhbGciOiJIUzI1NiJ9", "AKIAABCDEFGHIJKLMNOP", "MIIEowIBAAKCAQEA"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q not masked:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"SecretName: app-tls", "tokenFile=/var/run/secrets/token", "<set to the key 'password' in secret 'db'>", "TokenExpirationSeconds: 3607", "DB_PASSWORD=" + Mask, "BEGIN RSA PRIVATE KEY", `echo "token=` + Mask + `"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q missing:\n%s", keep, out)
		}
	}
}
