#!/usr/bin/env bash
# End-to-end test of the web UI, the M1 exit criterion: install k0s-monitor
# on this machine as a systemd service with `init`, sign in, upload cluster
# "a"'s kubeconfig as cluster.config (with the localhost address that only
# works on the controller), fix the address, test the connection, add the
# cluster with k0s-monitor's own read-only account, and check that its
# problems, their plain-language texts, logs and describe output come
# through, that several users work side by side, and that everything
# survives a restart.
#
# Runs after run.sh, on its clusters (KEEP=1). Needs sudo, systemd and jq.
# Usage: make build && KEEP=1 test/e2e/run.sh && test/e2e/web.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN="${BIN:-$ROOT/bin/k0s-monitor}"
WORK="${WORK:-$(mktemp -d)}"
PORT="${PORT:-18443}"
BASE="https://127.0.0.1:$PORT"
ATTEMPTS="${ATTEMPTS:-40}"
JAR="$WORK/web-cookies.txt"
PASSWORD="e2e-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CSRF=""

log() { echo "[web $(date -u +%H:%M:%S)] $*" >&2; }
fail() {
  log "FAIL: $*"
  sudo journalctl -u k0s-monitor --no-pager -n 100 >&2 || true
  exit 1
}
kc() { local c=$1; shift; docker exec -i "k0sm-$c" k0s kubectl "$@"; }

# api METHOD PATH [JSON]: prints the body; the status goes to $WORK/status.
api() {
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --cacert "$WORK/ca.crt" -b "$JAR" -c "$JAR" -X "$method" -o "$WORK/body" -w '%{http_code}'
    -H "Origin: $BASE" -H "X-CSRF-Token: $CSRF")
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' --data-binary "$body"); fi
  curl "${args[@]}" "$BASE$path" > "$WORK/status"
  cat "$WORK/body"
}
status() { cat "$WORK/status"; }
expect_status() { # want
  [ "$(status)" = "$1" ] || fail "want HTTP $1, got $(status): $(head -c 600 "$WORK/body")"
}

wait_healthy() {
  for _ in $(seq 1 60); do
    if curl -sf --cacert "$WORK/ca.crt" "$BASE/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "the service did not answer on $BASE"
}

sign_in() {
  rm -f "$JAR"
  CSRF=$(api POST /api/v1/session "$(jq -n --arg p "$PASSWORD" '{password: $p}')" | jq -r .csrfToken)
  expect_status 200
  [ -n "$CSRF" ] && [ "$CSRF" != null ] || fail "no CSRF token after sign-in"
}

install_service() {
  log "installing k0s-monitor as a systemd service"
  sudo install -m 0755 "$BIN" /usr/local/bin/k0s-monitor
  printf '%s\n' "$PASSWORD" > "$WORK/password"
  # allowFrom names another PC: this machine may always open the UI.
  sudo /usr/local/bin/k0s-monitor init --listen "127.0.0.1:$PORT" --password-file "$WORK/password" --allow-from 192.0.2.10 >&2
  rm -f "$WORK/password"
  # The e2e scenarios are minutes old; report them without the usual waits.
  sudo tee -a /etc/k0s-monitor/config.yaml >/dev/null <<'CFG'
thresholds:
  pendingAfter: 10s
  pvcPendingAfter: 10s
  deploymentUnavailableAfter: 10s
  containerCreatingAfter: 10s
  terminatingAfter: 10s
  notReadyAfter: 10s
  cordonedAfter: 10s
  lbPendingAfter: 10s
  namespaceTerminatingAfter: 10s
CFG
  sudo cat /etc/k0s-monitor/ca.crt > "$WORK/ca.crt"
  sudo grep -q '^allowFrom: \[192.0.2.10\]' /etc/k0s-monitor/config.yaml || fail "init --allow-from did not set allowFrom"
  # The hardened unit: no capabilities, a limited set of system calls.
  for want in 'CapabilityBoundingSet=$' 'SystemCallFilter=@system-service' 'ProtectSystem=strict' 'MemoryDenyWriteExecute=yes'; do
    grep -q "$want" /etc/systemd/system/k0s-monitor.service || fail "the unit lacks $want"
  done
  sudo systemctl daemon-reload
  sudo systemctl enable --now k0s-monitor
  wait_healthy
  log "service is up on $BASE"

  # Secrets on disk: the CA key stays root's, the rest is the service's.
  local perms
  perms=$(sudo sh -c "stat -c '%n %a %U' /etc/k0s-monitor/ca.key /etc/k0s-monitor/secret.key /etc/k0s-monitor/tls.key /var/lib/k0s-monitor/*.db")
  echo "$perms" >&2
  echo "$perms" | grep -q '/etc/k0s-monitor/ca.key 600 root' || fail "ca.key must be 0600 root"
  echo "$perms" | grep -Eq 'secret.key 600 k0s-monitor' || fail "secret.key must be 0600 k0s-monitor"
  if echo "$perms" | grep '\.db ' | grep -vq ' 600 k0s-monitor'; then fail "the database must be 0600 k0s-monitor"; fi
}

check_sign_in() {
  api GET /api/v1/clusters >/dev/null
  expect_status 401
  # /metrics too needs a session (or the token of metricsTokenFile).
  api GET /metrics >/dev/null
  expect_status 401
  api POST /api/v1/session '{"password":"wrong-password"}' >/dev/null
  expect_status 401
  sign_in
  api GET /metrics | grep -q '^k0s_monitor_stream_clients' || fail "/metrics with a session"
  expect_status 200
  log "signed in"
}

add_cluster() {
  # What the product hands out: the admin kubeconfig with a localhost
  # address, which only works on the controller itself.
  docker exec k0sm-a k0s kubeconfig admin |
    sed -E 's#server: https://[^[:space:]]+#server: https://localhost:6443#' > "$WORK/cluster.config"
  local ip
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' k0sm-a)
  local server="https://$ip:6443"

  log "uploading cluster.config"
  local imp draft
  imp=$(api POST /api/v1/clusters/import "$(jq -n --rawfile c "$WORK/cluster.config" '{files: [{name: "cluster.config", content: $c}]}')")
  expect_status 200
  echo "$imp" > "$WORK/import.json"
  draft=$(echo "$imp" | jq -r .draftId)
  [ -n "$draft" ] && [ "$draft" != null ] || fail "no draft: $imp"
  [ "$(echo "$imp" | jq -r '.result.files[0].type')" = kubeconfig ] || fail "cluster.config not detected as a kubeconfig: $imp"
  [ "$(echo "$imp" | jq -r '[.result.contexts[] | select(.loopback)] | length')" -ge 1 ] || fail "the localhost address was not flagged: $imp"

  log "testing the connection as uploaded (localhost), which must fail"
  local rep
  rep=$(api POST /api/v1/clusters/test "$(jq -n --arg d "$draft" '{draftId: $d}')")
  expect_status 200
  [ "$(echo "$rep" | jq -r .ok)" = false ] || fail "localhost:6443 should not work from the jump host: $rep"

  log "testing the connection through $server"
  rep=$(api POST /api/v1/clusters/test "$(jq -n --arg d "$draft" --arg s "$server" '{draftId: $d, server: $s}')")
  expect_status 200
  echo "$rep" > "$WORK/test.json"
  [ "$(echo "$rep" | jq -r .ok)" = true ] || fail "connection test failed: $(echo "$rep" | jq -c '.steps')"
  [ "$(echo "$rep" | jq -r .canCreateAccount)" = true ] || fail "admin credentials should be able to create the read-only account: $rep"
  [ "$(echo "$rep" | jq -r .k0s)" = true ] || fail "k0s not detected: $rep"

  log "adding the cluster with the read-only account"
  local add
  add=$(api POST /api/v1/clusters "$(jq -n --arg d "$draft" --arg s "$server" '{draftId: $d, name: "a", server: $s, account: "readonly"}')")
  expect_status 201
  log "added: $add"

  # The account can read what the rules need; Secrets only through the
  # optional role for certificates and the Secrets pages, asked for by default.
  kc a -n kube-system get serviceaccount k0s-monitor >/dev/null || fail "no k0s-monitor service account"
  local sa=system:serviceaccount:kube-system:k0s-monitor
  [ "$(kc a auth can-i list pods -A --as=$sa)" = yes ] || fail "the read-only account can't list pods"
  [ "$(kc a auth can-i get pods/log -A --as=$sa)" = yes ] || fail "the read-only account can't read logs"
  [ "$(kc a auth can-i list secrets -A --as=$sa)" = yes ] || fail "the read-only account can't read Secrets (the optional role)"
  kc a get clusterrole k0s-monitor:reader -o json | jq -e '[.rules[].resources[]?] | index("secrets") | not' >/dev/null ||
    fail "the reader role itself must not read Secrets"
  [ "$(kc a auth can-i delete pods -A --as=$sa || true)" = no ] || fail "the read-only account must not change anything"
}

wait_for_findings() {
  log "waiting for cluster a's problems"
  grep -E '^a ' "$ROOT/test/e2e/expected.txt" > "$WORK/expected-a.txt"
  local missing=""
  for attempt in $(seq 1 "$ATTEMPTS"); do
    local st
    st=$(api GET /api/v1/clusters/a/health)
    if [ "$(echo "$st" | jq -r .status)" = ok ]; then
      api GET /api/v1/clusters/a/findings | jq -r '.[] | "a \(.ruleId) \(.resource.kind) \(.resource.namespace // "-") \(.resource.name)"' |
        sort -u > "$WORK/web-found.txt"
      missing=$(grep -vxF -f "$WORK/web-found.txt" "$WORK/expected-a.txt" || true)
      if [ -z "$missing" ]; then
        log "attempt $attempt: every expected problem is shown"
        echo "$st" > "$WORK/health.json"
        return 0
      fi
      log "attempt $attempt: still missing $(echo "$missing" | wc -l) problem(s)"
    else
      log "attempt $attempt: cluster status $(echo "$st" | jq -r .status)"
    fi
    sleep 10
  done
  echo "$missing" >&2
  fail "not every problem came through the web UI"
}

check_details() {
  # Everything was readable with the read-only account, Prometheus
  # included (through the Role that adding the cluster granted): no rule
  # skipped.
  local health; health=$(cat "$WORK/health.json")
  [ "$(echo "$health" | jq -r '.info.unreadable // {} | length')" = 0 ] || fail "kinds the read-only account can't read: $(echo "$health" | jq -c .info.unreadable)"
  [ "$(echo "$health" | jq -r '.skippedRules // [] | length')" = 0 ] || fail "skipped rules: $(echo "$health" | jq -c .skippedRules)"
  [ "$(echo "$health" | jq -r '.info.prometheus.state')" = ok ] || fail "Prometheus: $(echo "$health" | jq -c .info.prometheus)"
  log "Prometheus: $(echo "$health" | jq -r '.info.prometheus | "\(.target): \(.message)"')"

  # The Nodes & VMs and Storage pages show what Prometheus said.
  local page
  page=$(api GET "/c/a/servers?mode=full")
  expect_status 200
  for want in "steal " "skew " "95%" "nodefs usage, last 24 h"; do
    grep -qF "$want" <<< "$page" || fail "the Nodes & VMs page lacks '$want'"
  done
  page=$(api GET "/c/a/storage?mode=full&pvc=k0sm-e2e/fill-data")
  expect_status 200
  for want in "fill-data" "filler-" "Only problems"; do
    grep -qF "$want" <<< "$page" || fail "the Storage page lacks '$want'"
  done

  # Prometheus's alerts: the volume's is linked to its problem, the other
  # to none (M5). They fire once Prometheus has evaluated its rules.
  local alerts linked=""
  for _ in $(seq 1 30); do
    alerts=$(api GET "/api/v1/clusters/a/alerts")
    linked=$(echo "$alerts" | jq -r '.alerts[] | select(.name=="E2EVolumeFillingUp") | .findings | length')
    [ -n "$linked" ] && [ "$linked" -gt 0 ] && break
    sleep 5
  done
  [ "$(echo "$alerts" | jq -r .read)" = true ] || fail "the alerts can't be read: $alerts"
  [ -n "$linked" ] && [ "$linked" -gt 0 ] || fail "E2EVolumeFillingUp isn't linked to the volume's problem: $alerts"
  [ "$(echo "$alerts" | jq -r '.alerts[] | select(.name=="E2EUnrelated") | .findings | length')" = 0 ] || fail "E2EUnrelated: $alerts"
  page=$(api GET "/c/a/alerts?mode=basic")
  expect_status 200
  for want in "Monitoring alerts" "E2EVolumeFillingUp" "k0s-monitor found no problem about this."; do
    grep -qF "$want" <<< "$page" || fail "the alerts page lacks '$want'"
  done

  # The Workloads page lists every workload and its pods, with a link to
  # each pod's logs; k0s's own parts only in Full mode or when asked.
  page=$(api GET "/c/a/apps?mode=full")
  expect_status 200
  for want in 'id="app-deploy-k0sm-e2e-crashloop"' 'id="app-sts-k0sm-e2e-sts-broken"' 'id="app-job-k0sm-e2e-job-fails"' \
      'id="app-cj-k0sm-e2e-cron-fails"' 'id="app-pod-k0sm-e2e-stuck-finalizer"' 'id="app-deploy-kube-system-coredns"' \
      "Scaled to 0" "Terminating" '/c/a/pods/k0sm-e2e/crashloop-'; do
    grep -qF "$want" <<< "$page" || fail "the Workloads page lacks '$want'"
  done
  grep -qE 'href="/c/a/pods/k0sm-e2e/crashloop-[a-z0-9-]+#logs"' <<< "$page" || fail "the Workloads page has no link to a pod's logs"
  page=$(api GET "/c/a/apps?mode=basic")
  expect_status 200
  grep -qF 'id="app-deploy-k0sm-e2e-crashloop"' <<< "$page" || fail "the Apps page lacks crashloop"
  grep -qF 'id="app-deploy-kube-system-coredns"' <<< "$page" && fail "Basic mode's Apps page lists kube-system without being asked"
  grep -qF 'id="app-deploy-kube-system-coredns"' <<< "$(api GET "/c/a/apps?mode=basic&system=1")" || fail "the Apps page doesn't show kube-system when asked"
  # A search keeps the matches and hides the rest (the page script can
  # show them again as the search changes).
  page=$(api GET "/c/a/apps?mode=full&q=memhog")
  grep -qE 'id="app-deploy-k0sm-e2e-memhog" data-search="[^"]*" class="collapsed"' <<< "$page" || fail "the search hid memhog"
  grep -qE 'id="app-deploy-k0sm-e2e-crashloop" data-search="[^"]*" class="collapsed hidden"' <<< "$page" || fail "the search for memhog shows crashloop"
  page=$(api GET "/c/a/apps?tab=services&mode=full")
  expect_status 200
  for want in "no-backend" "lb-waits" "No endpoints: scaled to 0"; do
    grep -qF "$want" <<< "$page" || fail "the Services tab lacks '$want'"
  done

  # The k0s system page: cluster a's controller, asked directly with the
  # read-only account, is ready and running; the stopped one comes from
  # the lease run.sh left.
  page=$(api GET "/c/a/k0s?mode=full")
  expect_status 200
  for want in "k0sm-a" "</i>ready<" "</i>running<" "v1.3" " d left" "k0sm-gone" "</i>stopped " "Controller k0sm-gone not running" \
    "Plan <span class=\"mono\">autopilot</span>" "nodes missing" "k0sm-ghost" "</i>not found<"; do
    grep -qF "$want" <<< "$page" || fail "the k0s system page lacks '$want'"
  done
  # The add-on run.sh made, read with the read-only account: its error and
  # its values, without the one that looks secret.
  for want in "Add-ons (Helm charts)" "e2e/missing 0.1.0" "not installed: failed" "token: ••••••" "replicas: 1" \
    "Add-on e2e-missing: its chart repository can&#39;t be reached"; do
    grep -qF "$want" <<< "$page" || fail "the k0s system page lacks '$want'"
  done
  ! grep -qF "e2e-not-a-secret" <<< "$page" || fail "the k0s system page shows an add-on's secret value"

  # The top problem and its plain-language text, as a non-expert sees them.
  local clusters top plain
  clusters=$(api GET /api/v1/clusters)
  top=$(echo "$clusters" | jq -r '.[] | select(.name=="a") | .topIssue.id')
  plain=$(echo "$clusters" | jq -r '.[] | select(.name=="a") | .topIssue.plainTitle')
  [ -n "$plain" ] && [ "$plain" != null ] || fail "the top problem has no plain title: $clusters"
  log "top problem in Basic mode: $plain"
  api GET "/c/a?mode=basic" > "$WORK/overview-basic.html"
  expect_status 200
  python3 -c 'import html,sys; print(html.unescape(open(sys.argv[1]).read()))' "$WORK/overview-basic.html" > "$WORK/overview-basic.txt"
  grep -qF "$plain" "$WORK/overview-basic.txt" || fail "the overview doesn't show the top problem '$plain'"
  grep -qF "needs your attention" "$WORK/overview-basic.txt" || fail "the overview doesn't say the cluster needs attention"
  api GET "/c/a/problems/$top?mode=basic" > "$WORK/top-basic.html"
  expect_status 200
  for want in "What happened" "Why" "What to do"; do
    grep -qi "$want" "$WORK/top-basic.html" || fail "the top problem's page lacks '$want'"
  done

  # Good practices are suggestions: Basic mode leaves them out and points to
  # Full mode, which lists them. Their terms are explained in the glossary.
  api GET "/c/a/problems?mode=basic" > "$WORK/problems-basic.html"
  if grep -qF "have no memory limit" "$WORK/problems-basic.html"; then fail "Basic mode lists good practices as problems"; fi
  grep -qF "about good practices" "$WORK/problems-basic.html" || fail "Basic mode doesn't point to the good practices"
  api GET "/c/a/problems?mode=full&category=hygiene" > "$WORK/problems-hygiene.html"
  grep -qF "hygiene.pdb-blocks-drain" "$WORK/problems-hygiene.html" || fail "Full mode doesn't list the good practices"
  [ "$(api GET /api/v1/clusters | jq -r '.[] | select(.name=="a") | .suggestions')" -ge 5 ] || fail "the cluster's suggestions aren't counted"
  api GET /glossary > "$WORK/glossary.html"
  grep -qF "CrashLoopBackOff" "$WORK/glossary.html" || fail "the glossary page"

  # The app certificate, read by the live engine with the read-only account.
  local tlsok=""
  for _ in $(seq 1 30); do
    if api GET "/api/v1/clusters/a/findings" | jq -e '[.[] | select(.ruleId=="tls.cert-expiry" and .resource.name=="shop-tls")] | length == 1' >/dev/null; then
      tlsok=1
      break
    fi
    sleep 3
  done
  [ -n "$tlsok" ] || fail "the app certificate isn't reported with the read-only account"
  api GET "/c/a/settings?mode=full" > "$WORK/settings.html"
  grep -qE "reading [0-9]+ certificates?" "$WORK/settings.html" || fail "the Connection page doesn't say the TLS Secrets are read"

  # The crash loop, and its pods' data read with the read-only account.
  # Its containers come and go, and a crashed run's log can be cleaned up
  # on the node before it is read: try each pod's last crashed and current
  # run for a while.
  local crash pods pod=""
  crash=$(api GET "/api/v1/clusters/a/findings" | jq -r '.[] | select(.ruleId=="pod.crashloop" and .resource.name=="crashloop") | .id')
  [ "$(api GET "/api/v1/clusters/a/findings/$crash" | jq -r '.finding.plain.title')" = "The app crashloop keeps crashing" ] || fail "crash loop plain title"
  pods=$(api GET "/api/v1/clusters/a/findings/$crash" | jq -r '.finding.affected[].name')
  for _ in $(seq 1 30); do
    for p in $pods; do
      for prev in true false; do
        api GET "/api/v1/clusters/a/pods/k0sm-e2e/$p/logs?previous=$prev&container=app" > "$WORK/crash-log.txt"
        if [ "$(status)" = 200 ] && grep -qF "FATAL cannot reach database" "$WORK/crash-log.txt"; then
          pod=$p
          break 3
        fi
        log "log of $p (previous=$prev): HTTP $(status): $(head -c 200 "$WORK/crash-log.txt")"
      done
    done
    sleep 3
  done
  [ -n "$pod" ] || fail "no log of the crash loop could be read"

  # Its page quotes the log lines that matter.
  local shown=""
  for _ in $(seq 1 20); do
    api GET "/c/a/problems/$crash?mode=full" > "$WORK/crash-full.html"
    if grep -qF "FATAL cannot reach database" "$WORK/crash-full.html"; then shown=1; break; fi
    log "the crash loop page shows no log lines yet: $(grep -o 'could not be read[^<]*' "$WORK/crash-full.html" || echo 'no error shown')"
    sleep 3
  done
  [ -n "$shown" ] || fail "the crash loop page doesn't show the important log lines"

  # The live engine reads the logs of the crashes: dep-api names the
  # service it can't reach, rollout-bad the update it came with.
  local explained="" rb
  for _ in $(seq 1 40); do
    if api GET "/api/v1/clusters/a/findings" | jq -e '[.[] | select(.ruleId=="pod.crashloop" and .resource.name=="dep-api") | .title | endswith(": Connection refused by dep-db:5432")] | any' >/dev/null; then
      explained=1
      break
    fi
    sleep 3
  done
  [ -n "$explained" ] || fail "the live engine doesn't explain dep-api's crash with its log"
  rb=$(api GET "/api/v1/clusters/a/findings" | jq -r '.[] | select(.ruleId=="pod.crashloop" and .resource.name=="rollout-bad") | .id')
  api GET "/c/a/problems/$rb?mode=full" > "$WORK/rollout-full.html"
  expect_status 200
  grep -qF "WHAT CHANGED: REVISION 1 → 2" "$WORK/rollout-full.html" || fail "rollout-bad's page doesn't show what its update changed"
  grep -qF "rollout undo deploy/rollout-bad --to-revision=1" "$WORK/rollout-full.html" || fail "rollout-bad's page doesn't say how to undo the update"
  if grep -q hunter22 "$WORK/rollout-full.html"; then fail "rollout-bad's page shows the password in DATABASE_URL"; fi

  api GET "/api/v1/clusters/a/pods/k0sm-e2e/$pod/describe" > "$WORK/crash-describe.txt"
  expect_status 200
  grep -q "^Name: *$pod" "$WORK/crash-describe.txt" || fail "describe: $(head -c 300 "$WORK/crash-describe.txt")"
  api GET "/api/v1/clusters/a/pods/k0sm-e2e/$pod/events" | jq -e 'length > 0' >/dev/null || fail "no events for $pod"

  # Acknowledge and reopen.
  api POST "/api/v1/clusters/a/findings/$crash/ack" '{}' >/dev/null
  expect_status 200
  [ "$(api GET "/api/v1/clusters/a/findings/$crash" | jq -r .finding.state)" = acknowledged ] || fail "acknowledge"
  api POST "/api/v1/clusters/a/findings/$crash/reopen" '{}' >/dev/null
  expect_status 200

  # Live updates, notifications and the audit log.
  local sse
  sse=$(curl -s --cacert "$WORK/ca.crt" -b "$JAR" -N --max-time 3 -o /dev/null -w '%{http_code} %{content_type}' "$BASE/api/v1/stream" || true)
  [[ "$sse" == "200 text/event-stream"* ]] || fail "event stream: $sse"
  api GET /api/v1/notifications | jq -e '.notifications | map(select(.cluster=="a")) | length > 0' >/dev/null || fail "no notification for cluster a"
  api GET /api/v1/audit | jq -e 'map(select(.action=="cluster.add")) | length == 1' >/dev/null || fail "cluster.add is not in the audit log"
}

# Named users: admin adds ivan; ivan signs in with his own cookies and
# acknowledges a problem, which then says it was him; admin sets ivan's
# password and ivan is signed out at once; on the jump host, passwd --user
# adds anna, who can sign in right away.
IVAN_PW="ivan-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# The Secrets pages on the live cluster: the list (the API server's table
# view) and a Secret's page show no values; values are off until turned on,
# then shown on request and logged, and k0s-monitor's own token is never
# shown.
check_secrets() {
  log "checking the Secrets pages and Secret values"
  local value page reveal=/api/v1/clusters/a/secrets/k0sm-e2e/e2e-db/reveal
  value="e2e-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  E2E_SECRET=$value
  kc a -n k0sm-e2e create secret generic e2e-db --from-literal=password="$value" --from-literal=user=shop >/dev/null
  page=$(api GET "/c/a/secrets?ns=k0sm-e2e&mode=full")
  expect_status 200
  grep -qF "e2e-db" <<< "$page" || fail "the Secrets list lacks e2e-db"
  grep -qF "kubernetes.io/tls" <<< "$page" || fail "the Secrets list lacks the TLS Secret's type"
  ! grep -qF "$value" <<< "$page" || fail "the Secrets list shows a value"
  page=$(api GET "/c/a/secrets/k0sm-e2e/e2e-db?mode=full")
  expect_status 200
  grep -qF "password" <<< "$page" || fail "the Secret's page lacks its keys"
  ! grep -qF "$value" <<< "$page" || fail "the Secret's page shows a value"

  api POST "$reveal" '{"key":"password"}' >/dev/null
  expect_status 403
  api PATCH /api/v1/settings '{"secretValues":true}' >/dev/null
  expect_status 200
  [ "$(api POST "$reveal" '{"key":"password"}' | jq -r .value)" = "$value" ] || fail "the value isn't shown once turned on"
  expect_status 200
  api POST /api/v1/clusters/a/secrets/kube-system/k0s-monitor-token/reveal '{"key":"token"}' >/dev/null
  expect_status 403
  api GET /api/v1/audit | jq -e '[.[] | select(.action == "secret.reveal" and .detail == "a: k0sm-e2e/e2e-db key password")] | length == 1' >/dev/null ||
    fail "the value shown isn't in the audit log"
  api PATCH /api/v1/settings '{"secretValues":false}' >/dev/null
  expect_status 200
}

# The report for support from the live cluster: a zip file whose summary
# stands on its own, with describe output and logs of the affected pods,
# and no secrets: not the Secret's value, not the password in rollout-bad's
# DATABASE_URL, not the Helm add-on's values, and with IP addresses masked,
# not the controller's address.
check_report() {
  log "checking the report for support"
  local dir="$WORK/report" addr leaks page
  page=$(api GET "/c/a/report?mode=basic")
  expect_status 200
  grep -qF "Prepare the report" <<< "$page" || fail "the report page lacks its button"
  api GET "/api/v1/clusters/a/report?maskIPs=true" >/dev/null
  expect_status 200
  cp "$WORK/body" "$WORK/report.zip"
  rm -rf "$dir"
  mkdir -p "$dir"
  unzip -q "$WORK/report.zip" -d "$dir" || fail "the report isn't a zip file"
  dir=$(echo "$dir"/k0s-monitor-report-a-*)
  for f in README.txt index.html problems.json cluster.json nodes.txt events.txt k0s.txt; do
    [ -s "$dir/$f" ] || fail "the report lacks $f"
  done
  ls "$dir"/describe/pod/k0sm-e2e/crashloop-*.txt >/dev/null 2>&1 || fail "the report lacks the crash-looping pod's describe output: $(cd "$dir" && find . -type f | sort | head -50)"
  [ -s "$dir/describe/deployment/k0sm-e2e/crashloop.txt" ] || fail "the report lacks the Deployment's describe output"
  ls "$dir"/logs/k0sm-e2e/crashloop-*/*.log >/dev/null 2>&1 || fail "the report lacks the crash-looping pod's logs"
  grep -qF "crashloop" "$dir/index.html" || fail "the summary lacks the crash-looping app"
  jq -e 'length > 0' "$dir/problems.json" >/dev/null || fail "problems.json is empty"
  leaks=$(grep -rlF -e hunter22 -e "${E2E_SECRET:?}" -e e2e-not-a-secret "$dir" || true)
  [ -z "$leaks" ] || fail "the report holds a secret in: $leaks"
  addr=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' k0sm-a)
  if [ -n "$addr" ] && grep -rqF "$addr" "$dir"; then fail "the report shows the controller's address $addr in: $(grep -rlF "$addr" "$dir")"; fi
  grep -qF "addresses were replaced" "$dir/README.txt" || fail "the read-me doesn't say the addresses were replaced"
  api GET /api/v1/audit | jq -e 'map(select(.action=="report.download")) | length >= 1' >/dev/null || fail "the report isn't in the audit log"
  log "report: $(find "$dir" -type f | wc -l) files, $(du -h "$WORK/report.zip" | cut -f1)"
}

# A product pack uploaded through the API: its check runs on the live
# cluster with its texts, the crash-looping app gets its friendly name and
# advice, and removing the pack takes them away.
check_packs() {
  log "checking a product pack"
  local pack f crash page
  # The add-node guide, with the cluster's own commands.
  page=$(api GET "/c/a/servers/add?mode=full")
  expect_status 200
  for want in "k0s token create --role=worker --expiry=1h" "k0s install worker --token-file" "8132/TCP" "kube-router"; do
    grep -qF "$want" <<< "$page" || fail "the add-node guide lacks '$want'"
  done
  pack='apiVersion: k0s-monitor/v1
kind: ProductPack
name: e2e
apps:
- select: {namespace: k0sm-e2e, name: crashloop}
  name: E2E crasher
checks:
- id: crashloop-replicas
  kind: replicas
  select: {namespace: k0sm-e2e, kind: Deployment, name: crashloop}
  min: 2
  plain: {title: "E2E: the crasher runs {{.Ready}} of the {{.Min}} copies it needs"}
guides:
- rules: [pod.crashloop]
  select: {namespace: k0sm-e2e, name: crashloop}
  whatToDo: Call the e2e support desk.'
  api POST /api/v1/packs "$pack" >/dev/null
  expect_status 201
  for _ in $(seq 1 30); do
    f=$(api GET /api/v1/clusters/a/findings | jq -c '[.[] | select(.ruleId=="pack.e2e.crashloop-replicas")][0]')
    [ "$f" != null ] && break
    sleep 2
  done
  [ "$f" != null ] || fail "the pack's check didn't run"
  [ "$(jq -r .plain.title <<< "$f")" = "E2E: the crasher runs 0 of the 2 copies it needs" ] || fail "the pack's check has the wrong texts: $f"
  crash=$(api GET /api/v1/clusters/a/findings | jq -c '[.[] | select(.ruleId=="pod.crashloop" and .resource.name=="crashloop")][0]')
  [ "$(jq -r .app <<< "$crash")" = "E2E crasher" ] || fail "the crash loop lacks the app's friendly name: $crash"
  [ "$(jq -r .plain.whatToDo <<< "$crash")" = "Call the e2e support desk." ] || fail "the crash loop lacks the pack's advice: $crash"
  jq -r .plain.title <<< "$crash" | grep -qF "E2E crasher" || fail "the Basic title doesn't use the friendly name: $crash"
  [ "$(jq -r .parentId <<< "$f")" = "$(jq -r .id <<< "$crash")" ] || fail "the pack's check isn't folded under the crash loop"
  api GET /api/v1/audit | jq -e 'map(select(.action=="pack.upload")) | length >= 1' >/dev/null || fail "the upload isn't in the audit log"
  api DELETE /api/v1/packs/e2e >/dev/null
  expect_status 204
  for _ in $(seq 1 30); do
    if ! api GET /api/v1/clusters/a/findings | jq -e '.[] | select(.ruleId=="pack.e2e.crashloop-replicas")' >/dev/null; then
      log "product pack: check, name and advice came and went"
      return 0
    fi
    sleep 2
  done
  fail "the pack's check stayed after the pack was removed"
}

check_users() {
  local admin_jar=$JAR admin_csrf=$CSRF ivan_jar="$WORK/ivan-cookies.txt" crash
  api POST /api/v1/users "$(jq -n --arg p "first-$IVAN_PW" '{name: "ivan", password: $p}')" >/dev/null
  expect_status 201
  JAR=$ivan_jar
  rm -f "$JAR"
  CSRF=$(api POST /api/v1/session "$(jq -n --arg p "first-$IVAN_PW" '{user: "ivan", password: $p}')" | jq -r .csrfToken)
  expect_status 200
  crash=$(api GET "/api/v1/clusters/a/findings" | jq -r '.[] | select(.ruleId=="pod.crashloop" and .resource.name=="crashloop") | .id')
  api POST "/api/v1/clusters/a/findings/$crash/ack" '{}' >/dev/null
  expect_status 200
  [ "$(api GET "/api/v1/clusters/a/findings/$crash" | jq -r .finding.stateBy)" = ivan ] || fail "the acknowledgement doesn't say it was ivan"
  api POST "/api/v1/clusters/a/findings/$crash/reopen" '{}' >/dev/null
  expect_status 200
  JAR=$admin_jar
  CSRF=$admin_csrf
  api PUT /api/v1/users/ivan/password "$(jq -n --arg p "$IVAN_PW" '{password: $p}')" >/dev/null
  expect_status 204
  JAR=$ivan_jar
  api GET /api/v1/clusters >/dev/null
  expect_status 401
  JAR=$admin_jar
  api GET /api/v1/clusters >/dev/null
  expect_status 200
  api GET /api/v1/audit | jq -e 'map(select(.user=="ivan" and .action=="finding.ack")) | length == 1' >/dev/null || fail "the audit log doesn't say ivan acknowledged"

  printf 'annas long password\n' | sudo /usr/local/bin/k0s-monitor passwd --user anna --password-file - >&2
  JAR="$WORK/anna-cookies.txt"
  rm -f "$JAR"
  api POST /api/v1/session '{"user":"anna","password":"annas long password"}' >/dev/null
  expect_status 200
  JAR=$admin_jar
  [ "$(api GET /api/v1/users | jq -c 'map(.name)')" = '["admin","anna","ivan"]' ] || fail "users: $(cat "$WORK/body")"
  log "users: admin, anna and ivan work side by side"
}

check_restart() {
  log "restarting the service"
  sudo systemctl restart k0s-monitor
  wait_healthy
  sign_in
  for _ in $(seq 1 30); do
    if [ "$(api GET /api/v1/clusters | jq -r '.[] | select(.name=="a") | .status')" = ok ]; then
      [ "$(api GET /api/v1/clusters | jq -r '.[] | select(.name=="a") | .addedInUi')" = true ] || fail "cluster a lost its origin"
      log "cluster a is back after the restart"
      # Users and their passwords survive it too.
      local admin_jar=$JAR
      JAR="$WORK/ivan-cookies.txt"
      rm -f "$JAR"
      api POST /api/v1/session "$(jq -n --arg p "$IVAN_PW" '{user: "ivan", password: $p}')" >/dev/null
      expect_status 200
      JAR=$admin_jar
      return 0
    fi
    sleep 2
  done
  fail "cluster a did not come back after a restart"
}

main() {
  command -v jq >/dev/null || { log "jq is required"; exit 1; }
  [ -x "$BIN" ] || { log "build first: make build"; exit 1; }
  docker inspect k0sm-a >/dev/null 2>&1 || { log "run test/e2e/run.sh with KEEP=1 first"; exit 1; }
  install_service
  check_sign_in
  add_cluster
  wait_for_findings
  check_details
  check_secrets
  check_report
  check_packs
  check_users
  check_restart
  log "PASS"
}

main "$@"
