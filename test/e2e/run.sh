#!/usr/bin/env bash
# End-to-end test: two real k0s clusters in Docker, broken on purpose,
# plus two clusters that cannot be reached. One `k0s-monitor scan` over all
# four must find every problem in expected.txt, with symptoms folded under
# their root causes and each unreachable cluster explained.
#
# Needs Docker with privileged containers and internet access for images.
# Usage: make build && test/e2e/run.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
K0S_IMAGE="${K0S_IMAGE:-docker.io/k0sproject/k0s:v1.36.4-k0s.1}"
BIN="${BIN:-$ROOT/bin/k0s-monitor}"
WORK="${WORK:-$(mktemp -d)}"
KEEP="${KEEP:-0}"
ATTEMPTS="${ATTEMPTS:-40}"
# CI machines often have little free disk. Without this the kubelet reports
# DiskPressure and keeps every scenario pod pending.
KUBELET_ARGS="${KUBELET_ARGS:---eviction-hard=memory.available<100Mi,nodefs.available<1%,nodefs.inodesFree<1%,imagefs.available<1%,imagefs.inodesFree<1%}"

log() { echo "[e2e $(date -u +%H:%M:%S)] $*" >&2; }
kc() { local c=$1; shift; docker exec -i "k0sm-$c" k0s kubectl "$@"; }

cleanup() {
  if [ "$KEEP" != 1 ]; then docker rm -f k0sm-a k0sm-b >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

start_cluster() { # name host-port [docker run flags...]
  local name=$1 port=$2
  shift 2
  log "starting k0s cluster $name ($K0S_IMAGE) on 127.0.0.1:$port"
  docker rm -f "k0sm-$name" >/dev/null 2>&1 || true
  docker run -d --name "k0sm-$name" --hostname "k0sm-$name" --privileged \
    -v /var/lib/k0s -v /var/log/pods --tmpfs /run "$@" \
    -p "127.0.0.1:$port:6443" "$K0S_IMAGE" \
    k0s controller --enable-worker --no-taints --kubelet-extra-args="$KUBELET_ARGS" >/dev/null
}

wait_cluster() { # name host-port
  for i in $(seq 1 90); do
    if kc "$1" get nodes 2>/dev/null | grep -q ' Ready'; then
      log "cluster $1 has a Ready node"
      docker exec "k0sm-$1" k0s kubeconfig admin |
        sed -E "s#server: https://[^[:space:]]+#server: https://127.0.0.1:$2#" > "$WORK/$1.conf"
      return 0
    fi
    sleep 5
  done
  log "cluster $1 did not become ready"; docker logs --tail 200 "k0sm-$1" || true
  return 1
}

# Conditions that k0s or Kubernetes may reset are re-applied before each scan.
refresh_transients() {
  kc a -n kube-system scale deploy coredns --replicas=0 >/dev/null ||
    log "could not scale coredns yet"
  local now; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  kc b patch node k0sm-fake-pressure --subresource=status --type=merge -p "{\"status\":{
    \"capacity\":{\"cpu\":\"2\",\"memory\":\"4Gi\",\"pods\":\"110\"},
    \"allocatable\":{\"cpu\":\"2\",\"memory\":\"4Gi\",\"pods\":\"110\"},
    \"conditions\":[
    {\"type\":\"Ready\",\"status\":\"True\",\"reason\":\"KubeletReady\",\"message\":\"e2e\",\"lastHeartbeatTime\":\"$now\",\"lastTransitionTime\":\"$now\"},
    {\"type\":\"DiskPressure\",\"status\":\"True\",\"reason\":\"KubeletHasDiskPressure\",\"message\":\"e2e: disk almost full\",\"lastHeartbeatTime\":\"$now\",\"lastTransitionTime\":\"$now\"},
    {\"type\":\"ReadonlyFilesystem\",\"status\":\"True\",\"reason\":\"FilesystemIsReadOnly\",\"message\":\"e2e: Filesystem is read-only\",\"lastHeartbeatTime\":\"$now\",\"lastTransitionTime\":\"$now\"}]}}" >/dev/null ||
    log "could not patch k0sm-fake-pressure"
}

found_lines() { # scan.json
  jq -r '.clusters[] | .name as $c | .findings[] |
    "\($c) \(.ruleId) \(.resource.kind) \(.resource.namespace // "-") \(.resource.name)"' "$1" | sort -u
}

check() { # scan.json -> 0 when everything expected is there
  local json=$1 missing=0
  found_lines "$json" > "$WORK/found.txt"
  while read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    if ! grep -qxF "$line" "$WORK/found.txt"; then
      echo "missing: $line" >> "$WORK/missing.txt"; missing=1
    fi
  done < "$ROOT/test/e2e/expected.txt"
  # The crashes are explained by their logs once each crashed and its log
  # was read.
  explained "$json" dep-api ': Connection refused by dep-db:5432' || missing=1
  explained "$json" dep-db ': Permission denied: /var/lib/postgresql/data' || missing=1
  explained "$json" rollout-bad ': Setting DATABASE_URL is missing' || missing=1
  # Prometheus's own alert about the filled volume shows on its problem.
  alerted "$json" pvc.usage fill-data E2EVolumeFillingUp || missing=1
  # V04 from both sources: the event's disk errors and the exporter's link.
  if ! jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="vm.kernel-errors") | .title |
      (contains("disk I/O errors (3)") and contains("eth9") and (contains("veth") | not))' "$json" >/dev/null; then
    echo "vm.kernel-errors lacks the disk errors or eth9's link" >> "$WORK/missing.txt"; missing=1
  fi
  return $missing
}

alerted() { # scan.json rule name alert
  jq -e --arg r "$2" --arg n "$3" --arg a "$4" '.clusters[] | select(.name=="a") | .findings[] |
    select(.ruleId==$r and .resource.name==$n) | [.alerts[]?.name] | index($a) != null' "$1" >/dev/null && return 0
  echo "no alert: $4 on $2 $3" >> "$WORK/missing.txt"
  return 1
}

explained() { # scan.json deployment title-suffix
  jq -e --arg n "$2" --arg s "$3" '.clusters[] | select(.name=="a") | .findings[] |
    select(.ruleId=="pod.crashloop" and .resource.name==$n) | .title | endswith($s)' "$1" >/dev/null && return 0
  echo "not explained: $2 ($3)" >> "$WORK/missing.txt"
  return 1
}

check_details() { # scan.json -> structural assertions beyond presence
  local json=$1 ok=0
  local crash; crash=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.crashloop" and .resource.name=="crashloop") | .id' "$json")
  for sym in 'deploy.unavailable crashloop' 'svc.no-endpoints crashloop'; do
    set -- $sym
    local parent; parent=$(jq -r --arg r "$1" --arg n "$2" '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId==$r and .resource.name==$n) | .parentId // ""' "$json")
    if [ "$parent" != "$crash" ]; then log "FAIL: $1 $2 should be folded under pod.crashloop ($crash), parent is '$parent'"; ok=1; fi
  done
  # The claim waits for a default StorageClass, and the pod for the claim.
  local sc; sc=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="sc.no-default") | .id' "$json")
  for sym in 'pvc.pending data-no-sc' 'pod.unschedulable pvc-user'; do
    set -- $sym
    local p; p=$(jq -r --arg r "$1" --arg n "$2" '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId==$r and .resource.name==$n) | .parentId // ""' "$json")
    if [ "$p" != "$sc" ]; then log "FAIL: $1 $2 should end up under sc.no-default ($sc), parent is '$p'"; ok=1; fi
  done
  local nr; nr=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.not-ready" and .resource.name=="never-ready") | .id' "$json")
  local nrd; nrd=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="deploy.unavailable" and .resource.name=="never-ready") | .parentId // ""' "$json")
  if [ "$nrd" != "$nr" ]; then log "FAIL: never-ready's outage should be folded under pod.not-ready"; ok=1; fi
  if jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.crashloop" and .resource.name=="liveness-fail")' "$json" >/dev/null; then
    log "FAIL: liveness-fail is restarted by its probe, not a crash loop"; ok=1
  fi
  if ! jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.stuck-creating" and .resource.name=="mount-missing") | .title | test("ConfigMap or Secret")' "$json" >/dev/null; then
    log "FAIL: mount-missing should be explained by the missing ConfigMap"; ok=1
  fi
  # The app certificate is reported, and nothing of its key shows.
  local cert; cert=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="tls.cert-expiry" and .resource.name=="shop-tls") | .title' "$json")
  if ! [[ "$cert" =~ ^Certificate\ for\ shop\.e2e\.test\ expires\ in\ [45]\ days\ \(Secret\ k0sm-e2e/shop-tls\)$ ]]; then log "FAIL: the app certificate: '$cert'"; ok=1; fi
  if grep -qF "$(base64 -w0 "$WORK/shop.key" | head -c 40)" "$json" "$WORK/scan.txt" || grep -q "PRIVATE KEY" "$json" "$WORK/scan.txt"; then
    log "FAIL: the certificate's private key shows in the scan"; ok=1
  fi
  # Good practices are suggestions: never folded, never above P4, left out
  # of the counts, and never about k0s's own components.
  local hyg; hyg=$(jq -c '[.clusters[] | select(.name=="a") | .findings[] | select(.category=="hygiene") | select(.parentId or .priority != "P4")] | length' "$json")
  if [ "$hyg" != 0 ]; then log "FAIL: $hyg good-practice findings are folded or above P4"; ok=1; fi
  if jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.category=="hygiene") | .evidence[].value | test("coredns|kube-router|konnectivity-agent|kube-proxy|metrics-server")' "$json" >/dev/null; then
    log "FAIL: a good-practice finding about k0s's own components"; ok=1
  fi
  local sugg; sugg=$(jq -r '.clusters[] | select(.name=="a") | .suggestions' "$json")
  local counted; counted=$(jq -r '[.clusters[] | select(.name=="a") | .findings[] | select((.parentId // "") == "" and .category != "hygiene")] | length' "$json")
  local total; total=$(jq -r '[.clusters[] | select(.name=="a") | .counts[]] | add' "$json")
  if [ "$sugg" -lt 5 ] || [ "$total" != "$counted" ]; then log "FAIL: suggestions $sugg, counted problems $total of $counted"; ok=1; fi
  local npd; npd=$(jq -r '.clusters[] | select(.name=="b") | .findings[] | select(.ruleId=="node.npd-condition") | .title' "$json")
  if [ "$npd" != "k0sm-fake-pressure: ReadonlyFilesystem" ]; then log "FAIL: node-problem-detector condition: '$npd'"; ok=1; fi
  # dep-api fails because dep-db does; rollout-bad because of its update.
  local db api; db=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.crashloop" and .resource.name=="dep-db") | .id' "$json")
  api=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.crashloop" and .resource.name=="dep-api") | .parentId // ""' "$json")
  if [ "$api" != "$db" ]; then log "FAIL: dep-api should be folded under dep-db's crash ($db), parent is '$api'"; ok=1; fi
  local rollout; rollout=$(jq -c '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.crashloop" and .resource.name=="rollout-bad") |
    {revision: .rollout.revision, previous: .rollout.previous, changes: [.rollout.changes[]? | .what], undo: ([.remedy.steps[].command // ""] | map(select(test("rollout undo deploy/rollout-bad --to-revision=1"))) | length)}' "$json")
  if [ "$rollout" != '{"revision":2,"previous":1,"changes":["command","env DATABASE_URL"],"undo":1}' ]; then log "FAIL: rollout-bad's update: $rollout"; ok=1; fi
  if grep -q hunter22 "$json" "$WORK/scan.txt"; then log "FAIL: a password from the environment shows in the scan"; ok=1; fi
  local dns kubedns; dns=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="dns.unhealthy") | .id' "$json")
  kubedns=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="svc.no-endpoints" and .resource.name=="kube-dns") | .parentId // ""' "$json")
  if [ "$kubedns" != "$dns" ]; then log "FAIL: kube-dns without endpoints should be folded under dns.unhealthy"; ok=1; fi
  # Pods that only wait for the fake nodes (DaemonSet pods) belong to them.
  local loose; loose=$(jq -r '.clusters[] | select(.name=="b") | .findings[] | select(.ruleId=="pod.unschedulable" and (.parentId // "") == "") | .resource.name' "$json")
  if [ -n "$loose" ]; then log "FAIL: pods waiting for sick nodes are not folded under them: $loose"; ok=1; fi
  if jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="pod.unschedulable" and .resource.name=="too-big") | .title | test("claims|preemption")' "$json" >/dev/null; then
    log "FAIL: the scheduler's extra notes leak into the too-big title"; ok=1
  fi
  # The fake node-exporter's boot time is older than the node: a node that
  # just joined, not a reboot.
  if jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="vm.reboot")' "$json" >/dev/null; then
    log "FAIL: vm.reboot for a node that booted before it joined the cluster"; ok=1
  fi
  for pair in 'c refused' 'd dns'; do
    set -- $pair
    local kind; kind=$(jq -r --arg c "$1" '.clusters[] | select(.name==$c) | .error.kind // ""' "$json")
    if [ "$kind" != "$2" ]; then log "FAIL: cluster $1 error kind is '$kind', want $2"; ok=1; fi
  done
  # The real controllers were asked directly, and are healthy.
  local cprules='["apiserver.readyz","etcd.health","cert.expiry","endpoint.tls-name"]'
  for c in a b; do
    local skipped; skipped=$(jq -r --arg c "$c" --argjson r "$cprules" '.clusters[] | select(.name==$c) | [.skippedRules[]? | select(.ruleId as $id | $r | index($id))] | length' "$json")
    if [ "$skipped" != 0 ]; then log "FAIL: control plane rules skipped on cluster $c: $(jq -c --arg c "$c" '.clusters[] | select(.name==$c) | .skippedRules' "$json")"; ok=1; fi
    local cp; cp=$(jq -r --arg c "$c" --argjson r "$cprules" '.clusters[] | select(.name==$c) | .findings[] | select(.ruleId as $id | $r | index($id)) | "\(.ruleId) \(.title)"' "$json")
    if [ -n "$cp" ]; then log "FAIL: a healthy controller reported on cluster $c: $cp"; ok=1; fi
  done
  if jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="controllers.count" and .resource.name!="k0sm-gone")' "$json" >/dev/null; then
    log "FAIL: the running controller of cluster a counted as down"; ok=1
  fi
  # k0s versions and updates, from k0s's own objects.
  local upd; upd=$(jq -r '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="k0s.update-stuck") | .title' "$json")
  if [ "$upd" != "k0s update to v1.36.4+k0s.1 can't finish: k0sm-ghost missing" ]; then log "FAIL: the Autopilot plan of cluster a: '$upd'"; ok=1; fi
  if jq -e '.clusters[] | select(.name=="a") | .findings[] | select(.ruleId=="k0s.version-drift")' "$json" >/dev/null; then
    log "FAIL: cluster a runs one version, but drift is reported"; ok=1
  fi
  local drift; drift=$(jq -r '.clusters[] | select(.name=="b") | .findings[] | select(.ruleId=="k0s.version-drift") | .title' "$json")
  # From its ControlNode (v1.36.4+k0s.1), else its API server (v1.36.4+k0s).
  if ! [[ "$drift" =~ ^Cluster\ runs\ k0s\ v1\.36\.4\+k0s(\.1)?,\ not\ v1\.36\.3\+k0s\.0$ ]]; then log "FAIL: cluster b's version: '$drift'"; ok=1; fi
  for c in a b; do
    local st; st=$(jq -r --arg c "$c" '.clusters[] | select(.name==$c) | .status' "$json")
    if [ "$st" = unreachable ]; then log "FAIL: cluster $c is unreachable"; ok=1; fi
    local k0s; k0s=$(jq -r --arg c "$c" '.clusters[] | select(.name==$c) | .info.k0s' "$json")
    if [ "$k0s" != true ]; then log "FAIL: cluster $c was not detected as k0s"; ok=1; fi
  done
  return $ok
}

main() {
  command -v jq >/dev/null || { log "jq is required"; exit 1; }
  [ -x "$BIN" ] || { log "build first: make build"; exit 1; }
  [ -s "$ROOT/test/e2e/expected.txt" ] || { log "missing test/e2e/expected.txt"; exit 1; }
  log "work directory: $WORK"
  df -h / /var/lib/docker 2>/dev/null >&2 || true

  # Cluster a's small tmpfs is the local volume that metrics.yaml fills.
  start_cluster a 16443 --tmpfs /mnt/e2e-vol:size=64m
  start_cluster b 16444
  wait_cluster a 16443
  wait_cluster b 16444

  # Unreachable clusters: a closed port, and a name that does not resolve.
  sed -E "s#server: https://[^[:space:]]+#server: https://127.0.0.1:16449#" "$WORK/a.conf" > "$WORK/c.conf"
  sed -E "s#server: https://[^[:space:]]+#server: https://k0sm-e2e.invalid:6443#" "$WORK/a.conf" > "$WORK/d.conf"

  cat > "$WORK/k0s-monitor.yaml" <<CFG
clusters:
- {name: a, kubeconfig: a.conf}
# b runs v1.36.4+k0s.1, while the product is said to ship v1.36.3+k0s.0.
- {name: b, kubeconfig: b.conf, k0sVersion: v1.36.3+k0s.0}
- {name: c, kubeconfig: c.conf}
- {name: d, kubeconfig: d.conf}
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
scan: {connectTimeout: 5s, syncTimeout: 60s}
CFG

  log "applying scenarios"
  kc a apply -f - < "$ROOT/test/scenarios/workloads.yaml"
  # A second controller that stopped 10 minutes ago, as k0s leaves its
  # lease: cluster a's one real controller keeps running.
  kc a apply -f - <<LEASE
apiVersion: coordination.k8s.io/v1
kind: Lease
metadata: {name: k0s-ctrl-k0sm-gone, namespace: kube-node-lease}
spec: {holderIdentity: e2e-gone, leaseDurationSeconds: 60, renewTime: "$(date -u -d '-10 min' +%Y-%m-%dT%H:%M:%S.000000Z)"}
LEASE
  # A k0s update through Autopilot that names a node the cluster doesn't
  # have: Autopilot stops it before touching any node.
  kc a apply -f - <<'PLAN'
apiVersion: autopilot.k0sproject.io/v1beta2
kind: Plan
metadata: {name: autopilot}
spec:
  id: e2e-missing-node
  timestamp: now
  commands:
  - k0supdate:
      version: v1.36.4+k0s.1
      platforms:
        linux-amd64: {url: "https://updates.example.invalid/k0s"}
        linux-arm64: {url: "https://updates.example.invalid/k0s"}
      targets:
        workers: {discovery: {static: {nodes: [k0sm-ghost]}}}
PLAN
  # A k0s Helm add-on whose chart repository doesn't exist: k0s reports
  # the error in the Chart's status (C07). Its values hold a fake secret
  # that must never show.
  kc a apply -f - <<'CHART'
apiVersion: helm.k0sproject.io/v1beta1
kind: Chart
metadata: {name: k0s-addon-chart-e2e-missing, namespace: kube-system}
spec:
  chartName: e2e/missing
  releaseName: e2e-missing
  namespace: default
  version: 0.1.0
  repository: {url: "https://charts.k0sm-e2e.invalid"}
  values: |
    token: e2e-not-a-secret
    replicas: 1
CHART
  kc a apply -f - < "$ROOT/test/scenarios/metrics.yaml"
  kc b apply -f - < "$ROOT/test/scenarios/nodes.yaml"
  # X09: a certificate that expires in 5 days, in the TLS Secret an Ingress
  # serves.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 5 \
    -subj /CN=shop.e2e.test -addext subjectAltName=DNS:shop.e2e.test \
    -keyout "$WORK/shop.key" -out "$WORK/shop.crt" 2>/dev/null
  kc a apply -f - <<SECRET
apiVersion: v1
kind: Secret
metadata: {name: shop-tls, namespace: k0sm-e2e}
type: kubernetes.io/tls
data:
  tls.crt: $(base64 -w0 "$WORK/shop.crt")
  tls.key: $(base64 -w0 "$WORK/shop.key")
SECRET
  # rollout-bad's second revision drops DATABASE_URL and crashes on it.
  kc a -n k0sm-e2e rollout status deploy/rollout-bad --timeout=180s ||
    log "rollout-bad's first revision is not ready"
  kc a -n k0sm-e2e patch deploy rollout-bad --type=json -p '[
    {"op": "replace", "path": "/spec/template/spec/containers/0/command",
     "value": ["sh", "-c", "echo config error: environment variable DATABASE_URL is not set; exit 1"]},
    {"op": "remove", "path": "/spec/template/spec/containers/0/env"}]'
  # V04: node-problem-detector's kernel monitor reports disk errors as an
  # event on the node.
  local now; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  kc a create -f - <<EVENT
apiVersion: v1
kind: Event
metadata: {name: k0sm-a.e2e-io-error, namespace: default}
involvedObject: {kind: Node, name: k0sm-a}
source: {component: kernel-monitor, host: k0sm-a}
type: Warning
reason: IOError
count: 3
firstTimestamp: "$now"
lastTimestamp: "$now"
message: "Buffer I/O error on dev sdz1, logical block 42, async page read"
EVENT
  # W08: the finalizer keeps the deleted pod. N08: cordoned "long ago".
  kc a -n k0sm-e2e delete pod stuck-finalizer --wait=false
  kc b cordon k0sm-fake-pressure

  for attempt in $(seq 1 "$ATTEMPTS"); do
    refresh_transients
    rm -f "$WORK/missing.txt"
    "$BIN" scan --config "$WORK/k0s-monitor.yaml" -o json > "$WORK/scan.json" || true
    if check "$WORK/scan.json"; then
      log "attempt $attempt: every expected problem was found"
      "$BIN" scan --config "$WORK/k0s-monitor.yaml" --no-color -v > "$WORK/scan.txt" || true
      "$BIN" scan --config "$WORK/k0s-monitor.yaml" --no-color || true
      if check_details "$WORK/scan.json"; then
        log "PASS"
        exit 0
      fi
      log "FAIL: problems found, but details are wrong"
      exit 1
    fi
    log "attempt $attempt: still missing $(wc -l < "$WORK/missing.txt") problem(s)"
    sleep 10
  done

  log "FAIL: not everything was found"
  cat "$WORK/missing.txt" >&2
  log "found:"; cat "$WORK/found.txt" >&2
  log "full scan:"; "$BIN" scan --config "$WORK/k0s-monitor.yaml" --no-color -v >&2 || true
  kc a get pods -A -o wide >&2 || true
  kc a -n monitoring logs deploy/prometheus --tail=50 >&2 || true
  kc b get nodes -o wide >&2 || true
  exit 1
}

main "$@"
