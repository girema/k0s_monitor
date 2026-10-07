#!/usr/bin/env bash
# End-to-end test of failover, the M3 exit criterion: a k0s cluster with
# three controllers in Docker, watched by `k0s-monitor serve` through the
# first controller's own address. When that controller stops, k0s-monitor
# must go on through another one without ever reporting the cluster
# unreachable, keep watching (a Deployment made after the stop shows up),
# report the stopped controller (C03) and the switch (F03), and go back to
# the first controller once it runs again.
#
# Needs Docker with privileged containers, jq and curl.
# Usage: make build && test/e2e/ha.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
K0S_IMAGE="${K0S_IMAGE:-docker.io/k0sproject/k0s:v1.36.4-k0s.1}"
BIN="${BIN:-$ROOT/bin/k0s-monitor}"
WORK="${WORK:-$(mktemp -d)}"
KEEP="${KEEP:-0}"
PORT="${PORT:-18445}"
BASE="https://127.0.0.1:$PORT"
NET="k0sm-ha"
# Fixed addresses: a restarted controller must come back at its own, which
# etcd and the kubeconfig know it by.
SUBNET="${SUBNET:-172.30.0.0/24}"
PREFIX="${SUBNET%.*}"
SERVE_PID=""

log() { echo "[ha $(date -u +%H:%M:%S)] $*" >&2; }
ip_of() { echo "$PREFIX.1$1"; }
kc() { docker exec -i k0sm-ha-2 k0s kubectl "$@"; } # a controller that stays up
api() { curl -sSk --max-time 10 "$BASE$1"; }
cluster_json() { api /api/v1/clusters | jq -c '.[] | select(.name == "ha")'; }
findings_json() { api /api/v1/clusters/ha/findings; }

dump() {
  log "cluster as k0s-monitor sees it:"; cluster_json >&2 || true
  log "findings:"; findings_json | jq -r '.[] | "\(.ruleId) \(.severity) \(.resource.kind)/\(.resource.name): \(.title)"' >&2 || true
  log "k0s-monitor log:"; tail -n 80 "$WORK/ha-serve.log" >&2 || true
  kc -n kube-node-lease get lease -o wide >&2 || true
}

fail() {
  log "FAIL: $*"
  dump
  exit 1
}

cleanup() {
  if [ -n "$SERVE_PID" ]; then kill "$SERVE_PID" 2>/dev/null || true; fi
  if [ "$KEEP" != 1 ]; then
    docker rm -f k0sm-ha-1 k0sm-ha-2 k0sm-ha-3 >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

start_controller() { # n [join token]
  local n=$1
  log "starting controller k0sm-ha-$n at $(ip_of "$n")"
  docker rm -f "k0sm-ha-$n" >/dev/null 2>&1 || true
  docker run -d --name "k0sm-ha-$n" --hostname "k0sm-ha-$n" --network "$NET" --ip "$(ip_of "$n")" --privileged \
    -v /var/lib/k0s --tmpfs /run "$K0S_IMAGE" k0s controller ${2:+"$2"} >/dev/null
}

wait_ready() { # n
  for _ in $(seq 1 60); do
    if [ "$(docker exec "k0sm-ha-$1" k0s kubectl get --raw=/readyz 2>/dev/null)" = ok ]; then
      log "controller k0sm-ha-$1 is ready"
      return 0
    fi
    sleep 5
  done
  docker logs --tail 100 "k0sm-ha-$1" >&2 || true
  fail "controller k0sm-ha-$1 did not become ready"
}

running_leases() {
  kc -n kube-node-lease get lease -o json 2>/dev/null | jq '[.items[] | select(.metadata.name | startswith("k0s-ctrl-"))
    | select((.spec.holderIdentity // "") != "")] | length'
}

# until SECONDS WHAT COMMAND...: retries the command every 3 seconds.
until_ok() {
  local secs=$1 what=$2
  shift 2
  local end=$((SECONDS + secs))
  while [ $SECONDS -lt $end ]; do
    if "$@"; then return 0; fi
    sleep 3
  done
  fail "timed out after ${secs}s waiting for $what"
}

finding() { # rule name-regex -> the finding's severity, if there is one
  findings_json | jq -r --arg r "$1" --arg n "$2" '[.[] | select(.ruleId == $r and (.resource.name | test($n)))][0].severity // empty'
}
has_finding() { [ "$(finding "$1" "$2")" = "$3" ]; } # rule name-regex severity
no_finding() { [ -z "$(finding "$1" .)" ]; }         # rule
three_running() { [ "$(running_leases)" = 3 ]; }
probe_seen() { [ -n "$(finding pod.unschedulable '^ha-probe')$(finding deploy.unavailable '^ha-probe$')" ]; }

three_asked() { [ "$(api '/c/ha/k0s?mode=full' | grep -o '</i>ready<' | wc -l)" -ge 3 ]; }
connected_to_first() {
  local c; c=$(cluster_json)
  [ "$(echo "$c" | jq -r .status)" = ok ] && [ "$(echo "$c" | jq -r '.fallback // empty')" = "" ] &&
    [ "$(echo "$c" | jq -r .server)" = "https://$(ip_of 1):6443" ]
}

# Records every status seen while the first controller is down: the cluster
# must never be reported unreachable.
failed_over() {
  local c; c=$(cluster_json)
  echo "$c" | jq -r .status >> "$WORK/ha-statuses"
  [ "$(echo "$c" | jq -r '.fallback.controller // empty')" != "" ] && [ "$(echo "$c" | jq -r .status)" = ok ]
}

main() {
  command -v jq >/dev/null || { log "jq is required"; exit 1; }
  [ -x "$BIN" ] || { log "build first: make build"; exit 1; }
  log "work directory: $WORK"

  docker network rm "$NET" >/dev/null 2>&1 || true
  docker network create --subnet "$SUBNET" "$NET" >/dev/null
  start_controller 1
  wait_ready 1
  for n in 2 3; do
    start_controller "$n" "$(docker exec k0sm-ha-1 k0s token create --role=controller --expiry=1h)"
    wait_ready "$n"
  done
  until_ok 180 "three running controllers" three_running
  log "three controllers run"

  # k0s-monitor uses the first controller's own address.
  docker exec k0sm-ha-1 k0s kubeconfig admin |
    sed -E "s#server: https://[^[:space:]]+#server: https://$(ip_of 1):6443#" > "$WORK/ha.conf"
  cat > "$WORK/ha.yaml" <<CFG
clusters:
- {name: ha, kubeconfig: ha.conf}
thresholds: {pendingAfter: 10s, deploymentUnavailableAfter: 10s}
scan: {connectTimeout: 3s, syncTimeout: 60s}
CFG
  "$BIN" serve --config "$WORK/ha.yaml" --listen "127.0.0.1:$PORT" --data-dir "$WORK/ha-data" > "$WORK/ha-serve.log" 2>&1 &
  SERVE_PID=$!
  until_ok 60 "k0s-monitor to answer" curl -sfk "$BASE/healthz" -o /dev/null
  until_ok 120 "the cluster through k0sm-ha-1" connected_to_first
  until_ok 120 "all three controllers asked directly" three_asked
  log "k0s-monitor watches the cluster through k0sm-ha-1 and has asked all three controllers"

  log "stopping k0sm-ha-1"
  docker stop -t 30 k0sm-ha-1 >/dev/null
  : > "$WORK/ha-statuses"
  until_ok 120 "k0s-monitor to use another controller" failed_over
  if grep -qx unreachable "$WORK/ha-statuses"; then fail "the cluster was reported unreachable while two controllers ran"; fi
  local c; c=$(cluster_json)
  log "failed over: $(echo "$c" | jq -c '{server, fallback: {controller: .fallback.controller, server: .fallback.server, error: .fallback.error.plain}}')"
  case "$(echo "$c" | jq -r .server)" in
    "https://$(ip_of 2):6443" | "https://$(ip_of 3):6443") ;;
    *) fail "connected to $(echo "$c" | jq -r .server), not to k0sm-ha-2 or k0sm-ha-3" ;;
  esac
  [ "$(echo "$c" | jq -r .fallback.server)" = "https://$(ip_of 1):6443" ] || fail "the fallback doesn't name the kubeconfig's server"

  # The watches work through the other controller.
  kc create deployment ha-probe --image=registry.k8s.io/pause:3.10 >/dev/null
  until_ok 120 "the Deployment made after the switch" probe_seen
  # The switch and the stopped controller are reported.
  until_ok 60 "endpoint.fallback" has_finding endpoint.fallback "^$(ip_of 1):6443\$" low
  until_ok 150 "controllers.count for k0sm-ha-1" has_finding controllers.count '^k0sm-ha-1$' high
  local page; page=$(api '/c/ha/k0s?mode=full')
  for s in "Connected through controller" ">in use<" "Controller k0sm-ha-1 not running (2 of 3 controllers run)"; do
    grep -qF "$s" <<< "$page" || fail "the k0s page lacks \"$s\""
  done
  log "k0s-monitor goes on through $(echo "$c" | jq -r .fallback.controller) and reports k0sm-ha-1 down"

  log "starting k0sm-ha-1 again"
  docker start k0sm-ha-1 >/dev/null
  wait_ready 1
  until_ok 300 "k0s-monitor to go back to k0sm-ha-1" connected_to_first
  until_ok 120 "endpoint.fallback to be resolved" no_finding endpoint.fallback
  log "back on k0sm-ha-1"
  log "PASS"
}

main "$@"
