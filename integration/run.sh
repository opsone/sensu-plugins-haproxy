#!/usr/bin/env bash
# Runs check-haproxy-status against a real HAProxy in Docker.
set -euo pipefail
cd "$(dirname "$0")"

image=check-haproxy-integration
container=check-haproxy-integration-$$
url=http://127.0.0.1:8404/stats

docker build -q -t "$image" . >/dev/null
docker run -d --rm --name "$container" "$image" >/dev/null
trap 'docker rm -f "$container" >/dev/null' EXIT

run() { docker exec -u root "$container" bash -c "$1"; }

# Wait for the health checks to mark the broken servers DOWN.
for _ in $(seq 30); do
  run "exec 3<>/dev/tcp/127.0.0.1/8404 && printf 'GET /stats;csv HTTP/1.0\r\nAuthorization: Basic c2Vuc3U6c2Vuc3Utc2VjcmV0\r\n\r\n' >&3 && cat <&3" 2>/dev/null \
    | grep -q '^web_down,ko2,.*,DOWN,' && break
  sleep 1
done

# Opens n TCP connections to the hold frontend, kept open until the container stops.
hold() { for _ in $(seq "$1"); do docker exec -d "$container" bash -c 'exec 3<>/dev/tcp/127.0.0.1/9100; sleep 3600'; done; sleep 2; }

failures=0
expect() {
  local want=$1 desc=$2; shift 2
  local out rc=0
  # Run as an unprivileged user, like sensu-agent does.
  out=$(docker exec -u nobody "$container" env "$@" 2>&1) || rc=$?
  out=$(tail -1 <<<"$out")
  if [[ $rc -eq $want ]]; then
    echo "ok   [$rc] $desc -> $out"
  else
    echo "FAIL [$rc, want $want] $desc -> $out"
    failures=$((failures + 1))
  fi
}

auth=(CHECK_HAPROXY_URL=$url CHECK_HAPROXY_USER=sensu CHECK_HAPROXY_PASSWORD=sensu-secret)

expect 3 "no argument" check-haproxy-status
expect 3 "no service" "${auth[@]}" check-haproxy-status
expect 3 "invalid url" check-haproxy-status --url 127.0.0.1:8404/stats -s web
expect 3 "invalid regex" "${auth[@]}" check-haproxy-status -s 'web('
expect 0 "credentials in the url" check-haproxy-status --url http://sensu:sensu-secret@127.0.0.1:8404/stats -s '^web_ok$'
expect 3 "wrong password in the url" check-haproxy-status --url http://sensu:wrong@127.0.0.1:8404/stats -s '^web_ok$'
expect 3 "wrong password" "${auth[@]}" CHECK_HAPROXY_PASSWORD=wrong check-haproxy-status -s web
expect 3 "wrong path" "${auth[@]}" check-haproxy-status --url http://127.0.0.1:8404/nope -s web
expect 2 "unreachable" check-haproxy-status --url http://127.0.0.1:1/stats -s web

expect 0 "all up" "${auth[@]}" check-haproxy-status -s '^web_ok$'
expect 1 "a third up" "${auth[@]}" check-haproxy-status -s '^web_third$'
expect 0 "a third up, lower warning" "${auth[@]}" check-haproxy-status -s '^web_third$' -w 30
expect 2 "a third up, higher critical" "${auth[@]}" check-haproxy-status -s '^web_third$' -c 40
expect 2 "all down" "${auth[@]}" check-haproxy-status -s '^web_down$'
expect 0 "maintenance ignored" "${auth[@]}" check-haproxy-status -s '^web_maint$'
expect 1 "min warn count" "${auth[@]}" check-haproxy-status -s '^web_maint$' -M 2
expect 2 "min crit count" "${auth[@]}" check-haproxy-status -s '^web_maint$' -X 2
expect 1 "no match" "${auth[@]}" check-haproxy-status -s nope
expect 1 "exact match, partial name" "${auth[@]}" check-haproxy-status -s web_ -e
expect 0 "exact match" "${auth[@]}" CHECK_HAPROXY_SERVICE=web_ok CHECK_HAPROXY_EXACT_MATCH=true check-haproxy-status
expect 0 "regex over every backend, 50% up" "${auth[@]}" check-haproxy-status -s '^web_'

# Every variable set to the check definition defaults.
checkconfig=(CHECK_HAPROXY_URL=http://sensu:sensu-secret@127.0.0.1:8404/stats CHECK_HAPROXY_SERVICE=.* CHECK_HAPROXY_EXACT_MATCH=false
  CHECK_HAPROXY_WARN_PERCENT=50 CHECK_HAPROXY_CRIT_PERCENT=25 CHECK_HAPROXY_SESSION_WARN_PERCENT=75 CHECK_HAPROXY_SESSION_CRIT_PERCENT=90
  CHECK_HAPROXY_BACKEND_SESSION_WARN_PERCENT=0 CHECK_HAPROXY_BACKEND_SESSION_CRIT_PERCENT=0
  CHECK_HAPROXY_MIN_WARN_COUNT=0 CHECK_HAPROXY_MIN_CRIT_COUNT=0 CHECK_HAPROXY_TIMEOUT=10)
expect 0 "check definition defaults, web_ok" "${checkconfig[@]}" CHECK_HAPROXY_SERVICE=^web_ok$ check-haproxy-status
expect 2 "check definition defaults, web_down" "${checkconfig[@]}" CHECK_HAPROXY_SERVICE=^web_down$ check-haproxy-status

expect 0 "sessions idle" "${auth[@]}" check-haproxy-status -s tcp_hold
hold 8
expect 1 "server sessions 80%" "${auth[@]}" check-haproxy-status -s tcp_hold
expect 1 "backend sessions 80%" "${auth[@]}" check-haproxy-status -s tcp_hold -b 75 -B 90
expect 0 "backend sessions 80%, higher limits" "${auth[@]}" check-haproxy-status -s tcp_hold -b 85 -B 95
hold 2
expect 2 "server sessions 100%" "${auth[@]}" check-haproxy-status -s tcp_hold
expect 2 "backend sessions 100%" "${auth[@]}" check-haproxy-status -s tcp_hold -b 75 -B 90

exit $failures
