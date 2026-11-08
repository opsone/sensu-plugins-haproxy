# sensu-plugins-haproxy

Sensu Go check `check-haproxy-status`: reads the HAProxy stats page (CSV export) and alerts on the servers of the matching backends (servers down, session limits).

Static Go binary (no CGO, no Ruby runtime): one asset for every Linux distribution, `amd64` only.

## Behavior

The check fetches `<url>;csv;norefresh`, keeps the proxies whose name matches `--service` (regular expression, or literal name with `--exact-match`) and evaluates their servers. Servers in maintenance (`MAINT`) and `FRONTEND` lines are ignored. A server counts as up when its status is `UP…`, `DRAIN…`, `OPEN` or `no check`.

Rules are applied in this order, the first match wins:

| Situation | State |
|---|---|
| No server matching `--service` | WARNING |
| Fewer servers than `--min-crit-count`, or up percentage below `--crit-percent` (25) | CRITICAL |
| A server above `--session-crit-percent` (90) of its session limit (`scur`/`slim`), or a backend above `--backend-session-crit-percent` when given | CRITICAL |
| Fewer servers than `--min-warn-count`, or up percentage below `--warn-percent` (50) | WARNING |
| A server above `--session-warn-percent` (75) of its session limit, or a backend above `--backend-session-warn-percent` when given | WARNING |
| Otherwise | OK |
| HAProxy unreachable (connection refused, timeout, TLS error) | CRITICAL |
| HTTP status other than 200 (bad credentials, wrong path), not an HAProxy CSV, invalid argument | UNKNOWN |

The up percentage is computed over all matching servers together and rounded down. Backend session thresholds, when set, replace the per server ones.

Output example:

```
check-haproxy-status WARNING: UP: 33% of 3 /^web$/ services, DOWN: web/web2[L4CON], web/web3[L4CON]
```

## Usage

```
check-haproxy-status [flags]
      --url string                         HAProxy stats page URL, e.g. http://127.0.0.1:8404/stats (required)
  -u, --user string                        Stats page basic auth user
  -p, --pass string                        Stats page basic auth password
  -s, --service string                     Regular expression matching the proxy names to check (required)
  -e, --exact-match                        Match the proxy name given with --service literally instead of as a regular expression
  -w, --warn-percent int                   WARNING when less than this percentage of servers is up (default 50)
  -c, --crit-percent int                   CRITICAL when less than this percentage of servers is up (default 25)
  -W, --session-warn-percent int           WARNING when a server uses more than this percentage of its session limit (default 75)
  -C, --session-crit-percent int           CRITICAL when a server uses more than this percentage of its session limit (default 90)
  -b, --backend-session-warn-percent int   WARNING when a backend uses more than this percentage of its session limit; replaces --session-warn-percent (0: disabled)
  -B, --backend-session-crit-percent int   CRITICAL when a backend uses more than this percentage of its session limit; replaces --session-crit-percent (0: disabled)
  -M, --min-warn-count int                 WARNING when fewer servers are found
  -X, --min-crit-count int                 CRITICAL when fewer servers are found
      --timeout int                        HTTP request timeout in seconds (default 10)
```

The URL is the `stats uri` of HAProxy, query included if any (`http://lb/haproxy?stats`); use `https://` for a TLS stats listener (the certificate is verified). Credentials can be given in the URL (`http://user:password@host/stats`) or with `--user`/`--pass`, which take precedence.

Every option can also be set with an environment variable, which keeps the password out of the process list:

| Option | Variable |
|---|---|
| `--url` | `CHECK_HAPROXY_URL` |
| `--user` / `--pass` | `CHECK_HAPROXY_USER` / `CHECK_HAPROXY_PASSWORD` |
| `--service` / `--exact-match` | `CHECK_HAPROXY_SERVICE` / `CHECK_HAPROXY_EXACT_MATCH` |
| `--warn-percent` / `--crit-percent` | `CHECK_HAPROXY_WARN_PERCENT` / `CHECK_HAPROXY_CRIT_PERCENT` |
| `--session-warn-percent` / `--session-crit-percent` | `CHECK_HAPROXY_SESSION_WARN_PERCENT` / `CHECK_HAPROXY_SESSION_CRIT_PERCENT` |
| `--backend-session-warn-percent` / `--backend-session-crit-percent` | `CHECK_HAPROXY_BACKEND_SESSION_WARN_PERCENT` / `CHECK_HAPROXY_BACKEND_SESSION_CRIT_PERCENT` |
| `--min-warn-count` / `--min-crit-count` | `CHECK_HAPROXY_MIN_WARN_COUNT` / `CHECK_HAPROXY_MIN_CRIT_COUNT` |
| `--timeout` | `CHECK_HAPROXY_TIMEOUT` |

Examples:

```sh
check-haproxy-status --url http://127.0.0.1:8404/stats -u sensu -s '^web$'      # password in CHECK_HAPROXY_PASSWORD
check-haproxy-status --url http://127.0.0.1/haproxy?stats -s web_app -e -M 2 -X 1
check-haproxy-status --url https://lb.example.com:8404/stats -s '.*' -b 75 -B 90
```

## Check definition

Every option is passed through `env_vars`, filled per host from entity annotations with token substitution (applied by the agent to the whole check definition, `env_vars` included). This keeps the password out of the process list, and one annotation maps to one option.

Naming rule: an annotation is named after its environment variable, lowercased, without the `CHECK_` prefix (`CHECK_HAPROXY_URL` → `haproxy_url`).

Every token has a non-empty `default`, equal to the plugin default: Sensu drops a check whose `env_vars` contains an empty value (`FOO=`) without any event. Never use `| default ""` there.

Stats page credentials, when HAProxy requires them (`stats auth`), go in the URL (`http://user:password@host:port/path`): unlike `--user`/`--pass`, an optional URL part needs no empty variable. The password is masked in the check output.

Annotations, e.g. in the agent configuration (`/etc/sensu/agent.yml`):

```yaml
annotations:
  haproxy_url: http://sensu:secret@127.0.0.1:8404/stats   # default http://127.0.0.1/
  haproxy_service: ^(web|api)$                           # default .* (every proxy)
  # optional thresholds
  haproxy_min_crit_count: "1"
  haproxy_backend_session_warn_percent: "75"
```

```yaml
---
type: CheckConfig
api_version: core/v2
metadata:
  name: check-haproxy-status
spec:
  command: check-haproxy-status
  env_vars:
    - CHECK_HAPROXY_URL={{ .annotations.haproxy_url | default "http://127.0.0.1/" }}
    - CHECK_HAPROXY_SERVICE={{ .annotations.haproxy_service | default ".*" }}
    - CHECK_HAPROXY_EXACT_MATCH={{ .annotations.haproxy_exact_match | default "false" }}
    - CHECK_HAPROXY_WARN_PERCENT={{ .annotations.haproxy_warn_percent | default "50" }}
    - CHECK_HAPROXY_CRIT_PERCENT={{ .annotations.haproxy_crit_percent | default "25" }}
    - CHECK_HAPROXY_SESSION_WARN_PERCENT={{ .annotations.haproxy_session_warn_percent | default "75" }}
    - CHECK_HAPROXY_SESSION_CRIT_PERCENT={{ .annotations.haproxy_session_crit_percent | default "90" }}
    - CHECK_HAPROXY_BACKEND_SESSION_WARN_PERCENT={{ .annotations.haproxy_backend_session_warn_percent | default "0" }}
    - CHECK_HAPROXY_BACKEND_SESSION_CRIT_PERCENT={{ .annotations.haproxy_backend_session_crit_percent | default "0" }}
    - CHECK_HAPROXY_MIN_WARN_COUNT={{ .annotations.haproxy_min_warn_count | default "0" }}
    - CHECK_HAPROXY_MIN_CRIT_COUNT={{ .annotations.haproxy_min_crit_count | default "0" }}
    - CHECK_HAPROXY_TIMEOUT={{ .annotations.haproxy_timeout | default "10" }}
  runtime_assets:
    - opsone/sensu-plugins-haproxy
  interval: 60
  timeout: 30
  publish: true
  subscriptions:
    - haproxy
```

To check several groups of backends with different thresholds on the same host, define one check per group with its own annotations (e.g. `haproxy_web_service`, `haproxy_api_service`).

Entity annotations are visible in the Sensu dashboard and API: to keep the password out of them, use a Sensu [secret](https://docs.sensu.io/sensu-go/latest/operations/manage-secrets/secrets/) holding the whole URL instead of the `CHECK_HAPROXY_URL` env var.

## Migrating from the Ruby version (≤ 0.1.0)

- The command loses its `.rb` suffix: `check-haproxy-status.rb` → `check-haproxy-status`.
- `-h`/`--hostname`, `-P`/`--port`, `-q`/`--statspath` and `--use-ssl` are replaced by a single `--url`: `-h 127.0.0.1 -P 8404 -q stats --use-ssl` → `--url https://127.0.0.1:8404/stats`. There is no default in the plugin anymore (it was port 80, path `/`); the default now lives in the check definition.
- `-u`/`-p` are kept (`CHECK_HAPROXY_USER`/`CHECK_HAPROXY_PASSWORD`); in the check definition, credentials go in the URL (`http://user:password@host/stats`).
- `-e` works: the Ruby version built a broken regular expression and never matched anything. It now compares the proxy name literally.
- `-b`/`-B` work: the Ruby version dropped the `BACKEND` lines before evaluating them, so they only disabled the per server session thresholds. They now alert on the backend session usage; `-b` reports WARNING (it was CRITICAL). `0` now disables them.
- Session messages report the session limit (`slim`) instead of the session peak (`smax`).
- An unreachable HAProxy is CRITICAL (it was UNKNOWN).
- The output prefix is `check-haproxy-status` (it was `CheckHaproxyStatus`).
- Thresholds have long options (`--warn-percent`, …) and environment variables.
- The asset no longer depends on the Ruby runtime asset, nor on the Debian release.

## Build and release

```sh
make test          # go vet + unit tests
make integration   # runs the check against a real HAProxy in Docker
```

Release:

```sh
git tag 0.2.0 && git push origin 0.2.0
make release       # version taken from the tag, or forced: make release VERSION=0.2.0
sensuctl create -f dist/opsone-sensu-plugins-haproxy_0.2.0.yml
```

`make release` runs `make dist`, which runs the tests then produces in `dist/`:

- one archive per architecture listed in `ARCHS` (`linux/amd64`) in Sensu asset layout (`bin/check-haproxy-status`);
- the sha512 checksums file;
- `opsone-sensu-plugins-haproxy_<version>.yml`, the asset definition pointing to the GitHub release of the tag.

It then creates the GitHub release of the tag with `gh`, uploads the archives and checksums, and uses the asset definition as release description.

`check-haproxy-status version` prints the version, commit and build date.
