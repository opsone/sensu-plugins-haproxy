# Changelog

## [Unreleased] - 0.2.0

### Changed
- Rewritten in Go with the Sensu plugin SDK: static binary for `linux/amd64`, no Ruby runtime asset.
- Command renamed without the `.rb` suffix (`check-haproxy-status`).
- `--hostname`, `--port`, `--statspath` and `--use-ssl` replaced by `--url` (`CHECK_HAPROXY_URL`), required, no default in the plugin.
- An unreachable HAProxy is CRITICAL instead of UNKNOWN.
- Session messages report the session limit (`slim`) instead of the session peak (`smax`).

### Fixed
- `-e` (`--exact-match`) never matched anything; it now compares the proxy name literally.
- `-b` / `-B` never alerted (the `BACKEND` lines were filtered out before being evaluated); `-b` reports WARNING instead of CRITICAL.
- No more double slash in the stats URL.

### Added
- Every option can be set through an environment variable (`CHECK_HAPROXY_*`).
- Long options for the thresholds, `--timeout`.
- Stats page credentials can be given in the URL (`http://user:password@host/stats`), the password being masked in the output.

## [0.1.0]

### Added
- `check-haproxy-status.rb`.
