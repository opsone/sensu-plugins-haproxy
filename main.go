package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	corev2 "github.com/sensu/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	URL        string
	User       string
	Password   string
	Service    string
	ExactMatch bool
	Thresholds Thresholds
	Timeout    int
}

// Thresholds are the alerting limits. Percentages are compared to integers;
// a backend session limit of 0 disables the backend session check.
type Thresholds struct {
	WarnPercent               int
	CritPercent               int
	SessionWarnPercent        int
	SessionCritPercent        int
	BackendSessionWarnPercent int
	BackendSessionCritPercent int
	MinWarnCount              int
	MinCritCount              int
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-haproxy-status",
			Short:    "Check the servers of HAProxy backends through the stats page",
			Keyspace: "sensu.io/plugins/check-haproxy-status/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Path:     "url",
			Env:      "CHECK_HAPROXY_URL",
			Argument: "url",
			Usage:    "HAProxy stats page URL, e.g. http://127.0.0.1:8404/stats (required)",
			Value:    &plugin.URL,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "user",
			Env:       "CHECK_HAPROXY_USER",
			Argument:  "user",
			Shorthand: "u",
			Usage:     "Stats page basic auth user",
			Value:     &plugin.User,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "pass",
			Env:       "CHECK_HAPROXY_PASSWORD",
			Argument:  "pass",
			Shorthand: "p",
			Secret:    true,
			Usage:     "Stats page basic auth password",
			Value:     &plugin.Password,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "service",
			Env:       "CHECK_HAPROXY_SERVICE",
			Argument:  "service",
			Shorthand: "s",
			Usage:     "Regular expression matching the proxy names to check (required)",
			Value:     &plugin.Service,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "exact-match",
			Env:       "CHECK_HAPROXY_EXACT_MATCH",
			Argument:  "exact-match",
			Shorthand: "e",
			Usage:     "Match the proxy name given with --service literally instead of as a regular expression",
			Value:     &plugin.ExactMatch,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "warn-percent",
			Env:       "CHECK_HAPROXY_WARN_PERCENT",
			Argument:  "warn-percent",
			Shorthand: "w",
			Default:   50,
			Usage:     "WARNING when less than this percentage of servers is up",
			Value:     &plugin.Thresholds.WarnPercent,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "crit-percent",
			Env:       "CHECK_HAPROXY_CRIT_PERCENT",
			Argument:  "crit-percent",
			Shorthand: "c",
			Default:   25,
			Usage:     "CRITICAL when less than this percentage of servers is up",
			Value:     &plugin.Thresholds.CritPercent,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "session-warn-percent",
			Env:       "CHECK_HAPROXY_SESSION_WARN_PERCENT",
			Argument:  "session-warn-percent",
			Shorthand: "W",
			Default:   75,
			Usage:     "WARNING when a server uses more than this percentage of its session limit",
			Value:     &plugin.Thresholds.SessionWarnPercent,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "session-crit-percent",
			Env:       "CHECK_HAPROXY_SESSION_CRIT_PERCENT",
			Argument:  "session-crit-percent",
			Shorthand: "C",
			Default:   90,
			Usage:     "CRITICAL when a server uses more than this percentage of its session limit",
			Value:     &plugin.Thresholds.SessionCritPercent,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "backend-session-warn-percent",
			Env:       "CHECK_HAPROXY_BACKEND_SESSION_WARN_PERCENT",
			Argument:  "backend-session-warn-percent",
			Shorthand: "b",
			Usage:     "WARNING when a backend uses more than this percentage of its session limit; replaces --session-warn-percent (0: disabled)",
			Value:     &plugin.Thresholds.BackendSessionWarnPercent,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "backend-session-crit-percent",
			Env:       "CHECK_HAPROXY_BACKEND_SESSION_CRIT_PERCENT",
			Argument:  "backend-session-crit-percent",
			Shorthand: "B",
			Usage:     "CRITICAL when a backend uses more than this percentage of its session limit; replaces --session-crit-percent (0: disabled)",
			Value:     &plugin.Thresholds.BackendSessionCritPercent,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "min-warn-count",
			Env:       "CHECK_HAPROXY_MIN_WARN_COUNT",
			Argument:  "min-warn-count",
			Shorthand: "M",
			Usage:     "WARNING when fewer servers are found",
			Value:     &plugin.Thresholds.MinWarnCount,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "min-crit-count",
			Env:       "CHECK_HAPROXY_MIN_CRIT_COUNT",
			Argument:  "min-crit-count",
			Shorthand: "X",
			Usage:     "CRITICAL when fewer servers are found",
			Value:     &plugin.Thresholds.MinCritCount,
		},
		&sensu.PluginConfigOption[int]{
			Path:     "timeout",
			Env:      "CHECK_HAPROXY_TIMEOUT",
			Argument: "timeout",
			Default:  10,
			Usage:    "HTTP request timeout in seconds",
			Value:    &plugin.Timeout,
		},
	}
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if plugin.URL == "" {
		return sensu.CheckStateUnknown, errors.New("--url is required")
	}
	if _, err := statsURL(plugin.URL); err != nil {
		return sensu.CheckStateUnknown, err
	}
	if plugin.Service == "" {
		return sensu.CheckStateUnknown, errors.New("--service is required")
	}
	if _, err := matcher(plugin.Service, plugin.ExactMatch); err != nil {
		return sensu.CheckStateUnknown, err
	}
	if plugin.Timeout <= 0 {
		return sensu.CheckStateUnknown, errors.New("--timeout must be greater than 0")
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {
	u, _ := statsURL(plugin.URL)
	match, _ := matcher(plugin.Service, plugin.ExactMatch)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(plugin.Timeout)*time.Second)
	defer cancel()

	result := run(ctx, u, match, serviceLabel(plugin.Service, plugin.ExactMatch))
	fmt.Printf("%s %s: %s\n", plugin.Name, stateLabel(result.State), result.Message)
	return result.State, nil
}

func run(ctx context.Context, u *url.URL, match func(string) bool, label string) Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{sensu.CheckStateUnknown, err.Error()}
	}
	if plugin.User != "" {
		req.SetBasicAuth(plugin.User, plugin.Password)
	}

	// A failed request means HAProxy (or its stats listener) does not answer.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{sensu.CheckStateCritical, fmt.Sprintf("fetching %s: %v", u.Redacted(), unwrapURLError(err))}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{sensu.CheckStateUnknown, fmt.Sprintf("fetching %s: HTTP %s", u.Redacted(), resp.Status)}
	}
	rows, err := parseStats(resp.Body)
	if err != nil {
		return Result{sensu.CheckStateUnknown, fmt.Sprintf("reading %s: %v", u.Redacted(), err)}
	}

	servers, backends := selectRows(rows, match)
	return evaluate(servers, backends, label, plugin.Thresholds)
}

// unwrapURLError drops the "Get <url>:" prefix added by net/http, the URL being already in the message.
func unwrapURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// statsURL validates the stats page URL and appends the CSV export suffix to it.
// The suffix goes at the very end of the request URI, query included, as HAProxy
// matches its "stats uri" as a prefix (e.g. "/haproxy?stats;csv;norefresh").
func statsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid --url %q: expected http(s)://host[:port]/path", raw)
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery += ";csv;norefresh"
	} else {
		u.Path += ";csv;norefresh"
	}
	return u, nil
}

// matcher returns the proxy name filter given with --service.
func matcher(service string, exact bool) (func(string) bool, error) {
	if exact {
		return func(name string) bool { return name == service }, nil
	}
	re, err := regexp.Compile(service)
	if err != nil {
		return nil, fmt.Errorf("invalid --service regular expression %q: %w", service, err)
	}
	return re.MatchString, nil
}

func serviceLabel(service string, exact bool) string {
	if exact {
		return service
	}
	return "/" + service + "/"
}

// Row is a line of the HAProxy CSV stats.
type Row struct {
	Proxy       string // pxname
	Name        string // svname: server name, FRONTEND or BACKEND
	Status      string
	CheckStatus string
	Sessions    int // scur
	Limit       int // slim
}

// parseStats reads the CSV export of the stats page ("# pxname,svname,...").
func parseStats(r io.Reader) ([]Row, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("empty or invalid CSV: %w", err)
	}
	col := map[string]int{}
	for i, name := range header {
		col[strings.TrimSpace(strings.TrimPrefix(name, "#"))] = i
	}
	for _, name := range []string{"pxname", "svname", "status"} {
		if _, ok := col[name]; !ok {
			return nil, fmt.Errorf("not an HAProxy CSV export: no %q column", name)
		}
	}
	field := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	number := func(rec []string, name string) int {
		n, _ := strconv.Atoi(field(rec, name))
		return n
	}

	var rows []Row
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return rows, nil
		}
		if err != nil {
			return nil, err
		}
		if len(rec) == 0 || strings.HasPrefix(rec[0], "#") {
			continue
		}
		rows = append(rows, Row{
			Proxy:       field(rec, "pxname"),
			Name:        field(rec, "svname"),
			Status:      field(rec, "status"),
			CheckStatus: field(rec, "check_status"),
			Sessions:    number(rec, "scur"),
			Limit:       number(rec, "slim"),
		})
	}
}

// selectRows keeps the rows of the matching proxies: the servers, except those in
// maintenance, and the BACKEND lines. FRONTEND lines are ignored.
func selectRows(rows []Row, match func(string) bool) (servers, backends []Row) {
	for _, r := range rows {
		if !match(r.Proxy) {
			continue
		}
		switch {
		case r.Name == "BACKEND":
			backends = append(backends, r)
		case r.Name == "FRONTEND", strings.HasPrefix(r.Status, "MAINT"):
		default:
			servers = append(servers, r)
		}
	}
	return servers, backends
}

func serverUp(r Row) bool {
	return strings.HasPrefix(r.Status, "UP") || strings.HasPrefix(r.Status, "DRAIN") ||
		r.Status == "OPEN" || r.Status == "no check"
}

// Result is the outcome of the evaluation.
type Result struct {
	State   int
	Message string
}

// evaluate applies the thresholds, in the order of the Ruby version: the first matching rule wins.
func evaluate(servers, backends []Row, label string, t Thresholds) Result {
	if len(servers) == 0 {
		return Result{sensu.CheckStateWarning, fmt.Sprintf("No services matching %s", label)}
	}

	up := 0
	var down []string
	for _, s := range servers {
		if serverUp(s) {
			up++
			continue
		}
		name := s.Proxy + "/" + s.Name
		if s.CheckStatus != "" {
			name += "[" + s.CheckStatus + "]"
		}
		down = append(down, name)
	}
	percentUp := 100 * up / len(servers)

	status := fmt.Sprintf("UP: %d%% of %d %s services", percentUp, len(servers), label)
	if len(down) > 0 {
		status += ", DOWN: " + strings.Join(down, ", ")
	}

	// Session usage: backend thresholds, when given, replace the per server ones.
	sessions := func(level string, serverPercent, backendPercent int) string {
		kind, over := "sessions", overLimit(servers, serverPercent, false)
		if backendPercent > 0 {
			kind, over = "backends", overLimit(backends, backendPercent, true)
		}
		if len(over) == 0 {
			return ""
		}
		return fmt.Sprintf("%s; Active %s %s: %s", status, kind, level, strings.Join(over, ", "))
	}
	critSessions := sessions("critical", t.SessionCritPercent, t.BackendSessionCritPercent)
	warnSessions := sessions("warning", t.SessionWarnPercent, t.BackendSessionWarnPercent)

	switch {
	case len(servers) < t.MinCritCount, percentUp < t.CritPercent:
		return Result{sensu.CheckStateCritical, status}
	case critSessions != "":
		return Result{sensu.CheckStateCritical, critSessions}
	case len(servers) < t.MinWarnCount, percentUp < t.WarnPercent:
		return Result{sensu.CheckStateWarning, status}
	case warnSessions != "":
		return Result{sensu.CheckStateWarning, warnSessions}
	default:
		return Result{sensu.CheckStateOK, status}
	}
}

// overLimit lists the rows using more than percent of their session limit,
// e.g. "9 of 10 web/web1" (or "9 of 10 web" for a backend).
func overLimit(rows []Row, percent int, backend bool) []string {
	var over []string
	for _, r := range rows {
		if r.Limit <= 0 || 100*float64(r.Sessions)/float64(r.Limit) <= float64(percent) {
			continue
		}
		name := r.Proxy + "/" + r.Name
		if backend {
			name = r.Proxy + " backend"
		}
		over = append(over, fmt.Sprintf("%d of %d %s", r.Sessions, r.Limit, name))
	}
	sort.Strings(over)
	return over
}

func stateLabel(state int) string {
	switch state {
	case sensu.CheckStateOK:
		return "OK"
	case sensu.CheckStateWarning:
		return "WARNING"
	case sensu.CheckStateCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
