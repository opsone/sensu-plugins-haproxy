package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sensu/sensu-plugin-sdk/sensu"
)

var defaults = Thresholds{WarnPercent: 50, CritPercent: 25, SessionWarnPercent: 75, SessionCritPercent: 90}

func srv(name, status string) Row {
	return Row{Proxy: "web", Name: name, Status: status}
}

func TestEvaluate(t *testing.T) {
	withMin := defaults
	withMin.MinWarnCount, withMin.MinCritCount = 3, 2
	backendLimits := defaults
	backendLimits.BackendSessionWarnPercent, backendLimits.BackendSessionCritPercent = 50, 80

	tests := []struct {
		name     string
		servers  []Row
		backends []Row
		t        Thresholds
		want     Result
	}{
		{
			name: "no server",
			t:    defaults,
			want: Result{sensu.CheckStateWarning, "No services matching /web/"},
		},
		{
			name:    "all up",
			servers: []Row{srv("a", "UP"), srv("b", "UP 1/3"), srv("c", "DRAIN"), srv("d", "no check")},
			t:       defaults,
			want:    Result{sensu.CheckStateOK, "UP: 100% of 4 /web/ services"},
		},
		{
			name:    "half up is not below the warning threshold",
			servers: []Row{srv("a", "UP"), {Proxy: "web", Name: "b", Status: "DOWN", CheckStatus: "L4CON"}},
			t:       defaults,
			want:    Result{sensu.CheckStateOK, "UP: 50% of 2 /web/ services, DOWN: web/b[L4CON]"},
		},
		{
			name:    "a third up is a warning",
			servers: []Row{srv("a", "UP"), srv("b", "DOWN"), srv("c", "NOLB")},
			t:       defaults,
			want:    Result{sensu.CheckStateWarning, "UP: 33% of 3 /web/ services, DOWN: web/b, web/c"},
		},
		{
			name:    "all down is critical",
			servers: []Row{srv("a", "DOWN"), srv("b", "DOWN 1/2")},
			t:       defaults,
			want:    Result{sensu.CheckStateCritical, "UP: 0% of 2 /web/ services, DOWN: web/a, web/b"},
		},
		{
			name:    "below minimum warning count",
			servers: []Row{srv("a", "UP"), srv("b", "UP")},
			t:       withMin,
			want:    Result{sensu.CheckStateWarning, "UP: 100% of 2 /web/ services"},
		},
		{
			name:    "below minimum critical count",
			servers: []Row{srv("a", "UP")},
			t:       withMin,
			want:    Result{sensu.CheckStateCritical, "UP: 100% of 1 /web/ services"},
		},
		{
			name:    "server sessions warning",
			servers: []Row{{Proxy: "web", Name: "a", Status: "UP", Sessions: 8, Limit: 10}, {Proxy: "web", Name: "b", Status: "UP", Sessions: 5}},
			t:       defaults,
			want:    Result{sensu.CheckStateWarning, "UP: 100% of 2 /web/ services; Active sessions warning: 8 of 10 web/a"},
		},
		{
			name:    "server sessions critical",
			servers: []Row{{Proxy: "web", Name: "a", Status: "UP", Sessions: 10, Limit: 10}},
			t:       defaults,
			want:    Result{sensu.CheckStateCritical, "UP: 100% of 1 /web/ services; Active sessions critical: 10 of 10 web/a"},
		},
		{
			name:     "backend thresholds replace server ones",
			servers:  []Row{{Proxy: "web", Name: "a", Status: "UP", Sessions: 10, Limit: 10}},
			backends: []Row{{Proxy: "web", Name: "BACKEND", Status: "UP", Sessions: 6, Limit: 10}},
			t:        backendLimits,
			want:     Result{sensu.CheckStateWarning, "UP: 100% of 1 /web/ services; Active backends warning: 6 of 10 web backend"},
		},
		{
			name:     "backend sessions critical",
			servers:  []Row{srv("a", "UP")},
			backends: []Row{{Proxy: "web", Name: "BACKEND", Status: "UP", Sessions: 9, Limit: 10}},
			t:        backendLimits,
			want:     Result{sensu.CheckStateCritical, "UP: 100% of 1 /web/ services; Active backends critical: 9 of 10 web backend"},
		},
		{
			name:    "down servers win over sessions",
			servers: []Row{{Proxy: "web", Name: "a", Status: "DOWN", Sessions: 10, Limit: 10}},
			t:       defaults,
			want:    Result{sensu.CheckStateCritical, "UP: 0% of 1 /web/ services, DOWN: web/a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evaluate(tt.servers, tt.backends, "/web/", tt.t); got != tt.want {
				t.Errorf("evaluate() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

const stats = `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,
stats,FRONTEND,,,1,1,262115,1,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,1,0,,,,0,0,0,1,,
web,web1,0,0,3,4,10,8,0,0,,0,,0,0,0,0,UP,1,1,0,0,0,10,0,,1,3,1,,8,,2,0,,1,L7OK,
web,web2,0,0,0,0,,0,0,0,,0,,0,0,0,0,DOWN,1,1,0,1,1,5,5,,1,3,2,,0,,2,0,,0,L4CON,
web,web3,0,0,0,0,,0,0,0,,0,,0,0,0,0,MAINT,1,1,0,0,0,5,5,,1,3,3,,0,,2,0,,0,,
web,BACKEND,0,0,3,4,20,8,0,0,0,0,,0,0,0,0,UP,1,1,0,,0,10,0,,1,3,0,,8,,1,0,,1,,
webapi,api1,0,0,0,0,,0,0,0,,0,,0,0,0,0,no check,1,1,0,,,10,,,1,4,1,,0,,2,0,,0,,
`

func TestParseAndSelect(t *testing.T) {
	rows, err := parseStats(strings.NewReader(stats))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 {
		t.Fatalf("got %d rows, want 6", len(rows))
	}

	match, _ := matcher("^web$", false)
	servers, backends := selectRows(rows, match)
	wantServers := []Row{
		{Proxy: "web", Name: "web1", Status: "UP", CheckStatus: "L7OK", Sessions: 3, Limit: 10},
		{Proxy: "web", Name: "web2", Status: "DOWN", CheckStatus: "L4CON"},
	}
	if !reflect.DeepEqual(servers, wantServers) {
		t.Errorf("servers = %+v, want %+v", servers, wantServers)
	}
	wantBackends := []Row{{Proxy: "web", Name: "BACKEND", Status: "UP", Sessions: 3, Limit: 20}}
	if !reflect.DeepEqual(backends, wantBackends) {
		t.Errorf("backends = %+v, want %+v", backends, wantBackends)
	}

	match, _ = matcher("web", false)
	if servers, _ := selectRows(rows, match); len(servers) != 3 {
		t.Errorf("regex web: got %d servers, want 3", len(servers))
	}
	match, _ = matcher("web", true)
	if servers, _ := selectRows(rows, match); len(servers) != 2 {
		t.Errorf("exact web: got %d servers, want 2", len(servers))
	}
}

func TestParseStatsInvalid(t *testing.T) {
	for _, body := range []string{"", "<html><body>Not found</body></html>\n"} {
		if _, err := parseStats(strings.NewReader(body)); err == nil {
			t.Errorf("parseStats(%q): expected an error", body)
		}
	}
}

func TestStatsURL(t *testing.T) {
	tests := []struct {
		raw, want string
		wantErr   bool
	}{
		{raw: "http://127.0.0.1:8404/stats", want: "http://127.0.0.1:8404/stats;csv;norefresh"},
		{raw: "http://127.0.0.1", want: "http://127.0.0.1/;csv;norefresh"},
		{raw: "https://lb.example.com/", want: "https://lb.example.com/;csv;norefresh"},
		{raw: "http://lb/haproxy?stats", want: "http://lb/haproxy?stats;csv;norefresh"},
		{raw: "127.0.0.1:8404/stats", wantErr: true},
		{raw: "ftp://lb/stats", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, tt := range tests {
		u, err := statsURL(tt.raw)
		if (err != nil) != tt.wantErr {
			t.Errorf("statsURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			continue
		}
		if err == nil && u.String() != tt.want {
			t.Errorf("statsURL(%q) = %q, want %q", tt.raw, u.String(), tt.want)
		}
	}
}

func TestMatcherInvalid(t *testing.T) {
	if _, err := matcher("web(", false); err == nil {
		t.Error("expected an error for an invalid regular expression")
	}
	if _, err := matcher("web(", true); err != nil {
		t.Errorf("exact match must not compile a regex: %v", err)
	}
}
