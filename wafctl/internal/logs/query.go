package logs

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Filter holds the common logs/stats/export filters.
type Filter struct {
	Sites      []string
	Since      time.Duration
	From, To   time.Time
	Action     string
	Shadow     string
	Rule       string
	Matched    bool
	IP         string
	Country    string
	PathPrefix string
	UserClass  string
	Status     int
	RID        string
	Node       string
	Limit      int
}

// strList is a repeatable string flag.
type strList []string

func (s *strList) String() string     { return strings.Join(*s, ",") }
func (s *strList) Set(v string) error { *s = append(*s, v); return nil }

// FilterFlags registers the common flags; call Finish after Parse.
type FilterFlags struct {
	f        Filter
	since    string
	from, to string
	sites    strList
}

// AddFilterFlags registers the common filter flags on fs.
func AddFilterFlags(fs *flag.FlagSet, defSince string, defLimit int) *FilterFlags {
	ff := &FilterFlags{}
	fs.Var(&ff.sites, "site", "site id (repeatable)")
	fs.StringVar(&ff.since, "since", defSince, "window ending now (e.g. 15m, 1h, 7d)")
	fs.StringVar(&ff.from, "from", "", "window start, RFC3339 with zone (UTC recommended)")
	fs.StringVar(&ff.to, "to", "", "window end, RFC3339 with zone (default now)")
	fs.StringVar(&ff.f.Action, "action", "", "ALLOW|BLOCK|FAIL")
	fs.StringVar(&ff.f.Shadow, "shadow", "", "shadow action (BLOCK)")
	fs.StringVar(&ff.f.Rule, "rule", "", "terminating rule name (with --matched: any matching rule)")
	fs.BoolVar(&ff.f.Matched, "matched", false, "--rule matches any matched rule, not only the terminating one")
	fs.StringVar(&ff.f.IP, "ip", "", "client IP")
	fs.StringVar(&ff.f.Country, "country", "", "country code (GeoIP)")
	fs.StringVar(&ff.f.PathPrefix, "path-prefix", "", "path prefix")
	fs.StringVar(&ff.f.UserClass, "user-class", "", "user class (backend|website|static|realtime|other)")
	fs.IntVar(&ff.f.Status, "status", 0, "HTTP status")
	fs.StringVar(&ff.f.RID, "rid", "", "request id")
	fs.StringVar(&ff.f.Node, "node", "", "node id (multi-node central)")
	fs.IntVar(&ff.f.Limit, "limit", defLimit, "max rows (1-100000)")
	return ff
}

var reDur = regexp.MustCompile(`^(\d+)([smhd])$`)

// ParseDuration accepts Go durations plus a "d" (days) suffix.
func ParseDuration(s string) (time.Duration, error) {
	if m := reDur.FindStringSubmatch(s); m != nil && m[2] == "d" {
		n, _ := strconv.Atoi(m[1])
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// ParseTime parses RFC3339 timestamps; a value without a zone is rejected.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %q: want RFC3339 with a zone, e.g. 2026-11-27T10:00:00Z", s)
	}
	return t.UTC(), nil
}

// Finish validates the flags and resolves the window against now.
func (ff *FilterFlags) Finish(now time.Time) (Filter, error) {
	f := ff.f
	f.Sites = append([]string(nil), ff.sites...)
	now = now.UTC()
	if ff.from != "" {
		t, err := ParseTime(ff.from)
		if err != nil {
			return f, err
		}
		f.From, f.To = t, now
		if ff.to != "" {
			if f.To, err = ParseTime(ff.to); err != nil {
				return f, err
			}
		}
	} else {
		if ff.to != "" {
			return f, errors.New("--to needs --from")
		}
		d, err := ParseDuration(ff.since)
		if err != nil {
			return f, err
		}
		f.Since, f.From, f.To = d, now.Add(-d), now
	}
	if !f.To.After(f.From) {
		return f, errors.New("empty window: --to must be after --from")
	}
	if f.Action != "" && !in(f.Action, "ALLOW", "BLOCK", "FAIL") {
		return f, fmt.Errorf("--action %q not in ALLOW|BLOCK|FAIL", f.Action)
	}
	if f.Shadow != "" && !in(f.Shadow, "ALLOW", "BLOCK") {
		return f, fmt.Errorf("--shadow %q not in ALLOW|BLOCK", f.Shadow)
	}
	if f.Matched && f.Rule == "" {
		return f, errors.New("--matched needs --rule")
	}
	if f.IP != "" {
		a, err := netip.ParseAddr(f.IP)
		if err != nil {
			return f, fmt.Errorf("--ip %q: %v", f.IP, err)
		}
		f.IP = a.String()
	}
	if f.Limit < 1 || f.Limit > 100000 {
		return f, fmt.Errorf("--limit %d not in 1-100000", f.Limit)
	}
	return f, nil
}

func in(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// Where builds the WHERE clause from fixed fragments and returns the parameters.
// User values never enter the SQL text.
func (f Filter) Where() (string, map[string]string) {
	p := map[string]string{
		"from_ms": strconv.FormatInt(f.From.UnixMilli(), 10),
		"to_ms":   strconv.FormatInt(f.To.UnixMilli(), 10),
	}
	c := []string{"ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')", "ts < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')"}
	if len(f.Sites) > 0 {
		p["site"] = arrayLiteral(f.Sites)
		c = append(c, "site_id IN {site:Array(String)}")
	}
	add := func(v, frag, name string) {
		if v != "" {
			p[name] = v
			c = append(c, frag)
		}
	}
	add(f.Action, "action = {action:String}", "action")
	add(f.Shadow, "shadow_action = {shadow:String}", "shadow")
	if f.Rule != "" {
		if f.Matched {
			p["rule"] = f.Rule
			c = append(c, "request_id IN (SELECT request_id FROM waf.matches WHERE rule_name = {rule:String} AND ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC') AND ts < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC'))")
		} else {
			p["rule"] = f.Rule
			c = append(c, "(terminating_rule = {rule:String} OR endsWith(terminating_rule, concat('/', {rule:String})))")
		}
	}
	add(f.IP, "client_ip = {ip:String}", "ip")
	add(f.Country, "country = {country:String}", "country")
	add(f.PathPrefix, "startsWith(path, {path_prefix:String})", "path_prefix")
	add(f.UserClass, "user_class = {user_class:String}", "user_class")
	add(f.RID, "request_id = {rid:String}", "rid")
	add(f.Node, "node_id = {node:String}", "node")
	if f.Status != 0 {
		p["status"] = strconv.Itoa(f.Status)
		c = append(c, "status = {status:UInt16}")
	}
	return strings.Join(c, " AND "), p
}

// arrayLiteral encodes a ClickHouse Array(String) parameter value: ['a','b'] with escaping.
func arrayLiteral(v []string) string {
	q := make([]string, len(v))
	for i, s := range v {
		s = strings.ReplaceAll(s, `\`, `\\`)
		q[i] = "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
	}
	return "[" + strings.Join(q, ",") + "]"
}

// ArrayParam is arrayLiteral for other packages (stats).
func ArrayParam(v []string) string { return arrayLiteral(v) }

// TS formats a ClickHouse DateTime64 string ("2026-11-27 00:01:44.869") as RFC3339 UTC.
func TS(s string) string {
	if len(s) >= 19 && s[10] == ' ' {
		return s[:10] + "T" + s[11:] + "Z"
	}
	return s
}
