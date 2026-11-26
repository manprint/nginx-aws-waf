// Package config loads node/site/profile YAML, merges WAF settings and validates them.
package config

// Config is a whole node config repository.
type Config struct {
	Dir      string
	Node     *Node
	Sites    []*Site
	Profiles map[string]*Profile
}

// Node is node.yaml.
type Node struct {
	Version     int       `yaml:"version"`
	NodeID      string    `yaml:"node_id"`
	Role        string    `yaml:"role"`
	Network     string    `yaml:"network"`
	Listen      Listen    `yaml:"listen"`
	Workers     int       `yaml:"workers"`
	GeoIP       GeoIP     `yaml:"geoip"`
	Audit       Audit     `yaml:"audit"`
	DefaultSite string    `yaml:"default_site"`
	Central     Central   `yaml:"central"`
	Retention   Retention `yaml:"retention"`
	Lab         Lab       `yaml:"lab"`
	File        string    `yaml:"-"`
}

// Listen holds the public ports.
type Listen struct {
	HTTP  int   `yaml:"http"`
	HTTPS int   `yaml:"https"`
	IPv6  *bool `yaml:"ipv6"`
}

// GeoIP toggles GeoLite2 lookups.
type GeoIP struct {
	Enabled bool `yaml:"enabled"`
}

// Audit selects which transactions reach the audit log.
type Audit struct {
	Scope string `yaml:"scope"`
}

// Central locates the central server.
type Central struct {
	Address    string `yaml:"address"`
	IngestPort int    `yaml:"ingest_port"`
	PKIPort    int    `yaml:"pki_port"`
}

// Retention of local raw logs.
type Retention struct {
	RawDays  int `yaml:"raw_days"`
	LogHours int `yaml:"log_hours"`
}

// Lab enables lab-only relaxations.
type Lab struct {
	Enabled bool `yaml:"enabled"`
}

// Site is sites/<site_id>.yaml.
type Site struct {
	Version     int      `yaml:"version"`
	SiteID      string   `yaml:"site_id"`
	ServerNames []string `yaml:"server_names"`
	App         string   `yaml:"app"`
	Profile     string   `yaml:"profile"`
	Upstream    Upstream `yaml:"upstream"`
	TLS         TLS      `yaml:"tls"`
	WAF         `yaml:",inline"`
	File        string `yaml:"-"`
}

// Upstream is the backend of a site.
type Upstream struct {
	Servers        []string  `yaml:"servers"`
	Realtime       *Realtime `yaml:"realtime"`
	TLS            bool      `yaml:"tls"`
	MaxBodySize    string    `yaml:"max_body_size"`
	ReadTimeoutSec int       `yaml:"read_timeout_sec"`
}

// Realtime is the long-polling/websocket backend (Odoo 8072).
type Realtime struct {
	Path    string   `yaml:"path"`
	Servers []string `yaml:"servers"`
}

// TLS of the public listener.
type TLS struct {
	Mode string `yaml:"mode"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Profile is profiles/<name>.yaml.
type Profile struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Extends     string `yaml:"extends"`
	WAF         `yaml:",inline"`
	File        string `yaml:"-"`
}

// WAF holds the settings allowed in profiles and sites.
type WAF struct {
	Mode               string         `yaml:"mode,omitempty"`
	DefaultAction      string         `yaml:"default_action,omitempty"`
	BodyLimit          int            `yaml:"body_limit,omitempty"`
	ClientIP           ClientIP       `yaml:"client_ip,omitempty"`
	Fail               Fail           `yaml:"fail,omitempty"`
	RuleGroups         []RuleGroup    `yaml:"rule_groups,omitempty"`
	CustomRules        []CustomRule   `yaml:"custom_rules,omitempty"`
	DisableCustomRules []string       `yaml:"disable_custom_rules,omitempty"`
	RateLimit          *RateLimit     `yaml:"rate_limit,omitempty"`
	GeoBlock           *GeoBlock      `yaml:"geo_block,omitempty"`
	PathOverrides      []PathOverride `yaml:"path_overrides,omitempty"`
	BlockPage          string         `yaml:"block_page,omitempty"`
}

// ClientIP selects the client address source; nil TrustedProxies = unset.
type ClientIP struct {
	Source         string   `yaml:"source,omitempty"`
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
}

// Fail selects closed|block|open per failure class.
type Fail struct {
	PCRELimit string `yaml:"pcre_limit,omitempty"`
	BodyError string `yaml:"body_error,omitempty"`
}

// RuleGroup configures one managed rule group.
type RuleGroup struct {
	Name                string            `yaml:"name"`
	Enabled             *bool             `yaml:"enabled,omitempty"`
	OverrideAction      string            `yaml:"override_action,omitempty"`
	RuleActionOverrides map[string]string `yaml:"rule_action_overrides,omitempty"`
	ScopeDown           *Match            `yaml:"scope_down,omitempty"`
}

// Match is an AND of conditions.
type Match struct {
	All []Cond `yaml:"all"`
}

// Cond is one condition; exactly one kind must be set.
type Cond struct {
	Label          string    `yaml:"label,omitempty"`
	LabelNamespace string    `yaml:"label_namespace,omitempty"`
	URIPath        *StrMatch `yaml:"uri_path,omitempty"`
	Header         *StrMatch `yaml:"header,omitempty"`
	QueryArg       *StrMatch `yaml:"query_arg,omitempty"`
	Method         []string  `yaml:"method,omitempty"`
	IPSet          []string  `yaml:"ip_set,omitempty"`
	Geo            []string  `yaml:"geo,omitempty"`
	Size           *Size     `yaml:"size,omitempty"`
	Negate         bool      `yaml:"negate,omitempty"`
}

// Kinds returns the names of the condition kinds that are set.
func (c Cond) Kinds() []string {
	var k []string
	add := func(set bool, n string) {
		if set {
			k = append(k, n)
		}
	}
	add(c.Label != "", "label")
	add(c.LabelNamespace != "", "label_namespace")
	add(c.URIPath != nil, "uri_path")
	add(c.Header != nil, "header")
	add(c.QueryArg != nil, "query_arg")
	add(c.Method != nil, "method")
	add(c.IPSet != nil, "ip_set")
	add(c.Geo != nil, "geo")
	add(c.Size != nil, "size")
	return k
}

// StrMatch is a string comparison; exactly one of Exact/StartsWith/Contains/Regex.
type StrMatch struct {
	Name       string   `yaml:"name,omitempty"`
	Exact      string   `yaml:"exact,omitempty"`
	StartsWith string   `yaml:"starts_with,omitempty"`
	Contains   string   `yaml:"contains,omitempty"`
	Regex      string   `yaml:"regex,omitempty"`
	Transform  []string `yaml:"transform,omitempty"`
}

// Size compares the size of a request component.
type Size struct {
	Component string `yaml:"component"`
	Op        string `yaml:"op"`
	Value     int    `yaml:"value"`
}

// CustomRule is a site/profile rule evaluated at a slot.
type CustomRule struct {
	Name   string `yaml:"name"`
	Slot   string `yaml:"slot"`
	Action string `yaml:"action"`
	Match  Match  `yaml:"match"`
}

// RateLimit is an nginx limit_req based rate rule.
type RateLimit struct {
	Limit     int    `yaml:"limit"`
	WindowSec int    `yaml:"window_sec"`
	Action    string `yaml:"action"`
}

// GeoBlock blocks/counts listed countries.
type GeoBlock struct {
	Countries []string `yaml:"countries"`
	Action    string   `yaml:"action"`
}

// PathOverride changes rule actions under a path prefix (nginx-only).
type PathOverride struct {
	PathPrefix string            `yaml:"path_prefix"`
	Rules      map[string]string `yaml:"rules"`
}
