package logs

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Event is the subset of waf.events used by the AWS log format.
type Event struct {
	TS              string            `json:"ts"`
	RequestID       string            `json:"request_id"`
	NodeID          string            `json:"node_id"`
	SiteID          string            `json:"site_id"`
	ClientIP        string            `json:"client_ip"`
	Country         string            `json:"country"`
	Method          string            `json:"method"`
	HTTPVersion     string            `json:"http_version"`
	Path            string            `json:"path"`
	Query           string            `json:"query"`
	Status          int               `json:"status"`
	Action          string            `json:"action"`
	TerminatingRule string            `json:"terminating_rule"`
	TerminatingType string            `json:"terminating_type"`
	Labels          []string          `json:"labels"`
	RequestHeaders  map[string]string `json:"request_headers"`
	Matches         []Match           `json:"matches,omitempty"`
}

// AWSLog is one AWS WAF log record (field order as in AWS logs).
type AWSLog struct {
	Timestamp                   int64           `json:"timestamp"`
	FormatVersion               int             `json:"formatVersion"`
	WebACLID                    string          `json:"webaclId"`
	TerminatingRuleID           string          `json:"terminatingRuleId"`
	TerminatingRuleType         string          `json:"terminatingRuleType"`
	Action                      string          `json:"action"`
	TerminatingRuleMatchDetails []any           `json:"terminatingRuleMatchDetails"`
	HTTPSourceName              string          `json:"httpSourceName"`
	HTTPSourceID                string          `json:"httpSourceId"`
	RuleGroupList               []AWSRuleGroup  `json:"ruleGroupList"`
	RateBasedRuleList           []any           `json:"rateBasedRuleList"`
	NonTerminatingMatchingRules []AWSRuleAction `json:"nonTerminatingMatchingRules"`
	RequestHeadersInserted      any             `json:"requestHeadersInserted"`
	ResponseCodeSent            *int            `json:"responseCodeSent"`
	HTTPRequest                 AWSHTTPRequest  `json:"httpRequest"`
	Labels                      []AWSLabel      `json:"labels"`
}

// AWSRuleGroup is one ruleGroupList entry.
type AWSRuleGroup struct {
	RuleGroupID                 string          `json:"ruleGroupId"`
	TerminatingRule             *AWSRuleAction  `json:"terminatingRule"`
	NonTerminatingMatchingRules []AWSRuleAction `json:"nonTerminatingMatchingRules"`
	ExcludedRules               any             `json:"excludedRules"`
}

// AWSRuleAction is a {ruleId, action} pair.
type AWSRuleAction struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
}

// AWSHTTPRequest is the httpRequest object.
type AWSHTTPRequest struct {
	ClientIP    string      `json:"clientIp"`
	Country     string      `json:"country"`
	Headers     []AWSHeader `json:"headers"`
	URI         string      `json:"uri"`
	Args        string      `json:"args"`
	HTTPVersion string      `json:"httpVersion"`
	HTTPMethod  string      `json:"httpMethod"`
	RequestID   string      `json:"requestId"`
}

// AWSHeader is one request header.
type AWSHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AWSLabel is one label.
type AWSLabel struct {
	Name string `json:"name"`
}

// ParseTS parses a ClickHouse DateTime64(3) string or RFC3339 as UTC.
func ParseTS(s string) time.Time {
	for _, l := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ToAWS maps an event and its matches to the AWS WAF log format.
// Only matches that AWS would have evaluated count: in scope and not after the terminating rule.
func ToAWS(ev Event, ms []Match) AWSLog {
	l := AWSLog{
		Timestamp: ParseTS(ev.TS).UnixMilli(), FormatVersion: 1,
		WebACLID:          "nginx-aws-waf:" + ev.NodeID + ":" + ev.SiteID,
		TerminatingRuleID: "Default_Action", TerminatingRuleType: "REGULAR", Action: ev.Action,
		TerminatingRuleMatchDetails: []any{}, HTTPSourceName: "ALB", HTTPSourceID: ev.SiteID,
		RuleGroupList: []AWSRuleGroup{}, RateBasedRuleList: []any{}, NonTerminatingMatchingRules: []AWSRuleAction{},
		Labels: []AWSLabel{},
	}
	termGroup, termRule := "", ""
	if ev.TerminatingRule != "" && ev.TerminatingType != "DEFAULT" {
		termGroup, termRule = ev.TerminatingRule, ev.TerminatingRule
		if i := strings.LastIndex(ev.TerminatingRule, "/"); i >= 0 {
			termGroup, termRule = ev.TerminatingRule[:i], ev.TerminatingRule[i+1:]
		}
		l.TerminatingRuleID, l.TerminatingRuleType = termRule, ev.TerminatingType
		if strings.HasPrefix(termGroup, "custom:") || ev.TerminatingType == "" {
			l.TerminatingRuleType = "REGULAR"
		}
	}
	if ev.Action == "BLOCK" {
		s := ev.Status
		l.ResponseCodeSent = &s
	}
	groups := map[string]*AWSRuleGroup{}
	var order []string
	for _, m := range ms {
		if m.InScope == 0 || m.PostTerminating == 1 {
			continue
		}
		isTerm := m.RuleGroup == termGroup && m.RuleName == termRule
		if strings.HasPrefix(m.RuleGroup, "custom:") {
			if !isTerm && m.ConfiguredAction == "COUNT" {
				l.NonTerminatingMatchingRules = append(l.NonTerminatingMatchingRules, AWSRuleAction{m.RuleName, "COUNT"})
			}
			continue
		}
		g := groups[m.RuleGroup]
		if g == nil {
			g = &AWSRuleGroup{RuleGroupID: "AWS#" + m.RuleGroup, NonTerminatingMatchingRules: []AWSRuleAction{}}
			groups[m.RuleGroup] = g
			order = append(order, m.RuleGroup)
		}
		switch {
		case isTerm:
			g.TerminatingRule = &AWSRuleAction{m.RuleName, m.ConfiguredAction}
		case m.ConfiguredAction == "COUNT":
			g.NonTerminatingMatchingRules = append(g.NonTerminatingMatchingRules, AWSRuleAction{m.RuleName, "COUNT"})
		}
	}
	for _, k := range order {
		l.RuleGroupList = append(l.RuleGroupList, *groups[k])
	}
	names := make([]string, 0, len(ev.RequestHeaders))
	for k := range ev.RequestHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	hs := make([]AWSHeader, 0, len(names))
	for _, k := range names {
		hs = append(hs, AWSHeader{k, ev.RequestHeaders[k]})
	}
	l.HTTPRequest = AWSHTTPRequest{ClientIP: ev.ClientIP, Country: ev.Country, Headers: hs, URI: ev.Path, Args: ev.Query,
		HTTPVersion: ev.HTTPVersion, HTTPMethod: ev.Method, RequestID: ev.RequestID}
	for _, s := range ev.Labels {
		l.Labels = append(l.Labels, AWSLabel{s})
	}
	return l
}

// MarshalAWS encodes one record without HTML escaping.
func MarshalAWS(l AWSLog) ([]byte, error) {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	err := e.Encode(l)
	return []byte(b.String()), err
}
