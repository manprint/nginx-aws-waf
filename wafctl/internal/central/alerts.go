package central

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AlertRule is one Grafana alert rule rendered from the central.yaml thresholds.
type AlertRule struct {
	UID, Title, SQL, Severity, Summary string
	Threshold                          int
}

// AlertRules returns the 5 WAF alert rules for the thresholds in a.
func AlertRules(a Alerts) []AlertRule {
	agg := func(cond string) string {
		return "SELECT site_id, sum(requests) AS value FROM waf.agg_requests_1m WHERE minute >= now() - INTERVAL 5 MINUTE AND " + cond + " GROUP BY site_id"
	}
	return []AlertRule{
		{UID: "waf-block-spike", Title: "WAF block spike", SQL: agg("action = 'BLOCK'"), Threshold: a.BlockSpikePer5m, Severity: "warning",
			Summary: fmt.Sprintf("site {{ $labels.site_id }}: {{ $values.B }} blocked requests in 5 min (threshold %d)", a.BlockSpikePer5m)},
		{UID: "waf-fail", Title: "WAF fail events", SQL: agg("action = 'FAIL'"), Threshold: a.FailPer5m - 1, Severity: "critical",
			Summary: fmt.Sprintf("site {{ $labels.site_id }}: {{ $values.B }} WAF engine failures (500) in 5 min (threshold %d)", a.FailPer5m)},
		{UID: "waf-disagree", Title: "WAF vs AWS default disagreement", SQL: agg("action != aws_default_action"), Threshold: a.DisagreementPer5m, Severity: "warning",
			Summary: fmt.Sprintf("site {{ $labels.site_id }}: {{ $values.B }} requests in 5 min where the action differs from the AWS default config (threshold %d)", a.DisagreementPer5m)},
		{UID: "waf-node-silent", Title: "WAF node silent",
			SQL:       "SELECT node_id, dateDiff('second', max(ts), now64(3)) AS value FROM waf.heartbeats GROUP BY node_id",
			Threshold: a.NodeSilentMin * 60, Severity: "critical",
			Summary: fmt.Sprintf("node {{ $labels.node_id }}: no heartbeat for {{ $values.B }} s (threshold %d min)", a.NodeSilentMin)},
		{UID: "waf-ingest-lag", Title: "WAF ingest lag",
			SQL:       "SELECT site_id, dateDiff('second', max(ts), now64(3)) AS value FROM waf.events WHERE ts > now() - INTERVAL 1 DAY GROUP BY site_id",
			Threshold: a.IngestLagMin * 60, Severity: "warning",
			Summary: fmt.Sprintf("site {{ $labels.site_id }}: last event {{ $values.B }} s ago (threshold %d min): no traffic or ingest stalled; check node-silent first", a.IngestLagMin)},
	}
}

// q renders s as a YAML double-quoted scalar (JSON strings are valid YAML).
func q(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// RulesYAML is grafana/provisioning/alerting/rules.yaml.
func RulesYAML(a Alerts) []byte {
	var b strings.Builder
	b.WriteString("# Rendered by wafctl central render from central.yaml alerts — do not edit.\napiVersion: 1\ngroups:\n  - orgId: 1\n    name: waf\n    folder: WAF\n    interval: 1m\n    rules:\n")
	for _, r := range AlertRules(a) {
		fmt.Fprintf(&b, `      - uid: %s
        title: %s
        condition: C
        data:
          - refId: A
            relativeTimeRange: {from: 600, to: 0}
            datasourceUid: ch
            model:
              refId: A
              datasource: {type: grafana-clickhouse-datasource, uid: ch}
              editorType: sql
              queryType: table
              format: 1
              rawSql: %s
          - refId: B
            datasourceUid: __expr__
            model:
              refId: B
              datasource: {type: __expr__, uid: __expr__}
              type: reduce
              expression: A
              reducer: last
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              datasource: {type: __expr__, uid: __expr__}
              type: threshold
              expression: B
              conditions:
                - evaluator: {type: gt, params: [%d]}
        noDataState: OK
        execErrState: Error
        for: 2m
        labels: {severity: %s}
        annotations:
          summary: %s
`, r.UID, q(r.Title), q(r.SQL), r.Threshold, r.Severity, q(r.Summary))
	}
	return []byte(b.String())
}

// contactPointYAML is snippets/grafana-contact-point.yaml (verified on Grafana 13.2.7, R6) with the
// template variable written $$t: Grafana file provisioning expands $NAME in contact-point settings
// (a plain $t arrives as an empty string → "unexpected := in command").
const contactPointYAML = `# Rendered by wafctl central render — do not edit.
# NOTE: toJson and ternary are NOT available in Grafana payload templates; use coll.Dict + data.ToJSON.
apiVersion: 1
contactPoints:
  - orgId: 1
    name: apprise
    receivers:
      - uid: apprise-webhook
        type: webhook
        settings:
          url: http://apprise:8000/notify/waf
          httpMethod: POST
          payload:
            template: |
              {{ $$t := "success" }}{{ if eq .Status "firing" }}{{ $$t = "warning" }}{{ end }}{{ coll.Dict "title" (printf "[WAF] %s" .CommonLabels.alertname) "body" (printf "%s: %d alert(s). %s" .Status (len .Alerts) .CommonAnnotations.summary) "type" $$t "tag" "waf" | data.ToJSON }}
`

const policiesYAML = `# Rendered by wafctl central render — do not edit.
apiVersion: 1
policies:
  - orgId: 1
    receiver: apprise
    group_by: [alertname, site_id]
    group_wait: 30s
    group_interval: 5m
    repeat_interval: 4h
`

// AppriseYAML is apprise/waf.yml: every URL tagged "waf" (the contact point notifies tag waf;
// apprise only notifies URLs carrying the requested tag).
func AppriseYAML(urls []string) []byte {
	var b strings.Builder
	b.WriteString("# Rendered by wafctl central render from the apprise URLs file — do not edit.\n")
	if len(urls) == 0 {
		b.WriteString("urls: []\n")
		return []byte(b.String())
	}
	b.WriteString("urls:\n")
	for _, u := range urls {
		fmt.Fprintf(&b, "  - %s:\n      - tag: waf\n", q(u))
	}
	return []byte(b.String())
}

// alertFiles are the alerting provisioning and apprise files.
func alertFiles(c Config, configDir string) (map[string][]byte, error) {
	urls, err := ReadURLs(filepath.Join(configDir, c.Apprise.URLsFile))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return map[string][]byte{
		"grafana/provisioning/alerting/rules.yaml":          RulesYAML(c.Alerts),
		"grafana/provisioning/alerting/contact-points.yaml": []byte(contactPointYAML),
		"grafana/provisioning/alerting/policies.yaml":       []byte(policiesYAML),
		"apprise/waf.yml": AppriseYAML(urls),
	}, nil
}
