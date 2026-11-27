package stats

// SQL per view. Every query takes {from_ms:Int64}, {to_ms:Int64}, {site:Array(String)} (empty = all
// sites) and, for top-N views, {top:UInt32}. User values never enter the SQL text.

const (
	evWindow  = "ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC') AND ts < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')"
	aggWindow = "minute >= toStartOfMinute(fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')) AND minute < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')"
	siteCond  = "(empty({site:Array(String)}) OR site_id IN {site:Array(String)})"
	winSecs   = "greatest(1, ({to_ms:Int64} - {from_ms:Int64}) / 1000)"
	// shadow_action is not in agg_requests_1m: always counted on events.
	shadowSub = "(SELECT countIf(shadow_action = 'BLOCK') FROM waf.events WHERE " + evWindow + " AND " + siteCond + ")"
)

// OverviewEvents / OverviewAgg: one row.
const (
	OverviewEvents = "SELECT count() AS requests, countIf(action = 'ALLOW') AS allow, countIf(action = 'BLOCK') AS block, " +
		"countIf(action = 'FAIL') AS fail, countIf(shadow_action = 'BLOCK') AS shadow_block, " +
		"countIf(aws_default_action = 'BLOCK') AS aws_default_block, countIf(action != aws_default_action) AS disagreements, " +
		"round(count() / " + winSecs + ", 3) AS rps_avg FROM waf.events WHERE " + evWindow + " AND " + siteCond
	OverviewAgg = "SELECT sum(a.requests) AS requests, sumIf(a.requests, action = 'ALLOW') AS allow, sumIf(a.requests, action = 'BLOCK') AS block, " +
		"sumIf(a.requests, action = 'FAIL') AS fail, " + shadowSub + " AS shadow_block, " +
		"sumIf(a.requests, aws_default_action = 'BLOCK') AS aws_default_block, sumIf(a.requests, action != aws_default_action) AS disagreements, " +
		"round(sum(a.requests) / " + winSecs + ", 3) AS rps_avg FROM waf.agg_requests_1m AS a WHERE " + aggWindow + " AND " + siteCond
)

// Site view.
const (
	SiteEvents = "SELECT site_id AS site, count() AS requests, countIf(action = 'ALLOW') AS allow, countIf(action = 'BLOCK') AS block, " +
		"countIf(action = 'FAIL') AS fail, countIf(aws_default_action = 'BLOCK') AS aws_default_block, countIf(action != aws_default_action) AS disagreements " +
		"FROM waf.events WHERE " + evWindow + " AND " + siteCond + " GROUP BY site ORDER BY requests DESC, site LIMIT {top:UInt32}"
	SiteAgg = "SELECT site_id AS site, sum(a.requests) AS requests, sumIf(a.requests, action = 'ALLOW') AS allow, sumIf(a.requests, action = 'BLOCK') AS block, " +
		"sumIf(a.requests, action = 'FAIL') AS fail, sumIf(a.requests, aws_default_action = 'BLOCK') AS aws_default_block, sumIf(a.requests, action != aws_default_action) AS disagreements " +
		"FROM waf.agg_requests_1m AS a WHERE " + aggWindow + " AND " + siteCond + " GROUP BY site ORDER BY requests DESC, site LIMIT {top:UInt32}"
)

// Rule view: TERMINATING = matches before/at the terminating point with a non-COUNT action;
// COUNTED = configured COUNT. {counted:UInt8} = 1 keeps only configured COUNT rules.
const (
	countedCond = "({counted:UInt8} = 0 OR configured_action = 'COUNT')"
	RuleEvents  = "SELECT rule_group AS group, rule_name AS rule, count() AS matches, " +
		"countIf(post_terminating = 0 AND configured_action != 'COUNT') AS terminating, countIf(configured_action = 'COUNT') AS counted, " +
		"uniqExact(site_id) AS sites FROM waf.matches WHERE " + evWindow + " AND " + siteCond + " AND " + countedCond +
		" GROUP BY group, rule ORDER BY matches DESC, group, rule LIMIT {top:UInt32}"
	RuleAgg = "SELECT rule_group AS group, rule_name AS rule, sum(a.matches) AS matches, " +
		"sumIf(a.matches, post_terminating = 0 AND configured_action != 'COUNT') AS terminating, sumIf(a.matches, configured_action = 'COUNT') AS counted, " +
		"uniqExact(site_id) AS sites FROM waf.agg_matches_1m AS a WHERE " + aggWindow + " AND " + siteCond + " AND " + countedCond +
		" GROUP BY group, rule ORDER BY matches DESC, group, rule LIMIT {top:UInt32}"
)

// topSQL builds a top-N events view; key is a constant column expression from the view table.
func topSQL(key, name string) string {
	return "SELECT " + key + " AS " + name + ", count() AS requests, countIf(action = 'BLOCK') AS block, countIf(action = 'FAIL') AS fail, " +
		"countIf(action != aws_default_action) AS disagreements FROM waf.events WHERE " + evWindow + " AND " + siteCond +
		" GROUP BY " + name + " ORDER BY if({sort_blocks:UInt8} = 1, block, requests) DESC, requests DESC, " + name + " LIMIT {top:UInt32}"
}

// Disagreements lists the top (action, aws_default_action, aws_default_rule, path) where the simulator and the
// AWS default ACL differ (report section 5).
const Disagreements = "SELECT action, aws_default_action, aws_default_rule, terminating_rule, path, count() AS requests FROM waf.events WHERE " +
	evWindow + " AND " + siteCond + " AND action != aws_default_action GROUP BY ALL ORDER BY requests DESC, path LIMIT {top:UInt32}"

// Timeline: per-hour allow/block/fail (report section 2).
const Timeline = "SELECT toString(toStartOfHour(minute)) AS hour, sumIf(a.requests, action = 'ALLOW') AS allow, sumIf(a.requests, action = 'BLOCK') AS block, " +
	"sumIf(a.requests, action = 'FAIL') AS fail FROM waf.agg_requests_1m AS a WHERE " + aggWindow + " AND " + siteCond + " GROUP BY hour ORDER BY hour"

// Fails lists FAIL events (report section 8).
const Fails = "SELECT ts, site_id AS site, fail_reason, method, path, status, request_id FROM waf.events WHERE " +
	evWindow + " AND " + siteCond + " AND action = 'FAIL' ORDER BY ts DESC LIMIT {top:UInt32}"
