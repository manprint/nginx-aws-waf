package ch

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"nginxawswaf/wafctl/internal/secrets"
)

// Migration is one embedded migrations/NNN-name.sql file.
type Migration struct {
	Version uint32
	Name    string
	SQL     string
}

var reMig = regexp.MustCompile(`^(\d{3})-[\w.-]+\.sql$`)

// ListMigrations returns the embedded migrations ordered by version (duplicates are an error).
func ListMigrations() ([]Migration, error) {
	ents, err := fs.ReadDir(Migrations, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []Migration
	seen := map[uint32]string{}
	for _, e := range ents {
		m := reMig.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %s: name must be NNN-name.sql", e.Name())
		}
		v, _ := strconv.ParseUint(m[1], 10, 32)
		if prev, ok := seen[uint32(v)]; ok {
			return nil, fmt.Errorf("migration version %03d used by %s and %s", v, prev, e.Name())
		}
		seen[uint32(v)] = e.Name()
		b, _ := Migrations.ReadFile("migrations/" + e.Name())
		ms = append(ms, Migration{uint32(v), e.Name(), string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Version < ms[j].Version })
	return ms, nil
}

// Statements splits a migration into single statements (the HTTP interface runs one per request).
func Statements(sql string) []string {
	var keep []string
	for _, l := range strings.Split(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "--") {
			continue
		}
		keep = append(keep, l)
	}
	var out []string
	for _, s := range strings.Split(strings.Join(keep, "\n"), ";\n") {
		if s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";")); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// AdminFromEnv is FromEnv with the waf_admin user (WAF_CH_ADMIN_PASSWORD from env or secrets.env).
func AdminFromEnv(configDir string) *Client {
	c := FromEnv(configDir)
	c.User = "waf_admin"
	c.Password = os.Getenv("WAF_CH_ADMIN_PASSWORD")
	if c.Password == "" {
		if m, err := secrets.Load(filepath.Join(configDir, "secrets.env")); err == nil {
			c.Password = m["WAF_CH_ADMIN_PASSWORD"]
		}
	}
	return c
}

func execSQL(ctx context.Context, q Querier, sql string, p map[string]string) error {
	return q.Query(ctx, sql, p, func(json.RawMessage) error { return nil })
}

// Pending returns the migrations not yet applied, given the applied versions and whether
// waf.events already exists (then 001, the initial DDL, counts as applied: initdb created it).
func Pending(all []Migration, applied map[uint32]bool, eventsExists bool) (pending []Migration, adopt001 bool) {
	for _, m := range all {
		if applied[m.Version] {
			continue
		}
		if m.Version == 1 && eventsExists {
			adopt001 = true
			continue
		}
		pending = append(pending, m)
	}
	return pending, adopt001
}

// Migrate applies pending migrations; it returns the log lines.
func Migrate(ctx context.Context, q Querier) ([]string, error) {
	all, err := ListMigrations()
	if err != nil {
		return nil, err
	}
	if err := execSQL(ctx, q, "CREATE DATABASE IF NOT EXISTS waf", nil); err != nil {
		return nil, err
	}
	if err := execSQL(ctx, q, "CREATE TABLE IF NOT EXISTS waf.schema_migrations (version UInt32, applied DateTime('UTC')) ENGINE = ReplacingMergeTree ORDER BY version", nil); err != nil {
		return nil, err
	}
	type vr struct {
		Version uint32 `json:"version"`
	}
	rows, err := Collect[vr](ctx, q, "SELECT DISTINCT version FROM waf.schema_migrations", nil)
	if err != nil {
		return nil, err
	}
	applied := map[uint32]bool{}
	for _, r := range rows {
		applied[r.Version] = true
	}
	type ex struct {
		N uint64 `json:"n"`
	}
	e, err := Collect[ex](ctx, q, "SELECT count() AS n FROM system.tables WHERE database = 'waf' AND name = 'events'", nil)
	if err != nil {
		return nil, err
	}
	pending, adopt := Pending(all, applied, len(e) > 0 && e[0].N > 0)
	var log []string
	mark := func(v uint32) error {
		return execSQL(ctx, q, "INSERT INTO waf.schema_migrations (version, applied) VALUES ({v:UInt32}, now())", map[string]string{"v": strconv.Itoa(int(v))})
	}
	if adopt {
		if err := mark(1); err != nil {
			return log, err
		}
		log = append(log, "001 already present (waf.events exists): marked applied")
	}
	for _, m := range pending {
		for i, st := range Statements(m.SQL) {
			if err := execSQL(ctx, q, st, nil); err != nil {
				return log, fmt.Errorf("%s statement %d: %w", m.Name, i+1, err)
			}
		}
		if err := mark(m.Version); err != nil {
			return log, err
		}
		log = append(log, "applied "+m.Name)
	}
	if len(log) == 0 {
		log = append(log, fmt.Sprintf("up to date (%d migrations)", len(all)))
	}
	return log, nil
}

// RetentionTables: raw tables (TTL on ts) and aggregate tables (TTL on minute).
var (
	RawTables = []string{"events", "matches"}
	AggTables = []string{"agg_requests_1m", "agg_matches_1m"}
)

// TTL is one table's current TTL.
type TTL struct {
	Table string `json:"table"`
	TTL   string `json:"ttl"`
	Days  int    `json:"days"`
}

var reDays = regexp.MustCompile(`toIntervalDay\((?:_CAST\()?(\d+)`)

// Retention returns the TTL clause of the waf tables (from system.tables.create_table_query).
func Retention(ctx context.Context, q Querier) ([]TTL, error) {
	rows, err := Collect[TTL](ctx, q, "SELECT name AS table, extract(create_table_query, 'TTL (.*?)(?: SETTINGS|$)') AS ttl FROM system.tables "+
		"WHERE database = 'waf' AND name IN ('events', 'matches', 'agg_requests_1m', 'agg_matches_1m', 'heartbeats') ORDER BY name", nil)
	for i := range rows {
		if m := reDays.FindStringSubmatch(rows[i].TTL); m != nil {
			rows[i].Days, _ = strconv.Atoi(m[1])
		}
	}
	return rows, err
}

// SetRetention changes the TTL of raw tables (rawDays > 0) and/or aggregate tables (aggDays > 0).
func SetRetention(ctx context.Context, q Querier, rawDays, aggDays int) error {
	set := func(tables []string, expr string, days int) error {
		for _, t := range tables {
			// table names come from the fixed lists above; days is a parameter
			if err := execSQL(ctx, q, "ALTER TABLE waf."+t+" MODIFY TTL "+expr+" + INTERVAL {days:UInt32} DAY DELETE", map[string]string{"days": strconv.Itoa(days)}); err != nil {
				return err
			}
		}
		return nil
	}
	if rawDays > 0 {
		if err := set(RawTables, "toDateTime(ts)", rawDays); err != nil {
			return err
		}
	}
	if aggDays > 0 {
		return set(AggTables, "minute", aggDays)
	}
	return nil
}

// ValidateRetention checks 1 ≤ raw ≤ 3650 and agg ≥ raw (current values fill unset flags).
func ValidateRetention(rawDays, aggDays, curRaw, curAgg int) error {
	r, a := curRaw, curAgg
	if rawDays != 0 {
		r = rawDays
		if rawDays < 1 || rawDays > 3650 {
			return fmt.Errorf("--raw-days %d not in 1-3650", rawDays)
		}
	}
	if aggDays != 0 {
		a = aggDays
		if aggDays < 1 || aggDays > 3650 {
			return fmt.Errorf("--agg-days %d not in 1-3650", aggDays)
		}
	}
	if a < r {
		return fmt.Errorf("aggregate retention (%d days) must be >= raw retention (%d days)", a, r)
	}
	return nil
}
