package ch

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
)

// Migrations holds migrations/NNN-*.sql; 001-schema.sql is deploy/clickhouse/initdb/001-schema.sql
// (identity asserted by TestQ4_).
//
//go:embed migrations/*.sql
var Migrations embed.FS

// SchemaSQL returns the initial DDL.
func SchemaSQL() string {
	b, _ := Migrations.ReadFile("migrations/001-schema.sql")
	return string(b)
}

var reCodec = regexp.MustCompile(`\s+CODEC\(.*\)$`)

// Columns returns "name Type" lines of CREATE TABLE waf.<table> (codecs and defaults removed).
func Columns(ddl, table string) ([]string, error) {
	head := "CREATE TABLE IF NOT EXISTS waf." + table + "\n("
	i := strings.Index(ddl, head)
	if i < 0 {
		return nil, fmt.Errorf("schema: table %s not found", table)
	}
	body := ddl[i+len(head):]
	j := strings.Index(body, "\n)")
	if j < 0 {
		return nil, fmt.Errorf("schema: table %s not terminated", table)
	}
	var cols []string
	for _, l := range strings.Split(body[:j], "\n") {
		l = strings.TrimSuffix(strings.TrimSpace(l), ",")
		if l == "" {
			continue
		}
		cols = append(cols, reCodec.ReplaceAllString(l, ""))
	}
	return cols, nil
}

// Structure returns the clickhouse "file(..., structure)" string for a table.
func Structure(table string) (string, error) {
	cols, err := Columns(SchemaSQL(), table)
	if err != nil {
		return "", err
	}
	return strings.Join(cols, ", "), nil
}
