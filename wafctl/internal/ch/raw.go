package ch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Image runs clickhouse local for --raw.
const Image = "clickhouse/clickhouse-server:26.8-alpine"

// Raw queries raw JSONL (<dir>/<YYYY-MM-DD>/{events,matches}.jsonl) offline with clickhouse local.
// It defines waf.events / waf.matches as views over the files and waf.agg_* as views with the
// materialized-view SELECTs of the DDL, so the same SQL runs online and offline.
type Raw struct {
	Dir string
	Run func(ctx context.Context, args []string, stdin []byte) ([]byte, error) // test hook
}

var reAggMV = regexp.MustCompile(`(?s)CREATE MATERIALIZED VIEW IF NOT EXISTS waf\.mv_(agg_\w+) TO waf\.agg_\w+ AS\n(.*?);`)

// Prelude returns the statements that create the raw views.
func Prelude() (string, error) {
	var b strings.Builder
	b.WriteString("CREATE DATABASE IF NOT EXISTS waf;\n")
	for _, t := range []string{"events", "matches"} {
		st, err := Structure(t)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "CREATE VIEW waf.%s AS SELECT * FROM file('/raw/*/%s.jsonl', 'JSONEachRow', '%s');\n",
			t, t, strings.ReplaceAll(st, "'", `\'`))
	}
	for _, m := range reAggMV.FindAllStringSubmatch(SchemaSQL(), -1) {
		fmt.Fprintf(&b, "CREATE VIEW waf.%s AS %s;\n", m[1], m[2])
	}
	return b.String(), nil
}

// Query runs prelude + sql in a clickhouse local container; params become --param_<name>.
func (r *Raw) Query(ctx context.Context, sql string, params map[string]string, out func(json.RawMessage) error) error {
	dir, err := filepath.Abs(r.Dir)
	if err != nil {
		return err
	}
	pre, err := Prelude()
	if err != nil {
		return err
	}
	args := []string{"run", "--rm", "-i", "-v", dir + ":/raw:ro", Image, "clickhouse", "local",
		"--date_time_input_format=best_effort", "--input_format_skip_unknown_fields=1",
		"--output-format=JSONEachRow"}
	for k, s := range Settings {
		args = append(args, "--"+k+"="+s)
	}
	for k, p := range params {
		args = append(args, "--param_"+k+"="+p)
	}
	stdin := []byte(pre + strings.TrimRight(strings.TrimSpace(sql), ";") + ";\n")
	run := r.Run
	if run == nil {
		run = dockerRun
	}
	b, err := run(ctx, args, stdin)
	if err != nil {
		return err
	}
	return decodeLines(bytes.NewReader(b), out)
}

func dockerRun(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("clickhouse local: %v: %s", err, bytes.TrimSpace(errb.Bytes()))
	}
	return out.Bytes(), nil
}
