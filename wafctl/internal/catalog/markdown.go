package catalog

import (
	"fmt"
	"io"
	"strings"
)

// MarkdownHeader is the exact header line of the markdown catalog table.
const MarkdownHeader = "| ID | Group | Rule | Default | Fidelity | Detectors(vars → op) |"

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// DetectorString renders one detector chain as "vars → op [t:...]" links joined by " AND ".
func DetectorString(chain []Link) string {
	var p []string
	for _, l := range chain {
		s := l.Vars + " → " + l.Op
		if len(l.T) > 0 {
			s += " [t:" + strings.Join(l.T, ",") + "]"
		}
		p = append(p, s)
	}
	return strings.Join(p, " AND ")
}

// WriteMarkdown writes the rules as a markdown table (detectors joined by " OR ").
func WriteMarkdown(w io.Writer, rules []*Rule) {
	fmt.Fprintln(w, MarkdownHeader)
	fmt.Fprintln(w, "|---|---|---|---|---|---|")
	for _, r := range rules {
		var d []string
		for _, c := range r.Detectors {
			d = append(d, "`"+mdEscape(DetectorString(c))+"`")
		}
		det := strings.Join(d, " OR ")
		if det == "" {
			det = "— (stub)"
		}
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s |\n", r.ID, r.Group.Key, r.Name, r.DefaultAction, r.Fidelity, det)
	}
}
