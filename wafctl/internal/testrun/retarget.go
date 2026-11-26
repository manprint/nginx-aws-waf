package testrun

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SpecialSites hold engine-semantics cases that are never retargeted.
var SpecialSites = map[string]bool{"tuned": true, "allowlist": true, "strict": true, "shadow": true}

// Exception replaces the expectation of a case on some sites.
type Exception struct {
	Case   string   `yaml:"case"`
	Sites  []string `yaml:"sites"`
	Expect Expect   `yaml:"expect"`
	Reason string   `yaml:"reason"`
}

type exceptionsFile struct {
	Version    int         `yaml:"version"`
	Exceptions []Exception `yaml:"exceptions"`
}

// ParseExceptions decodes an exceptions file strictly; every exception needs a reason.
func ParseExceptions(b []byte) ([]Exception, error) {
	var f exceptionsFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("exceptions: version must be 1")
	}
	for i, e := range f.Exceptions {
		if e.Case == "" || len(e.Sites) == 0 {
			return nil, fmt.Errorf("exceptions[%d]: case and sites are required", i)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("exceptions[%d] (%s): reason is required", i, e.Case)
		}
		if e.Expect.Status == 0 || e.Expect.TerminatingRule == "" {
			return nil, fmt.Errorf("exceptions[%d] (%s): expect.status and expect.terminating_rule are required", i, e.Case)
		}
	}
	return f.Exceptions, nil
}

// LoadExceptions reads an exceptions file.
func LoadExceptions(path string) ([]Exception, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ex, err := ParseExceptions(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ex, nil
}

// ParseRetarget parses "FROM=TO[,FROM=TO]".
func ParseRetarget(s string) (map[string]string, error) {
	m := map[string]string{}
	if s == "" {
		return m, nil
	}
	for _, kv := range strings.Split(s, ",") {
		from, to, ok := strings.Cut(kv, "=")
		if !ok || from == "" || to == "" {
			return nil, fmt.Errorf("invalid --retarget %q (want FROM=TO)", kv)
		}
		m[from] = to
	}
	return m, nil
}

// FilterSite keeps the cases of one site ("" keeps all).
func FilterSite(cases []Case, site string) []Case {
	if site == "" {
		return cases
	}
	var out []Case
	for _, c := range cases {
		if c.Site == site {
			out = append(out, c)
		}
	}
	return out
}

// Retarget moves cases to other sites and applies the matching exceptions.
func Retarget(cases []Case, m map[string]string, ex []Exception) []Case {
	out := make([]Case, 0, len(cases))
	for _, c := range cases {
		if to, ok := m[c.Site]; ok && !SpecialSites[c.Site] {
			c.Site = to
		}
		for _, e := range ex {
			if e.Case != c.ID {
				continue
			}
			for _, s := range e.Sites {
				if s == c.Site {
					c.Expect = e.Expect
				}
			}
		}
		out = append(out, c)
	}
	return out
}
