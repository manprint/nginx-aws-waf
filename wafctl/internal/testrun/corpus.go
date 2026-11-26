// Package testrun sends corpus requests to a WAF node and checks the outcome in the audit log.
package testrun

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Repeat builds a body of prefix + count×char + suffix.
type Repeat struct {
	Char   string `yaml:"char"`
	Count  int    `yaml:"count"`
	Prefix string `yaml:"prefix"`
	Suffix string `yaml:"suffix"`
}

// Multipart is a single-file multipart/form-data body.
type Multipart struct {
	Field    string `yaml:"field"`
	Filename string `yaml:"filename"`
	Content  string `yaml:"content"`
}

// Request describes what to send.
type Request struct {
	Method      string            `yaml:"method"`
	Path        string            `yaml:"path"`
	Host        string            `yaml:"host"`
	Headers     map[string]string `yaml:"headers"`
	XFF         string            `yaml:"xff"`
	Body        string            `yaml:"body"`
	BodyRepeat  *Repeat           `yaml:"body_repeat"`
	ContentType string            `yaml:"content_type"`
	Multipart   *Multipart        `yaml:"multipart"`
	Chunked     bool              `yaml:"chunked"`
}

// Expect is the asserted outcome.
type Expect struct {
	Status          int      `yaml:"status"`
	TerminatingRule string   `yaml:"terminating_rule"`
	Matches         []string `yaml:"matches"`
}

// Case is one corpus entry.
type Case struct {
	ID      string  `yaml:"id"`
	Site    string  `yaml:"site"`
	Request Request `yaml:"request"`
	Expect  Expect  `yaml:"expect"`
	File    string  `yaml:"-"`
}

type corpusFile struct {
	Version int    `yaml:"version"`
	Cases   []Case `yaml:"cases"`
}

// ParseCorpus decodes one corpus file strictly (unknown keys are errors).
func ParseCorpus(b []byte, name string) ([]Case, error) {
	var f corpusFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: version must be 1", name)
	}
	for i := range f.Cases {
		c := &f.Cases[i]
		c.File = name
		if c.ID == "" || c.Site == "" {
			return nil, fmt.Errorf("%s: case %d: id and site are required", name, i)
		}
		if c.Expect.Status == 0 || c.Expect.TerminatingRule == "" {
			return nil, fmt.Errorf("%s: %s: expect.status and expect.terminating_rule are required", name, c.ID)
		}
		if c.Request.Path == "" {
			c.Request.Path = "/"
		}
		if c.Request.Method == "" {
			c.Request.Method = "GET"
		}
		if c.Request.XFF == "" {
			c.Request.XFF = "198.51.100.10"
		}
	}
	return f.Cases, nil
}

// LoadSuite loads a corpus file or every *.yaml in a directory; ids must be unique.
func LoadSuite(path string) ([]Case, error) {
	files := []string{path}
	if st, err := os.Stat(path); err != nil {
		return nil, err
	} else if st.IsDir() {
		m, _ := filepath.Glob(filepath.Join(path, "*.yaml"))
		sort.Strings(m)
		files = m
	}
	var all []Case
	seen := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		cs, err := ParseCorpus(b, filepath.Base(f))
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if prev, ok := seen[c.ID]; ok {
				return nil, fmt.Errorf("duplicate case id %s (%s, %s)", c.ID, prev, c.File)
			}
			seen[c.ID] = c.File
		}
		all = append(all, cs...)
	}
	return all, nil
}

// BuildBody returns the body bytes and content type of a request.
func BuildBody(r *Request) ([]byte, string) {
	ct := r.ContentType
	var b []byte
	switch {
	case r.Multipart != nil:
		const bd = "wafctltestboundary"
		m := r.Multipart
		b = []byte(fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: text/html\r\n\r\n%s\r\n--%s--\r\n", bd, m.Field, m.Filename, m.Content, bd))
		if ct == "" {
			ct = "multipart/form-data; boundary=" + bd
		}
	case r.BodyRepeat != nil:
		br := r.BodyRepeat
		ch := br.Char
		if ch == "" {
			ch = "x"
		}
		b = []byte(br.Prefix + strings.Repeat(ch, br.Count) + br.Suffix)
	default:
		b = []byte(r.Body)
	}
	if len(b) > 0 && ct == "" {
		ct = "application/x-www-form-urlencoded"
	}
	return b, ct
}
