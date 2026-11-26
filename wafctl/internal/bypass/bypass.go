// Package bypass keeps the per-site temporary count-mode state ($WAF_CONFIG_DIR/state/bypass.yaml).
package bypass

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Entry is one active bypass.
type Entry struct {
	Until   time.Time `yaml:"until"`
	Reason  string    `yaml:"reason"`
	By      string    `yaml:"by"`
	Created time.Time `yaml:"created"`
}

// State is the bypass file.
type State struct {
	Sites map[string]Entry `yaml:"sites"`
}

// Path returns the state file path for a config dir.
func Path(configDir string) string { return filepath.Join(configDir, "state", "bypass.yaml") }

// Load reads the state; a missing file is an empty state.
func Load(path string) (*State, error) {
	s := &State{Sites: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Sites == nil {
		s.Sites = map[string]Entry{}
	}
	return s, nil
}

// Save writes the state atomically.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Active returns site → true for entries with until > now.
func (s *State) Active(now time.Time) map[string]bool {
	m := map[string]bool{}
	for id, e := range s.Sites {
		if e.Until.After(now) {
			m[id] = true
		}
	}
	return m
}

// Expire removes entries with until <= now; returns the removed site ids.
func (s *State) Expire(now time.Time) []string {
	var gone []string
	for id, e := range s.Sites {
		if !e.Until.After(now) {
			gone = append(gone, id)
			delete(s.Sites, id)
		}
	}
	sort.Strings(gone)
	return gone
}
