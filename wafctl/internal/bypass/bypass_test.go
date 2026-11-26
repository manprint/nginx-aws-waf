package bypass

import (
	"path/filepath"
	"testing"
	"time"
)

func TestB1_Expire(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := &State{Sites: map[string]Entry{
		"old":  {Until: now.Add(-time.Minute), Reason: "x"},
		"edge": {Until: now, Reason: "x"},
		"new":  {Until: now.Add(time.Hour), Reason: "x"},
	}}
	p := filepath.Join(t.TempDir(), "state", "bypass.yaml")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	gone := l.Expire(now)
	if len(gone) != 2 || gone[0] != "edge" || gone[1] != "old" {
		t.Errorf("gone = %v", gone)
	}
	if a := l.Active(now); len(a) != 1 || !a["new"] {
		t.Errorf("active = %v", a)
	}
	if m, _ := Load(filepath.Join(t.TempDir(), "missing.yaml")); len(m.Sites) != 0 {
		t.Errorf("missing file not empty")
	}
}
