package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSEC1_InitKeepsAndForces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	w, err := Init(p, false)
	if err != nil || len(w) != len(Keys) {
		t.Fatalf("init: %v %v", w, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	m1, _ := Load(p)
	for _, k := range Keys {
		if len(m1[k]) != 32 {
			t.Errorf("%s: %q (want 32 base64url chars)", k, m1[k])
		}
	}
	if w, _ := Init(p, false); len(w) != 0 {
		t.Errorf("second init rewrote %v", w)
	}
	m2, _ := Load(p)
	if m2[Keys[0]] != m1[Keys[0]] {
		t.Error("value changed without --force")
	}
	if _, err := Init(p, true); err != nil {
		t.Fatal(err)
	}
	m3, _ := Load(p)
	if m3[Keys[0]] == m1[Keys[0]] {
		t.Error("--force kept the old value")
	}
}
