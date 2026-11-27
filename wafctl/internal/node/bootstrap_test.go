package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nginxawswaf/wafctl/internal/central"
)

func bsOpts(t *testing.T, role string) BootstrapOptions {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	d := t.TempDir()
	return BootstrapOptions{NodeID: "t1", Role: role, Central: "central.example.com", Home: "/opt/nginx-aws-waf",
		ConfigDir: filepath.Join(d, "etc"), DataDir: filepath.Join(d, "srv")}
}

func TestBS1_BootstrapWritesRepo(t *testing.T) {
	o := bsOpts(t, "node")
	next, err := Bootstrap(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".gitignore", "node.yaml", "sites/README.md", "profiles/.gitkeep", "secrets.env", ".git/HEAD"} {
		if _, err := os.Stat(filepath.Join(o.ConfigDir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	if _, err := os.Stat(filepath.Join(o.ConfigDir, "central.yaml")); err == nil {
		t.Errorf("role node wrote central.yaml")
	}
	gi, _ := os.ReadFile(filepath.Join(o.ConfigDir, ".gitignore"))
	for _, l := range []string{"state/", "secrets.env", "pki/private/", "pki/tokens.json", "*.key", "apprise-urls.txt"} {
		if !strings.Contains("\n"+string(gi), "\n"+l+"\n") {
			t.Errorf(".gitignore lacks %q", l)
		}
	}
	if st, _ := os.Stat(filepath.Join(o.ConfigDir, "secrets.env")); st.Mode().Perm() != 0o600 {
		t.Errorf("secrets.env mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Join(o.DataDir, "certs/_node")); st == nil || st.Mode().Perm() != 0o700 {
		t.Errorf("certs/_node: %v", st)
	}
	if b, _ := os.ReadFile(filepath.Join(o.ConfigDir, "node.yaml")); !strings.Contains(string(b), "node_id: t1\nrole: node\nnetwork: host\n") ||
		!strings.Contains(string(b), "central: {address: central.example.com, ingest_port: 6000, pki_port: 6001}") {
		t.Errorf("node.yaml:\n%s", b)
	}
	out, err := exec.Command("git", "-C", o.ConfigDir, "log", "--format=%s").Output()
	if err != nil || strings.TrimSpace(string(out)) != "bootstrap t1" {
		t.Errorf("git log %q %v", out, err)
	}
	tracked, _ := exec.Command("git", "-C", o.ConfigDir, "ls-files").Output()
	if strings.Contains(string(tracked), "secrets.env") {
		t.Errorf("secrets.env committed: %s", tracked)
	}
	if !strings.Contains(next, "wafctl node enroll") {
		t.Errorf("next steps: %s", next)
	}
	// central roles: central.yaml valid, apprise file 0600 and untracked
	c := bsOpts(t, "all-in-one")
	if _, err := Bootstrap(c); err != nil {
		t.Fatal(err)
	}
	cc, err := central.Load(c.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	if errs, _ := cc.Validate(c.ConfigDir); len(errs) > 0 || cc.Ingress.ServerNames[0] != "central.example.com" {
		t.Errorf("central.yaml: %v %v", errs, cc.Ingress)
	}
	tracked, _ = exec.Command("git", "-C", c.ConfigDir, "ls-files").Output()
	if !strings.Contains(string(tracked), "central.yaml") || strings.Contains(string(tracked), "apprise-urls.txt") {
		t.Errorf("tracked: %s", tracked)
	}
}

func TestBS2_BootstrapTwiceRefused(t *testing.T) {
	o := bsOpts(t, "node")
	if _, err := Bootstrap(o); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(o); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("second run: %v", err)
	}
	o.Force = true
	if _, err := Bootstrap(o); err != nil {
		t.Errorf("--force: %v", err)
	}
	for _, bad := range []BootstrapOptions{{NodeID: "Bad_ID", Role: "node"}, {NodeID: "ok", Role: "x"}, {NodeID: "ok", Role: "node", Network: "nat"}} {
		bad.ConfigDir, bad.DataDir = t.TempDir(), t.TempDir()
		if _, err := Bootstrap(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
