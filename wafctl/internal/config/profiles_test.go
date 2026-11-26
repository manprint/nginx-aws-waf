package config

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestPRF1_OdooProfilesAwsCompatible: every shipped profiles/odoo-*.yaml loads, validates and is aws-compatible (D27).
func TestPRF1_OdooProfilesAwsCompatible(t *testing.T) {
	home, _ := filepath.Abs("../../..")
	t.Setenv("WAF_HOME", home)
	shipped, _ := filepath.Glob(filepath.Join(home, "profiles", "odoo-*.yaml"))
	if len(shipped) < 5 {
		t.Fatalf("expected odoo-common + 4 version profiles, found %d", len(shipped))
	}
	files := map[string]string{"node.yaml": "version: 1\nnode_id: t\n"}
	var ids []string
	for _, p := range shipped {
		name := filepath.Base(p)
		name = name[:len(name)-len(".yaml")]
		id := "s-" + name
		ids = append(ids, id)
		files["sites/"+id+".yaml"] = fmt.Sprintf("version: 1\nsite_id: %s\nserver_names: [%s.test]\napp: odoo\nprofile: %s\nupstream: {servers: [\"127.0.0.1:8069\"], realtime: {path: /websocket, servers: [\"127.0.0.1:8072\"]}}\n", id, id, name)
	}
	cfg, err := Load(writeFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	cat := testCat(t)
	for _, i := range Validate(cfg, cat) {
		if i.Severity == "error" {
			t.Errorf("validation: %s", i.String())
		}
	}
	for _, id := range ids {
		e := eff(t, cfg, id, false)
		if r := Compat(e, cat); len(r) != 0 {
			t.Errorf("%s: not aws-compatible: %v", id, r)
		}
	}
}
