package node

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"nginxawswaf/wafctl/internal/secrets"
)

//go:embed templates/*
var tmplFS embed.FS

// BootstrapOptions of `wafctl node bootstrap`.
type BootstrapOptions struct {
	NodeID, Role, Central, Network string
	Home, ConfigDir, DataDir       string
	Force, InstallSystemd          bool
	SystemdDir, DefaultFile        string                                  // "" → /etc/systemd/system, /etc/default/wafctl
	Run                            func(name string, args ...string) error // nil → exec (git, systemctl)
	Now                            func() time.Time
}

var reNodeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Timers enabled per role by --install-systemd (units from $WAF_HOME/deploy/systemd).
var Timers = map[string][]string{
	"node":       {"wafctl-bypass-expire.timer", "wafctl-logs.timer", "wafctl-node-renew.timer"},
	"central":    {"wafctl-pki-crl.timer", "wafctl-pki.service"},
	"all-in-one": {"wafctl-bypass-expire.timer", "wafctl-logs.timer", "wafctl-pki-crl.timer", "wafctl-pki.service"},
}

// DataSubdirs are created under $WAF_DATA_DIR (certs/_node is 0700).
var DataSubdirs = []string{"runtime", "logs", "raw", "lists", "geoip", "certs", "certs/_node", "vector", "central"}

// Bootstrap creates the node's config repository and data dirs. Returns the next steps to print.
func Bootstrap(o BootstrapOptions) (string, error) {
	if err := o.defaults(); err != nil {
		return "", err
	}
	nodeYAML := filepath.Join(o.ConfigDir, "node.yaml")
	if _, err := os.Stat(nodeYAML); err == nil && !o.Force {
		return "", fmt.Errorf("bootstrap: %s exists (use --force to overwrite the generated files)", nodeYAML)
	}
	if o.InstallSystemd && os.Geteuid() != 0 {
		return "", errors.New("bootstrap: --install-systemd requires root")
	}
	data := map[string]string{"NodeID": o.NodeID, "Role": o.Role, "Network": o.Network, "Central": o.Central,
		"CentralName": o.centralName(), "Home": o.Home, "ConfigDir": o.ConfigDir, "DataDir": o.DataDir,
		"Date": o.Now().UTC().Format("2006-01-02T15:04:05Z")}
	for _, d := range []string{o.ConfigDir, filepath.Join(o.ConfigDir, "sites"), filepath.Join(o.ConfigDir, "profiles")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", err
		}
	}
	files := map[string]string{".gitignore": "gitignore", "node.yaml": "node.yaml.tmpl", "sites/README.md": "sites-README.md"}
	if o.Role != "node" {
		files["central.yaml"] = "central.yaml.tmpl"
	}
	for dst, src := range files {
		if err := writeTmpl(filepath.Join(o.ConfigDir, dst), src, data, 0o644); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(o.ConfigDir, "profiles", ".gitkeep"), nil, 0o644); err != nil {
		return "", err
	}
	if o.Role != "node" {
		p := filepath.Join(o.ConfigDir, "apprise-urls.txt")
		if _, err := os.Stat(p); err != nil {
			if err := os.WriteFile(p, []byte("# one Apprise URL per line, e.g. mailtos://user:pass@example.com?to=ops@example.com\n"), 0o600); err != nil {
				return "", err
			}
		}
	}
	if _, err := secrets.Init(filepath.Join(o.ConfigDir, "secrets.env"), false); err != nil {
		return "", err
	}
	for _, d := range DataSubdirs {
		mode := os.FileMode(0o755)
		if d == "certs/_node" {
			mode = 0o700
		}
		p := filepath.Join(o.DataDir, d)
		if err := os.MkdirAll(p, mode); err != nil {
			return "", err
		}
		if err := os.Chmod(p, mode); err != nil {
			return "", err
		}
	}
	if o.InstallSystemd {
		if err := o.installSystemd(data); err != nil {
			return "", err
		}
	}
	if err := o.gitCommit(); err != nil {
		return "", err
	}
	return o.nextSteps(), nil
}

func (o *BootstrapOptions) defaults() error {
	if !reNodeID.MatchString(o.NodeID) {
		return fmt.Errorf("bootstrap: --node-id %q must match %s", o.NodeID, reNodeID)
	}
	switch o.Role {
	case "node", "central", "all-in-one":
	default:
		return fmt.Errorf("bootstrap: --role %q not in {node,central,all-in-one}", o.Role)
	}
	if o.Network == "" {
		o.Network = "host"
	}
	if o.Network != "host" && o.Network != "bridge" {
		return fmt.Errorf("bootstrap: --network %q not in {host,bridge}", o.Network)
	}
	if o.Central != "" && !regexp.MustCompile(`^[A-Za-z0-9.:-]+$`).MatchString(o.Central) {
		return fmt.Errorf("bootstrap: --central %q: want a host name or IP", o.Central)
	}
	if o.SystemdDir == "" {
		o.SystemdDir = "/etc/systemd/system"
	}
	if o.DefaultFile == "" {
		o.DefaultFile = "/etc/default/wafctl"
	}
	if o.Run == nil {
		o.Run = func(name string, args ...string) error {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
			}
			return nil
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return nil
}

func (o *BootstrapOptions) centralName() string {
	if o.Central != "" {
		return o.Central
	}
	return "central.example.com"
}

func writeTmpl(dst, src string, data any, mode os.FileMode) error {
	b, err := tmplFS.ReadFile("templates/" + src)
	if err != nil {
		return err
	}
	t, err := template.New(src).Option("missingkey=error").Parse(string(b))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return err
	}
	return os.WriteFile(dst, buf.Bytes(), mode)
}

func (o *BootstrapOptions) installSystemd(data map[string]string) error {
	src := filepath.Join(o.Home, "deploy", "systemd")
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(o.SystemdDir, e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	if err := writeTmpl(o.DefaultFile, "default-wafctl", data, 0o644); err != nil {
		return err
	}
	if err := o.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	units := append([]string(nil), Timers[o.Role]...)
	sort.Strings(units)
	return o.Run("systemctl", append([]string{"enable", "--now"}, units...)...)
}

func (o *BootstrapOptions) gitCommit() error {
	d := o.ConfigDir
	if _, err := os.Stat(filepath.Join(d, ".git")); err != nil {
		if err := o.Run("git", "-C", d, "init", "-q"); err != nil {
			return err
		}
	}
	if err := o.Run("git", "-C", d, "add", "-A"); err != nil {
		return err
	}
	// identity only for this repo when none is configured (fresh hosts)
	return o.Run("git", "-C", d, "-c", "user.name=wafctl", "-c", "user.email=wafctl@"+o.NodeID,
		"commit", "-q", "--allow-empty", "-m", "bootstrap "+o.NodeID)
}

func (o *BootstrapOptions) nextSteps() string {
	var b strings.Builder
	fmt.Fprintf(&b, "bootstrapped %s (role %s) in %s, data in %s\nnext steps:\n", o.NodeID, o.Role, o.ConfigDir, o.DataDir)
	step := 1
	p := func(f string, a ...any) { fmt.Fprintf(&b, "  %d. "+f+"\n", append([]any{step}, a...)...); step++ }
	if o.Role != "node" {
		p("wafctl pki init --name <name>   (then keep an offline copy of %s/pki/private)", o.ConfigDir)
		p("edit central.yaml (ingress.server_names) and apprise-urls.txt")
	}
	p("%s/scripts/fetch-ip-lists.sh && cp %s/data/ip-reputation/*.txt %s/lists/   (IP reputation lists; daily cron)", o.Home, o.Home, o.DataDir)
	p("add sites/<site_id>.yaml, then: wafctl validate && wafctl apply")
	if o.Role == "node" {
		p("on the central: wafctl pki token --cn %s ; here: wafctl node enroll --token <T> --ca-sha256 <H>", o.NodeID)
	}
	if !o.InstallSystemd {
		p("as root: wafctl node bootstrap ... --force --install-systemd   (timers)")
	}
	return b.String()
}
