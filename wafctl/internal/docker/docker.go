// Package docker drives the node's docker compose project.
package docker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Engine is what apply needs from the container runtime (faked in tests).
type Engine interface {
	Running(svc string) (bool, error)
	Exec(svc string, args ...string) (string, error)
	RunOnce(svc string, args ...string) (string, error)
	Up() error
	Health(svc string) (string, error)
	Restart(svc string) error
}

// Compose is the docker compose implementation of Engine.
type Compose struct {
	Project string
	Files   []string
	Env     []string // extra environment (e.g. WAF_DATA_DIR)
	EnvFile string   // --env-file (secrets.env), optional
}

// Params selects the compose files and environment of a node.
type Params struct {
	Home, Role, Network, NodeID    string
	DataDir, ConfigDir, CentralDir string
	Extra                          []string // extra KEY=value environment (e.g. GF_BIND)
}

// Files returns the compose files for a role (relative to home/deploy/compose):
// node → node.yml + node.<network>.yml; central → central.yml;
// all-in-one → both (+ central.bridge.yml in bridge mode, so the node Vector reaches vector-central).
func Files(role, network string) []string {
	node := []string{"node.yml", "node." + network + ".yml"}
	switch role {
	case "central":
		return []string{"central.yml"}
	case "all-in-one":
		f := append(node, "central.yml")
		if network == "bridge" {
			f = append(f, "central.bridge.yml")
		}
		return f
	}
	return node
}

// NewCompose picks the role's compose files + $WAF_COMPOSE_EXTRA (colon-separated) under home.
// $WAF_CONFIG_DIR/secrets.env, when present, is passed with --env-file.
func NewCompose(p Params) (*Compose, error) {
	home := p.Home
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, errors.New("docker is not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		return nil, errors.New("docker compose is not installed")
	}
	d := filepath.Join(home, "deploy", "compose")
	var files []string
	for _, f := range Files(p.Role, p.Network) {
		files = append(files, filepath.Join(d, f))
	}
	if x := os.Getenv("WAF_COMPOSE_EXTRA"); x != "" {
		for _, f := range strings.Split(x, ":") {
			if f == "" {
				continue
			}
			if !filepath.IsAbs(f) {
				f = filepath.Join(home, f)
			}
			files = append(files, f)
		}
	}
	proj := os.Getenv("WAF_COMPOSE_PROJECT")
	if proj == "" {
		proj = "waf"
	}
	c := &Compose{Project: proj, Files: files, Env: []string{"WAF_DATA_DIR=" + p.DataDir, "WAF_CONFIG_DIR=" + p.ConfigDir,
		"WAF_CENTRAL_DIR=" + p.CentralDir, "WAF_NODE_ID=" + p.NodeID}}
	c.Env = append(c.Env, p.Extra...)
	if sf := filepath.Join(p.ConfigDir, "secrets.env"); fileExists(sf) {
		c.EnvFile = sf
	}
	return c, nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func (c *Compose) base() []string {
	a := []string{"compose", "-p", c.Project}
	if c.EnvFile != "" {
		a = append(a, "--env-file", c.EnvFile)
	}
	for _, f := range c.Files {
		a = append(a, "-f", f)
	}
	return a
}

func (c *Compose) run(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), c.Env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return out.String(), nil
}

// Running reports whether svc is running.
func (c *Compose) Running(svc string) (bool, error) {
	out, err := c.run(append(c.base(), "ps", "--status", "running", "--services")...)
	if err != nil {
		return false, err
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == svc {
			return true, nil
		}
	}
	return false, nil
}

// Exec runs a command in the running svc.
func (c *Compose) Exec(svc string, args ...string) (string, error) {
	return c.run(append(append(c.base(), "exec", "-T", svc), args...)...)
}

// RunOnce runs a command in a fresh svc container.
func (c *Compose) RunOnce(svc string, args ...string) (string, error) {
	return c.run(append(append(c.base(), "run", "--rm", "--no-deps", "-T", svc), args...)...)
}

// Up starts the project.
func (c *Compose) Up() error {
	out, err := c.run(append(c.base(), "up", "-d", "--build")...)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// Health returns the docker health status of svc.
func (c *Compose) Health(svc string) (string, error) {
	id, err := c.run(append(c.base(), "ps", "-q", svc)...)
	if err != nil {
		return "", err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "missing", nil
	}
	out, err := c.run("inspect", "-f", "{{.State.Health.Status}}", id)
	return strings.TrimSpace(out), err
}

// Restart restarts svc (e.g. vector after its forward config changed).
func (c *Compose) Restart(svc string) error {
	out, err := c.run(append(c.base(), "restart", svc)...)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}
