package render

import (
	"bytes"
	"embed"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"text/template"

	"nginxawswaf/wafctl/internal/config"
)

//go:embed templates/*.tmpl
var tmplFS embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
}).ParseFS(tmplFS, "templates/*.tmpl"))

// DefaultMaxBody is client_max_body_size when upstream.max_body_size is unset.
const DefaultMaxBody = "10m"

// DefaultReadTimeout is the proxy timeout when upstream.read_timeout_sec is unset.
const DefaultReadTimeout = 60

type nginxData struct {
	Version, NodeID, Workers, R string
	Bridge, DefaultServer       bool
	RateZones, DefaultListens   []string
}

type siteData struct {
	ID, App, Names, R, Cert, Key, MaxBody, Scheme string
	Bridge, TLS, Redirect                         bool
	Servers, Listens, HTTPListens, RealIP         []string
	RT                                            *config.Realtime
	Rate                                          *config.RateLimit
	ReadTimeout                                   int
}

func listens(port int, ipv6, ssl, def bool) []string {
	suf := ""
	if ssl {
		suf += " ssl"
	}
	if def {
		suf += " default_server"
	}
	out := []string{fmt.Sprintf("listen %d%s;", port, suf)}
	if ipv6 {
		out = append(out, fmt.Sprintf("listen [::]:%d%s;", port, suf))
	}
	return out
}

// RateZone returns the limit_req_zone line of a site.
func RateZone(id string, rl *config.RateLimit) string {
	rate := int(math.Ceil(float64(rl.Limit) * 60 / float64(rl.WindowSec)))
	return fmt.Sprintf("limit_req_zone $binary_remote_addr zone=rl_%s:10m rate=%dr/m;", id, rate)
}

func (r *renderer) nginxFiles(files map[string][]byte) error {
	n := r.cfg.Node
	ipv6 := n.Listen.IPv6 == nil || *n.Listen.IPv6
	d := nginxData{Version: r.opt.Version, NodeID: n.NodeID, R: r.R, Bridge: n.Network == "bridge", Workers: "auto"}
	if n.Workers > 0 {
		d.Workers = strconv.Itoa(n.Workers)
	}
	anyTLS := false
	for _, s := range r.sites {
		if s.Eff.Site.TLS.Mode != "off" {
			anyTLS = true
		}
		if rl := s.Eff.WAF.RateLimit; rl != nil {
			d.RateZones = append(d.RateZones, RateZone(s.Eff.Site.SiteID, rl))
		}
	}
	if n.DefaultSite == "" {
		d.DefaultServer = true
		d.DefaultListens = listens(n.Listen.HTTP, ipv6, false, true)
		if anyTLS {
			d.DefaultListens = append(d.DefaultListens, listens(n.Listen.HTTPS, ipv6, true, true)...)
			d.DefaultListens = append(d.DefaultListens, "ssl_reject_handshake on;")
		}
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "nginx.conf.tmpl", d); err != nil {
		return err
	}
	files["nginx/nginx.conf"] = b.Bytes()

	for _, s := range r.sites {
		st := s.Eff.Site
		w := &s.Eff.WAF
		def := n.DefaultSite == st.SiteID
		sd := siteData{ID: st.SiteID, App: st.App, R: r.R, Bridge: d.Bridge, Servers: st.Upstream.Servers,
			RT: st.Upstream.Realtime, Rate: w.RateLimit, MaxBody: st.Upstream.MaxBodySize,
			ReadTimeout: st.Upstream.ReadTimeoutSec, Scheme: "http"}
		for i, nm := range st.ServerNames {
			if i > 0 {
				sd.Names += " "
			}
			sd.Names += nm
		}
		if sd.MaxBody == "" {
			sd.MaxBody = DefaultMaxBody
		}
		if sd.ReadTimeout == 0 {
			sd.ReadTimeout = DefaultReadTimeout
		}
		if st.Upstream.TLS {
			sd.Scheme = "https"
		}
		if w.ClientIP.Source == "xff" {
			sd.RealIP = w.ClientIP.TrustedProxies
		}
		switch st.TLS.Mode {
		case "off":
			sd.Listens = listens(n.Listen.HTTP, ipv6, false, def)
		case "on":
			sd.Listens = append(listens(n.Listen.HTTP, ipv6, false, def), listens(n.Listen.HTTPS, ipv6, true, def)...)
		case "redirect":
			sd.Redirect = true
			sd.HTTPListens = listens(n.Listen.HTTP, ipv6, false, def)
			sd.Listens = listens(n.Listen.HTTPS, ipv6, true, def)
		}
		if st.TLS.Mode != "off" {
			sd.TLS = true
			cert, key := config.CertPaths(st)
			sd.Cert, sd.Key = filepath.Base(cert), filepath.Base(key)
		}
		var sb bytes.Buffer
		if err := tmpl.ExecuteTemplate(&sb, "site.conf.tmpl", sd); err != nil {
			return err
		}
		files["nginx/sites/"+st.SiteID+".conf"] = append(sb.Bytes(), '\n')
	}
	return nil
}
