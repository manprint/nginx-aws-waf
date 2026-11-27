package render

import (
	"fmt"
	"net/netip"
	"strings"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
)

// MaxConds is the maximum number of conditions per custom rule / scope-down (ids N+1..N+6).
const MaxConds = 6

func strOp(m *config.StrMatch) (string, error) {
	switch {
	case m.Exact != "":
		return "@streq " + m.Exact, nil
	case m.StartsWith != "":
		return "@beginsWith " + m.StartsWith, nil
	case m.Contains != "":
		return "@contains " + m.Contains, nil
	case m.Regex != "":
		return "@rx " + m.Regex, nil
	}
	return "", fmt.Errorf("string match without exact|starts_with|contains|regex")
}

// condLink maps a condition to the ModSecurity variable, operator and extra transforms.
func condLink(c config.Cond, cat *catalog.Catalog) (variable, op string, transforms []string, err error) {
	k := c.Kinds()
	if len(k) != 1 {
		return "", "", nil, fmt.Errorf("condition must have exactly one kind, has %v", k)
	}
	switch k[0] {
	case "label":
		r := cat.RuleByLabel(c.Label)
		if r == nil {
			return "", "", nil, fmt.Errorf("unknown label %q", c.Label)
		}
		return fmt.Sprintf("TX:lbl_%d", r.ID), "@eq 1", nil, nil
	case "label_namespace":
		for _, g := range cat.Groups {
			if g.LabelNS == c.LabelNamespace {
				return "TX:ns_" + g.Key, "@eq 1", nil, nil
			}
		}
		return "", "", nil, fmt.Errorf("unknown label namespace %q", c.LabelNamespace)
	case "uri_path":
		op, err := strOp(c.URIPath)
		return "TX:raw_path", op, c.URIPath.Transform, err
	case "header":
		op, err := strOp(c.Header)
		return "REQUEST_HEADERS:" + c.Header.Name, op, c.Header.Transform, err
	case "query_arg":
		op, err := strOp(c.QueryArg)
		return "ARGS_GET:" + c.QueryArg.Name, op, c.QueryArg.Transform, err
	case "method":
		return "REQUEST_METHOD", "@rx ^(?:" + strings.Join(c.Method, "|") + ")$", nil, nil
	case "ip_set":
		return "REMOTE_ADDR", "@ipMatch " + strings.Join(ipMatchList(c.IPSet), ","), nil, nil
	case "geo":
		return "TX:geo_cc", "@rx ^(?:" + strings.Join(c.Geo, "|") + ")$", nil, nil
	case "size":
		var v string
		comp := c.Size.Component
		switch {
		case comp == "body":
			v = "REQUEST_BODY"
		case comp == "query_string":
			v = "QUERY_STRING"
		case comp == "uri_path":
			v = "TX:raw_path"
		case comp == "cookie":
			v = "REQUEST_HEADERS:Cookie"
		case strings.HasPrefix(comp, "header:"):
			v = "REQUEST_HEADERS:" + strings.TrimPrefix(comp, "header:")
		default:
			return "", "", nil, fmt.Errorf("unknown size component %q", comp)
		}
		ops := map[string]string{"gt": "@gt", "ge": "@ge", "lt": "@lt", "le": "@le", "eq": "@eq"}
		o, ok := ops[c.Size.Op]
		if !ok {
			return "", "", nil, fmt.Errorf("unknown size op %q", c.Size.Op)
		}
		return v, fmt.Sprintf("%s %d", o, c.Size.Value), []string{"length"}, nil
	}
	return "", "", nil, fmt.Errorf("unsupported condition kind %s", k[0])
}

// helpers renders one helper rule pair per condition; var name prefix e.g. "c1502000" or "sd1600420".
func helpers(siteID string, base int, prefix string, conds []config.Cond, cat *catalog.Catalog) ([]string, error) {
	if len(conds) == 0 {
		return nil, fmt.Errorf("no conditions")
	}
	if len(conds) > MaxConds {
		return nil, fmt.Errorf("%d conditions exceed the maximum of %d", len(conds), MaxConds)
	}
	var out []string
	for i, c := range conds {
		v, op, ts, err := condLink(c, cat)
		if err != nil {
			return nil, err
		}
		out = append(out,
			fmt.Sprintf(`SecRule TX:site "@streq %s" "id:%d,phase:2,pass,nolog,chain"`, siteID, base+i+1),
			fmt.Sprintf(`SecRule %s "%s" "%s,setvar:tx.%s_%d=1"`, v, q(op), tline(ts), prefix, i+1))
	}
	return out, nil
}

// condChain renders the AND chain over helper vars; the last link gets final.
func condChain(prefix string, conds []config.Cond, final string) []string {
	var out []string
	for i, c := range conds {
		acts := "t:none,chain"
		if i == len(conds)-1 {
			acts = "t:none," + final
		}
		if c.Negate {
			out = append(out, fmt.Sprintf(`SecRule &TX:%s_%d "@eq 0" "%s"`, prefix, i+1, acts))
		} else {
			out = append(out, fmt.Sprintf(`SecRule TX:%s_%d "@eq 1" "%s"`, prefix, i+1, acts))
		}
	}
	return out
}

// ipMatchList writes full-length prefixes (/32, /128) as bare addresses: libmodsecurity 3
// rejects an IPv6 /128 in @ipMatch ("Rules error"); other entries are kept as written.
func ipMatchList(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = s
		if p, err := netip.ParsePrefix(s); err == nil && p.Bits() == p.Addr().BitLen() {
			out[i] = p.Addr().String()
		}
	}
	return out
}
