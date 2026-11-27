package awsexport

import (
	"fmt"
	"net/netip"
	"strings"

	"nginxawswaf/wafctl/internal/config"
)

// M is a JSON object of the CreateWebACL input.
type M = map[string]any

var transformNames = map[string]string{"urlDecodeUni": "URL_DECODE_UNI", "lowercase": "LOWERCASE"}

// textTransformations maps the condition transforms; none → [{0, NONE}].
func textTransformations(ts []string) []M {
	if len(ts) == 0 {
		return []M{{"Priority": 0, "Type": "NONE"}}
	}
	out := make([]M, len(ts))
	for i, t := range ts {
		out[i] = M{"Priority": i, "Type": transformNames[t]}
	}
	return out
}

// stmtCtx carries what a statement needs beyond the condition: the IP sets being collected.
type stmtCtx struct {
	b    *builder
	rule string // owning rule name (IP set names)
}

// match converts an AND of conditions: one → the statement itself, several → AndStatement.
func (c stmtCtx) match(m *config.Match) (M, error) {
	var ss []M
	for _, cond := range m.All {
		s, err := c.cond(cond)
		if err != nil {
			return nil, err
		}
		ss = append(ss, s)
	}
	switch len(ss) {
	case 0:
		return nil, fmt.Errorf("rule %s: empty match", c.rule)
	case 1:
		return ss[0], nil
	}
	return M{"AndStatement": M{"Statements": ss}}, nil
}

func (c stmtCtx) cond(k config.Cond) (M, error) {
	s, err := c.condPos(k)
	if err != nil || !k.Negate {
		return s, err
	}
	return M{"NotStatement": M{"Statement": s}}, nil
}

func (c stmtCtx) condPos(k config.Cond) (M, error) {
	switch {
	case k.Label != "":
		return M{"LabelMatchStatement": M{"Scope": "LABEL", "Key": k.Label}}, nil
	case k.LabelNamespace != "":
		return M{"LabelMatchStatement": M{"Scope": "NAMESPACE", "Key": k.LabelNamespace}}, nil
	case k.URIPath != nil:
		return strMatch(M{"UriPath": M{}}, k.URIPath), nil
	case k.Header != nil:
		return strMatch(M{"SingleHeader": M{"Name": strings.ToLower(k.Header.Name)}}, k.Header), nil
	case k.QueryArg != nil:
		return strMatch(M{"SingleQueryArgument": M{"Name": k.QueryArg.Name}}, k.QueryArg), nil
	case k.Method != nil:
		var ss []M
		for _, m := range k.Method {
			ss = append(ss, M{"ByteMatchStatement": M{"SearchString": strings.ToUpper(m), "FieldToMatch": M{"Method": M{}},
				"TextTransformations": textTransformations(nil), "PositionalConstraint": "EXACTLY"}})
		}
		return orOf(ss), nil
	case k.IPSet != nil:
		return c.ipSet(k.IPSet)
	case k.Geo != nil:
		return M{"GeoMatchStatement": M{"CountryCodes": append([]string(nil), k.Geo...)}}, nil
	case k.Size != nil:
		f, err := sizeField(k.Size.Component)
		if err != nil {
			return nil, err
		}
		return M{"SizeConstraintStatement": M{"FieldToMatch": f, "ComparisonOperator": strings.ToUpper(k.Size.Op),
			"Size": k.Size.Value, "TextTransformations": textTransformations(nil)}}, nil
	}
	return nil, fmt.Errorf("rule %s: empty condition", c.rule)
}

func orOf(ss []M) M {
	if len(ss) == 1 {
		return ss[0]
	}
	return M{"OrStatement": M{"Statements": ss}}
}

func strMatch(field M, s *config.StrMatch) M {
	tt := textTransformations(s.Transform)
	if s.Regex != "" {
		return M{"RegexMatchStatement": M{"RegexString": s.Regex, "FieldToMatch": field, "TextTransformations": tt}}
	}
	v, pc := s.Exact, "EXACTLY"
	switch {
	case s.StartsWith != "":
		v, pc = s.StartsWith, "STARTS_WITH"
	case s.Contains != "":
		v, pc = s.Contains, "CONTAINS"
	}
	return M{"ByteMatchStatement": M{"SearchString": v, "FieldToMatch": field, "TextTransformations": tt, "PositionalConstraint": pc}}
}

func sizeField(comp string) (M, error) {
	switch {
	case comp == "body":
		return M{"Body": M{"OversizeHandling": "CONTINUE"}}, nil
	case comp == "query_string":
		return M{"QueryString": M{}}, nil
	case comp == "uri_path":
		return M{"UriPath": M{}}, nil
	case comp == "cookie":
		return M{"Cookies": M{"MatchPattern": M{"All": M{}}, "MatchScope": "ALL", "OversizeHandling": "CONTINUE"}}, nil
	case strings.HasPrefix(comp, "header:"):
		return M{"SingleHeader": M{"Name": strings.ToLower(strings.TrimPrefix(comp, "header:"))}}, nil
	}
	return nil, fmt.Errorf("size component %q", comp)
}

// ipSet registers waf-<site>-<rule>-v4/-v6 IP sets and references them (Or when both exist).
func (c stmtCtx) ipSet(cidrs []string) (M, error) {
	var v4, v6 []string
	for _, s := range cidrs {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("rule %s: ip_set: %w", c.rule, err)
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	var refs []M
	for _, v := range []struct {
		suffix, version string
		addrs           []string
	}{{"v4", "IPV4", v4}, {"v6", "IPV6", v6}} {
		if len(v.addrs) == 0 {
			continue
		}
		name := c.b.ipSetName(c.rule, v.suffix)
		c.b.doc.IPSets = append(c.b.doc.IPSets, M{"Name": name, "Scope": "REGIONAL", "IPAddressVersion": v.version, "Addresses": v.addrs})
		refs = append(refs, M{"IPSetReferenceStatement": M{"ARN": c.b.ipSetARN(name)}})
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("rule %s: empty ip_set", c.rule)
	}
	return orOf(refs), nil
}

// parsePrefix accepts a CIDR or a bare address (→ /32 or /128).
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP or CIDR", s)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}
