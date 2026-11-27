#!/usr/bin/env bash
# Run every panel query (and every query variable) of deploy/grafana/dashboards/*.json through
# Grafana's /api/ds/query as admin; fail on any query error. Prints "OK <dashboard> <panel>".
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECRETS="${WAF_CONFIG_DIR:-$ROOT/lab/config}/secrets.env"
GF_ADMIN_PASSWORD="${GF_ADMIN_PASSWORD:-$(sed -n 's/^GF_ADMIN_PASSWORD=//p' "$SECRETS" 2>/dev/null)}"
export GF_URL="${WAF_GRAFANA_URL:-http://127.0.0.1:3000}" GF_ADMIN_PASSWORD
exec python3 - "$ROOT"/deploy/grafana/dashboards/*.json <<'PY'
import base64, json, os, re, sys, urllib.request

url, pw = os.environ["GF_URL"], os.environ["GF_ADMIN_PASSWORD"]
auth = "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()
# Interpolate like Grafana with default values: "All" of a variable with a custom allValue is
# inserted verbatim (no :format applied); textboxes default to '' (sqlstring → '').
def interpolate(s, variables):
    def rep(m):
        v = variables.get(m.group(1), {})
        if v.get("type") in ("query", "custom") and v.get("includeAll"):
            if v.get("allValue") is None:
                raise SystemExit(f"variable {m.group(1)}: includeAll needs an allValue")
            return v["allValue"]
        if m.group(2) == "sqlstring":
            return "''"
        return ""
    return re.sub(r"\$\{(\w+)(?::(\w+))?\}", rep, s)

def query(t, variables):
    t = json.loads(json.dumps(t))
    for k in ("rawSql", "expr"):
        if k in t and "$" in t[k]:
            t[k] = interpolate(t[k], variables)
    body = json.dumps({"queries": [t], "from": "now-1h", "to": "now"}).encode()
    req = urllib.request.Request(url + "/api/ds/query", data=body, method="POST",
                                 headers={"Authorization": auth, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        res = json.loads(e.read() or b"{}")
        if "results" not in res:
            return f"HTTP {e.code}: {res}"
    a = res.get("results", {}).get(t.get("refId", "A"), {})
    return a.get("error")

fails = 0
for path in sys.argv[1:]:
    d = json.load(open(path))
    variables = {v["name"]: v for v in d.get("templating", {}).get("list", [])}
    items = [(p["title"], p["targets"][0]) for p in d["panels"]]
    for v in d.get("templating", {}).get("list", []):
        if v.get("type") == "query":
            items.append((f"var {v['name']}", {"datasource": v["datasource"], "editorType": "sql", "queryType": "table",
                                               "format": 1, "rawSql": v["query"], "refId": "A"}))
    for title, t in items:
        err = query(t, variables)
        if err:
            fails += 1
            print(f"FAIL {d['uid']} {title}: {err}")
        else:
            print(f"OK {d['uid']} {title}")
print("ALL PASS" if not fails else f"FAILED {fails} quer(ies)")
sys.exit(1 if fails else 0)
PY
