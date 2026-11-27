#!/usr/bin/env python3
"""Generate deploy/grafana/dashboards/*.json from deploy/grafana/panels.py (stdlib only).

  scripts/gen-dashboards.py           write the JSON files
  scripts/gen-dashboards.py --check   validate titles/grid and that the committed JSON is current
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "deploy" / "grafana" / "dashboards"
DS = {
    "ch": {"type": "grafana-clickhouse-datasource", "uid": "ch"},
    "prom": {"type": "prometheus", "uid": "prom"},
}


def load_panels():
    spec = importlib.util.spec_from_file_location("panels", ROOT / "deploy" / "grafana" / "panels.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.DASHBOARDS


def layout(panels):
    """Row-major placement on a 24-column grid."""
    x = y = row_h = 0
    out = []
    for p in panels:
        w, h = p["w"], p["h"]
        if x + w > 24:
            x, y, row_h = 0, y + row_h, 0
        out.append({"x": x, "y": y, "w": w, "h": h})
        x += w
        row_h = max(row_h, h)
    return out


def target(p):
    if p["ds"] == "ch":
        ts = p["type"] == "timeseries"
        return {"datasource": DS["ch"], "editorType": "sql", "queryType": "timeseries" if ts else "table",
                "format": 0 if ts else 1, "rawSql": p["sql"], "refId": "A"}
    t = {"datasource": DS["prom"], "expr": p["expr"], "refId": "A"}
    if p.get("legend"):
        t["legendFormat"] = p["legend"]
    return t


def panel(i, p, grid):
    defaults = {}
    if p.get("unit"):
        defaults["unit"] = p["unit"]
    if p["type"] == "timeseries":
        defaults["custom"] = {"stacking": {"mode": "normal" if p.get("stack") else "none", "group": "A"},
                              "fillOpacity": 30 if p.get("stack") else 10, "drawStyle": "line"}
    out = {"id": i, "type": p["type"], "title": p["title"], "gridPos": grid, "datasource": DS[p["ds"]],
           "targets": [target(p)], "fieldConfig": {"defaults": defaults, "overrides": []}, "options": {}}
    if p["type"] == "stat":
        out["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "colorMode": "none", "graphMode": "none"}
    elif p["type"] == "piechart":
        out["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}, "legend": {"displayMode": "table", "placement": "right"}}
    elif p["type"] == "barchart":
        out["options"] = {"xField": p["x"], "orientation": "horizontal"}
    elif p["type"] == "table":
        out["options"] = {"showHeader": True}
    return out


def variable(v):
    base = {"name": v["name"], "label": v.get("label", v["name"]), "hide": 0}
    if v["type"] == "textbox":
        return {**base, "type": "textbox", "query": "", "current": {"text": "", "value": ""}}
    if v["type"] == "custom":
        opts = v["query"].split(",")
        return {**base, "type": "custom", "query": v["query"], "multi": v.get("multi", False), "includeAll": v.get("includeAll", False),
                "allValue": v.get("allValue"), "current": {"text": ["All"], "value": ["$__all"]},
                "options": [{"text": o, "value": o, "selected": False} for o in opts]}
    return {**base, "type": "query", "datasource": DS[v["ds"]], "definition": v["query"], "query": v["query"],
            "multi": v.get("multi", False), "includeAll": v.get("includeAll", False), "allValue": v.get("allValue"),
            "refresh": 2, "sort": 1, "current": {"text": ["All"], "value": ["$__all"]}}


def dashboard(d):
    grid = layout(d["panels"])
    return {"uid": d["uid"], "title": d["title"], "schemaVersion": 39, "version": 1, "editable": False,
            "tags": ["waf"], "timezone": "utc", "time": {"from": "now-6h", "to": "now"}, "refresh": "30s",
            "templating": {"list": [variable(v) for v in d["vars"]]},
            "panels": [panel(i + 1, p, g) for i, (p, g) in enumerate(zip(d["panels"], grid))]}


def render():
    return {d["uid"] + ".json": json.dumps(dashboard(d), indent=2, ensure_ascii=False) + "\n" for d in load_panels()}


def check():
    errs = []
    for d in load_panels():
        titles = [p["title"] for p in d["panels"]]
        for t in set(titles):
            if titles.count(t) > 1:
                errs.append(f"{d['uid']}: duplicate title {t!r}")
        cells = {}
        for p, g in zip(d["panels"], layout(d["panels"])):
            if g["w"] < 1 or g["x"] + g["w"] > 24:
                errs.append(f"{d['uid']}: {p['title']!r} exceeds 24 columns")
            for cx in range(g["x"], g["x"] + g["w"]):
                for cy in range(g["y"], g["y"] + g["h"]):
                    if (cx, cy) in cells:
                        errs.append(f"{d['uid']}: {p['title']!r} overlaps {cells[(cx, cy)]!r}")
                        break
                    cells[(cx, cy)] = p["title"]
            if p["type"] not in ("timeseries", "table", "stat", "barchart", "piechart") or p["ds"] not in DS:
                errs.append(f"{d['uid']}: {p['title']!r} bad type/ds")
            if ("sql" if p["ds"] == "ch" else "expr") not in p:
                errs.append(f"{d['uid']}: {p['title']!r} has no query")
    for name, body in render().items():
        f = OUT / name
        if not f.exists() or f.read_text() != body:
            errs.append(f"{name}: not current (run make dashboards)")
    for e in sorted(set(errs)):
        print("ERROR", e)
    n = sum(len(d["panels"]) for d in load_panels())
    if not errs:
        print(f"OK {len(load_panels())} dashboards, {n} panels: unique titles, no grid overlap, JSON current")
    return 1 if errs else 0


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        sys.exit(check())
    OUT.mkdir(parents=True, exist_ok=True)
    for name, body in render().items():
        (OUT / name).write_text(body)
        print("wrote", OUT / name)
