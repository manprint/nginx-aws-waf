#!/usr/bin/env python3
"""Genera grafana/dashboards/waf-ip.json (dashboard "WAF IP": IP bloccati / non bloccati con GeoIP).

  python3 grafana/waf-ip.py      # riscrive il JSON; Grafana lo ricarica da solo in ~10 s
Modifica questo file, non il JSON.
"""
import json
import pathlib
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent / "dashboards" / "waf-ip.json"
DS = {"type": "grafana-clickhouse-datasource", "uid": "ch"}

# ---- frammenti SQL ----------------------------------------------------------------------------
SITE = "('__all__' IN (${site:singlequote}) OR site_id IN (${site:singlequote}))"
CIDR_RE = r"'^[0-9a-fA-F:.]+/[0-9]{1,3}$'"
IPF = ("(${ip:sqlstring} = '' OR position(client_ip, ${ip:sqlstring}) > 0 OR (match(${ip:sqlstring}, " + CIDR_RE +
       ") AND isIPAddressInRange(client_ip, if(match(${ip:sqlstring}, " + CIDR_RE + "), ${ip:sqlstring}, '255.255.255.255/32'))))")


def private(x):
    nets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
            "fc00::/7", "fe80::/10"]
    return "(" + " OR ".join(f"isIPAddressInRange({x}, '{n}')" for n in nets) + f" OR {x} = '::1')"


# paese di una riga: ISO2 da GeoIP, LAN per reti private, ?? se sconosciuto
GEO_ROW = f"multiIf(country != '', country, {private('client_ip')}, 'LAN', '??')"
PAESE_F = "('__all__' IN (${paese:singlequote}) OR " + GEO_ROW + " IN (${paese:singlequote}))"
WHERE = f"WHERE $__timeFilter(ts) AND {SITE} AND {IPF} AND {PAESE_F}"
STATO_X = "multiIf(blk = 0, 'consentito', blk = req, 'bloccato', 'misto')"
STATO_F = "('__all__' IN (${stato:singlequote}) OR " + STATO_X + " IN (${stato:singlequote}))"


def flag(x):
    return (f"if(match({x}, '^[A-Z]{{2}}$'), concat(char(240, 159, 135, 166 + ascii(substring({x}, 1, 1)) - 65), "
            f"char(240, 159, 135, 166 + ascii(substring({x}, 2, 1)) - 65), ' ', {x}), if({x} = 'LAN', '🏠 LAN', '❔ ??'))")


CAUSA = "waf_causa(replaceRegexpOne(terminating_rule, '^.*/', ''), terminating_type)"

# un IP per riga, con stato calcolato sul periodo e filtri applicati
PER_IP = (f"SELECT client_ip AS ip, anyLast({GEO_ROW}) AS geo, anyLast(asn) AS asn_, "
          f"anyLast(as_org) AS org, count() AS req, countIf(action = 'BLOCK') AS blk, {STATO_X} AS stato "
          f"FROM waf.events {WHERE} GROUP BY ip HAVING {STATO_F}")

# ---- costruzione pannelli -----------------------------------------------------------------------
panels = []
_y = [0]
_row = {"x": 0, "h": 0}


def add(p, w, h):
    if _row["x"] + w > 24:
        _y[0] += _row["h"]
        _row["x"], _row["h"] = 0, 0
    p["gridPos"] = {"x": _row["x"], "y": _y[0], "w": w, "h": h}
    _row["x"] += w
    _row["h"] = max(_row["h"], h)
    p["id"] = len(panels) + 1
    p.setdefault("datasource", DS)
    panels.append(p)


def tgt(sql, ref="A", fmt=1):
    return {"datasource": DS, "editorType": "sql", "queryType": "table", "format": fmt, "rawSql": sql, "refId": ref}


def stat(title, sql, color, desc="", unit="short"):
    add({"type": "stat", "title": title, "description": desc, "targets": [tgt(sql)],
         "fieldConfig": {"defaults": {"unit": unit, "color": {"mode": "fixed", "fixedColor": color}}, "overrides": []},
         "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                     "colorMode": "background", "graphMode": "none", "textMode": "value"}}, 4, 4)


def ov(name, *props):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": k, "value": v} for k, v in props]}


def width(name, w):
    return ov(name, ("custom.width", w))


STATO_MAP = ("mappings", [{"type": "value", "options": {
    "bloccato": {"text": "⛔ sempre bloccato", "color": "red", "index": 0},
    "misto": {"text": "⚠ in parte bloccato", "color": "orange", "index": 1},
    "consentito": {"text": "✅ mai bloccato", "color": "green", "index": 2}}}])
BG = ("custom.cellOptions", {"type": "color-background"})
PCT_TH = ("thresholds", {"mode": "absolute", "steps": [{"color": "green", "value": None},
                                                       {"color": "orange", "value": 10}, {"color": "red", "value": 50}]})
IP_LINKS = ("links", [
    {"title": "Dettaglio di ${__value.raw} (in questa dashboard)",
     "url": "/d/waf-ip/waf-ip?${__url_time_range}&${site:queryparam}&var-ip=${__value.raw}"},
    {"title": "Richieste di ${__value.raw} in WAF Richieste",
     "url": "/d/waf-requests/waf-richieste?${__url_time_range}&${site:queryparam}&var-ip=${__value.raw}", "targetBlank": True}])

# Riga 1: riepilogo
stat("IP distinti", f"SELECT count() FROM ({PER_IP})", "blue", "IP client visti nel periodo (con i filtri in alto).")
stat("Sempre bloccati", f"SELECT countIf(stato = 'bloccato') FROM ({PER_IP})", "red",
     "IP con tutte le richieste bloccate dal WAF.")
stat("In parte bloccati", f"SELECT countIf(stato = 'misto') FROM ({PER_IP})", "orange",
     "IP con alcune richieste bloccate e altre consentite (utenti veri che hanno fatto scattare una regola, o scanner).")
stat("Mai bloccati", f"SELECT countIf(stato = 'consentito') FROM ({PER_IP})", "green",
     "IP con nessuna richiesta bloccata.")
stat("Paesi", f"SELECT uniqIf(geo, geo NOT IN ('LAN', '??')) FROM ({PER_IP})", "purple",
     "Paesi distinti di provenienza (servono i database GeoIP in data/geoip).")
stat("IP senza paese", f"SELECT countIf(geo IN ('LAN', '??')) FROM ({PER_IP})", "text",
     "IP di reti private/locali (LAN) o non presenti nel database GeoIP (??).")

# Riga 2: mappa + paesi
MAP_SQL = ("SELECT geo AS Paese, count() AS IP, sum(req) AS Richieste, countIf(blk > 0) AS `IP bloccati`, "
           f"countIf(blk = 0) AS `IP mai bloccati`, sum(blk) AS `Richieste bloccate` FROM ({PER_IP}) "
           "WHERE geo NOT IN ('LAN', '??') GROUP BY geo")


def layer(name, ref, size_field, color):
    return {"type": "markers", "name": name, "tooltip": True, "filterData": {"id": "byRefId", "options": ref},
            "location": {"mode": "lookup", "lookup": "Paese", "gazetteer": "public/gazetteer/countries.json"},
            "config": {"showLegend": False, "style": {
                "size": {"field": size_field, "fixed": 5, "min": 6, "max": 40},
                "color": {"fixed": color}, "opacity": 0.55,
                "symbol": {"mode": "fixed", "fixed": "img/icons/marker/circle.svg"},
                "text": {"mode": "field", "field": "Paese", "fixed": ""},
                "textConfig": {"fontSize": 10, "offsetY": -14}}}}


add({"type": "geomap", "title": "Da dove arrivano gli IP — 🔴 IP bloccati, 🟢 IP mai bloccati (dimensione = numero di IP)",
     "description": "Localizzazione per paese (GeoIP DB-IP/MaxMind). Gli IP di reti private (LAN) e quelli non "
                    "presenti nel database GeoIP non compaiono sulla mappa: vedi la tabella. Clic su un cerchio per i numeri.",
     "targets": [tgt(MAP_SQL + " HAVING `IP mai bloccati` > 0", "A"), tgt(MAP_SQL + " HAVING `IP bloccati` > 0", "B")],
     "fieldConfig": {"defaults": {}, "overrides": []},
     "options": {"view": {"id": "zero", "lat": 30, "lon": 10, "zoom": 1.3, "allLayers": True},
                 "controls": {"showZoom": True, "mouseWheelZoom": True, "showAttribution": True},
                 "basemap": {"type": "default", "name": "Base", "config": {}},
                 "layers": [layer("IP mai bloccati", "A", "IP mai bloccati", "green"),
                            layer("IP bloccati", "B", "IP bloccati", "red")],
                 "tooltip": {"mode": "details"}}}, 14, 13)

add({"type": "table", "title": "Paesi",
     "description": "Per paese: IP distinti, quanti bloccati almeno una volta, richieste e percentuale bloccata. "
                    "Clic sul paese per filtrare la dashboard.",
     "targets": [tgt(f"SELECT {flag('geo')} AS Paese, geo AS cc, count() AS IP, countIf(blk > 0) AS `IP bloccati`, "
                     f"countIf(blk = 0) AS `Mai bloccati`, sum(req) AS Richieste, sum(blk) AS Bloccate, "
                     f"round(100 * Bloccate / greatest(Richieste, 1), 1) AS `% bloccate` FROM ({PER_IP}) "
                     "GROUP BY geo ORDER BY IP DESC, Richieste DESC")],
     "fieldConfig": {"defaults": {"custom": {"filterable": True, "cellOptions": {"type": "auto"}}}, "overrides": [
         ov("IP bloccati", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "red"})),
         ov("Mai bloccati", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "green"})),
         ov("% bloccate", ("custom.cellOptions", {"type": "color-background"}), PCT_TH, ("color", {"mode": "thresholds"})),
         ov("cc", ("custom.hidden", True)),
         ov("Paese", ("links", [{"title": "Filtra ${__data.fields.cc}",
                                 "url": "/d/waf-ip/waf-ip?${__url_time_range}&${site:queryparam}&var-paese=${__data.fields.cc}"}])),
     ]},
     "options": {"showHeader": True, "cellHeight": "sm"}}, 10, 13)

# Riga 3: andamento, stato, ASN
add({"type": "timeseries", "title": "IP attivi nel tempo",
     "description": "Per ogni intervallo: IP con almeno una richiesta bloccata e IP con sole richieste consentite.",
     "targets": [tgt(f"SELECT t AS time, countIf(b > 0) AS `IP bloccati`, countIf(b = 0) AS `IP solo consentiti` FROM "
                     f"(SELECT $__timeInterval(ts) AS t, client_ip, countIf(action = 'BLOCK') AS b FROM waf.events {WHERE} "
                     f"AND client_ip IN (SELECT ip FROM ({PER_IP})) GROUP BY t, client_ip) GROUP BY time ORDER BY time", fmt=0)],
     "fieldConfig": {"defaults": {"unit": "short", "custom": {"drawStyle": "bars", "fillOpacity": 80,
                                                               "stacking": {"mode": "normal"}, "lineWidth": 1}},
                     "overrides": [ov("IP bloccati", ("color", {"mode": "fixed", "fixedColor": "red"})),
                                   ov("IP solo consentiti", ("color", {"mode": "fixed", "fixedColor": "green"}))]},
     "maxDataPoints": 60,
     "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}}}, 10, 9)

add({"type": "piechart", "title": "IP per stato",
     "targets": [tgt(f"SELECT countIf(stato = 'bloccato') AS `Sempre bloccati`, countIf(stato = 'misto') AS `In parte bloccati`, "
                     f"countIf(stato = 'consentito') AS `Mai bloccati` FROM ({PER_IP})")],
     "fieldConfig": {"defaults": {"unit": "short"}, "overrides": [
         ov("Sempre bloccati", ("color", {"mode": "fixed", "fixedColor": "red"})),
         ov("In parte bloccati", ("color", {"mode": "fixed", "fixedColor": "orange"})),
         ov("Mai bloccati", ("color", {"mode": "fixed", "fixedColor": "green"}))]},
     "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "pieType": "donut",
                 "legend": {"displayMode": "table", "placement": "bottom", "values": ["value", "percent"]},
                 "tooltip": {"mode": "single"}}}, 5, 9)

add({"type": "table", "title": "Reti / provider (ASN)",
     "description": "Organizzazione proprietaria degli IP (database GeoIP ASN): utile per capire se il traffico "
                    "bloccato arriva da hosting/cloud (bot) o da provider residenziali.",
     "targets": [tgt(f"SELECT if(asn_ = 0, '—', toString(asn_)) AS ASN, if(org = '', if(geo = 'LAN', 'rete locale', 'sconosciuto'), org) AS Organizzazione, "
                     f"count() AS IP, countIf(blk > 0) AS `IP bloccati`, sum(req) AS Richieste, sum(blk) AS Bloccate "
                     f"FROM ({PER_IP}) GROUP BY ASN, Organizzazione ORDER BY `IP bloccati` DESC, IP DESC LIMIT 100")],
     "fieldConfig": {"defaults": {"custom": {"filterable": True, "cellOptions": {"type": "auto"}}}, "overrides": [
         width("ASN", 70), width("IP", 50), width("IP bloccati", 100),
         ov("IP bloccati", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "red"}))]},
     "options": {"showHeader": True, "cellHeight": "sm"}}, 9, 9)

# Riga 4: tabella IP
IP_SQL = (f"SELECT {STATO_X} AS Stato, client_ip AS IP, {flag('geo')} AS Paese, "
          f"if(asn_ = 0, '', toString(asn_)) AS ASN, if(org = '', if(geo = 'LAN', 'rete locale', ''), org) AS Organizzazione, "
          f"count() AS req, countIf(action = 'BLOCK') AS blk, req AS Richieste, blk AS Bloccate, "
          f"round(100 * blk / req, 1) AS `% bloccate`, uniq(path) AS Percorsi, "
          f"arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray(site_id)), ', ') AS Siti, min(ts) AS `Prima vista`, max(ts) AS `Ultima vista`, "
          f"if(blk = 0, NULL, maxIf(ts, action = 'BLOCK')) AS `Ultimo blocco`, "
          f"arrayStringConcat(groupUniqArrayIf(5)({CAUSA}, action = 'BLOCK'), ' · ') AS `Perché è stato bloccato`, "
          f"any(user_agent) AS `User-Agent`, anyLast({GEO_ROW}) AS geo, "
          f"anyLast(asn) AS asn_, anyLast(as_org) AS org "
          f"FROM waf.events {WHERE} GROUP BY client_ip HAVING {STATO_F} ORDER BY blk DESC, req DESC LIMIT 1000")
TS = ("unit", "dateTimeAsIso")
add({"type": "table", "title": "IP (max 1000) — clic su un IP per il dettaglio qui sotto o per aprirne le richieste",
     "description": "Una riga per IP client. Stato: ⛔ tutte le richieste bloccate, ⚠ alcune bloccate, ✅ nessuna bloccata. "
                    "Paese e organizzazione da GeoIP. 'Perché è stato bloccato' = cause dei blocchi (fino a 5). "
                    "Per bloccare un IP a mano o metterlo in allowlist vedi il riquadro in fondo.",
     "targets": [tgt(IP_SQL)],
     "fieldConfig": {"defaults": {"custom": {"filterable": True, "cellOptions": {"type": "auto"}, "inspect": True}},
                     "overrides": [
                         ov("Stato", BG, STATO_MAP, ("custom.width", 150)),
                         ov("IP", ("custom.width", 125), IP_LINKS),
                         width("Paese", 70), width("ASN", 65), width("Organizzazione", 190),
                         width("Richieste", 95), width("Bloccate", 90), width("Percorsi", 85), width("Siti", 90),
                         ov("Bloccate", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "red"})),
                         ov("% bloccate", ("custom.cellOptions", {"type": "color-background"}), PCT_TH,
                            ("color", {"mode": "thresholds"}), ("custom.width", 105)),
                         ov("Prima vista", TS, ("custom.width", 160)), ov("Ultima vista", TS, ("custom.width", 160)),
                         ov("Ultimo blocco", TS, ("custom.width", 160)),
                         ov("Perché è stato bloccato", ("custom.cellOptions", {"type": "color-text", "wrapText": True}),
                            ("color", {"mode": "fixed", "fixedColor": "red"}), ("custom.width", 330)),
                         *[ov(n, ("custom.hidden", True)) for n in ("req", "blk", "geo", "asn_", "org")],
                     ]},
     "options": {"showHeader": True, "cellHeight": "sm",
                 "sortBy": [{"displayName": "Bloccate", "desc": True}]}}, 24, 16)

# Riga 5: dettaglio dell'IP selezionato
add({"type": "row", "title": "Dettaglio IP: ${ip} (scrivi un IP, una parte o un CIDR nel filtro IP in alto)",
     "collapsed": False, "panels": []}, 24, 1)
DET = f"WHERE $__timeFilter(ts) AND {SITE} AND {IPF} AND ${{ip:sqlstring}} != ''"
add({"type": "table", "title": "Chi è",
     "targets": [tgt(f"SELECT client_ip AS IP, {flag(GEO_ROW)} AS Paese, anyLast(asn) AS ASN, anyLast(as_org) AS Organizzazione, "
                     f"if({private('client_ip')}, 'privata / locale', 'pubblica') AS Rete, count() AS Richieste, "
                     f"countIf(action = 'BLOCK') AS Bloccate, uniq(user_agent) AS `User-Agent distinti`, "
                     f"min(ts) AS `Prima vista`, max(ts) AS `Ultima vista` FROM waf.events {DET} "
                     f"GROUP BY client_ip, Paese, Rete ORDER BY Richieste DESC LIMIT 50")],
     "fieldConfig": {"defaults": {"custom": {"cellOptions": {"type": "auto"}}}, "overrides": [
         ov("IP", IP_LINKS), ov("Prima vista", TS), ov("Ultima vista", TS),
         ov("Bloccate", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "red"}))]},
     "options": {"showHeader": True, "cellHeight": "sm"}}, 24, 5)
add({"type": "timeseries", "title": "Richieste dell'IP nel tempo",
     "targets": [tgt(f"SELECT $__timeInterval(ts) AS time, countIf(action != 'BLOCK') AS consentite, "
                     f"countIf(action = 'BLOCK') AS bloccate FROM waf.events {DET} GROUP BY time ORDER BY time", fmt=0)],
     "fieldConfig": {"defaults": {"unit": "short", "custom": {"drawStyle": "bars", "fillOpacity": 80,
                                                               "stacking": {"mode": "normal"}, "lineWidth": 1}},
                     "overrides": [ov("consentite", ("color", {"mode": "fixed", "fixedColor": "green"})),
                                   ov("bloccate", ("color", {"mode": "fixed", "fixedColor": "red"}))]},
     "maxDataPoints": 60,
     "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}}}, 12, 8)
add({"type": "table", "title": "Perché è stato bloccato",
     "targets": [tgt(f"SELECT {CAUSA} AS Causa, if(terminating_type = 'RATE_BASED', 'RateLimit', replaceRegexpOne(terminating_rule, '^[^/]*/', '')) AS Regola, count() AS Richieste, "
                     f"max(ts) AS Ultima FROM waf.events {DET} AND action = 'BLOCK' GROUP BY Causa, Regola ORDER BY Richieste DESC")],
     "fieldConfig": {"defaults": {"custom": {"cellOptions": {"type": "auto"}}}, "overrides": [
         ov("Ultima", TS), ov("Causa", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "red"}))]},
     "options": {"showHeader": True, "cellHeight": "sm"}}, 12, 8)
add({"type": "table", "title": "Ultime richieste dell'IP (clic su request_id per il dettaglio completo)",
     "targets": [tgt(f"SELECT ts AS Ora, client_ip AS IP, site_id AS Sito, method AS Metodo, "
                     f"concat(path, if(query = '', '', concat('?', query))) AS URL, status AS Stato, action AS Esito, "
                     f"if(action = 'BLOCK', {CAUSA}, '') AS Causa, user_agent AS `User-Agent`, request_id "
                     f"FROM waf.events {DET} ORDER BY ts DESC LIMIT 200")],
     "fieldConfig": {"defaults": {"custom": {"filterable": True, "cellOptions": {"type": "auto"}}}, "overrides": [
         ov("Ora", TS, ("custom.width", 170)), width("IP", 115), width("Sito", 70), width("Metodo", 65), width("Stato", 55),
         width("URL", 320),
         ov("Esito", BG, ("custom.width", 110), ("mappings", [{"type": "value", "options": {
             "BLOCK": {"text": "⛔ BLOCCATA", "color": "red", "index": 0},
             "ALLOW": {"text": "✅ consentita", "color": "green", "index": 1},
             "FAIL": {"text": "⚠ errore WAF", "color": "orange", "index": 2}}}])),
         ov("Causa", ("custom.cellOptions", {"type": "color-text"}), ("color", {"mode": "fixed", "fixedColor": "red"})),
         ov("request_id", ("custom.width", 95), ("links", [{"title": "Dettaglio richiesta",
            "url": "/d/waf-requests/waf-richieste?${__url_time_range}&var-rid=${__value.raw}", "targetBlank": True}]))]},
     "options": {"showHeader": True, "cellHeight": "sm"}}, 24, 10)

# Riga 6: come gestire gli IP
add({"type": "text", "title": "Come bloccare o sbloccare un IP", "datasource": None,
     "options": {"mode": "markdown", "content": """
**Bloccare** uno o più IP: scrivili (IP o CIDR, uno per riga) in `config/lists/custom-reputation.txt`
(crea la cartella se manca). Il WAF li carica entro 30 s e li blocca come la *AWSManagedIPReputationList*
(causa: *IP con cattiva reputazione*). Per sbloccarli togli la riga; per disattivare la lista svuota il file, non cancellarlo.

**Non bloccare mai** un IP (ufficio, monitoraggio, VPN aziendale): regola custom `allow` nel file del sito, es. `config/sites/odoo.yaml`:

```yaml
custom_rules:
  - name: AllowOffice
    slot: start
    action: allow
    match: {all: [{ip_set: [203.0.113.10/32, 192.168.10.0/24]}]}
```

**Bloccare interi paesi**: `geo_block: {countries: [CN, RU], action: block}` nel file del sito (serve `WAF_GEOIP=true` e i database in `data/geoip`).

Le modifiche a `config/sites/` sono applicate entro 10 s, senza riavvio. Controllo: `docker compose logs -f waf`.
"""}}, 24, 11)

dash = {
    "uid": "waf-ip", "title": "WAF IP", "tags": ["waf"], "schemaVersion": 39, "editable": True,
    "time": {"from": "now-24h", "to": "now"}, "refresh": "30s", "timezone": "browser", "graphTooltip": 1,
    "description": "Gestione degli IP client: bloccati, in parte bloccati, mai bloccati, con paese e provider (GeoIP).",
    "links": [{"type": "dashboards", "tags": ["waf"], "asDropdown": True, "title": "Altre dashboard WAF"}],
    "templating": {"list": [
        {"name": "site", "label": "Sito", "type": "query", "datasource": DS, "multi": True, "includeAll": True,
         "allValue": "'__all__'", "current": {"text": ["All"], "value": ["$__all"]}, "refresh": 2, "sort": 1,
         "query": "SELECT DISTINCT site_id FROM waf.agg_requests_1m WHERE minute > now() - INTERVAL 30 DAY ORDER BY site_id"},
        {"name": "stato", "label": "Stato IP", "type": "custom", "multi": True, "includeAll": True, "allValue": "'__all__'",
         "query": "Sempre bloccati : bloccato, In parte bloccati : misto, Mai bloccati : consentito",
         "current": {"text": ["All"], "value": ["$__all"]}, "options": []},
        {"name": "paese", "label": "Paese", "type": "query", "datasource": DS, "multi": True, "includeAll": True,
         "allValue": "'__all__'", "current": {"text": ["All"], "value": ["$__all"]}, "refresh": 2, "sort": 1,
         "query": f"SELECT DISTINCT {GEO_ROW} AS geo FROM waf.events WHERE $__timeFilter(ts) ORDER BY geo"},
        {"name": "ip", "label": "IP (anche parziale o CIDR)", "type": "textbox", "query": "",
         "current": {"text": "", "value": ""}},
    ]},
    "panels": panels,
}
with open(OUT, "w") as f:
    json.dump(dash, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"{OUT}: {len(panels)} pannelli")
