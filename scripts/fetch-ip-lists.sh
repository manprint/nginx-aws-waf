#!/usr/bin/env bash
# Approssima le liste IP (non pubbliche) dei rule group AWS con feed open.
# Output: data/ip-reputation/<lista>.txt, un IP/CIDR per riga (formato @ipMatchFromFile).
#
#   AWSManagedRulesAmazonIpReputationList
#     AWSManagedIPReputationList    <- Spamhaus DROP v4/v6, ET compromised, abuse.ch Feodo
#     AWSManagedReconnaissanceList  <- DShield top blocks, CINS Army
#     AWSManagedIPDDoSList          <- nessun feed pubblico equivalente (file vuoto)
#   AWSManagedRulesAnonymousIpList (non attivo di default su ALB, scaricato per completezza)
#     AnonymousIPList               <- Tor exit nodes
#
# Gli indirizzi privati/riservati vengono scartati: non devono mai bloccare il traffico di test locale.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/data/ip-reputation}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

fetch() { # url dest
  if ! curl -fsSL --retry 2 -m 60 "$1" -o "$2"; then
    echo "WARN  download fallito: $1" >&2; : > "$2"
  fi
}

fetch https://www.spamhaus.org/drop/drop_v4.json                   "$TMP/drop4.json"
fetch https://www.spamhaus.org/drop/drop_v6.json                   "$TMP/drop6.json"
fetch https://rules.emergingthreats.net/blockrules/compromised-ips.txt "$TMP/et.txt"
fetch https://feodotracker.abuse.ch/downloads/ipblocklist.txt      "$TMP/feodo.txt"
fetch https://feeds.dshield.org/block.txt                          "$TMP/dshield.txt"
fetch https://cinsscore.com/list/ci-badguys.txt                    "$TMP/cins.txt"
fetch https://check.torproject.org/torbulkexitlist                 "$TMP/tor.txt"

# Normalizzazione: estrai CIDR/IP, valida, dedup, scarta reti non globali.
normalize() { # out_file label in_files...
  local out="$1" label="$2"; shift 2
  python3 - "$out" "$label" "$@" <<'PY'
import ipaddress, json, re, sys, datetime
out, label, files = sys.argv[1], sys.argv[2], sys.argv[3:]
nets = set()
for f in files:
    for line in open(f, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("{"):                       # Spamhaus JSON lines
            try: cand = json.loads(line).get("cidr")
            except ValueError: continue
        elif "\t" in line:                             # DShield: start end prefix ...
            p = line.split("\t")
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]): continue
            cand = f"{p[0]}/{p[2]}"
        else:
            cand = line.split()[0]
        if not cand: continue
        try: n = ipaddress.ip_network(cand, strict=False)
        except ValueError: continue
        if not n.is_global: continue
        nets.add(n)
nets = sorted(nets, key=lambda n: (n.version, n))
with open(out, "w") as fh:
    fh.write(f"# {label} - generato {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%dT%H:%MZ} - {len(nets)} voci\n")
    for n in nets:
        fh.write((str(n.network_address) if n.num_addresses == 1 else str(n)) + "\n")
print(f"ok    {out.rsplit('/',1)[-1]:<36} {len(nets):>7} voci")
PY
}

normalize "$OUT/AWSManagedIPReputationList.txt"   "AWSManagedIPReputationList (approx)"   "$TMP/drop4.json" "$TMP/drop6.json" "$TMP/et.txt" "$TMP/feodo.txt"
normalize "$OUT/AWSManagedReconnaissanceList.txt" "AWSManagedReconnaissanceList (approx)" "$TMP/dshield.txt" "$TMP/cins.txt"
normalize "$OUT/AnonymousIPList.txt"              "AnonymousIPList (approx, Tor)"         "$TMP/tor.txt"
echo "# AWSManagedIPDDoSList - nessun feed pubblico equivalente" > "$OUT/AWSManagedIPDDoSList.txt"
echo "ok    AWSManagedIPDDoSList.txt (vuoto)"

# Lista manuale per i test (versionata, non sovrascritta).
[ -f "$OUT/custom-test.txt" ] || cat > "$OUT/custom-test.txt" <<'EOF'
# IP aggiunti a mano per testare le regole di reputazione (trattati come AWSManagedIPReputationList).
# Esempio: rete di documentazione TEST-NET-3, usabile con X-Forwarded-For nei test.
203.0.113.0/24
EOF
