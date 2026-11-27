#!/bin/sh
# Scarica i database GeoIP gratuiti DB-IP Lite (paese + ASN), senza account.
# Licenza CC BY 4.0: "IP Geolocation by DB-IP" (https://db-ip.com).
# Salvati con i nomi attesi da WAF e Vector: GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb
set -eu
OUT=/geoip
mkdir -p "$OUT"
this=$(date -u +%Y-%m)
prev=$(date -u -d "@$(( $(date +%s) - 32 * 86400 ))" +%Y-%m)   # all'inizio del mese il file nuovo può mancare

get() { # tipo destinazione
	for m in "$this" "$prev"; do
		url="https://download.db-ip.com/free/dbip-$1-lite-$m.mmdb.gz"
		if curl -sSfL --retry 2 -m 300 "$url" -o "/tmp/$1.gz"; then
			gunzip -c "/tmp/$1.gz" >"$OUT/$2.tmp"
			mv "$OUT/$2.tmp" "$OUT/$2"
			echo "ok  $2  ($(du -h "$OUT/$2" | cut -f1), DB-IP $m)"
			return 0
		fi
	done
	echo "ERRORE: download di $1 fallito" >&2
	return 1
}

get country GeoLite2-Country.mmdb
get asn GeoLite2-ASN.mmdb
echo "fatto. Ora: docker compose restart metrics   (e waf, se usi WAF_GEOIP=true)"
