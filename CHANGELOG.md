# Changelog

## Non rilasciato

### Protezione per tipo di sito
- Sei nuovi gruppi opzionali nel catalogo, dai rule group AWS "use-case"/"OS":
  AdminProtection, Linux, Unix (POSIX), Windows, PHP, WordPress (25 regole, fidelity `approx`;
  ID 1410000–1470099). Nuovo file dati `waf/data/linux-lfi.data`.
- Nuovi profili: `web-common` (base per qualunque sito), `php`, `wordpress`, `static`, `api`,
  `aspnet`. Bloccano anche file riservati (`.env`, `.git`, backup), sonde degli scanner, webshell,
  phpMyAdmin, enumerazione utenti WordPress. Tutto disattivabile per sito.
- `app: wordpress`: classificazione `user_class` (backend/api/static/website) nella pipeline Vector.
- `rule_groups[].enabled: false` spegne senza avvisi un gruppo abilitato da un profilo padre.
- Scope-down: ID `1600000 + siteIdx·1000 + groupIdx·10` (prima `·100`, bastava per < 10 gruppi).
- Stack Odoo: `waf_causa` descrive in italiano le nuove regole.
- Profilo `odoo-common`: `BlockSensitiveFiles`, `BlockScannerProbes` e `OdooBlockScriptProbes`
  (script PHP/ASP/JSP e percorsi WordPress) in count, da portare a block dopo la verifica.
- Corpus `tests/corpus/profiles.yaml` (siti di lab `p-<profilo>`).

## 0.1.0 — 27-11-2026

Prima versione completa (piano 001). Riproduce la web ACL AWS WAF "one-click" per ALB su nginx +
libmodsecurity v3, con laboratorio di tuning, osservabilità, multi-nodo ed export verso AWS.

### Fondamenta (fase 0)
- Catalogo regole `waf/catalog/rules.yaml`, fonte unica per render, documentazione, export e
  test. Contiene IpReputation, AnonymousIp, CommonRuleSet, KnownBadInputs e SQLi, con fidelity
  per regola.
- File dati dei pattern e pagine 403/500 uguali a quelle dell'ALB.
- `wafctl` (Go): schema di configurazione (`node.yaml`, `sites/`, profili con `extends`),
  merge default ← profilo ← sito ← bypass, validazione, classificazione `aws-compatible` /
  `nginx-only`.

### Motore (fase 1)
- Render di `main.conf` (detector → label → evaluator, first-wins come AWS) e dei file per sito.
- Override per regola (Count/Block/Allow), override di gruppo, scope-down, label rule, custom
  rule negli slot `start` / `after:<gruppo>`, path override, geo block, rate limit (`limit_req`).
- Immagine del motore, compose del nodo (host/bridge) e stack `lab-min`.
- `wafctl apply`: `nginx -t` in staging, swap atomico con rollback. Anche `diff`, `explain` e
  `bypass` con TTL (timer systemd).
- Test runner con corpus YAML. Pipeline Vector del nodo: access log + audit uniti in un evento
  JSON per richiesta. Rotazione dei log.
- Benchmark D29: GET ≥ 3500 req/s, POST ≥ 3000 req/s, p99 ≤ 5 ms.

### Laboratorio Odoo (fase 2)
- Odoo Community 12/14/16/18 con Postgres, flussi legittimi Playwright, nuclei + nikto, matrice
  di lab.
- Profili `odoo-12|14|16|18` aws-compatible (Count + label rule fuori dai prefissi ammessi).

### Storage centrale (fase 3)
- ClickHouse + Vector centrale con arricchimento GeoIP/ASN e heartbeat dei nodi.
- `wafctl logs search|show|tail|export` (formato log AWS WAF, CSV, JSONL), `wafctl stats`,
  `wafctl report --html` autocontenuto, retention e migrazioni (`wafctl ch`).

### Dashboard e alert (fase 4)
- Prometheus (metriche di nginx, host e Vector per nodo).
- Grafana con 4 dashboard (Overview, Rules & Tuning, Request Explorer, Nodes Health) e 5 alert.
  Le notifiche passano da apprise (Slack, Google Chat, Telegram, …).
- `wafctl central render`, `wafctl grafana user`.

### Multi-nodo (fase 5)
- PKI propria (ECDSA P-256, CA 10 anni, certificati foglia 90 giorni) con `wafctl pki`.
- Ingress mTLS sul centrale (nginx stream + CRL), forwarding TLS dai nodi.
- Enrollment con token monouso, rinnovo automatico (timer), revoca immediata.
- `wafctl node bootstrap`, `install-node.sh`, tarball di release, scheletro Terraform AWS
  (EC2, security group, user-data).

### Export AWS, funzioni opzionali, liste, accettazione (fase 6)
- Test end to end di SQLi, AnonymousIp, rate limit (block e count, `RATE_BASED` in ClickHouse)
  e geo block (IPv4 e IPv6).
- `wafctl export-aws` in JSON (CreateWebACL + CreateIPSet) e Terraform, con elenco delle
  funzioni `lossy`. Validazione offline con la AWS CLI (`scripts/aws-validate-acl.sh`) e con
  `terraform validate` (`scripts/tf-validate-export.sh`). Vedi [docs/aws-export.md](docs/aws-export.md).
- `wafctl lists update`: aggiornamento delle liste IP con protezione dai download falliti (50 %)
  e validazione delle righe. Timer `wafctl-lists` e `wafctl-geoip` (MaxMind GeoLite2).
- `make final-check`: scenario di riferimento G-FINAL in 8 passi.

### Correzioni in fase 6
- `@ipMatch`: i prefissi a lunghezza piena (`/32`, `/128`) ora sono scritti come indirizzo
  semplice. libmodsecurity 3 rifiuta `/128` e `nginx -t` falliva.
- Vector del nodo: `max_read_bytes` alzato a 1 MiB. Le righe di audit con body grandi
  ritardavano gli eventi di circa 7 s. Ora l'evento arriva in ClickHouse entro 3–5 s.
