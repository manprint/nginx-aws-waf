# Tuning delle regole

Obiettivo: arrivare a un sito in `enforce` senza falsi positivi, restando se possibile
**aws-compatible** (stessa configurazione riproducibile su AWS WAF).

## Flusso consigliato

1. **Shadow.** Nuovo sito con `profile: shadow` (tutte le regole in Count). Le richieste passano,
   ma ogni match finisce nell'audit log e negli eventi (`action` = `ALLOW`, `shadow_action` =
   cosa avrebbe fatto AWS).
2. **Statistiche.** Dopo un periodo di traffico reale guardare quali regole matchano
   (`.run/raw/<giorno>/matches.jsonl` ora, `wafctl stats` e Grafana dalla fase 3).
   Per riprodurre una richiesta: `wafctl test request --site <id> --path '…' -H 'K: V' --data '…'`.
3. **Count mirato + label rule.** Per ogni falso positivo scegliere la correzione più stretta:
   - `rule_action_overrides: {Regola: count}` sul gruppo;
   - più una **custom rule su label** che blocca ancora fuori dal caso legittimo
     (`label` + condizione negata), come fa AWS;
   - oppure `scope_down` sul gruppo, se un intero percorso non va ispezionato.
4. **Enforce.** Togliere `profile: shadow` (o impostare `mode: enforce`), `wafctl diff`, `wafctl apply`.

`path_overrides` è comodo ma **nginx-only**: preferire la coppia count + label rule.

## Esempi dai siti di lab (`lab/config/sites/`)

| Sito | Tecnica | Effetto |
|---|---|---|
| `tuned` | `SizeRestrictions_BODY: count` + custom rule `BlockLargeBodyOutsideRpc` (label + path negato) | body > 8 KB ammessi solo su `/web/dataset/` (RPC Odoo), bloccati altrove |
| `tuned` | `scope_down` su KnownBadInputs con `uri_path starts_with /static-ok/` negato | il gruppo non valuta `/static-ok/…` |
| `tuned` | `body_limit: 16384` | ispezione dei primi 16 KB (aws-compatible) |
| `tuned` | `path_overrides` `/files/` → `RestrictedExtensions_URIPATH: count` | nginx-only |
| `allowlist` | `default_action: block` + `AllowPublic` (slot `start`) | solo `/public/` passa |
| `shadow` | `profile: shadow` | tutto in Count |
| `strict` | `profile: strict` | aggiunge SQLi e AnonymousIp |

## Strumenti

| Comando | Uso |
|---|---|
| `wafctl explain <sito> [--format json]` | tabella `GROUP RULE DEFAULT EFFECTIVE ORIGIN FIDELITY` (da dove viene ogni azione: default, profilo, sito, bypass), scope-down, custom rule in ordine di valutazione, impostazioni, riga di compatibilità |
| `wafctl diff` | differenze fra la config attiva (`runtime/current`) e quella che verrebbe renderizzata; exit 1 se diverse |
| `wafctl apply [--dry-run]` | valida, renderizza una nuova rev, `nginx -t`, attiva e ricarica; se qualcosa fallisce la config attiva non cambia |
| `wafctl test run --suite tests/corpus` | regressione: ogni caso verifica stato HTTP, regola terminante e match |

## Bypass temporaneo

Per un'emergenza (falso positivo bloccante in produzione) senza toccare la configurazione:

```bash
wafctl bypass <sito> --ttl 30m --reason "ticket 123"   # sito in Count fino alla scadenza (1m–72h)
wafctl bypass list
wafctl bypass clear <sito>                              # torna subito in enforce
```

Lo stato è in `$WAF_CONFIG_DIR/state/bypass.yaml`; il timer systemd `wafctl-bypass-expire.timer`
(ogni minuto) rimuove i bypass scaduti e riapplica. Durante il bypass gli eventi hanno
`waf_mode = count` e `explain` mostra l'origine `bypass`.
