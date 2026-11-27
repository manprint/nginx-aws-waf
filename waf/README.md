# waf/ — motore WAF (catalogo, pattern, pagine)

## Catalogo `catalog/rules.yaml`
Unica fonte di verità delle regole (rendering, documentazione, export AWS, test).
L'ordine dei gruppi e delle regole è l'ordine di valutazione AWS.

Campi per gruppo: `key` (iprep, anonip, crs, kbi, sqli), `name` (nome AWS), `vendor`,
`wcu`, `label_ns` (prefisso delle label AWS), `optional` (true = disattivo salvo
`enabled: true` nella config del sito), `rules`.

Campi per regola:
| Campo | Significato |
|---|---|
| `id` | ID base B della regola (multiplo di 10) |
| `name` | nome AWS (usato in `rule_action_overrides`) |
| `label` | suffisso label; label completa = `label_ns + label` |
| `default_action` | `block` o `count` (azione predefinita AWS) |
| `fidelity` | `exact` (logica documentata), `approx` (pattern AWS non pubblici), `stub` (nessun detector) |
| `detectors` | lista di catene (max 7); ogni catena è una lista di link `{vars, op, t}` in AND; le catene sono in OR |

## Schema ID ModSecurity
| ID | Uso |
|---|---|
| 11000xx / 14500xx / 12000xx / 13000xx / 14000xx | gruppi iprep / anonip / crs / kbi / sqli |
| 14100xx / 14200xx / 14300xx / 14400xx / 14600xx / 14700xx | gruppi opzionali admin / linux / unix / windows / php / wordpress |
| `B+0..B+6` | detector della regola |
| `B+7` | regola label (setta la label se un detector ha fatto match) |
| `B+8` | candidato terminante (azione effettiva) |
| `B+9` | esito AWS-default (solo regole non opzionali con default block) |
| `1G00001` | skip del gruppo (`SecMarker END_GRP_<KEY>`) |
| `1500000 + siteIdx*1000 + ruleIdx*10` | custom rule |
| `1600000 + siteIdx*1000 + groupIdx*10` | scope-down |
| `1700000 + siteIdx*100 + i` | path override |
| 1900001–1900099 | engine |
| `1910000 + siteIdx*10 + k` | variabili di sito |
| 1900800–1900930 | evaluator finale (SUMMARY, FAIL, BLOCK, DEFAULT_BLOCK) |

`siteIdx` = indice nella lista ordinata dei site_id (max 100 siti per nodo).

## `data/`
Un pattern per riga, senza commenti né righe vuote:
- `bad-bots.data` — user agent di scanner (da CRS `scanners-user-agents.data`);
- `ec2-metadata.data` — endpoint metadata cloud (SSRF);
- `lfi-targets.data` — file sensibili (LFI).

## `static/`
`403.html` e `500.html`: corpo identico alle risposte di default AWS (CRLF).
