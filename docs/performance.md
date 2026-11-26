# Prestazioni del nodo WAF

Obiettivo D29 (piano 001): sul lab, con 2 worker nginx, ruleset completo, audit log completo
(corpi inclusi) su volume bind-mount e `oha -c 8` per 10 s:

| Caso | Soglia req/s | Soglia p99 |
|---|---|---|
| GET `/web/login?redirect=%2Fweb` | ≥ 3500 | ≤ 5 ms |
| POST `/web/dataset/call_kw`, JSON-RPC 353 B (`tests/bench/rpc.json`) | ≥ 3000 | ≤ 5 ms |

## Metodo

```bash
source scripts/lab-env.sh
make lab-min-up            # nodo + echo + vector
scripts/bench.sh           # [--target URL] [--host NAME]; exit 1 se una soglia fallisce
```

`scripts/bench.sh` lancia `oha -z 10s -c 8 --no-tui` per i due casi e stampa una riga CSV
`date,commit,case,rps,p50_ms,p99_ms,waf_rss_mb` (RSS da `docker stats` del container `waf-waf-1`,
variabile `WAF_CONTAINER` per cambiarlo). Exit 3 se `oha` manca.

## Risultati (26-11-2026, commit 6cb1879, mediana di 3 run)

Hardware: Intel Core 7 240H, 16 core (`nproc`), 46 GB RAM (`free -g`); Docker bridge
(`waf_lab`), upstream `echo` (nginx `return 200`), Vector attivo sullo stesso host.

| Caso | req/s | p50 ms | p99 ms | RSS waf MB |
|---|---|---|---|---|
| GET | 6101 | 1.27 | 2.32 | 46.6 |
| POST JSON-RPC | 5282 | 1.47 | 2.75 | 50.1 |

Run singoli: GET 6109/5932/6101 req/s (p99 2.32/2.65/2.32 ms); POST 5163/5384/5282 req/s
(p99 3.38/2.53/2.75 ms). Tutte le soglie D29 rispettate con margine (prototipo R8: GET 4890,
POST 4231 req/s).

## Note

- **Audit log su bind mount.** Con l'audit log nel filesystem overlay del container il p99
  sale a circa 57 ms (R8, ×10 più lento). `deploy/compose/node.yml` monta sempre
  `${WAF_DATA_DIR}/logs` su `/var/log/waf`: non spostarlo.
- **Volume di log.** Con corpi registrati, 10 s di benchmark scrivono centinaia di MB di
  audit log; `wafctl logs rotate` (timer orario) ruota sopra 512 MiB.
- Se il risultato scende sotto soglia: controllare `docker stats`, che i log siano su bind
  mount e che `worker_processes` sia 2 nel `nginx.conf` renderizzato.
