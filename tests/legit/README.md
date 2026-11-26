# Flussi legittimi Odoo (Playwright)

Flussi reali di un utente Odoo che passano dal WAF: nessuno deve essere bloccato.

```sh
make lab-up        # stack Odoo 12/14/16/18
make lab-legit     # = tests/legit/run.sh shop12,shop14,shop16,shop18
```

- Gira nel container `mcr.microsoft.com/playwright:v1.65.1-noble` (servizio `playwright`,
  profilo `tools`, `deploy/compose/lab-tools.yml`) sulla rete `waf_lab`. I nomi
  `shopNN.lab.test` sono alias di rete del container WAF (porta 8080).
- Ogni richiesta porta `X-Waf-Test: <RUN_ID>-legit`; l'ultima riga di `run.sh` è
  `RUN_ID=<id>`. Verifica sugli eventi (T-LEG1, atteso 0):

  ```sh
  jq -c --arg h "$RUN_ID-legit" 'select(.action=="BLOCK" and any(.request_headers|to_entries[]; (.key|ascii_downcase)=="x-waf-test" and .value==$h))' .run/raw/*/events.jsonl | wc -l
  ```
- `wafGuard` (helpers.ts) fallisce il test se una risposta è 403/500 con `Server: awselb/2.0`.

| Spec | Flusso |
|---|---|
| `backend.spec.ts` | login, Contatti, pipeline CRM, logout |
| `rpc.spec.ts` | JSON-RPC: partner con 40 KB di HTML, write, search_read con "select", allegato 200 KB, messaggio chatter con `<script>` |
| `website.spec.ts` | `/`, `/shop`, `/contactus`, invio modulo contatti (testo con "UNION … DROP" e URL), avatar |

Differenze per versione (gestite negli helper/spec):
- Odoo 18 ignora gli URL `/web#…`: si usano `/odoo/contacts` e `/odoo/crm`.
- Odoo 12 non ha figli in `.o_action_manager`: l'attesa della vista usa anche `.o_content`.
- Modulo contatti: `/website_form/` (12/14) o `/website/form/` (16/18).
- Le viste backend tengono aperto il long-polling/bus: non si usa `networkidle`.

Dipendenze: `@playwright/test` 1.65.1 esatto, `package-lock.json` committato.
