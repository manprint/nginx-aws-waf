# Phase 5 — Multi-node: PKI, mTLS ingest with CRL, enrollment/renewal, node bootstrap, Terraform skeleton

Intent:
- A second node (lab: compose project `waf2`, `lab-node-2`) enrolls with a one-time token and forwards its events over mTLS to the central ingress, where they land in ClickHouse.
- Revoking its certificate stops ingest after the CRL is reloaded.
- Certificates auto-renew 30 days before expiry.
- `wafctl node bootstrap` prepares a fresh Ubuntu node.
- A Terraform skeleton passes `terraform validate`.

Prerequisites: P3 DONE (P4 recommended for the node-silent alert).
Phase closure: P5; review by agent-1.

## State and ownership contract
Read STATE.md §1 first (and PROTOCOL.md once without this skill) for scope, ownership, recovery, checks and commit rules. Open a unit before editing; checkpoint at a recovery boundary; close with evidence. Missing design goes to agent-1, the supervisor. Executor power: low. Follow the steps literally. Crypto parameters are fixed here; do not change them.

## Local design context
Plan revision: rev 1.
- **D26:** PKI in Go, ECDSA P-256, CA 10 y, leaf 90 d, renew at < 30 d, nginx stream mTLS with `ssl_crl`.
- **R10 (new, verified 26-11-2026):** `snippets/ingress-stream-probe.conf`. Vector 0.62 `vector` sink with `tls {crt_file, key_file, ca_file, verify_hostname: true}` → nginx stream `ssl_alpn h2` + `ssl_verify_client on` + `ssl_crl` → plain Vector `vector` source. A valid client is accepted; a revoked one is rejected (`certificate revoked`). **An expired CRL makes nginx reject every client**, so the CRL is valid for 7 d and regenerated daily.
- **I-8:** keys never committed. The CA key lives only on the central host, mode 0600.

### PKI layout (`$WAF_PKI_DIR`, default `$WAF_CONFIG_DIR/pki`; central role only)
```
ca.pem                     CA certificate
private/ca.key             PKCS#8 PEM, 0600 (dir 0700)
issued/<serial-hex>.pem    every issued leaf
index.json                 [{serial, cn, kind: client|server, not_before, not_after, revoked_at|null, renewed_by|null}]
crl.pem                    CRL v2, this_update=now, next_update=now+7d, number = monotonically increasing (index.json "crl_number")
tokens.json                [{sha256, cn, expires, used_at|null}]
```
Crypto parameters:
- **CA:** subject `CN=nginx-aws-waf CA <name>`, `IsCA`, `MaxPathLenZero`, KeyUsage `CertSign|CRLSign`, validity 10 y.
- **Leaf:** 90 d, `NotBefore = now − 5 min`, KeyUsage `DigitalSignature`.
  - client: EKU `ClientAuth`, `CN=<node_id>`, SAN DNS `<node_id>`;
  - server: EKU `ServerAuth`, SANs from flags.
- **Serial:** 128-bit random.
- **CRL:** `x509.CreateRevocationList`.
- **Locking:** every write takes an exclusive flock on `index.json.lock`.

Commands (central):
- `wafctl pki init --name N`: refuses to run if `ca.pem` exists.
- `wafctl pki issue --cn CN --kind client|server [--dns D]… [--ip I]… [--out DIR]`: writes `<cn>.pem`, `<cn>.key` and `ca.pem`.
- `wafctl pki revoke <serial|cn>`: revokes, regenerates the CRL, and runs `docker compose … exec ingress nginx -s reload` if ingress is running.
- `wafctl pki list [--format]`: columns `SERIAL CN KIND NOT_AFTER STATUS(valid|expiring|expired|revoked)`.
- `wafctl pki crl`: regenerates and reloads; run by the daily timer.
- `wafctl pki token --cn CN [--ttl 24h]`: prints `token=<32 random bytes base64url>` and `ca_sha256=<hex sha256 of the CA DER>`. Only the sha256 of the token is stored.
- `wafctl pki serve [--addr :6001]`: see 5.3.

Central config additions (`central.yaml`):
```yaml
ingress: {bind: "0.0.0.0", ingest_port: 6000, pki_port: 6001, server_names: [central.example.com], server_ips: []}
```
`wafctl central render` writes `$WAF_CENTRAL_DIR/ingress/nginx.conf` (snippet shape, with these paths: certs `/etc/waf/pki/{ingress.pem,ingress.key,ca.pem,crl.pem}`; `proxy_pass vector-central:6000`; `proxy_connect_timeout 5s`; `proxy_timeout 10m`; `error_log /dev/stderr notice`). It also issues the server cert `ingress` (SANs = server_names + server_ips + `ingress`) into `$WAF_CENTRAL_DIR/ingress/certs/` if missing or expiring in under 30 d.

### Node side
- `node.yaml central: {address: central.example.com, ingest_port: 6000, pki_port: 6001}` (exists since P0).
- Node certs live in `$WAF_DATA_DIR/certs/_node/{node.pem,node.key,ca.pem}`. `_node` is reserved; validation rejects site_id `_node` (it already fails the site regex).
- Rendered `forward.yaml` for role node with an address:
  ```yaml
  sinks:
    fwd_central:
      type: vector
      inputs: [fwd_events, fwd_matches, fwd_hb, m_tag]
      address: "<address>:<ingest_port>"
      tls: {enabled: true, crt_file: /etc/waf/certs/_node/node.pem, key_file: /etc/waf/certs/_node/node.key, ca_file: /etc/waf/certs/_node/ca.pem, verify_hostname: true}
      buffer: {type: disk, max_size: 2147483648, when_full: block}
  ```
  The vector service mounts `${WAF_DATA_DIR}/certs/_node:/etc/waf/certs/_node:ro`.
- Commands:
  - `wafctl node enroll --token T --ca-sha256 H [--central host:pki_port]`:
    1. Fetches `https://<central>/ca` with `InsecureSkipVerify` and compares the sha256 of the returned DER with H (pinning). Mismatch → abort.
    2. Generates the key locally (0600).
    3. Builds a CSR with CN = node_id.
    4. Sends `POST /enroll` `{token, csr}`, writes node.pem and ca.pem, then restarts vector.
  - `wafctl node renew [--force]`: if node.pem expires in under 30 d (or `--force`), new key + CSR → `POST /renew` over mTLS with the current cert → swap files atomically (write `.new` + rename) → restart vector. Daily timer.

### `pki serve` HTTP API (TLS with the `ingress` server cert; `ClientAuth: VerifyClientCertIfGiven` against the CA pool)
| Method/path | Auth | Request | Response |
|---|---|---|---|
| GET /ca | none | — | `ca.pem` |
| POST /enroll | token | `{"token": "...", "csr": "<PEM>"}` | 200 `{"cert": "<PEM>", "ca": "<PEM>"}`; 403 on a bad/used/expired token or a CN mismatch |
| POST /renew | client cert (not revoked, not expired) | `{"csr": "<PEM>"}`, CSR CN == cert CN | 200 `{"cert", "ca"}`; the old serial gets `renewed_by` (not revoked: it expires naturally) |
| GET /healthz | none | — | `ok` |

Rate limit: 10 requests/min per IP (in-memory token bucket); 429 otherwise. The serve process runs on the central host as systemd `wafctl-pki.service` (`Restart=always`), not in Docker, so the CA key never enters a container. In the lab it runs as a background process started by the e2e script.

### Lab second node
- Config `lab/config-node2/`:
  - `node.yaml`: node_id `lab-node-2`, role node, network bridge, `listen {http: 18080, https: 18443}`, `central.address: ingress`, `lab.enabled: true`;
  - `sites/demo.yaml`: a copy of the lab demo site.
- Data dir `.run2/`. Compose project `waf2`, set via a new env `WAF_COMPOSE_PROJECT` read by `docker.Compose`.
- `node.bridge.yml` ports become `"${WAF_HTTP_PORT}:${WAF_HTTP_PORT}"` and `"${WAF_HTTPS_PORT}:${WAF_HTTPS_PORT}"`, exported by wafctl from the listen ports. The network `waf_lab` is declared `external: true` when `WAF_COMPOSE_PROJECT` ≠ `waf`. Implement this with an extra file `node.bridge-ext.yml` that redefines the network as external; wafctl picks it when the project ≠ `waf`.

## Sub-phases

### 5.1 PKI core
- **Agent:** agent-1
- **Assignment:** implement; self-review (security-sensitive: check modes, randomness, the EKUs).
- **Files:** NEW: `wafctl/internal/pki/{ca.go,issue.go,crl.go,index.go,token.go,pki_test.go}`. WRITE: `cmd/wafctl/main.go`.
- **Change:**
  - Preconditions: P3 DONE.
  - Contract: as in the PKI layout. Uses stdlib `crypto/ecdsa`, `crypto/x509`, `crypto/rand` only.
  - Steps:
    1. S1 — CA init + index with flock (`syscall.Flock`).
    2. S2 — Issue + list.
    3. S3 — Revoke + CRL.
    4. S4 — Tokens.
- **Unit tests** (in a temp dir):
  - T-PKI1: init → ca.pem parses, IsCA, the key file mode is 0600;
  - T-PKI2: a client cert verifies against the CA with `ExtKeyUsageClientAuth` and fails `ServerAuth`;
  - T-PKI3: revoke → the CRL contains the serial, next_update ≈ +7 d, and the number increments;
  - T-PKI4: a token is single-use and expires (an injected clock);
  - T-PKI5: init twice → error.
  - G-U51.
- **e2e tests:** `openssl verify -CAfile ca.pem node.pem` OK; `openssl crl -in crl.pem -noout -text` lists the revoked serial. G-U51.
- **Done:** G-U51 passes.

### 5.2 Central ingress + TLS forwarding
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - READ: `snippets/ingress-stream-probe.conf`.
  - NEW: `wafctl/internal/central/ingress.go`, `deploy/systemd/{wafctl-pki-crl.service,wafctl-pki-crl.timer}`, `deploy/compose/node.bridge-ext.yml`, `lab/config-node2/{node.yaml,sites/demo.yaml}`, `tests/e2e/multinode.sh` (first part; the script takes an optional argument `part1` that runs only part 1).
  - WRITE: `deploy/compose/central.yml` (service `ingress`: D1 image, entrypoint `nginx -g 'daemon off;' -c /etc/waf/ingress/nginx.conf`, volumes `${WAF_CENTRAL_DIR}/ingress/nginx.conf:/etc/waf/ingress/nginx.conf:ro` and `${WAF_CENTRAL_DIR}/ingress/certs:/etc/waf/pki:ro`. The `certs` dir holds only `ingress.pem`, `ingress.key`, `ca.pem` and `crl.pem`, copied by render; the CA key is never copied or mounted. Ports `${INGRESS_BIND}:6000:6000`; vector-central loses its published 6000 for role central, but keeps `127.0.0.1:6000` for all-in-one host mode), `wafctl/internal/docker/docker.go` (`WAF_COMPOSE_PROJECT`, port env), `wafctl/internal/render/vector.go` (TLS forward), `deploy/compose/node.yml` (cert mount), `deploy/compose/node.bridge.yml` (port env), `lab/config/central.yaml` (ingress server_names `[ingress, central.lab.test]`).
- **Change:**
  - Preconditions: 5.1 DONE.
  - Contract:
    - as in Local design;
    - `pki crl` (and `revoke`) also copies `crl.pem` into `$WAF_CENTRAL_DIR/ingress/certs/` before the reload;
    - timer: `OnCalendar=daily`, `Persistent=true`, `ExecStart=/usr/local/bin/wafctl pki crl`.
  - Steps:
    1. S1 — Ingress render + compose.
    2. S2 — Node TLS forward render.
    3. S3 — Project/port env.
    4. S4 — e2e part 1: issue a client cert for lab-node-2 manually (`pki issue --kind client --cn lab-node-2 --out .run2/certs/_node`), start node2 with `WAF_CONFIG_DIR=lab/config-node2 WAF_DATA_DIR=$PWD/.run2 WAF_COMPOSE_PROJECT=waf2 wafctl apply`, run 20 requests on :18080, and expect `SELECT count() FROM waf.events WHERE node_id='lab-node-2'` ≥ 20 within 15 s.
  - Failure handling:
    - a TLS handshake error → compare against the snippet (`ssl_alpn h2`, SAN `ingress`);
    - stream module directives are rejected → run `nginx -V` in the image and read the error. The R10 probe used the same image.
- **Unit tests:** T-ING1: the ingress nginx.conf render is golden; T-FWD1: forward.yaml for role node includes tls. G-U52.
- **e2e tests:** multinode part 1 (T-MN1). G-U52.
- **Done:** G-U52 passes.

### 5.3 Enrollment, renewal, revocation flow
- **Agent:** agent-1
- **Assignment:** implement; self-review (security).
- **Files:**
  - NEW: `wafctl/internal/pki/{serve.go,serve_test.go}`, `wafctl/internal/node/{enroll.go,renew.go,node_test.go}`, `deploy/systemd/{wafctl-pki.service,wafctl-node-renew.service,wafctl-node-renew.timer}`.
  - WRITE: `cmd/wafctl/main.go`, `tests/e2e/multinode.sh` (part 2).
- **Change:**
  - Preconditions: 5.2 DONE.
  - Contract: the HTTP API table above. Client requests have a 15 s timeout. Renew timer: `OnCalendar=daily`, `RandomizedDelaySec=1h`.
  - Steps:
    1. S1 — The serve handlers + rate limit.
    2. S2 — Node enroll/renew.
    3. S3 — The systemd units.
    4. S4 — e2e part 2.
  - e2e part 2 (`multinode.sh`):
    1. `rm -rf .run2/certs/_node`.
    2. Start `wafctl pki serve --addr 127.0.0.1:6001 &`. In the lab the node container is not involved: enrollment runs on the host, with `--central 127.0.0.1:6001`. The ingress cert includes IP SAN 127.0.0.1 in the lab central.yaml `server_ips: [127.0.0.1]`.
    3. `T=$(wafctl pki token --cn lab-node-2)`, then `wafctl node enroll` with the token and ca_sha256 (T-MN2).
    4. Traffic → events from node 2 (T-MN2).
    5. Reuse the token → 403 (T-MN3).
    6. `wafctl node renew --force` → a new serial is in `pki list`, the old one shows renewed, and traffic still flows (T-MN4).
    7. `wafctl pki revoke lab-node-2` (the current serial).
    8. Send 20 requests on node 2, wait 20 s, and expect no new events after the revoke timestamp (T-MN5). The node2 vector log contains handshake or broken-pipe errors.
    9. Clean up by issuing a fresh cert so the lab keeps working.
- **Unit tests:**
  - T-SRV1: enroll with a valid token returns a cert whose CN equals the token CN;
  - T-SRV2: a CN mismatch → 403;
  - T-SRV3: renew without a client cert → 401; with a revoked cert → 403;
  - T-SRV4: the rate limiter returns 429 on the 11th request;
  - T-ND1: renew skips when > 30 d remain.
  - G-U53.
- **e2e tests:** multinode part 2. G-U53.
- **Done:** G-U53 passes.

### 5.4 Node bootstrap and installation
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `wafctl/internal/node/bootstrap.go`, `wafctl/internal/node/templates/{gitignore,node.yaml.tmpl,default-wafctl}`, `scripts/install-node.sh`, `scripts/build-release.sh`, `tests/e2e/bootstrap.sh`.
  - WRITE: `cmd/wafctl/main.go`, `Makefile` (`release`).
- **Change:**
  - Preconditions: 5.3 DONE.
  - Contract:
    - `wafctl node bootstrap --node-id ID --role node|central|all-in-one [--central HOST] [--network host|bridge] [--install-systemd]`:
      1. Creates `$WAF_CONFIG_DIR` with `git init`, `.gitignore` (template: `state/`, `secrets.env`, `pki/private/`, `pki/tokens.json`, `*.key`, `apprise-urls.txt`), `node.yaml`, `sites/README.md`, `profiles/` and, for central roles, `central.yaml`.
      2. Runs `secrets init`.
      3. Creates the `$WAF_DATA_DIR` subdirs.
      4. With `--install-systemd` (root required): copies `$WAF_HOME/deploy/systemd/*` to `/etc/systemd/system/`, writes `/etc/default/wafctl` (`WAF_HOME`, `WAF_CONFIG_DIR`, `WAF_DATA_DIR`), runs `systemctl daemon-reload`, and enables the timers for the role:
         - node: bypass-expire, logs, node-renew;
         - central: pki-crl, pki;
         - all-in-one: all except node-renew.
      5. Makes the first git commit `bootstrap <node_id>`.
      6. Prints next steps.

      It refuses to run if `node.yaml` exists, unless `--force`.
    - `scripts/install-node.sh` (Ubuntu 22.04/24.04, run as root):
      1. Checks `docker compose version`; if missing, prints the Docker install URL and exits 1 (it does not install Docker itself).
      2. Copies the release tarball contents to `/opt/nginx-aws-waf` (`WAF_HOME`) and links `wafctl` into `/usr/local/bin`.
      3. Prints the bootstrap command.
    - `scripts/build-release.sh VERSION` → `build/nginx-aws-waf-VERSION.tar.gz` with `wafctl` (linux/amd64, CGO off, `-ldflags "-X …version.Version=VERSION"`), `waf/`, `deploy/`, `profiles/`, `scripts/fetch-ip-lists.sh`, `scripts/install-node.sh`, `docs/`.
  - Steps:
    1. S1 — Bootstrap.
    2. S2 — The scripts.
    3. S3 — e2e.
- **Unit tests:** T-BS1: bootstrap into a temp dir writes the expected files and the `.gitignore` lines; T-BS2: a second run → error. G-U54.
- **e2e tests:** `tests/e2e/bootstrap.sh`:
  - in an `ubuntu:24.04` container (no systemd), run `install-node.sh` from the built tarball, then `wafctl node bootstrap --node-id t1 --role node` (without systemd) and `wafctl validate` → exit 0;
  - `git -C $WAF_CONFIG_DIR log --oneline | wc -l` = 1.
  - G-U54.
- **Done:** G-U54 passes.

### 5.5 Terraform skeleton + multi-node docs
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW: `deploy/terraform/{README.md,versions.tf,variables.tf,main.tf,outputs.tf,user-data.sh.tftpl}`, `docs/multi-node.md`. WRITE: `Makefile` (`tf-validate`), `README.md`.
- **Change:**
  - Preconditions: 5.4 DONE.
  - Contract:
    - **Terraform:**
      - `aws_security_group` (80/443 world; 6000/6001 only from `var.node_cidrs` for central);
      - `aws_instance` per node from `var.nodes` (map: name → {role, instance_type, subnet_id});
      - `user_data` installs Docker (`apt-get install docker.io docker-compose-v2`), downloads the release from `var.release_url`, and runs install-node + bootstrap.
      - Required provider `hashicorp/aws ~> 6.0`.
      - NOT applied (D30).
    - Pin the Terraform image: run `docker run --rm hashicorp/terraform:1 version`, then pin `hashicorp/terraform:<printed x.y.z>` in the Makefile, and record it in §6 and in the R4 addendum.
    - `make tf-validate` runs `docker run --rm -v $PWD/deploy/terraform:/tf -w /tf hashicorp/terraform:<v> init -backend=false && … validate`.
    - **`docs/multi-node.md` (Italian):**
      - topology (central on-premise / AWS / tailnet);
      - ports and firewall;
      - PKI: init, tokens, enroll, renew, revoke, CRL timer;
      - the warning about an expired CRL;
      - Tailscale: use the tailnet name/IP in `ingress.server_names/server_ips` and `node.central.address`;
      - backup of the CA (offline copy).
  - Steps:
    1. S1 — TF files.
    2. S2 — Docs.
    3. S3 — `make tf-validate`.
  - Failure handling: provider download blocked (network) → BLOCKED with question to the user.
- **Unit tests:** N/A — IaC/docs.
- **e2e tests:** `make tf-validate` → `Success!`. G-U55.
- **Done:** G-U55 passes.

## Phase gates and closure
- Required gates: G-U51..G-U55, G-SEC, then G-P5 (`make test-unit && make lab-up && tests/e2e/multinode.sh && tests/e2e/bootstrap.sh && make tf-validate`).
- README obligation: unit 5.5.
- Every sub-phase DONE or SKIPPED with a reason. Run the full phase gates now.
- agent-1 reviews I-8 (G-SEC), key modes, token handling, the revocation e2e and the docs.
- Open P5, record the review, mark DONE. Commit `phase(001/P5): PHASE 5 COMPLETE — Multi-node and PKI; gates and review passed`.
