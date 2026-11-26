SHELL := /bin/bash
.PHONY: help fetch wafctl test-unit

help: ## list targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | sort

fetch: ## download vendor sources, IP lists, AWS docs
	./scripts/fetch-all.sh

wafctl: ## build wafctl into wafctl/bin
	cd wafctl && go build -o bin/wafctl ./cmd/wafctl

test-unit: ## go unit tests
	cd wafctl && go test ./...

.PHONY: lists
lists: ## prepare .run/lists for lab renders and nginx -t
	mkdir -p .run/lists && cp data/ip-reputation/*.txt .run/lists/ && cp data/ip-reputation/custom-test.txt .run/lists/custom-reputation.txt && printf '2001:db8:bad::/48\n' >> .run/lists/custom-reputation.txt && printf '# placeholder\n' > .run/lists/HostingProviderIPList.txt

export WAF_HOME := $(CURDIR)
export WAF_CONFIG_DIR ?= $(CURDIR)/lab/config
export WAF_DATA_DIR ?= $(CURDIR)/.run
export WAF_COMPOSE_EXTRA ?= deploy/compose/lab-min.yml
COMPOSE_NODE := docker compose -p waf -f deploy/compose/node.yml -f deploy/compose/node.bridge.yml -f deploy/compose/lab-min.yml

.PHONY: lab-min-up lab-min-down
lab-min-up: wafctl lists ## start the minimal lab (WAF node + echo)
	mkdir -p .run/runtime .run/logs .run/certs .run/geoip .run/raw .run/vector
	./wafctl/bin/wafctl apply
	$(COMPOSE_NODE) up -d --build --wait

lab-min-down: ## stop the minimal lab
	$(COMPOSE_NODE) down

COMPOSE_LAB := $(COMPOSE_NODE) -f deploy/compose/lab.yml

.PHONY: lab-up lab-down lab-reset
lab-up: export WAF_COMPOSE_EXTRA = deploy/compose/lab-min.yml:deploy/compose/lab.yml
lab-up: lab-min-up ## start the full lab (WAF node + Odoo 12/14/16/18)
	$(COMPOSE_LAB) up -d pg12 pg13 pg15 pg16
	./scripts/lab-init-odoo.sh
	./wafctl/bin/wafctl apply

lab-down: ## stop the full lab (volumes kept)
	$(COMPOSE_LAB) down

lab-reset: ## stop the full lab and delete its volumes (Odoo databases)
	@if [ "$(FORCE)" != 1 ]; then read -p "Delete all lab volumes (Odoo databases)? [y/N] " a; [ "$$a" = y ]; fi
	$(COMPOSE_LAB) down -v

.PHONY: lab-legit
lab-legit: ## Playwright legit Odoo flows through the WAF (G-U23)
	tests/legit/run.sh shop12,shop14,shop16,shop18

.PHONY: lab-attack
lab-attack: ## nuclei + nikto against the Odoo sites (G-U24)
	scripts/lab-attack.sh shop12,shop14,shop16,shop18

.PHONY: lab-matrix
lab-matrix: ## lab matrix (clickhouse local over today's raw logs) → build/lab/matrix.md
	scripts/lab-matrix.sh

.PHONY: test-odoo
test-odoo: ## run the demo corpus against the four Odoo sites (G-U22)
	@rc=0; for v in 12 14 16 18; do echo "== shop$$v"; ./wafctl/bin/wafctl test run --suite tests/corpus --filter-site demo --retarget demo=shop$$v --exceptions tests/odoo-exceptions.yaml || rc=1; done; exit $$rc

.PHONY: test-e2e
test-e2e: lab-min-up ## run the request corpus against the lab node (G-U16)
	./wafctl/bin/wafctl test run --suite tests/corpus
