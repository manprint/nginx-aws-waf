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

lab-min-down: ## stop the minimal lab
	$(COMPOSE_NODE) down
