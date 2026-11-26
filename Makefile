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
