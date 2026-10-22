# Top-level Makefile: build / test / check / clean.

.PHONY: all build deps test check lint stack-check flag-status smoke clean tidy run

GOLANGCI_VERSION := v2.14.0
# The toolchain go.mod names. `go run tool@version` would otherwise build the
# tool with the lowest Go its own go.mod allows, and a Go-analysing tool built
# with an older Go than go.mod's refuses to run.
GO_PINNED := $(shell awk '/^go /{print "go" $$2; exit}' go.mod)

all: build

## build: compile auth-server + auth-admin into ./bin
build:
	@mkdir -p bin
	GOTOOLCHAIN=auto go build -o bin/auth-server ./cmd/auth-server
	GOTOOLCHAIN=auto go build -o bin/auth-admin  ./cmd/auth-admin

## deps: resolve go.mod + populate vendor cache
deps:
	GOTOOLCHAIN=auto go mod download

## tidy: clean up go.mod + go.sum
tidy:
	GOTOOLCHAIN=auto go mod tidy

## test: go test all packages
test:
	GOTOOLCHAIN=auto go test ./...
	bash scripts/test/auth_cli_test.sh
	bash scripts/test/doctor_test.sh
	bash scripts/test/ssh_test.sh

## stack-check: Elcano frontend standard (stack.conf, AGENTS.md block,
##              flag.lock drift, no remote assets); offline, as CI runs it
stack-check:
	scripts/stack-check.sh

## flag-status: compare the vendored Flag files with a ../flag checkout
##              (FLAG_DIR=... to point elsewhere); update with
##              scripts/flag-sync.sh sync
flag-status:
	scripts/flag-sync.sh status $(FLAG_DIR)

## lint: stack-check + gofmt -s check + golangci-lint (matches the CI lint gate)
lint: stack-check
	@out="$$(gofmt -s -l .)"; if [ -n "$$out" ]; then echo "gofmt -s needed on:"; echo "$$out"; echo "run: gofmt -s -w ."; exit 1; fi
	GOTOOLCHAIN=$(GO_PINNED) go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./...

## check: the pre-push gate (lint + vet + build + test)
check:
	$(MAKE) lint
	GOTOOLCHAIN=auto go vet ./...
	$(MAKE) build
	$(MAKE) test

## smoke: boot the real binary and drive legacy magic-link, password, and
##        confidential-application PKCE handoffs with throwaway databases.
smoke:
	bash scripts/smoke.sh
	bash scripts/smoke-password.sh

## run: build + start with the local .env.local. Magic-link development with
##      the stdout driver also requires the explicit loopback-only
##      AUTH_ALLOW_INSECURE_DEV setting documented in the example env file.
run: build
	./bin/auth-server -env .env.local

clean:
	rm -rf bin
