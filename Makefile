# Top-level Makefile. Mirrors chat's shape (build / test / check / clean).

.PHONY: all build deps test check lint smoke clean tidy run

GOLANGCI_VERSION := v2.12.0

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

## lint: gofmt -s check + golangci-lint (matches the CI lint gate)
lint:
	@out="$$(gofmt -s -l .)"; if [ -n "$$out" ]; then echo "gofmt -s needed on:"; echo "$$out"; echo "run: gofmt -s -w ."; exit 1; fi
	GOTOOLCHAIN=auto go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./...

## check: the pre-push gate (lint + vet + build + test)
check:
	$(MAKE) lint
	GOTOOLCHAIN=auto go vet ./...
	$(MAKE) build
	$(MAKE) test

## smoke: boot the real binary and drive both legacy magic-link and password
##        round-trips with throwaway databases on loopback ports.
smoke:
	bash scripts/smoke.sh
	bash scripts/smoke-password.sh

## run: build + start with the local .env.local (creates one if missing).
##      Talks to whatever AUTH_EMAIL_DRIVER is set to — default 'stdout'
##      prints magic links to the console so you can develop without
##      configuring a provider.
run: build
	./bin/auth-server -env .env.local

clean:
	rm -rf bin
