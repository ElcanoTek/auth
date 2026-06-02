# Top-level Makefile. Mirrors chat's shape (build / test / check / clean).

.PHONY: all build deps test check smoke clean tidy run

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

## check: the pre-push gate (vet + build + test)
check:
	GOTOOLCHAIN=auto go vet ./...
	$(MAKE) build
	$(MAKE) test

## smoke: boot the real binary + drive a full magic-link round-trip
##        (stdout driver, throwaway DB, loopback port). No secrets/network.
smoke:
	bash scripts/smoke.sh

## run: build + start with the local .env.local (creates one if missing).
##      Talks to whatever AUTH_EMAIL_DRIVER is set to — default 'stdout'
##      prints magic links to the console so you can develop without
##      configuring a provider.
run: build
	./bin/auth-server -env .env.local

clean:
	rm -rf bin
