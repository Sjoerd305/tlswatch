VERSION ?= $(shell sh scripts/version.sh)
LDFLAGS := -s -w -X main.version=$(VERSION)
DEVDATA := ./tmp/dev

.PHONY: build frontend test test-go test-frontend lint run clean openapi

build: frontend
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o tlswatch ./cmd/tlswatch

frontend:
	npm ci --no-audit --no-fund
	npx tsc -p tsconfig.json

test: test-frontend test-go

test-frontend: frontend
	npm run check-deps
	npm test

test-go:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	govulncheck ./...
	gosec -quiet ./...

# Rewrite docs/openapi.json after an intended change to the public API.
openapi:
	go test ./internal/web -run TestOpenAPIGolden -update

# A throw-away instance on http://127.0.0.1:8080.
run: build
	mkdir -p $(DEVDATA)
	TLSWATCH_DB=$(DEVDATA)/tlswatch.db TLSWATCH_LOG_JSON=false ./tlswatch serve

clean:
	rm -rf tlswatch dist tmp
