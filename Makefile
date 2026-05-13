BINARY_NAME=oblivio
APP_PATH=./cmd/oblivio

air:
	air -c .air.toml

start:
	go run $(APP_PATH) start -c config.yaml

fmt:
	gofumpt -l -w .

lint:
	golangci-lint run

# Migrations

migrateup:
	go run $(APP_PATH) migrations up -c config.yaml

migratedown:
	go run $(APP_PATH) migrations down -c config.yaml

migratecreate:
	go run $(APP_PATH) migrations create -p ./sql/migrations -name $(filter-out $@,$(MAKECMDGOALS))

# Infrastructure

infra-up:
	docker compose -p oblivio -f dev/deploy/docker-compose.yml up -d

infra-stop:
	docker compose -p oblivio -f dev/deploy/docker-compose.yml stop

infra-down:
	docker compose -p oblivio -f dev/deploy/docker-compose.yml down

# Generate

genenvs:
	go run $(APP_PATH) config genenvs

genreadme:
	go run $(APP_PATH) utils readme

gensql:
	pgxgen -config sql/pgxgen.yaml generate

genproto:
	rm -rf internal/api/pb
	rm -rf frontend/src/api/gen
	cd proto && buf lint && buf generate

# Test vector regeneration. Run after touching anything that produces them
# (cmd/genvectors). Always commit the result; both Go and TS tests consume it.
genvectors:
	go run ./cmd/genvectors -o testdata/crypto-vectors.json

# Testing

# Unit tests (no Docker, no Postgres). Fast — for the inner loop.
test:
	go test ./...

# Unit + integration. Integration tests are gated by the `integration` build
# tag and require Docker (testcontainers). Skip cleanly without docker.
test-integration:
	go test -tags=integration -timeout 5m ./...

# Coverage gate: produces a profile across all packages (unit + integration),
# then runs cmd/covgate which fails if any package falls below its threshold
# (see testdata/coverage.yaml). Required on every PR via CI.
test-coverage:
	go test -tags=integration -timeout 5m -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
	go run ./cmd/covgate -profile coverage.out -config testdata/coverage.yaml -v

# Frontend tests (vitest in @oblivio/crypto). Requires `pnpm install` in
# frontend/. Coverage thresholds live in the vitest config.
test-frontend:
	cd frontend/packages/crypto && pnpm test

# Convenience: run everything (matches CI).
test-all: test-coverage test-frontend

# Fuzz the critical parsers/wrappers for FUZZ_TIME each (default 30s).
# Override via `make fuzz FUZZ_TIME=2m`. CI runs the same loop with longer time.
FUZZ_TIME ?= 30s
fuzz:
	go test -run=NoTest -fuzz=FuzzParsePHC      -fuzztime=$(FUZZ_TIME) ./internal/auth/
	go test -run=NoTest -fuzz=FuzzAESGCMOpen    -fuzztime=$(FUZZ_TIME) ./internal/crypto/
	go test -run=NoTest -fuzz=FuzzAESGCMSeal    -fuzztime=$(FUZZ_TIME) ./internal/crypto/
	go test -run=NoTest -fuzz=FuzzCanonicalJSON -fuzztime=$(FUZZ_TIME) ./internal/audit/

# Quick benchmark sweep — useful for spot-checking Argon2id cost on a new
# host before changing user_kdf_params defaults.
bench:
	go test -bench=BenchmarkHashAuthKey -benchmem -run=NoTest ./internal/auth/
