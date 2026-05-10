BINARY_NAME=oblivio
APP_PATH=./cmd/oblivio

air:
	air -c .air.toml

start:
	go run ./cmd/oblivio start -c config.yaml

fmt:
	gofumpt -l -w .

lint:
	golangci-lint run

# Migrations

migrateup:
	go run $(APP_PATH) migrations up -db-path ./data/sqlite/db.sqlite

migratedown:
	go run $(APP_PATH) migrations down -db-path ./data/sqlite/db.sqlite

migratecreate:
	go run $(APP_PATH) migrations create -p ./sql/migrations -name $(filter-out $@,$(MAKECMDGOALS))

# Generate

genenvs:
	go run ./cmd/oblivio config genenvs

gensql:
	pgxgen -config sql/pgxgen.yaml generate

genproto:
	rm -rf api/gen
	rm -rf frontend/src/api/gen
	cd api && \
	buf lint && \
	buf generate
