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

# Generate

genenvs:
	go run $(APP_PATH) config genenvs

gensql:
	pgxgen -config sql/pgxgen.yaml generate

genproto:
	rm -rf internal/api/pb
	rm -rf frontend/src/api/gen
	cd proto && buf lint && buf generate
