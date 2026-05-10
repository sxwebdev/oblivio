# Oblivio

Backend: Go + Fiber + Pebble. Frontend: Vite + React.

## Backend

Env:

- `OBLIVIO_LISTEN_ADDR=:8080`
- `OBLIVIO_DB_PATH=./data/pebble`
- `OBLIVIO_ADMIN_SECRET=dev-admin` (MVP only!)

Run:

```sh
OBLIVIO_ADMIN_SECRET=dev-admin go run ./cmd/oblivio
```

## Frontend

From `frontend/`:

```sh
pnpm install
pnpm dev
```

Then open <http://localhost:3000>

Note: API base is `/v1` and expects the backend on the same origin in dev or configure a proxy.
