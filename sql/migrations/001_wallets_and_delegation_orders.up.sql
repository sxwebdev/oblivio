CREATE TABLE wallets (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      TEXT NOT NULL,
    address                   TEXT NOT NULL UNIQUE,
    blockchain                TEXT NOT NULL CHECK (blockchain != ''),
    energy_threshold          BIGINT NOT NULL DEFAULT 0,
    bandwidth_threshold       BIGINT NOT NULL DEFAULT 0,
    energy_delegate_amount    BIGINT NOT NULL DEFAULT 0,
    bandwidth_delegate_amount BIGINT NOT NULL DEFAULT 0,
    energy_period             TEXT NOT NULL DEFAULT '1h',
    bandwidth_period          TEXT NOT NULL DEFAULT '1h',
    is_active                 BOOLEAN NOT NULL DEFAULT TRUE,
    current_energy            BIGINT NOT NULL DEFAULT 0,
    current_bandwidth         BIGINT NOT NULL DEFAULT 0,
    current_balance           TEXT NOT NULL DEFAULT '0',
    last_checked_at           TIMESTAMPTZ NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE delegation_resource_type AS ENUM ('energy', 'bandwidth');
CREATE TYPE delegation_status AS ENUM ('pending', 'processing', 'completed', 'failed');

CREATE TABLE delegation_orders (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id         UUID REFERENCES wallets(id) ON DELETE SET NULL,
    target_address    TEXT NOT NULL,
    resource_type     delegation_resource_type NOT NULL,
    amount            BIGINT NOT NULL,
    period            TEXT NOT NULL DEFAULT '1h',
    status            delegation_status NOT NULL DEFAULT 'pending',
    provider          TEXT NOT NULL DEFAULT '',
    provider_order_id TEXT,
    error_message     TEXT,
    is_manual         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_delegation_orders_wallet_id  ON delegation_orders(wallet_id);
CREATE INDEX idx_delegation_orders_status     ON delegation_orders(status);
CREATE INDEX idx_delegation_orders_created_at ON delegation_orders(created_at DESC);

-- Prevent concurrent duplicate in-flight delegations for the same (wallet, resource):
-- at most one pending/processing order per (wallet_id, resource_type). Closes the
-- race window between the application-level check and the INSERT atomically.
CREATE UNIQUE INDEX uq_delegation_orders_active
    ON delegation_orders (wallet_id, resource_type)
    WHERE status IN ('pending', 'processing');

-- Application settings (key-value with JSONB)
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed default settings
INSERT INTO settings (key, value) VALUES
    ('providers', '{"items": [{"name": "tronegy", "enabled": true, "priority": 1}, {"name": "netts", "enabled": true, "priority": 2}]}'),
    ('transfers', '{"energy_per_transfer": 65000, "bandwidth_per_transfer": 650}');
