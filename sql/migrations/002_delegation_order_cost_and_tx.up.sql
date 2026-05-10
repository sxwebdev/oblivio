ALTER TABLE delegation_orders
    ADD COLUMN cost_trx         NUMERIC(20, 6),
    ADD COLUMN tx_hash          TEXT,
    ADD COLUMN delivered_amount BIGINT;
