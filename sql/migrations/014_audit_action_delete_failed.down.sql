-- Postgres does not support removing values from an enum without
-- recreating the type. We leave the value in place on rollback; it's
-- harmless when no row uses it.
SELECT 1;
