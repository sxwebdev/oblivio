-- Surface failed account-deletion attempts in the tamper-evident chain.
-- Previously DeleteMe emitted `account_delete` on success and nothing on
-- failure, leaving forensic blind spots when an attacker probes the
-- crypto-shred path with a stolen access token. The new value lets the
-- handler append a row with the rejection reason in metadata before
-- returning the connect.Unauthenticated to the caller.
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'account_delete_attempt_failed';
