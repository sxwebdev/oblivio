-- Store the authenticator-data flags byte alongside each WebAuthn
-- credential. The go-webauthn library enforces that the BackupEligible
-- flag is identical between registration and login (per WebAuthn §7.2
-- "Backup Eligible flag is immutable"). Without persisting it, our
-- restored credential has Flags=0 and any passkey that registered with
-- BE=1 (Apple iCloud Keychain, Chrome sync, etc.) fails CompleteMFA with
-- "Backup Eligible flag inconsistency detected during login validation".
--
-- Storage shape: the raw protocol.AuthenticatorFlags byte, packaged via
-- (webauthn.CredentialFlags).MsgpByte / CredentialFlagsFromMsgpByte. A
-- single SMALLINT is enough for current and any near-future flag bits.
ALTER TABLE user_webauthn_credentials
    ADD COLUMN flags SMALLINT NOT NULL DEFAULT 0;
