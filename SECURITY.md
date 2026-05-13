# Security Policy

## Reporting a vulnerability

Email **security@oblivio.local** with as much detail as you can share. Please
do not open a public issue for security-relevant bugs until a fix has shipped.

A `/.well-known/security.txt` is served by the application; it points to this
file as the canonical policy.

## Supported versions

Only the latest `master` is actively maintained. Security fixes are merged
to `master`; users on earlier commits should upgrade.

## Scope and ground rules

In scope:

- Cryptographic primitives (key derivation, AEAD envelopes, blind index, hash chain).
- Authentication (Argon2id PHC handling, refresh-token rotation, 2FA, recovery).
- Data isolation (RLS, AAD discipline, idempotency keys).
- Supply chain (dependency advisories, lockfile drift).

Out of scope:

- Tests that intentionally exercise destructive paths (e.g. tampering with
  rows under a superuser role).
- Issues that only reproduce against a single fork of a dependency.

## Coordinated disclosure

We acknowledge a report within five business days and aim to ship a fix or
mitigation within thirty days. Reporters who wish to be credited will be
listed in the release notes for the corresponding fix.

## Threat model notes

### Passkey-based vault unlock (opt-in)

Oblivio is a zero-knowledge vault: `vault_key` is wrapped under
`master_key = Argon2id(master_password, salt_user)` and the server never
sees `master_key`. By default, decryption requires the user's master
password — no provider, device, or attacker who has not also compromised
the master password can reach `vault_key`.

The "Use to unlock" toggle on a WebAuthn credential changes this for
that credential by storing a _second_ wrapping of `vault_key` under a
key derived from the WebAuthn **PRF extension** output. The blob is
useless without the authenticator (PRF is computed inside the secure
element / TPM with user verification), but it does mean:

- A **synced passkey** (iCloud Keychain, Chrome Sync, 1Password-as-passkey,
  etc.) extends vault access to anyone who can take over the provider
  account. The user has explicitly opted into trusting the provider with
  vault contents.
- A **platform authenticator** (Touch ID, Windows Hello) extends vault
  access to anyone who can satisfy user verification on that device
  (biometric, device PIN).
- A **hardware key** with PRF (e.g. modern YubiKey) requires physical
  possession plus the PIN — strongest of the three, but still wider than
  master-password-only.

This is enforced as an opt-in per credential. The settings UI shows an
explicit warning before enabling. If the user later suspects compromise:

- **Remove the credential** — deletes the row and the wrapped blob.
- **Change master password with “Also revoke passkey-unlock”** — wipes
  every stored unlock bundle in one shot while leaving the credentials
  themselves usable as a second factor at sign-in. Use this when the
  master password rotation is itself a compromise response (the bundle
  uses a PRF-derived key, not `master_key`, so a password rotation
  alone does **not** invalidate it).

`UV=required` is enforced on every relevant ceremony (registration,
enable, unlock) so authenticator possession alone never unlocks the
vault.

### Tamper-evident audit chain

`account_delete` is appended to `audit_log` only on a successful
deletion, where every required factor (auth_key, TOTP, passkey
assertion) verified. Every failed attempt at the crypto-shred path
emits `account_delete_attempt_failed` with a `stage` (`auth_key` /
`totp` / `passkey`) and a `reason` field in metadata. The two actions
are searchable via `AuditService.ListAudit` filtering and live in the
same hash-chained log as everything else, so probes are forensically
visible without polluting the success record.
