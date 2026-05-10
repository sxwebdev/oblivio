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
