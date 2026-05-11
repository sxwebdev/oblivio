# Environment Variables

## Vault

| **Name**                 | **Required** | **Secret** | **Default value** | **Usage** | **Example**        |
|--------------------------|--------------|------------|-------------------|-----------|--------------------|
| `VAULT_ENABLED`          |              |            | `false`           |           |                    |
| `VAULT_ADDR`             | ✅            |            |                   |           |                    |
| `VAULT_SECRET_PATH`      | ✅            |            |                   |           |                    |
| `VAULT_KUBE_ROLE`        | ✅            |            |                   |           |                    |
| `VAULT_KUBE_JWT_PATH`    | ✅            |            |                   |           |                    |
| `VAULT_KUBE_MOUNT_PATH`  | ✅            |            | `kubernetes`      |           |                    |
| `VAULT_AUTH_KIND`        |              |            | `kubernetes`      |           | `kubernetes,token` |
| `VAULT_TOKEN`            | ✅            |            |                   |           |                    |
| `VAULT_REFRESH_INTERVAL` |              |            | `20s`             |           |                    |

## Application

| **Name**                                                | **Required** | **Secret** | **Default value** | **Usage**                                          | **Example**    |
|---------------------------------------------------------|--------------|------------|-------------------|----------------------------------------------------|----------------|
| `OBLIVIO_LOG_FORMAT`                                    |              |            | `json`            | allows to set custom formatting                    | `json`         |
| `OBLIVIO_LOG_LEVEL`                                     |              |            | `info`            | allows to set custom logger level                  | `info`         |
| `OBLIVIO_LOG_CONSOLE_COLORED`                           |              |            | `false`           | allows to set colored console output               | `false`        |
| `OBLIVIO_LOG_TRACE`                                     |              |            | `fatal`           | allows to set custom trace level                   | `fatal`        |
| `OBLIVIO_LOG_WITH_CALLER`                               |              |            | `false`           | allows to show caller                              | `false`        |
| `OBLIVIO_LOG_WITH_STACK_TRACE`                          |              |            | `false`           | allows to show stack trace                         | `false`        |
| `OBLIVIO_OPS_ENABLED`                                   |              |            | `false`           | allows to enable ops server                        | `false`        |
| `OBLIVIO_OPS_NETWORK`                                   | ✅            |            | `tcp`             | allows to set ops listen network: tcp/udp          | `tcp`          |
| `OBLIVIO_OPS_TRACING_ENABLED`                           |              |            | `false`           | allows to enable tracing                           | `false`        |
| `OBLIVIO_OPS_METRICS_ENABLED`                           |              |            | `false`           | allows to enable metrics                           | `true`         |
| `OBLIVIO_OPS_METRICS_PATH`                              | ✅            |            | `/metrics`        | allows to set custom metrics path                  | `/metrics`     |
| `OBLIVIO_OPS_METRICS_PORT`                              | ✅            |            | `10000`           | allows to set custom metrics port                  | `10000`        |
| `OBLIVIO_OPS_METRICS_BASIC_AUTH_ENABLED`                |              |            | `false`           | allows to enable basic auth                        |                |
| `OBLIVIO_OPS_METRICS_BASIC_AUTH_USERNAME`               |              |            |                   | auth username                                      |                |
| `OBLIVIO_OPS_METRICS_BASIC_AUTH_PASSWORD`               |              |            |                   | auth password                                      |                |
| `OBLIVIO_OPS_HEALTHY_ENABLED`                           |              |            | `false`           | allows to enable health checker                    | `true`         |
| `OBLIVIO_OPS_HEALTHY_PATH`                              | ✅            |            | `/healthy`        | allows to set custom healthy path                  | `/healthy`     |
| `OBLIVIO_OPS_HEALTHY_PORT`                              | ✅            |            | `10000`           | allows to set custom healthy port                  | `10000`        |
| `OBLIVIO_OPS_HEALTHY_LIVENESS_PATH`                     |              |            | `/livez`          | liveness probe path                                | `/livez`       |
| `OBLIVIO_OPS_HEALTHY_READINESS_PATH`                    |              |            | `/readyz`         | readiness probe path                               | `/readyz`      |
| `OBLIVIO_OPS_PROFILER_ENABLED`                          |              |            | `false`           | allows to enable profiler                          | `false`        |
| `OBLIVIO_OPS_PROFILER_PATH`                             | ✅            |            | `/debug/pprof`    | allows to set custom profiler path                 | `/debug/pprof` |
| `OBLIVIO_OPS_PROFILER_PORT`                             | ✅            |            | `10000`           | allows to set custom profiler port                 | `10000`        |
| `OBLIVIO_OPS_PROFILER_WRITE_TIMEOUT`                    |              |            | `60`              | HTTP server write timeout in seconds               | `60`           |
| `OBLIVIO_SERVER_ADDR`                                   | ✅            |            | `:8080`           |                                                    |                |
| `OBLIVIO_SERVER_TLS_CERT_FILE`                          |              |            |                   |                                                    |                |
| `OBLIVIO_SERVER_TLS_KEY_FILE`                           |              |            |                   |                                                    |                |
| `OBLIVIO_SERVER_PUBLIC_URL`                             |              |            |                   |                                                    |                |
| `OBLIVIO_POSTGRES_HOST`                                 | ✅            |            | `localhost`       |                                                    |                |
| `OBLIVIO_POSTGRES_PORT`                                 | ✅            |            | `5432`            |                                                    |                |
| `OBLIVIO_POSTGRES_DATABASE`                             | ✅            |            |                   |                                                    |                |
| `OBLIVIO_POSTGRES_USERNAME`                             | ✅            | ✅          |                   |                                                    |                |
| `OBLIVIO_POSTGRES_PASSWORD`                             | ✅            | ✅          |                   |                                                    |                |
| `OBLIVIO_POSTGRES_SSL_MODE`                             |              |            | `verify-full`     |                                                    |                |
| `OBLIVIO_AUTH_ACCESS_TOKEN_TTL`                         |              |            | `20m0s`           |                                                    |                |
| `OBLIVIO_AUTH_REFRESH_TOKEN_TTL`                        |              |            | `720h0m0s`        |                                                    |                |
| `OBLIVIO_AUTH_ACCESS_TOKEN_SECRET_KEY`                  |              | ✅          |                   | signing key for access tokens; generated if empty  |                |
| `OBLIVIO_AUTH_REFRESH_TOKEN_SECRET_KEY`                 |              | ✅          |                   | signing key for refresh tokens; generated if empty |                |
| `OBLIVIO_AUTH_ARGON_2_SERVER_T`                         |              |            | `3`               |                                                    |                |
| `OBLIVIO_AUTH_ARGON_2_SERVER_M_KI_B`                    |              |            | `65536`           |                                                    |                |
| `OBLIVIO_AUTH_ARGON_2_SERVER_P`                         |              |            | `1`               |                                                    |                |
| `OBLIVIO_AUTH_ARGON_2_SERVER_MAX_CONCURRENT`            |              |            | `0`               |                                                    |                |
| `OBLIVIO_AUTH_RATE_LIMITS_AUTH_LOGIN_PER_EMAIL_PER_MIN` |              |            | `5`               |                                                    |                |
| `OBLIVIO_AUTH_RATE_LIMITS_AUTH_LOGIN_PER_IP_PER_MIN`    |              |            | `20`              |                                                    |                |
| `OBLIVIO_AUTH_RATE_LIMITS_KDF_PARAMS_PER_IP_PER_MIN`    |              |            | `30`              |                                                    |                |
| `OBLIVIO_AUTH_RATE_LIMITS_REGISTER_PER_IP_PER_HOUR`     |              |            | `5`               |                                                    |                |
| `OBLIVIO_WEB_AUTHN_RPID`                                |              |            |                   |                                                    |                |
| `OBLIVIO_WEB_AUTHN_RP_NAME`                             |              |            | `Oblivio`         |                                                    |                |
| `OBLIVIO_WEB_AUTHN_RP_ORIGIN`                           |              |            |                   |                                                    |                |
| `OBLIVIO_JOBS_AUDIT_CHAIN_VERIFY_INTERVAL`              |              |            | `24h0m0s`         |                                                    |                |
| `OBLIVIO_JOBS_AUDIT_CHAIN_ANCHOR_INTERVAL`              |              |            | `1h0m0s`          |                                                    |                |
| `OBLIVIO_JOBS_SESSIONS_GC_INTERVAL`                     |              |            | `1h0m0s`          |                                                    |                |
| `OBLIVIO_JOBS_AUTH_TOKENS_GC_INTERVAL`                  |              |            | `1h0m0s`          |                                                    |                |
| `OBLIVIO_JOBS_IDEMPOTENCY_GC_INTERVAL`                  |              |            | `1h0m0s`          |                                                    |                |
| `OBLIVIO_JOBS_MFAGC_INTERVAL`                           |              |            | `5m0s`            |                                                    |                |
| `OBLIVIO_JOBS_RECOVERY_GC_INTERVAL`                     |              |            | `5m0s`            |                                                    |                |
| `OBLIVIO_JOBS_RATE_LIMIT_GC_INTERVAL`                   |              |            | `1h0m0s`          |                                                    |                |
| `OBLIVIO_EMAIL_PROVIDER`                                |              |            |                   |                                                    |                |
| `OBLIVIO_EMAIL_FROM`                                    |              |            |                   |                                                    |                |
| `OBLIVIO_EMAIL_SMTP_HOST`                               |              |            |                   |                                                    |                |
| `OBLIVIO_EMAIL_SMTP_PORT`                               |              |            | `587`             |                                                    |                |
| `OBLIVIO_EMAIL_SMTP_USERNAME`                           |              | ✅          |                   |                                                    |                |
| `OBLIVIO_EMAIL_SMTP_PASSWORD`                           |              | ✅          |                   |                                                    |                |
| `OBLIVIO_EMAIL_SMTP_ALLOW_INSECURE`                     |              |            | `false`           |                                                    |                |

## Manual env vars (not part of config.Config)

These are read directly via `os.Getenv` at startup. They live outside the
layered config so the deployment can keep them in a different secret store
than the rest of the configuration. None are required; each documents the
fallback that applies when unset.

| **Name**               | **Secret** | **Usage**                                                                                                                                                                                                                                                              |
| ---------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OBLIVIO_MASTER_SEED`  | ✅         | 32+ byte hex or base64 seed used to derive JWT access/refresh signing keys via HKDF. Same seed → same keys across instances and restarts. When set, the on-disk `data/secrets/secrets.json` fallback is skipped. Recommended for production when Vault is not in use. |
| `OBLIVIO_MFA_KEK_SEED` | ✅         | 16+ byte hex or base64 seed used to derive the MFA-store KEK via HKDF. Required for multi-instance deploys — without it each instance generates a per-process random KEK and MFA challenges become instance-pinned.                                                  |
