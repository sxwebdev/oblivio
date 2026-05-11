# Oblivio — план реализации

Облачный мульти-юзерский менеджер секретов. Сервер + WebUI (Go + React,
zero-knowledge крипта на клиенте). Высокая планка надёжности: ZK-модель,
audit-chain, memguard на сервере, RLS как defence-in-depth.

---

## 1. Контекст

`oblivio` — облачный мульти-юзерский менеджер секретов: пароли, заметки,
TOTP-секреты, custom-поля, организованные по проектам. Модель: `server + WebUI`
(без TUI/GUI), позже — mobile / desktop GUI / browser extension.

**Что хранит пользователь:**

- Проекты (логические группы записей).
- Записи (entries), привязанные к проекту. Тип записи (`entry_kind`): `login`,
  `totp`, `card`, `identity`, `ssh_key`, `note`. Заметки — это просто
  `kind='note'` с другим набором полей в `encrypted_blob`. Отдельной таблицы
  `notes` нет.
- TOTP-секреты (RFC 6238) — поле в записи `kind='login'` (`has_totp=true`)
  или отдельная запись `kind='totp'`.

**Один аккаунт = один пользователь.** Нет организаций, команд, sharing,
RBAC-ролей. Каждый юзер — изолированный vault. Если позже понадобятся team-vaults,
архитектура их допускает, но MVP их не делает.

**Принципиальные решения, утверждённые пользователем:**

| Развилка                       | Выбор                                        |
| ------------------------------ | -------------------------------------------- |
| Криптомодель                   | Zero-knowledge (вся крипта на клиенте)       |
| Хранилище зашифрованных данных | Только Postgres                              |
| K_root для серверных секретов  | Admin secret + HashiCorp Vault               |
| Восстановление мастер-пароля   | Recovery code, выдаваемый при регистрации    |
| Транспорт                      | ConnectRPC + buf (вместо текущего gofiber)   |
| Vault-структура                | Один vault на пользователя, проекты — внутри |
| 2FA                            | TOTP + WebAuthn/Passkey сразу в MVP          |
| Текущие остатки в скелете      | Полная зачистка перед реализацией            |

**Целевые клиенты:** WebUI сейчас, mobile / desktop GUI / browser extension позже.
Архитектура должна позволять подключать новые клиенты без изменения серверного контракта.

---

## 2. Threat model

| Угроза                                            | Защита                                                                                                                                                                                                          |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Кража диска / БД                                  | Все ценные данные зашифрованы клиентскими ключами; сервер не имеет ключей расшифровки                                                                                                                           |
| Honest-but-curious оператор сервера               | То же — даже root-доступ к Postgres не даёт plaintext                                                                                                                                                           |
| Активный взлом сервера и подмена ciphertext       | AAD = `vault_id\|item_id\|version`; ротация item version; integrity log; client side проверка подписей                                                                                                          |
| Утечка серверных секретов (Vault token, JWT keys) | `memguard.LockedBuffer` в RAM сервера, Vault для root-of-trust, ротация ключей JWT                                                                                                                              |
| Brute-force мастер-пароля                         | Argon2id `t=3, m=128 MiB, p=4`; per-user salt; rate-limit на `/auth/kdf-params` и `/auth/login`                                                                                                                 |
| Перехват пароля в TLS                             | TLS 1.3 only, HSTS preload, `verify-full` к Postgres                                                                                                                                                            |
| XSS на WebUI                                      | Strict CSP с Trusted Types, нет inline-скриптов, нет third-party CDN, lockfile lint, SRI                                                                                                                        |
| Кража токена / cookie                             | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`; rotating refresh токены; revoke при logout                                                                                                           |
| Утечка через буфер обмена                         | Auto-clear через 30s, проверка содержимого перед очисткой                                                                                                                                                       |
| Утечка через swap / coredump (server)             | `memguard` для JWT-ключей и временно-производных KDF-материалов; на хосте — отключить swap или включить swap-encryption. Plaintext, передаваемый в `crypto/aes`, всё равно копируется в обычную heap — см. §8.3 |
| Утечка через swap / coredump (desktop GUI на Go)  | `memguard` для K_master/K_vault/K_item на десктопе                                                                                                                                                              |
| Утечка через DevTools / Redux DevTools (Web)      | Расшифровка только при клике "View"/"Copy"; Redux DevTools отключён в проде                                                                                                                                     |
| Phishing / replay логина                          | WebAuthn рекомендуется как обязательный 2-й фактор для прод-аккаунтов. UV (PIN/biometric) пока не форсится — см. §17                                                                                            |
| Auto-lock                                         | По бездействию (`visibilitychange`/таймер), `beforeunload`, ручной lock                                                                                                                                         |
| Tamper / rollback на сервере                      | Audit-chain в Postgres (см. §6.5); head хранится в `system_state` той же БД — внешний якорь не реализован, см. §17                                                                                              |
| Honest-but-curious оператор: TOTP login-secret    | Defence-in-depth: secret шифруется ключом из `auth_key`, который сервер не хранит. Но в момент login сервер видит plaintext в RAM — это не ZK, см. §5.3                                                         |

**Из скопа исключаются** (для MVP, можно добавить позже): supply-chain атака на собственные
NPM-зависимости (минимизация числа deps + lockfile lint + SBOM), фишинговые
поддельные клиенты (защита через WebAuthn — origin binding).

---

## 3. Архитектура высокого уровня

```
┌─────────────────────────────────────────────────────────────────────┐
│ Web client (React + Vite + Tailwind + shadcn)                       │
│ + TanStack Router/Query + Zustand                                   │
│                                                                     │
│ Crypto core (изолированный TS пакет @oblivio/crypto):               │
│   • Argon2id WASM (multi-thread, COOP/COEP)                         │
│   • WebCrypto AES-GCM-256                                           │
│   • Дерево ключей: master → vault → item                            │
│   • TOTP RFC 6238                                                   │
│   • Blind-index HMAC-SHA256                                         │
│                                                                     │
│ Видит plaintext только в момент использования.                      │
└──────────────┬──────────────────────────────────────────────────────┘
               │ HTTPS + ConnectRPC (protobuf)
               │ Bearer access token + refresh token
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Oblivio Server (Go)                                                 │
│ — mx launcher (lifecycle, LIFO shutdown)                            │
│ — ConnectRPC handlers (AuthService, VaultService, …)                │
│ — connectrpc.com/authn middleware + rbacconnect                     │
│ — sxwebdev/tokenmanager: access (20 min) + refresh (30 days)        │
│ — Argon2id для server-side хеша auth_key (двух-стадийное KDF)       │
│ — memguard для JWT ключей, Vault token, lockout state               │
│ — Audit log writer (append-only, hash-chained)                      │
│ — Prometheus metrics, structured logs                               │
│                                                                     │
│ Хранит: ciphertext, salt, kdf_params, verifier, hash(auth_key),     │
│         wrapped_recovery_key, project_blob, entry_blob, note_blob,  │
│         WebAuthn public keys, sessions, audit                       │
│                                                                     │
│ Не видит: master_password, master_key, vault_key, item_key,         │
│           plaintext полей, totp_secret, plaintext заметок           │
└──────┬──────────────────────────────────────┬───────────────────────┘
       │                                      │
       ▼                                      ▼
┌──────────────────┐                ┌──────────────────────────────┐
│ Postgres 18      │                │ HashiCorp Vault              │
│ TLS verify-full  │                │ (KV для admin_secret,        │
│ pgxpool          │                │  PKI для TLS, transit для    │
│ RLS включён      │                │  подписи JWT при ротации)    │
│ pgaudit          │                │ AppRole / Kubernetes auth    │
└──────────────────┘                └──────────────────────────────┘
```

**Postgres** — единственное хранилище данных. Pebble + TPM stub из текущего скелета удаляются:
при ZK сервер не имеет ключей и расшифровывать ciphertext не может, а anti-tamper решается
через append-only audit-chain в той же Postgres.

**Vault** обслуживает только серверные секреты, никогда — пользовательские.

---

## 4. Криптографическая схема (zero-knowledge)

### 4.1 Жизненный цикл ключей

```
master_password (только в браузере)
    │
    │ Argon2id(salt_user, kdf_params)         params per-user из БД
    ▼
master_key (32 байта)
    │
    ├──► auth_key = HKDF-SHA256(master_key, info="oblivio/auth/v1", salt=email)
    │      │
    │      └──► отправляется на сервер при login
    │           сервер хранит argon2id(auth_key) для проверки
    │
    └──► AES-GCM unwrap
         │
         ▼
    vault_key (32 байта, случайный, генерируется при регистрации)
         │
         ├──► AES-GCM unwrap (для каждой записи)
         │     │
         │     ▼
         │   item_key (32 байта на запись/заметку/проект, случайный)
         │     │
         │     │ AES-GCM
         │     ▼
         │   ciphertext поля (title, username, password, url, notes,
         │                    totp_secret, custom_fields)
         │
         └──► HMAC-SHA256 для blind index (поиск по точному совпадению title)
```

**Двух-стадийное KDF** (как в Bitwarden web vault):

- `master_key` используется только для шифрования и никогда не покидает клиент.
- `auth_key` отправляется на сервер при login и регистрации. Сервер хранит
  `argon2id(auth_key)` — это серверный пароль, который не позволяет раскрыть
  `master_password` (нужно обратить два слоя KDF).
- Это классическая схема ZK-аутентификации без OPAQUE/aPAKE.

**Замечание про HKDF salt.** В реализации `auth_key` выводится через
`HKDF-SHA256(master_key, info="oblivio/auth/v1", salt=lowercase(email))`.
Email — публичная низкоэнтропийная величина: схема работает, но (а) HKDF salt
по best practice — случайный, (б) смена email потребует пере-вывода `auth_key`
и `auth_key_hash`. Целевое улучшение — мигрировать salt на per-user `salt_user`
(уже хранится в БД), чтобы email можно было менять без переаутентификации.
См. §17.

### 4.2 Параметры Argon2id

| Слой                                 | t (iters) | m (KiB)          | p (threads)  |
| ------------------------------------ | --------- | ---------------- | ------------ |
| Client `master_key` (per-user из БД) | 3         | 131072 (128 MiB) | 1 (см. ниже) |
| Server `argon2(auth_key)`            | 3         | 131072 (128 MiB) | 4            |

Параметры клиентского KDF хранятся в `user_kdf_params` per-user, чтобы поднять их
впоследствии без миграции миллионов записей. Серверные — фиксированы в коде, версионируются.

**Клиентский parallelism.** Multi-thread Argon2id в браузере требует COOP/COEP
заголовков и `crossOriginIsolated`. На страницах без изоляции клиент принудительно
использует `p=1` (single-thread). На устройствах с жёсткими лимитами памяти
(в первую очередь iOS Safari, где WASM-инстанс может OOM-нуть на 128 MiB) сейчас
fallback на меньшее `m` **не реализован** — пользователь на старом iPhone может
не суметь залогиниться. Это open issue в §17; решение — runtime device-detect и
per-device параметры с сохранением единого `salt_user`.

**Серверная concurrency.** Каждый `Authorize` запускает Argon2id с m=128 MiB.
Без semaphore сервер может OOM при флуде анонимных логинов — это известный
DoS-вектор; митигация сейчас — rate-limit middleware (см. §7.4). Жёсткий
concurrency-cap планируется (см. §17).

### 4.3 AEAD и AAD

- AEAD: **AES-256-GCM** через WebCrypto (нативный, constant-time).
- Nonce: 12 байт случайных (CSPRNG); полный envelope: `nonce(12) || ciphertext || tag(16)`.
- AAD для item: `item_id || version || vault_id || "item"` — защита от swap- и
  rollback-атак.
- AAD для wrapped key: `parent_id || child_id || version || "wrap"`.
- AAD для recovery wrap: `user_id || "recovery"`.

### 4.4 Blind index для поиска по title

```
title_hash = HMAC-SHA256(K_blind, lowercase(NFKC(title)))
K_blind = HKDF-SHA256(vault_key, info="oblivio/blind/v1")
```

Колонка `title_hash BYTEA` индексируется с `(user_id, title_hash)`. Точное совпадение —
без plaintext. Полнотекстовый поиск делается на клиенте после расшифровки списка.

### 4.5 Recovery

При регистрации генерируется `recovery_code` (128 бит, base32 в формате типа
`XXXX-XXXX-XXXX-XXXX-XXXX`). Клиент:

1. Выводит `recovery_key = Argon2id(recovery_code, recovery_salt, params)`.
2. Шифрует `vault_key` ключом `recovery_key` → `recovery_wrapped_vault_key`.
3. Сохраняет `recovery_salt` и `recovery_wrapped_vault_key` на сервере.
4. Показывает recovery_code пользователю **ровно один раз** для ручного копирования
   (на странице с предупреждением о том, что это последняя возможность).
   Автоматический копир в clipboard **не делаем** — clipboard может быть перехвачен
   расширениями/процессами, окно перехвата с auto-clear через 30s избыточно.
   Пользователь обязан сохранить код вне приложения (бумага, менеджер другого вендора).

При потере мастер-пароля пользователь вводит recovery_code, получает
`recovery_wrapped_vault_key + recovery_salt`, восстанавливает `vault_key`,
выбирает новый `master_password`, перешифровывает только `wrapped_vault_key`
(не сами записи) и обновляет `verifier` + `auth_key_hash`.

### 4.6 Версионирование крипто-протокола

Текущий envelope-формат: `nonce(12) || ciphertext || tag(16)`. **Версионный байт
внутри ciphertext-envelope пока не введён** — формат однозначно дешифруется
текущим алгоритмом, и любая ротация алгоритма потребует либо миграции всех
blob-ов, либо введения version-byte с decoder-registry. Это known limitation:
до первого реального протокол-апгрейда (XChaCha20-Poly1305 / post-quantum)
вводить дополнительный байт нет смысла, но при апгрейде он должен появиться
вместе с reader-side dispatcher (см. §17).

Версионирование вне envelope уже есть: `user_vault.vault_key_version` и
`system_state.crypto_protocol_version` позволяют делать stepped rollout.

---

## 5. Аутентификация и сессии

### 5.1 Регистрация

```
1. Клиент: пользователь вводит email + master_password.
2. Клиент: salt_user = randbytes(16); recovery_salt = randbytes(16).
3. Клиент: master_key = Argon2id(master_password, salt_user, kdf_params).
4. Клиент: auth_key = HKDF(master_key, "oblivio/auth/v1", email).
5. Клиент: vault_key = randbytes(32).
6. Клиент: wrapped_vault_key = AES-GCM(master_key, vault_key, AAD="vault-wrap").
7. Клиент: verifier = AES-GCM(master_key, "oblivio-verify").
8. Клиент: recovery_code = generate(); recovery_key = Argon2id(recovery_code, recovery_salt).
9. Клиент: recovery_wrapped_vault_key = AES-GCM(recovery_key, vault_key, AAD="recovery").
10. Клиент: POST AuthService.Register {
        email, salt_user, kdf_params, auth_key,
        verifier, wrapped_vault_key,
        recovery_salt, recovery_wrapped_vault_key,
    }
11. Сервер: argon2id(auth_key) → user_auth.password_hash; всё остальное сохраняется как есть.
12. Сервер: генерирует email-verification token, отправляет письмо.
13. Клиент: показывает recovery_code один раз, требует подтверждения.
```

Никогда не уходят на сервер: `master_password`, `master_key`, `vault_key`, `recovery_key`.

### 5.2 Login

```
1. POST AuthService.GetKDFParams { email } → { salt_user, kdf_params }
   • Anonymous endpoint, rate-limited per-IP И per-email (5/мин).
   • Возвращает фиктивные стабильные параметры для несуществующих email
     (защита от user enumeration).
2. Клиент: master_key = Argon2id(master_password, salt_user, kdf_params).
3. Клиент: auth_key = HKDF(master_key, "oblivio/auth/v1", email).
4. POST AuthService.Authorize { email, auth_key, totp_code? } → { challenge_for_2fa? | tokens }
   Сервер сравнивает argon2id(auth_key) с user_auth.password_hash
   через subtle.ConstantTimeCompare. Для несуществующего email сервер
   всё равно прогоняет argon2id против фиксированного dummy-hash
   (lazy-инициализируется при первом обращении), чтобы выровнять время
   ответа и закрыть timing-канал user-enumeration на Authorize.
5. Если 2FA включён, сервер требует TOTP/WebAuthn перед выдачей токенов.
6. После успеха сервер возвращает:
   { access_token, refresh_token, expires_at, device_id,
     verifier, wrapped_vault_key }
7. Клиент: master_key.decrypt(verifier) == "oblivio-verify"? — sanity check.
8. Клиент: vault_key = master_key.decrypt(wrapped_vault_key).
9. Клиент: master_key затирается (memguard / typed array fill 0 / GC hint).
10. Клиент: vault_key хранится в Zustand store **в RAM**, никогда не пишется в localStorage/IndexedDB.
```

### 5.3 2FA: TOTP

- Secret 20 байт (160 бит).
- TOTP secret хранится **зашифрованным** в `entry_blob` отдельной "auth"-записи
  пользователя ИЛИ как поле основной записи. Сервер не видит plaintext-секрета.
- TOTP при login: пользователь вводит код, клиент локально сверяет с локальным
  `validateTOTP(secret, code)` — но это бесполезно для server-side проверки.
- **Поэтому TOTP для login делаем серверным**: при включении 2FA клиент шифрует
  `totp_secret` ключом `K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1")` и шлёт
  на сервер. Сервер сохраняет — это технически server-side, **но secret выводится
  из auth_key, который сервер не может развернуть в master_password**. В момент login
  клиент посылает `auth_key` → сервер выводит `K_login_totp` → расшифровывает secret →
  проверяет код. После проверки К_login_totp сразу затирается из memguard.
- TOTP-секреты **внутри vault** (для генерации кодов любых сторонних сервисов) шифруются
  обычным `vault_key/item_key` и расшифровываются только клиентом — это zero-knowledge.

**Честная оценка модели безопасности login-TOTP.** Это **не** zero-knowledge:
в момент login сервер получает `auth_key`, выводит `K_login_totp`, расшифровывает
`totp_secret` и видит plaintext в RAM на время сравнения. Honest-but-curious
оператор с доступом к процессу может его перехватить. Защита держится на двух
свойствах: (а) секрет в БД зашифрован ключом, выводимым из `auth_key` — атакующий
с одним только dump БД не получает секрет; (б) plaintext существует короткое
время в derived-key buffer (memguard) и сразу затирается. Альтернатива (client-side
TOTP с PAKE) — отложена. Не позиционировать login-TOTP как ZK-фичу.

**Гэп с ChangeMasterPassword / Recovery.** `K_login_totp` выводится из `auth_key`.
При смене master_password (и, соответственно, `auth_key`) старый
`encrypted_secret` в `user_login_totp` становится нерасшифровываемым. Сейчас
handler-ы `ChangeMasterPassword` и `RecoveryComplete` это не обрабатывают —
2FA «молча ломается» до повторного setup. Целевая правка: клиент при смене
пароля заранее расшифровывает старый secret своим текущим `auth_key`,
перешифровывает новым `K_login_totp` и передаёт новое значение в payload
ротации. См. §17.

### 5.4 2FA: WebAuthn / Passkey

- Library: `github.com/go-webauthn/webauthn` на сервере, нативный браузерный API на клиенте.
- Origin binding защищает от phishing.
- Регистрация: клиент → `Register Begin` → challenge → `navigator.credentials.create` →
  `Register Finish` с attestation → сервер хранит `credential_id`, `public_key`,
  `sign_count` в `user_webauthn_credentials`.
- Аутентификация: после первичной проверки `auth_key` сервер выдаёт challenge для WebAuthn,
  клиент → `navigator.credentials.get` → assertion → сервер проверяет подпись.
- WebAuthn — это **только аутентификация** (proof of identity), не источник ключей
  расшифровки. `vault_key` всё равно требует `master_password`.

**User Verification.** Сейчас RP-конфиг не форсит `UserVerification: required` —
действует библиотечный default ("preferred"). Это значит, что passkey без
PIN/biometric тоже принимается, что слабее заявленной модели для secret-manager.
Целевая правка — `AuthenticatorSelection.UserVerification = required` для
Begin/Finish; см. §17.

### 5.5 Recovery flow

```
1. POST AuthService.GetRecoveryParams { email } → { recovery_salt, kdf_params }
2. Клиент: recovery_key = Argon2id(recovery_code, recovery_salt, kdf_params).
3. POST AuthService.RecoveryStart { email, recovery_proof = HKDF(recovery_key, "auth/v1") }
   Сервер сравнивает с argon2(recovery_proof) (хранится отдельно).
4. Сервер возвращает recovery_wrapped_vault_key.
5. Клиент: vault_key = recovery_key.decrypt(recovery_wrapped_vault_key).
6. Клиент: пользователь задаёт новый master_password.
7. Клиент: новый master_key, новый verifier, новый wrapped_vault_key, новый auth_key.
8. POST AuthService.RecoveryComplete с новыми артефактами.
9. Сервер инвалидирует все сессии, требует re-login через WebAuthn (если был включён).
```

Recovery не перешифровывает записи — только обёртку `vault_key`. **Известная
неполнота:** `user_login_totp.encrypted_secret` остаётся зашифрованным старым
`K_login_totp`, выведенным из старого `auth_key`, — после recovery TOTP-вход
сломан и требует повторного setup. Это та же проблема, что в §5.3, и решается
одинаково: клиент перешифровывает secret и передаёт в `RecoveryComplete`.

### 5.6 Сессии

Реализуем через `goauth` skill: `tokenmanager.Manager[SessionData]` × 2 (access + refresh),
session store в Postgres (отдельная таблица `auth_sessions`). Поля `SessionData`:
`user_id, device_id, device_type, device_name, ip, country, created_at`.
По device_id одно устройство — одна сессия; пользователь видит и может терминировать.

Refresh ротация: при `RefreshToken` старая пара отзывается, выдаётся новая. Reuse →
ошибка → инвалидация всей сессии.

**Транспорт токенов: только Bearer.** Auth-middleware принимает токены
исключительно из заголовка `Authorization: Bearer <token>`. Cookies для auth
не используются (изначально планировались `__Host-Auth=`, но в итоге выбран
единый механизм для web/mobile/extension). Это упрощает CSRF-модель
(`Authorization` не отправляется браузером автоматически), но требует, чтобы
WebUI хранил access-token в RAM (Zustand) и refresh-token — в защищённом
storage. Side-effect: если в будущем потребуются HttpOnly cookies, понадобится
явная CSRF-защита (origin/sec-fetch-site check).

---

## 6. Postgres-схема

Все таблицы (кроме `users` и `user_auth`) имеют `user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`.

### 6.1 Базовое

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;       -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;         -- email case-insensitive
```

### 6.2 Пользователи и аутентификация

```sql
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               CITEXT UNIQUE NOT NULL,
    email_verified_at   TIMESTAMPTZ,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_kdf_params (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    salt_user           BYTEA NOT NULL,
    argon2_t            INT  NOT NULL,
    argon2_m_kib        INT  NOT NULL,
    argon2_p            INT  NOT NULL,
    algo                TEXT NOT NULL DEFAULT 'argon2id'
);

CREATE TABLE user_auth (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- argon2id(auth_key), формат PHC
    auth_key_hash       TEXT NOT NULL,
    failed_attempts     INT  NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ
);

CREATE TABLE user_vault (
    user_id                       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    verifier                      BYTEA NOT NULL,        -- AES-GCM(master_key, "oblivio-verify")
    wrapped_vault_key             BYTEA NOT NULL,        -- AES-GCM(master_key, vault_key)
    vault_key_version             INT   NOT NULL DEFAULT 1,
    -- recovery
    recovery_salt                 BYTEA NOT NULL,
    recovery_wrapped_vault_key    BYTEA NOT NULL,
    recovery_proof_hash           TEXT  NOT NULL,        -- argon2id(HKDF(recovery_key,"auth/v1"))
    recovery_used_at              TIMESTAMPTZ
);

CREATE TABLE user_login_totp (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- AES-GCM(K_login_totp, totp_secret), где K_login_totp = HKDF(auth_key,"login-totp/v1")
    encrypted_secret    BYTEA NOT NULL,
    nonce               BYTEA NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_webauthn_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    credential_id       BYTEA UNIQUE NOT NULL,
    public_key          BYTEA NOT NULL,
    aaguid              BYTEA,
    sign_count          BIGINT NOT NULL DEFAULT 0,
    transports          TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ
);
CREATE INDEX idx_webauthn_user_id ON user_webauthn_credentials(user_id);
```

### 6.3 Сессии

```sql
CREATE TABLE auth_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL,
    device_type         TEXT NOT NULL,         -- web, ios, android, desktop, extension
    device_name         TEXT,
    ip                  INET,
    country             TEXT,
    access_token_hash   BYTEA NOT NULL,        -- SHA-256(token); токен в виде raw не храним
    refresh_token_hash  BYTEA NOT NULL,
    access_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, device_id)
);
CREATE INDEX idx_sessions_refresh_hash ON auth_sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_access_hash  ON auth_sessions(access_token_hash)  WHERE revoked_at IS NULL;
```

### 6.4 Vault, проекты, записи, заметки

```sql
CREATE TABLE projects (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- AES-GCM(item_key_project, JSON{name, description, color, icon}), AAD=project_id|version|vault|"project"
    encrypted_blob      BYTEA NOT NULL,
    wrapped_item_key    BYTEA NOT NULL,
    name_hash           BYTEA NOT NULL,
    version             INT  NOT NULL DEFAULT 1,
    sort_order          INT  NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_projects_user_id   ON projects(user_id);
CREATE INDEX idx_projects_name_hash ON projects(user_id, name_hash);

-- Заметки — это просто entry с kind='note' (другой набор полей в encrypted_blob).
CREATE TYPE entry_kind AS ENUM ('login', 'totp', 'card', 'identity', 'ssh_key', 'note');

CREATE TABLE entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id          UUID REFERENCES projects(id) ON DELETE SET NULL,
    kind                entry_kind NOT NULL DEFAULT 'login',
    -- AES-GCM(item_key, JSON{title, username, password, url, notes_md, totp_secret, custom_fields…})
    encrypted_blob      BYTEA NOT NULL,
    wrapped_item_key    BYTEA NOT NULL,
    title_hash          BYTEA NOT NULL,
    -- метаданные для list-view БЕЗ plaintext (например favicon-domain hash для login).
    -- Замечание: domain_hash вычисляется на клиенте из K_blind. Низкая cardinality
    -- доменов делает его уязвимым к словарной атаке если когда-нибудь утечёт K_blind.
    domain_hash         BYTEA,
    has_totp            BOOLEAN NOT NULL DEFAULT FALSE,
    is_favorite         BOOLEAN NOT NULL DEFAULT FALSE,
    version             INT  NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_entries_user_id    ON entries(user_id);
CREATE INDEX idx_entries_project_id ON entries(project_id);
CREATE INDEX idx_entries_kind       ON entries(user_id, kind);
CREATE INDEX idx_entries_title_hash ON entries(user_id, title_hash);
CREATE INDEX idx_entries_updated_at ON entries(user_id, updated_at DESC);
```

### 6.5 Audit log

```sql
CREATE TYPE audit_action AS ENUM (
    'register','login','logout','refresh','password_change',
    'recovery_start','recovery_complete',
    'webauthn_register','webauthn_remove','totp_enable','totp_disable',
    'project_create','project_update','project_delete',
    'entry_create','entry_update','entry_view','entry_delete',
    'session_terminate'
);

CREATE TABLE audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    action              audit_action NOT NULL,
    target_id           UUID,
    ip                  INET,
    user_agent          TEXT,
    metadata            JSONB,
    -- Hash chain: prev_hash для защиты от удаления записей админом
    prev_hash           BYTEA NOT NULL,
    self_hash           BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_user_id    ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_action     ON audit_log(action, created_at DESC);
```

`self_hash = SHA-256(prev_hash || row_canonical_json)`. Genesis `prev_hash` — это
32 нулевых байта, сидится при первой миграции и хранится в `system_state` под
ключом `audit_chain_head`. Сервер обновляет это значение под row-lock после
каждой записи; раз в сутки фоновый job пересчитывает цепочку и сравнивает с
кешированным head — alarm при mismatch.

**Ограничение по threat-model.** Head живёт в той же Postgres, что и сами строки
аудита. Это защищает от случайной порчи и от атакующего, который пишет в
audit_log в обход аппликейшна (RLS-обход → strict-чек), но не от
противника с полным DB-доступом, который пересчитает chain и переустановит
head. Внешний якорь (s3 object lock / подпись приватным ключом из Vault transit /
external transparency witness) — целевое улучшение, не реализовано. См. §17.

### 6.6 Системное состояние и rate limiting

```sql
CREATE TABLE system_state (
    key                 TEXT PRIMARY KEY,
    value               JSONB NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Ключи: 'audit_chain_head', 'jwt_keys_kid', 'crypto_protocol_version'.

CREATE TABLE rate_limit_buckets (
    bucket_key          TEXT PRIMARY KEY,        -- "auth_login:<email>", "kdf_params:<ip>", …
    tokens              REAL NOT NULL,
    last_refill_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Где сейчас живут счётчики.** Таблица `rate_limit_buckets` присутствует в
схеме, но активный rate-limit реализован in-memory (token-bucket на
`golang.org/x/time/rate`) — выбрано в Sprint 4, чтобы избежать DB round-trip
на каждом анонимном запросе. Минус: счётчики не переживают рестарт и не
работают в multi-node deploy. Таблица оставлена под будущую миграцию на
shared store (Postgres или Redis), см. §17.

### 6.7 RLS как defence-in-depth

```sql
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_owner ON projects
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- то же для entries, user_webauthn_credentials, auth_sessions, audit_log
```

**Инвариант — обязательная транзакция.** `SET LOCAL` действует только внутри
транзакции, поэтому каждый RLS-чувствительный запрос **обязан** идти через
ConnectRPC-интерсептор, который для каждого вызова открывает транзакцию,
выполняет `SET LOCAL app.current_user_id = $userID` и кладёт `pgx.Tx` в
контекст. Репозитории работают с tx из контекста, никогда не вызывая
`pool.Query` напрямую под RLS-таблицами. Системные операции (без user-scope)
идут через отдельный wrapper, который выставляет `app.bypass_rls = on` в
своей собственной транзакции. Чтение `current_setting` использует missing_ok
вариант, чтобы отсутствие значения возвращало пустую строку, а не падало.

### 6.8 Удаление аккаунта

Все удаления — **физические**, без `deleted_at`. `DELETE FROM users WHERE id = $1`
каскадно удаляет vault, проекты, записи, сессии, audit-log пользователя. После
удаления сервер не имеет ни ciphertext-а, ни обёртки `vault_key` для этого юзера.

**Честная оговорка про "crypto-shred".** Это не криптографический shred в строгом
смысле: и `wrapped_vault_key`, и ciphertext пользователя одновременно
присутствуют в **бэкапах** Postgres. Любой, кто получит бэкап + знает (или
сбрутит) `master_password` или `recovery_code` пользователя, восстановит данные
до тех пор, пока бэкап не истечёт (типично 90 дней). Это «delete + ожидание
retention», а не «уничтожение ключа». Реальный crypto-shred требует
per-user envelope-ключа, который физически живёт **вне** Postgres (например,
в Vault transit), и при `DeleteMe` уничтожается там же — тогда даже свежий
бэкап БД нечитаем мгновенно. Эта модель — целевое улучшение, см. §17.

### 6.9 Миграции

`golang-migrate` через `iofs` (как уже подключено в `cmd/oblivio/start.go:152-168`). Файлы:

```text
sql/migrations/001_init_users_and_auth.up.sql   / .down.sql
sql/migrations/002_vault_and_sessions.up.sql    / .down.sql
sql/migrations/003_projects_and_entries.up.sql  / .down.sql
sql/migrations/004_audit_and_system.up.sql      / .down.sql
sql/migrations/005_rls_policies.up.sql          / .down.sql
sql/migrations/006_rate_limit.up.sql            / .down.sql
```

Существующие 001–002 (`wallets`, `delegation_orders`, `settings`) удаляются полностью.

---

## 7. ConnectRPC API

### 7.1 Структура proto

```text
proto/
  buf.yaml
  buf.gen.yaml
  oblivio/v1/
    auth.proto             # AuthService
    vault.proto            # VaultService (verifier/wrapped_vault_key, password change)
    projects.proto         # ProjectsService
    entries.proto          # EntriesService (включая kind='note')
    webauthn.proto         # WebAuthnService
    sessions.proto         # SessionsService (list + terminate)
    audit.proto            # AuditService (read-only для пользователя)
    common.proto           # Pagination, Cursor, Timestamp aliases
```

`buf.gen.yaml` генерирует:

- `internal/api/pb/**/*.connect.go`, `*.pb.go` (Go)
- `frontend/src/api/gen/**/*_pb.ts`, `*_connect.ts` (TS через `@bufbuild/protoc-gen-es`)

### 7.2 Сервисы и методы (упрощённо, JSON для краткости)

```text
AuthService
  Register({email, salt_user, kdf_params, auth_key, verifier,
            wrapped_vault_key, recovery_salt, recovery_wrapped_vault_key,
            recovery_proof_hash}) → {user_id, email_verification_required}
  VerifyEmail({token}) → {}
  ResendVerification({email}) → {}                                  // anonymous, rate-limited
  GetKDFParams({email}) → {salt_user, kdf_params}                   // anonymous, rate-limited
  Authorize({email, auth_key, totp_code?, device_info}) →
        {auth_payload | mfa_challenge}
  CompleteWebAuthn({mfa_session_id, assertion}) → {auth_payload}
  RefreshToken({refresh_token, device_info}) → {auth_payload}
  Logout({}) → {}                                                   // requires auth
  ChangeMasterPassword({old_auth_key, new_auth_key, new_salt_user, new_kdf_params,
                        new_verifier, new_wrapped_vault_key}) → {}  // requires auth + reauth
  GetRecoveryParams({email}) → {recovery_salt, kdf_params}          // anonymous, rate-limited
  RecoveryStart({email, recovery_proof}) → {recovery_session_id, recovery_wrapped_vault_key}
  RecoveryComplete({recovery_session_id, new_master_password_artifacts…}) → {}

VaultService
  GetMyKeys() → {verifier, wrapped_vault_key, vault_key_version}
  GetMe() → {user, totp_enabled, webauthn_credentials_count, …}
  DeleteMe({reason?}) → {}                                          // crypto-shred

WebAuthnService
  RegisterBegin() → {challenge, options}
  RegisterFinish({attestation, name}) → {credential_id}
  ListCredentials() → {credentials[]}
  RemoveCredential({credential_id}) → {}

LoginTOTPService
  Setup({encrypted_secret, nonce}) → {}                             // ZK-encrypted, см. 5.3
  Enable({totp_code}) → {}
  Disable({totp_code | webauthn_assertion}) → {}

ProjectsService
  List({pagination}) → {projects[]}
  Get({id}) → {project}
  Create({encrypted_blob, wrapped_item_key, name_hash, sort_order}) → {project}
  Update({id, expected_version, encrypted_blob, wrapped_item_key, name_hash}) → {project}
  Delete({id, expected_version}) → {}
  Reorder({ordered_ids[]}) → {}

EntriesService                                                     // включая kind='note'
  List({project_id?, kind?, query_hashes?, cursor, limit}) → {entries_meta[], next}
  GetByIds({ids[]}) → {entries[]}                                  // включает encrypted_blob
  Create({project_id?, kind, encrypted_blob, wrapped_item_key,
          title_hash, domain_hash?, has_totp, is_favorite}) → {entry}
  Update({id, expected_version, …}) → {entry}
  Delete({id}) → {}
  ToggleFavorite({id, is_favorite}) → {}

SessionsService
  List() → {sessions[]}
  Terminate({session_id}) → {}
  TerminateAllExceptCurrent() → {}

AuditService
  List({pagination, action_filter?, from?, to?}) → {records[], next}
```

### 7.3 Аутентификация в API

В oblivio один аккаунт = один пользователь, ролевой модели нет. RBAC-библиотека
`rbacconnect` **не используется**. Достаточно простой авторизации «требуется
аутентифицированный пользователь» с явным списком публичных процедур.

`internal/api/middleware/auth.go` — `connectrpc.com/authn.Middleware`:

1. По URL извлекает имя процедуры.
2. Если процедура входит в anonymous-allowlist (`AuthService.Register`,
   `AuthService.VerifyEmail`, `AuthService.ResendVerification`,
   `AuthService.GetKDFParams`, `AuthService.Authorize`,
   `AuthService.CompleteWebAuthn`, `AuthService.RefreshToken`,
   `AuthService.GetRecoveryParams`, `AuthService.RecoveryStart`,
   `AuthService.RecoveryComplete`, healthcheck) — пропускает без аутентификации.
3. Иначе извлекает Bearer-токен, валидирует через
   `tokenmanager.Manager[SessionData].Authenticate`, читает пользователя из
   `auth_sessions` + `users`, кладёт `UserDataContext` в `context.Context`.
4. После handler-а каждый репозиторий выполняет
   `SET LOCAL app.current_user_id = $userID` — RLS обеспечивает изоляцию.

Anonymous-allowlist живёт константой в `internal/api/middleware/auth.go` и
покрывается тестом, проверяющим, что любая новая процедура по умолчанию
требует Bearer.

### 7.4 Серверная защита эндпоинтов

- **Rate limiting**: per-IP и per-email на `Authorize`, `GetKDFParams`,
  `GetRecoveryParams`, `RecoveryStart`. Реализация — in-memory token-bucket
  (`golang.org/x/time/rate`); single-node only, см. §6.6 и §17.
- **Audit**: для всех мутаций и для `EntriesService.GetByIds` / `NotesService.GetByIds`
  (расшифровка — критичное событие).
- **Idempotency**: header `Idempotency-Key` на `Create`/`Update` записей.
  Хранилище — таблица `idempotency_keys` в Postgres, TTL 24 часа; ключ скоупится
  per-user/per-procedure.
- **Optimistic concurrency**: `expected_version` в `Update`/`Delete`.
- **Prevent enumeration**: `GetKDFParams` для несуществующих email возвращает
  стабильные псевдо-параметры (HMAC от email + server-secret); `Authorize` для
  несуществующего email прогоняет argon2id против фиксированного dummy-hash,
  чтобы выровнять время ответа.
- **Bot prevention**: на `Register`, `Authorize` — опциональный hCaptcha/Turnstile (config-flag).
  Без него open-registration уязвим к argon2-amplified DoS — рекомендуется
  включать в любой публичной деплой-цепочке.

---

## 8. Серверный Go-код

### 8.1 Layout

```
cmd/oblivio/                    main, version, start, migrations, config
internal/
  api/
    server.go                   ConnectRPC + HTTP mux + headers + CORS
    auth/
      auth_service.go
      kdf_helpers.go
      rate_limiter.go
    webauthn/
      webauthn_service.go
    projects/
      projects_service.go
    entries/
      entries_service.go        включая kind='note'
    sessions/
      sessions_service.go
    audit/
      audit_service.go
    middleware/
      auth.go                   connectrpc.com/authn + anonymous allowlist
      audit_log.go              запись каждой мутации
      security_headers.go       CSP, COOP, COEP, HSTS, X-CT-O, Referrer-Policy
      idempotency.go
    pb/                         (gen) ConnectRPC stubs
  auth/
    manager.go                  tokenmanager wrapper по goauth-skill
    service.go                  Service[U IUser] generic
    argon2.go                   argon2id PHC encode/parse (forked из текущего auth/password.go)
    sessions.go                 session repo + revoke + rotate
    secrets.go                  загрузка/генерация JWT keys, memguard.LockedBuffer
  audit/
    chain.go                    hash-chain helpers, verify job
    repo.go
  crypto/                       МИНИМАЛЬНЫЙ серверный набор:
    aead.go                     AES-GCM helpers для encrypted_blob операций (НЕ для расшифровки)
    hkdf.go                     HKDF-SHA256
    secure.go                   memguard wrappers (LockedBuffer, GetSlice, Destroy)
  config/
    config.go                   расширить: AuthConfig, VaultConfig, RateLimitConfig, CORSConfig
    load.go
  store/                        pgxgen-сгенерированные репозитории + extras
    repos/
      users/
      user_kdf_params/
      user_auth/
      user_vault/
      user_login_totp/
      user_webauthn_credentials/
      auth_sessions/
      projects/
      entries/
      audit_log/
      system_state/
      rate_limit_buckets/
    store.go                    aggregate
  jobs/
    service.go                  River queue (как сейчас)
    audit_chain_verify.go       periodic: 1/day
    rate_limit_gc.go            periodic: 1/h
    sessions_gc.go              expired sessions cleanup
    pwned_password_check.go     (опционально) HIBP API offline
  metrics/                      prometheus counters: login_success/_failure, refresh_*, etc
proto/                          buf workspace
sql/
  migrations/
  queries/
  pgxgen.yaml
secrets/                        gitignored — (генерация при первом запуске, если Vault недоступен)
```

### 8.2 Зачистка существующего кода

**Удалить полностью:**

- `internal/storage/` (Pebble + seal.go + users.go) — заменено Postgres + audit-chain.
- `internal/tpm/` — TPM-stub не используется (Vault для admin secret).
- `internal/keys/` — переписать в `internal/auth/secrets.go`.
- `internal/api/server.go` (текущий gofiber) — заменён ConnectRPC.
- `internal/store/repos/{wallets,delegation_orders,settings}/` — из другого проекта.
- `sql/migrations/001_wallets_*`, `002_delegation_*` — заменяются.
- `sql/queries/{wallets,delegation_orders,settings}/` — заменяются.
- `internal/auth/totp.go` (server-side TOTP) — оставить только для server-login-TOTP
  и переименовать в `internal/auth/login_totp.go`.

**Оставить и переиспользовать:**

- `cmd/oblivio/{main,start,migrations,config,version,utils}.go` — каркас CLI и mx-launcher.
- `internal/auth/password.go` — функции `HashPassword`/`VerifyPassword` (Argon2id PHC),
  убрать `bcrypt` упоминание (его нет, всё ок), параметры выровнять по §4.2.
- `internal/config/{config.go,load.go}` — расширить AuthConfig/VaultConfig.
- `internal/jobs/service.go` — каркас River, наполнить новыми воркерами.
- `internal/metrics/metrics.go` — добавить новые счётчики.
- `pkg/postgres/postgres.go` — без изменений.
- `embed.go`, `templates/`, `Makefile`, `dev/` — без изменений.

**Удалить из `go.mod`:** `gofiber/v2`, `valyala/fasthttp`, `goccy/go-yaml` (заменён `xconfigyaml`),
`shopspring/decimal` (для крипто-проекта без денег не нужен), `huandu/go-sqlbuilder`
(pgxgen достаточно).

**Добавить в `go.mod`:**

- `connectrpc.com/connect`
- `connectrpc.com/authn`
- `github.com/sxwebdev/tokenmanager`
- `github.com/awnumar/memguard`
- `github.com/go-webauthn/webauthn`
- `github.com/sxwebdev/xutils` (если ещё нет)
- `golang.org/x/time/rate`

### 8.3 memguard в серверном коде

Под `memguard.LockedBuffer` сейчас защищены:

- JWT access signing key
- JWT refresh signing key
- Производный `K_login_totp` на время одной операции дешифровки (создаётся,
  используется, `Destroy()` сразу после)

**Чего memguard не защищает.** Plaintext, который Go-stdlib `crypto/aes` принимает
на вход (или возвращает из `Open`) — обычный heap-`[]byte`, копия в нелокированной
памяти. То же для строк (`string` иммутабелен и его нельзя гарантированно
обнулить). MFA-store (короткоживущие challenge-объекты с `auth_key`) сейчас
не обёрнут — оправдание: TTL ~10 минут, store in-memory без персистенса.
Заявление «memguard для всего критичного» **переоценено**: защита эффективна
от swap/coredump в простое, а не для plaintext в момент использования.

`memguard.CatchInterrupt()` — чистит залоченные буферы при SIGINT/SIGTERM.

**Self-hosted без Vault.** Если ENV-переменные с access/refresh seed-ами пусты,
сервис при первом старте генерирует случайные 32-байтные ключи и пишет их в
файл `secrets.json` под mode 0600. Файл хранится **в plaintext** (base64).
Это приемлемо для single-node dev и for-self deployments, где доступ к диску
охраняется ОС, но для production рекомендуется передавать seed-ы из Vault через
ENV (`vault.enabled: true`). См. §17.

### 8.4 mx launcher и порядок старта

```go
lnc.ServicesRunner().Register(
    launcher.NewService(launcher.WithService(pg),         launcher.WithStartupPriority(1)),
    launcher.NewService(launcher.WithService(secrets),    launcher.WithStartupPriority(2)),
    launcher.NewService(launcher.WithService(jobService), launcher.WithStartupPriority(3)),
    launcher.NewService(launcher.WithService(apiServer),  launcher.WithStartupPriority(4)),
)
```

LIFO shutdown гарантирует: сначала останавливается API, потом jobs, потом memguard
(destroy buffers), потом Postgres.

### 8.5 Vault интеграция

Уже есть `xconfig/sourcers/xconfigvault`. Конфиг:

```yaml
vault:
  address: https://vault.internal:8200
  auth:
    method: approle # approle | kubernetes | token
    role_id_path: /run/secrets/vault-role-id
    secret_id_path: /run/secrets/vault-secret-id
  paths:
    admin_secret: secret/data/oblivio/admin
    jwt_access_seed: secret/data/oblivio/jwt-access
    jwt_refresh_seed: secret/data/oblivio/jwt-refresh
```

При старте: получить admin_secret и seeds, положить в `memguard.LockedBuffer`,
вывести JWT-ключи через HKDF от seed (для возможности ротации без перевыдачи).

Self-hosted сценарий (без Vault): `secrets.json` в `data/` с правами 0600,
генерируется на первом запуске. Конфигурация: `vault.enabled: false`.

---

## 9. Клиентская крипто-библиотека `@oblivio/crypto`

Изолированный TypeScript-пакет внутри `frontend/packages/crypto/`. Требования:

- Никаких зависимостей кроме `argon2-browser` (или собственной WASM-сборки `argon2-cffi`)
  и нативного WebCrypto.
- 100% покрытие тестами через Vitest (round-trip для всех слоёв).
- Тестовые векторы синхронизированы с `crypto/aead.go` на сервере
  (для Encrypt → server stores → Decrypt path-через-network).
- Lockfile-lint и `npm audit --audit-level=high` блокируют CI.

### 9.1 API

```typescript
// types.ts
export type Argon2Params = { t: number; m_kib: number; p: number };
export type WrappedKey = { ciphertext: Uint8Array; nonce: Uint8Array };
export type ItemEnvelope = {
  blob: Uint8Array; // nonce || ciphertext || tag
  wrapped_key: WrappedKey;
  aad: Uint8Array;
};

// kdf.ts
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: Argon2Params,
): Promise<CryptoKey>;
export async function deriveAuthKey(
  masterKey: CryptoKey,
  email: string,
): Promise<Uint8Array>;
export async function deriveBlindIndexKey(
  vaultKey: CryptoKey,
): Promise<CryptoKey>;
export async function deriveLoginTotpKey(
  authKey: Uint8Array,
): Promise<CryptoKey>;

// vault.ts
export async function generateVaultKey(): Promise<CryptoKey>;
export async function wrapVaultKey(
  masterKey: CryptoKey,
  vaultKey: CryptoKey,
): Promise<WrappedKey>;
export async function unwrapVaultKey(
  masterKey: CryptoKey,
  wrapped: WrappedKey,
): Promise<CryptoKey>;
export async function makeVerifier(masterKey: CryptoKey): Promise<Uint8Array>;
export async function checkVerifier(
  masterKey: CryptoKey,
  verifier: Uint8Array,
): Promise<boolean>;

// item.ts
export async function generateItemKey(): Promise<CryptoKey>;
export async function wrapItemKey(
  vaultKey: CryptoKey,
  itemKey: CryptoKey,
  aad: Uint8Array,
): Promise<WrappedKey>;
export async function unwrapItemKey(
  vaultKey: CryptoKey,
  wrapped: WrappedKey,
  aad: Uint8Array,
): Promise<CryptoKey>;
export async function encryptBlob(
  itemKey: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array>;
export async function decryptBlob(
  itemKey: CryptoKey,
  blob: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array>;

// blind.ts
export async function blindIndex(
  blindKey: CryptoKey,
  value: string,
): Promise<Uint8Array>;

// totp.ts
export function generateTotpCode(secret: string, t?: Date): string; // RFC 6238
export function totpRemainingSeconds(period?: number, t?: Date): number;

// recovery.ts
export function generateRecoveryCode(): string; // 25 групп по 5 base32

// password-gen.ts
export function generatePassword(opts: GenOpts): string;
export function generatePassphrase(words: number): string; // EFF wordlist

// memory.ts (best-effort на browser)
export function zeroize(view: Uint8Array): void; // заполнить нулями
```

### 9.2 Multi-thread Argon2id

Требует HTTP-заголовков от сервера (статика и API):

```
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

Иначе — fallback на single-thread (т.е. `p=1` через флаг `forceSingleThread` в Argon2Params).

### 9.3 Обнуление чувствительных данных

WebCrypto `CryptoKey` нельзя гарантированно обнулить (хранится в браузерном окружении).
Стратегия:

- Хранить минимум key-material в виде `Uint8Array` (зануляются явно).
- `CryptoKey` создавать с `extractable=false` где возможно.
- При lock vault — установить все ссылки в null, попросить GC.
- Проверка через DevTools, что в snapshot нет plaintext-полей.

---

## 10. Frontend (React + Vite + Tailwind 4 + shadcn)

### 10.1 Текущее состояние и план

Уже установлено: React 19, Vite 8, Tailwind 4, shadcn-cli, base-ui. Нужно добавить:

- `@tanstack/react-router`, `@tanstack/react-query`
- `@bufbuild/connect-web`, `@bufbuild/protobuf`, `@connectrpc/connect-query`
- `zustand`, `zustand/middleware/persist`
- `argon2-browser` (или собственная сборка)
- `@simplewebauthn/browser`
- `qrcode.react` (для регистрации TOTP)
- `react-hook-form`, `zod`
- `@oblivio/crypto` (локальный пакет)

`pnpm-workspace.yaml` уже создан, добавить пакет `packages/crypto`.

### 10.2 Структура `frontend/src`

```
frontend/
  packages/
    crypto/                       Изолированный crypto-пакет (см. §9)
  src/
    api/
      gen/                        ConnectRPC TS-стабы (buf)
      client.ts                   Transport + interceptor (Bearer + 401-retry)
    stores/
      auth.ts                     Zustand persist(session, deviceId)
      vault.ts                    Zustand НЕ-persist (vault_key, dirty caches)
      ui.ts
    routes/                       TanStack Router file-based
      __root.tsx
      _public/
        login.tsx
        register.tsx
        recover.tsx
        verify-email.tsx
      _auth/                      protected (redirect → /login if not auth)
        layout.tsx                + header, sidebar, lock UI
        index.tsx                 dashboard
        projects/
          index.tsx               list
          $projectId.tsx          detail
        entries/
          index.tsx               единый список с фильтром по kind
          $entryId.tsx            detail (UI отличается по kind: login / note / card / …)
          new.tsx                 create (kind выбирается в форме)
        settings/
          security.tsx            password change, recovery code re-show, sessions
          two-factor.tsx          TOTP / WebAuthn
          audit-log.tsx
          danger.tsx              delete account
    components/
      ui/                         shadcn primitives
      forms/
      vault/
        EntryCard.tsx
        EntryForm.tsx
        TotpDisplay.tsx           live-обновляющийся
        PasswordField.tsx         show/hide + copy + auto-clear
        ProjectSelector.tsx
      auth/
        AutoLock.tsx              visibility/idle/blur listeners
        SessionList.tsx
    lib/
      crypto-context.tsx          React-обёртка над @oblivio/crypto (vault_key in mem)
      query-client.ts
      utils.ts
    config/
      app-config.ts
    main.tsx
    App.tsx
```

### 10.3 Auto-lock и защита

- На монтировании `_auth/layout.tsx` — `<AutoLock />`.
- Идл-таймер (по умолчанию 5 минут, конфигурируется).
- `document.visibilitychange` → стартует короткий таймер (по умолчанию 60 сек).
- `window.beforeunload` → синхронно зануляет `vault_key`.
- Любое действие, требующее `vault_key`, через хук `useVaultKey()` — если nullable,
  редиректит на экран ре-аутентификации с master_password (без полного логаута).
- DevTools detection не делается (это фикция), но в production-сборке
  `__REDUX_DEVTOOLS_EXTENSION__ = undefined`.

### 10.4 Clipboard auto-clear

```typescript
async function copySecret(text: string) {
  await navigator.clipboard.writeText(text);
  setTimeout(async () => {
    try {
      const cur = await navigator.clipboard.readText();
      if (cur === text) await navigator.clipboard.writeText("");
    } catch {
      /* permission denied */
    }
  }, 30_000);
}
```

### 10.5 Безопасные HTTP-заголовки

Сервер ставит на все ответы (включая static):

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval';
                         style-src 'self' 'unsafe-inline'; img-src 'self' data:;
                         connect-src 'self'; frame-ancestors 'none'; base-uri 'none';
                         form-action 'self'; object-src 'none'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload  (только если HSTS включён в config)
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: clipboard-read=(self), clipboard-write=(self), interest-cohort=()
```

**Известные ослабления CSP относительно идеального профиля.**

- `style-src 'unsafe-inline'` — стартовый компромисс из-за inline-стилей,
  которые иногда вставляют Tailwind 4 / shadcn-runtime. Целевая правка —
  убрать `unsafe-inline` и переехать на статический CSS-bundle.
- `require-trusted-types-for 'script'` **пока не выставляется** —
  React/TanStack Router без явных trusted-types policies ломаются. Целевая
  правка — добавить policy в bootstrap фронта и затем включить заголовок.

Snapshot-тест на security-headers фиксирует точные строки, чтобы любое
ослабление было осознанным diff-ом, а не молчаливой регрессией.

### 10.6 Embedding фронтенда

`embed.go` в корне (есть) — `//go:embed all:frontend/dist`. На production-сборке
сервер раздаёт статику + JSON ConnectRPC по одному и тому же origin. Это устраняет
CORS и упрощает CSP.

Для разработки — Vite dev server на `:5173` с прокси `/api` → `:8080`.

---

## 11. Конфигурация и запуск

### 11.1 `config.yaml`

```yaml
log:
  level: debug
  format: console
  console_colored: true

server:
  addr: ":8080"
  tls:
    cert_file: /etc/oblivio/tls/cert.pem
    key_file: /etc/oblivio/tls/key.pem
  allowed_origins: ["https://oblivio.example.com"] # пусто = same-origin only

postgres:
  host: localhost
  port: "5432"
  database: oblivio
  username: oblivio
  password: "" # из Vault или ENV
  ssl_mode: verify-full

auth:
  access_token_ttl: 20m
  refresh_token_ttl: 720h
  argon2_server:
    t: 3
    m_kib: 65536
    p: 1
  rate_limits:
    auth_login_per_email_per_min: 5
    auth_login_per_ip_per_min: 20
    kdf_params_per_ip_per_min: 30
    register_per_ip_per_hour: 5

webauthn:
  rp_id: oblivio.example.com
  rp_name: Oblivio
  rp_origin: https://oblivio.example.com

vault:
  enabled: true
  address: https://vault.internal:8200
  auth_method: approle
  role_id_path: /run/secrets/vault-role-id
  secret_id_path: /run/secrets/vault-secret-id

ops:
  metrics_addr: ":9090"
  pprof_enabled: false

jobs:
  audit_chain_verify_cron: "0 3 * * *"
  rate_limit_gc_interval: 1h
  sessions_gc_interval: 1h

email:
  provider: smtp # smtp | sendgrid | postmark
  from: no-reply@oblivio.example.com
  smtp:
    host: smtp.internal
    port: 587
    username: "" # из Vault
    password: "" # из Vault
```

`xconfig` уже подключён, теги `vault:"true"` для секретов работают.

### 11.2 Команды CLI

`cmd/oblivio/`:

- `oblivio start` — запуск сервиса (есть, наполняем).
- `oblivio migrations up|down|status` — миграции (есть).
- `oblivio admin create-user --email …` — служебная регистрация (с заранее заготовленным
  пакетом артефактов от клиентского CLI).
- `oblivio version` — есть.
- `oblivio config print` — есть.

### 11.3 Docker / docker-compose

`dev/deploy/docker-compose.yml` — обновить под Postgres 18 + Vault dev-mode +
volume для `secrets/`. Production-Dockerfile — distroless, multi-stage,
`go build -trimpath -ldflags="-s -w"`.

---

## 12. Roadmap по спринтам

### Sprint 0 — Зачистка и каркас (1–2 дня)

1. Удалить файлы из §8.2 «Удалить полностью».
2. Очистить `go.mod`, `go.sum` (`go mod tidy`).
3. Убрать `gofiber` из imports, заменить `internal/api/server.go` на ConnectRPC-каркас.
4. Заменить миграции `001-002` на пустой `001_init_users_and_auth.up.sql`.
5. `make build` зелёный, `make migrate-up` зелёный, `oblivio start` поднимается без ошибок.
6. Verify: `curl http://localhost:8080/v1/health` (или `grpcurl localhost:8080 oblivio.v1.HealthService/Check`).

### Sprint 1 — Auth core (3–4 дня)

1. proto `auth.proto`, `vault.proto`, buf.gen.
2. Миграции `001-002` (users, user_kdf_params, user_auth, user_vault, user_login_totp,
   auth_sessions).
3. pgxgen-репозитории для всех таблиц.
4. `internal/auth/manager.go` (tokenmanager wrapper).
5. `internal/api/auth/auth_service.go` — Register, GetKDFParams, Authorize, RefreshToken,
   Logout, GetMyKeys.
6. `connectrpc.com/authn` middleware, `rbacconnect` policy с anonymous-разрешением.
7. memguard для JWT keys.
8. `@oblivio/crypto` пакет (kdf, vault, item, verifier, blind, recovery).
9. Frontend: TanStack Router routes `_public/*`, `_auth/*` skeleton; Zustand auth store;
   ConnectRPC client + interceptor.
10. Login + Register пути работают end-to-end через WebUI.
11. Verify: e2e тест Register → Logout → Login → GetMe; round-trip vault_key через сервер.

### Sprint 2 — Vault data (CRUD) (3–4 дня)

1. Миграции `003-004` (projects, entries, audit_log, system_state, rate_limit_buckets).
2. proto + handlers для ProjectsService, EntriesService (включая kind='note'), AuditService.
3. RLS-политики (миграция `005`).
4. Idempotency middleware.
5. Frontend: страницы `_auth/projects`, `_auth/entries` — list / detail / create / edit / delete.
   В UI заметки = entries с фильтром по `kind='note'`.
6. Авто-обновление при создании/правке через TanStack Query invalidation.
7. Blind-index поиск по title, client-side фильтрация по полям.
8. Auto-lock + clipboard auto-clear.
9. Verify: создание/правка/просмотр/удаление; перезагрузка страницы → требует unlock;
   tampering test (изменить blob в БД через psql → клиент видит ошибку AAD).

### Sprint 3 — TOTP + WebAuthn + Recovery (3 дня)

1. TOTP-rendering для записей (live-обновление каждую секунду).
2. proto + handlers LoginTOTPService, WebAuthnService.
3. `go-webauthn/webauthn` интеграция, миграция для `user_webauthn_credentials`.
4. Frontend: страницы `_auth/settings/two-factor` (включение/отключение TOTP, регистрация
   passkey).
5. Recovery flow: `recover.tsx`, `RecoveryStart`, `RecoveryComplete`.
6. Verify: e2e — добавить TOTP, выйти, войти с TOTP; зарегистрировать passkey, выйти,
   войти с passkey; забыть пароль → восстановить через recovery_code.

### Sprint 4 — Безопасность и наблюдаемость (2–3 дня)

1. Rate limiting middleware на чувствительных эндпоинтах.
2. Audit log writer + chain verify job.
3. CSP / COOP / COEP / HSTS заголовки на проде.
4. Prometheus метрики для login/refresh/decryption events.
5. Sessions UI (`_auth/settings/security`) + terminate.
6. Audit log UI (`_auth/settings/audit-log`).
7. Crypto-shred при удалении аккаунта.
8. Verify: rate-limit срабатывает; audit chain verify проходит; CSP-violations не падают
   на легитимный flow.

### Sprint 5 — Polish, тесты, деплой (2–3 дня)

1. Vitest + Go test coverage > 80% для криптослоев.
2. Round-trip тесты Go ↔ TS (общий test-vector файл).
3. govulncheck, gosec, golangci-lint, npm audit, lockfile-lint в CI.
4. SBOM (cyclonedx-gomod).

---

## 13. Тестирование

Тестирование — **first-class требование**, не «потом». Любой PR, понижающий
покрытие критических модулей, блокируется в CI. Цели и обязательные тестовые
сценарии расписаны ниже модуль за модулем.

### 13.1 Что считается «критическим модулем»

| Модуль                                                                                                 | Сторона | Целевое покрытие                   | Почему критично                           |
| ------------------------------------------------------------------------------------------------------ | ------- | ---------------------------------- | ----------------------------------------- |
| `packages/crypto` (TS): KDF, AEAD, vault/item-key wrap, blind index, TOTP, recovery-code, password-gen | client  | ≥95%, branches ≥90%                | Любой баг = silent corruption или утечка  |
| `internal/auth/argon2` (PHC encode/parse, server-side hash auth_key)                                   | server  | ≥95%                               | Ошибка парсинга PHC = false-accept логина |
| `internal/auth/manager` (tokenmanager wrapper, Authorize/Refresh/Logout)                               | server  | ≥90%                               | Сессии — основа доверия системы           |
| `internal/auth/sessions` (session store, rotate, revoke)                                               | server  | ≥90%                               | Replay/reuse refresh = захват аккаунта    |
| `internal/auth/secrets` (memguard load/zeroize/rotate)                                                 | server  | ≥85%                               | Утечка JWT key = forged сессии            |
| `internal/audit/chain` (hash-chain append + verify)                                                    | server  | ≥95%                               | Tamper-detect — это весь смысл audit-log  |
| `internal/api/middleware/auth` (anonymous allowlist, Bearer-extract, RLS-set)                          | server  | ≥95%                               | Любой bypass = полное обхождение auth     |
| `internal/api/middleware/idempotency`                                                                  | server  | ≥85%                               | Двойной create запись                     |
| `internal/api/middleware/security_headers`                                                             | server  | snapshot ≥100% (точные строки)     | CSP-регрессия = реальный XSS              |
| `internal/auth/login_totp` (server-side TOTP с derived key)                                            | server  | ≥95%                               | Bypass 2FA                                |
| `internal/api/{auth,projects,entries,sessions,webauthn}` handlers                                      | server  | happy + edge ≥80%                  | Контракт API                              |
| pgxgen-репозитории                                                                                     | server  | базовые CRUD + RLS-isolation тесты | Изоляция между юзерами                    |

Покрытие проверяется в CI: `go test -coverprofile`, `vitest run --coverage`.
Пороги — в `Makefile` и `pnpm test` скрипте; падают, если ниже.

### 13.2 Cross-language test vectors

`testdata/crypto-vectors.json` — единый источник правды для Go и TS, который
прогоняется обеими сторонами. Тестовые векторы:

```json
{
  "argon2id": [
    {
      "password": "...",
      "salt_hex": "...",
      "t": 3,
      "m_kib": 131072,
      "p": 4,
      "hash_hex": "..."
    }
  ],
  "hkdf": [
    {
      "ikm_hex": "...",
      "info": "oblivio/auth/v1",
      "salt": "user@example.com",
      "out_hex": "..."
    }
  ],
  "aes_gcm": [
    {
      "key_hex": "...",
      "nonce_hex": "...",
      "aad_hex": "...",
      "plaintext_hex": "...",
      "ciphertext_hex": "..."
    }
  ],
  "verifier": [{ "master_key_hex": "...", "verifier_hex": "..." }],
  "blind_index": [
    { "vault_key_hex": "...", "title": "GitHub", "hash_hex": "..." }
  ],
  "totp_rfc6238": [
    {
      "secret_b32": "JBSWY3DPEHPK3PXP",
      "unix": 1234567890,
      "period": 30,
      "digits": 6,
      "code": "123456"
    }
  ],
  "recovery_wrap": [
    {
      "recovery_code": "AAAA-...",
      "salt_hex": "...",
      "vault_key_hex": "...",
      "wrapped_hex": "..."
    }
  ]
}
```

Go-тест: `internal/crypto/vectors_test.go`, TS-тест:
`packages/crypto/__tests__/vectors.test.ts` — оба обязаны давать identical output.

### 13.3 Конкретные сценарии для критических модулей

**Crypto (TS + Go round-trip):**

- KDF: соответствие RFC 9106 reference vectors; per-user различные параметры;
  `forceSingleThread` fallback даёт корректный result; пустой password → ошибка;
  invalid params → ошибка.
- AEAD: успешное seal/open; mutated ciphertext → `OperationError`;
  mutated AAD → `OperationError`; неверный nonce length → ошибка; nonce reuse —
  не должен возникать, добавить тест-генератор уникальности на 100k записей.
- Wrap/unwrap дерева ключей: master→vault→item полный round-trip; не тот AAD →
  ошибка; replay из чужого user_id → ошибка (через AAD).
- Verifier: правильный master_key проходит, неправильный — `false` без panic.
- Blind index: одинаковый title для одного `vault_key` даёт одинаковый hash;
  разный `vault_key` → разный hash; NFKC-нормализация (Юникод).
- TOTP: вектора RFC 6238 с SHA-1, period=30, digits=6,8.
- Recovery: round-trip кода, неверный код → fail decrypt.
- Password gen: длина и алфавит, отсутствие смещений (chi-squared sanity).

**Auth manager:**

- Authorize: верный auth_key → пара токенов; неверный → ошибка с тем же
  сообщением, что и для несуществующего email (anti-enumeration).
- Refresh: валидный refresh → новая пара, старый revoked. Reuse старого refresh →
  все сессии этого `user_id` revoked, метрика инкрементируется.
- Logout: токен проходит проверку, потом `Authenticate` тех же токенов → ошибка.
- Concurrency: 100 одновременных Refresh с тем же refresh — ровно один успех.
- Lockout: после `failed_attempts >= N` за интервал → `locked_until` ставится,
  Authorize возвращает `RESOURCE_EXHAUSTED`.

**Sessions:**

- Поле device_id уникально per-user; повторная авторизация с тем же device_id →
  переиспользование записи (не дубликат).
- TTL: после `access_expires_at` валидация выдаёт ошибку.
- `TerminateAllExceptCurrent` оставляет только текущую.

**Audit chain:**

- Append идёт корректно: `self_hash[i] = SHA256(prev_hash || canonical(row[i]))`,
  `prev_hash[i+1] = self_hash[i]`.
- Verify-job на чистой цепочке проходит.
- Удаление любой записи / правка — verify падает с указанием первой
  поломанной строки.
- Канонизация JSON стабильна: повторная сериализация даёт идентичные байты
  (sorted keys, no whitespace).

**Anonymous allowlist middleware:**

- Каждая публичная процедура из списка проходит без Bearer.
- Любая другая (включая будущие, добавляемые тестом-сканером всего набора
  procedure name'ов из `pb.*`) — без Bearer → `UNAUTHENTICATED`.
- Bearer с истёкшим токеном → `UNAUTHENTICATED`, не `INTERNAL`.
- После успешной auth контекст содержит `user_id`, и это значение реально
  попадает в `SET LOCAL app.current_user_id` (проверяется E2E через RLS).

**RLS isolation:**

- В тесте поднимаются два юзера A и B; запросы от A не видят и не модифицируют
  данные B даже при попытке `WHERE id = $idOfB`.

**Memguard secrets:**

- Загрузка → `Bytes()` возвращает ожидаемое; после `Destroy()` доступ panics.
- Ротация: новые подписи проходят, старые остаются валидны до `expires_at`.

**Security headers:**

- Snapshot-тест: каждый ожидаемый header присутствует точной строкой.
- Любой запрос (включая 4xx, 5xx) содержит CSP/COOP/COEP/HSTS.

### 13.4 Integration / E2E тесты

- `cmd/oblivio start` поднимается на тестовой БД (`postgres -c fsync=off` в
  testcontainers); E2E через ConnectRPC TS-клиент против реального сервера.
- Tamper-test: после `Create` `UPDATE entries SET encrypted_blob[0] = 0x00` →
  `GetByIds` на клиенте падает с decryption error.
- Cross-user tamper: попытка прочитать чужую запись через подмену `id` →
  `NOT_FOUND` (RLS).
- Replay: повторное использование старого refresh → вся сессия revoked.
- Rate-limit: 6 неудачных Authorize за минуту с одного email → 7-й возвращает
  `RESOURCE_EXHAUSTED`.
- Recovery: полный flow recovery_code → новый master_password → старый
  master_password больше не работает; все сессии invalidated.
- WebAuthn: register + authenticate против `go-webauthn/webauthn` virtual
  authenticator.
- Crypto-shred: `DeleteMe` → CASCADE удаляет данные; снэпшот БД через
  `pg_dump` не содержит ни одной строки этого `user_id`.

### 13.5 Security / supply chain

- `gosec` strict, `govulncheck` в CI на каждый PR.
- `npm audit --audit-level=high` блокирует merge.
- Lockfile-lint: `lockfile-lint --validate-https --validate-package-names`.
- `cyclonedx-gomod` SBOM генерируется при release.
- `cosign` подпись docker image (опционально).
- `security.txt` под `/.well-known/security.txt`.
- Зависимости: pinned by SHA для GitHub Actions; weekly `dependabot` PR.

### 13.6 Performance / fuzz

- Fuzz-test (Go 1.18+) на PHC parser, AEAD wrappers, hash-chain canonical JSON.
- Bench для Argon2id с per-user params (контроль регрессий по времени логина).

---

## 14. Деплой

- Один Postgres 18+ (`sslmode=verify-full`), TLS-сертификаты от внутреннего CA или Let's Encrypt.
- HashiCorp Vault Agent на той же машине / sidecar.
- Сервер за TLS-терминатором (nginx / Cloudflare WAF).
- Бэкапы Postgres: `pgBackRest` или `wal-g`, S3 с Object Lock + Bucket Versioning + KMS.
- Logs в SIEM **без plaintext** (только метаданные: user_id, action, IP, UA).
- Pre-launch checklist:
  - [ ] CSP/HSTS включены и протестированы (Mozilla Observatory > A+).
  - [ ] hstspreload.org заявка отправлена.
  - [ ] Внешний crypto-аудит (Cure53 / Trail of Bits / Doyensec).
  - [ ] Bug bounty programme опубликована.
  - [ ] Restore-drill из бэкапа проведён минимум 1 раз.

---

## 15. Чек-лист критических файлов (для исполнения)

**Удалить:**

- `internal/storage/{seal.go,storage.go,users.go}`
- `internal/tpm/tpm.go`
- `internal/keys/keys.go`
- `internal/api/server.go` (текущий gofiber)
- `internal/store/repos/{wallets,delegation_orders,settings}/`
- `sql/migrations/001_wallets_*.{up,down}.sql`
- `sql/migrations/002_delegation_*.{up,down}.sql`
- `sql/queries/{wallets,delegation_orders,settings}/`
- `internal/models/models_gen.go` (перегенерируется pgxgen)

**Заменить полностью:**

- `internal/auth/totp.go` → `internal/auth/login_totp.go` (server-side TOTP с derived key)
- `cmd/oblivio/start.go` (раскомментировать + переписать на ConnectRPC)
- `config.yaml` (см. §11.1)

**Создать новые:**

- `proto/oblivio/v1/*.proto` + `buf.yaml` + `buf.gen.yaml`
- `sql/migrations/00{1..6}_*.{up,down}.sql`
- `sql/queries/{users,user_kdf_params,user_auth,user_vault,user_login_totp,user_webauthn_credentials,auth_sessions,projects,entries,audit_log,system_state,rate_limit_buckets}/*.sql`
- `internal/api/{server.go,auth/,webauthn/,projects/,entries/,sessions/,audit/,middleware/}`
- `internal/auth/{manager.go,service.go,sessions.go,secrets.go,argon2.go,login_totp.go}`
- `internal/audit/{chain.go,repo.go}`
- `internal/crypto/{aead.go,hkdf.go,secure.go}` (минимально; основная крипта — на клиенте)
- `frontend/packages/crypto/` (новый workspace-пакет)
- `frontend/src/{api,stores,routes,components,lib}/...`

**Без изменений:**

- `cmd/oblivio/{main,version,migrations,utils,config}.go`
- `internal/config/{config.go,load.go}` (расширить, не удалять)
- `internal/jobs/service.go` (наполнить, каркас оставить)
- `internal/metrics/metrics.go`
- `pkg/postgres/postgres.go`
- `embed.go`, `templates/`, `Makefile`, `dev/`

---

## 16. Verification (как проверить готовый сервис end-to-end)

1. `make build && make migrate-up && oblivio start` — сервис поднимается, healthcheck отвечает.
2. `pnpm --filter frontend dev` (через Vite) ИЛИ открыть `https://localhost:8080`.
3. Регистрация: создать пользователя, получить recovery_code, подтвердить email.
4. Включить TOTP, добавить passkey.
5. Logout / login: повторить с TOTP, повторить с passkey (без TOTP).
6. Создать проект, добавить запись с TOTP-секретом, убедиться что TOTP-код обновляется.
7. Создать заметку.
8. Через psql: `SELECT encrypted_blob FROM entries LIMIT 1` — должно быть случайной шумоподобной байтстрокой.
9. Через psql: `UPDATE entries SET encrypted_blob = '\\x00...' WHERE id = …` — клиент при чтении должен показать ошибку integrity.
10. Logout всех сессий с другого устройства, текущая сессия остаётся.
11. Forgot-password flow: ввести recovery_code, задать новый master_password, перезайти.
12. Удалить аккаунт: данные исчезают из БД, бэкапы становятся нечитаемы (после ротации).
13. `curl -X POST https://localhost:8080/oblivio.v1.AuthService/Authorize` 6 раз с неверным паролем за минуту — на 6-й приходит `RESOURCE_EXHAUSTED`.
14. `make test`, `pnpm test`, `govulncheck ./...`, `npm audit --audit-level=high` — всё зелёное.
15. Mozilla Observatory grade ≥ A+ на проде.

---

## 17. Известные ограничения и целевые улучшения

Раздел нужен, чтобы текущая реализация была корректно описана. Каждый пункт —
осознанный компромисс или незакрытая работа, **не** «забыли». Пользователи и
ревьюеры должны видеть честную картину, прежде чем доверять данным.

### 17.1 Криптомодель и ключевой материал

- **Login-TOTP не zero-knowledge.** Сервер видит plaintext TOTP-секрета во время
  одной операции при login (расшифровкой ключом, выведенным из `auth_key`).
  См. §5.3. Альтернатива (client-side TOTP с PAKE) — не делалась в MVP.
- **HKDF salt = email** для вывода `auth_key`. Работает, но (а) email — публичная
  низкоэнтропийная величина, (б) при смене email нужна полная перерегистрация
  `auth_key`. Целевая правка — мигрировать на `salt_user`.
- **Crypto-shred не криптографический.** При `DeleteMe` запись удаляется
  каскадно, но и обёртка ключа, и ciphertext остаются в бэкапах БД до истечения
  retention. Целевая модель — per-user envelope-ключ в Vault transit, который
  уничтожается при удалении аккаунта.
- **Envelope без version-byte.** Текущий формат blob-а не несёт явного байта
  версии. До первого протокол-апгрейда не критично; при апгрейде нужно ввести
  decoder-registry. См. §4.6.

### 17.2 Аутентификация и сессии

- **WebAuthn UserVerification по умолчанию ("preferred").** Сейчас passkey
  без PIN/biometric тоже принимается. Целевая правка — `UV = required` для
  secret-manager-уровня доверия. См. §5.4.
- **`ChangeMasterPassword` и `RecoveryComplete` не обновляют `login_totp`.**
  Старый `encrypted_secret` после смены `auth_key` нечитаем — 2FA молча ломается
  до повторного setup. Целевая правка — клиент перешифровывает secret и
  отправляет новое значение в payload ротации. См. §5.3 и §5.5.
- **Argon2id на клиенте, фиксированные параметры.** m=128 MiB на iOS Safari
  может OOM-нуть. Сейчас fallback на меньшее `m` нет. Целевая правка —
  device-aware параметры с сохранением `salt_user`. См. §4.2.

### 17.3 Доступность и DoS

- **Argon2id concurrency-cap на сервере отсутствует.** Защита — только
  rate-limit middleware. Большой одновременный флуд `Authorize` может
  выбить RAM. Целевая правка — semaphore вокруг argon2-вызовов плюс
  обязательный CAPTCHA на `Register` в production.
- **Rate-limit in-memory.** Counter-ы не переживают рестарт и не делятся
  между инстансами. Single-node only. Целевая правка — миграция на
  `rate_limit_buckets` (Postgres) или Redis при горизонтальном масштабировании.
- **Multi-instance assumptions нет.** MFA-store, tokenmanager in-memory cache,
  rate-limit — всё локально. При двух инстансах за LB пользователь рискует
  потерять MFA-challenge при попадании на «не тот» инстанс. Целевая правка —
  shared store перед deploy с N>1.

### 17.4 Audit и integrity

- **Audit-chain head в той же БД, что и сам log.** Это защита от случайной
  порчи и от компроматов в обход аппликейшна, но не от противника с
  полным DB-доступом, который перепишет цепочку и обновит head. Целевая
  правка — внешний якорь (s3 object-lock, подпись Vault transit, witness service).
- **Polling-only sync.** Pushpull/SSE/long-poll для уведомлений о новых
  записях между устройствами нет. UX компенсируется TanStack Query
  invalidation и manual refresh. Целевая правка — SSE-stream на изменения
  пользовательского namespace.

### 17.5 Хранение серверных секретов

- **`secrets.json` plaintext для self-hosted без Vault.** Файл под mode 0600 с
  base64-ключами; компрометация диска = forge сессий. Приемлемо для single-node
  dev/self-host, не для production. Целевая правка — рекомендовать Vault или
  derive-from-env (`OBLIVIO_MASTER_SEED` + HKDF). См. §8.3.
- **memguard покрывает только in-rest буферы.** Plaintext, который stdlib-crypto
  принимает на вход, всё равно лежит в обычной heap-памяти. См. §8.3.

### 17.6 Метаданные и side-channels

- **`domain_hash` низкой cardinality.** Если когда-нибудь утечёт `K_blind` (например,
  через XSS в браузерной памяти), популярные домены угадаются по словарю. То же
  касается `title_hash` (но cardinality выше). Целевая правка — добавить
  per-user pepper, либо отказаться от `domain_hash` в пользу client-side favicon.

---

## 18. Open questions (можно отложить)

- **Sharing записей** между пользователями (team password manager) — **вне скопа MVP**.
  В MVP один аккаунт = один пользователь, sharing/RBAC отсутствуют. Если позже понадобится:
  реализуется через X25519-публичные ключи в `users` и пере-обёртывание `item_key`.
- **Файловые вложения** к записям — после MVP, отдельный store (S3 / on-disk)
  с ZK-шифрованием AES-GCM-stream.
- **Browser extension** — отдельный воркспейс пакета `extension/` с reuse `@oblivio/crypto`.
  Manifest v3 — service worker + content scripts + popup.
- **Mobile** (React Native / Expo) — переиспользовать `@oblivio/crypto` через
  react-native-quick-crypto + WASM-Argon2.
- **Desktop GUI** (Wails / Tauri) — Go нативное + memguard + system keychain
  для refresh_token.
- **Импорт из Bitwarden / 1Password / KeePass** — после MVP, отдельный CLI-tool,
  который на клиенте читает экспорт, шифрует и заливает через API.

Эти пункты задокументированы, чтобы архитектура изначально не мешала их добавить.
