# Аудиторский отчёт — Oblivio (zero-knowledge password manager)

**Аудит проведён по состоянию на коммит `3d34895` ветки `init-repo`.**
Скоп: серверный Go (`internal/**`, `cmd/oblivio`), клиентская крипта (`frontend/packages/crypto/src/**`), миграции, проектная архитектура из `docs/oblivio.md`.

---

## 1. Топ-5 критических проблем

### 1.1. Recovery code никогда не ротируется — постоянный backdoor к vault_key

**Где:** [sql/queries/user_vault/user_vault.sql:17-27](../sql/queries/user_vault/user_vault.sql#L17-L27) и явный комментарий в этой же query:

> "The recovery-related material (salt + wrapped) stays put so the same recovery code can still be used (the client should generate a new one after a successful recovery, but that is a UX nicety — not enforced)."

`CompleteRecovery` обновляет `verifier`, `wrapped_vault_key`, `vault_key_version`, но **не трогает** `recovery_salt`, `recovery_wrapped_vault_key`, `recovery_proof_hash`. То же самое делает `ChangeMasterPassword` — [internal/api/auth/service.go:724-730](../internal/api/auth/service.go#L724-L730).

`vault_key` не ротируется при recovery (только переоборачивается под новый master_key). Следовательно `recovery_wrapped_vault_key = AES-GCM(recovery_key, vault_key)` остаётся валидным навечно для того же `recovery_code`.

**Эксплуатация.** Пользователь регистрируется в 2025, сохраняет recovery_code в облачную заметку. В 2027 меняет master_password 5 раз, проходит через recovery. В 2028 атакующий получает доступ к старой заметке — у него **актуальный** recovery_code, дающий доступ ко всему текущему vault'у. Никаких признаков компрометации в audit_log нет (recovery flow никогда не использовался атакующим до этого момента).

В архитектурном документе §17 этот недостаток **не зафиксирован**. Это нарушение принципа forward secrecy для recovery-канала.

**Как чинить.**

1. В `RecoveryComplete` обязательно требовать у клиента новые `recovery_salt`, `recovery_wrapped_vault_key`, `recovery_proof_hash` (клиент генерирует новый recovery_code, показывает пользователю, перешифровывает текущий vault_key). Аналогично — в `ChangeMasterPassword` (опционально, с UI-флагом).
2. Альтернатива покрепче: при recovery ротировать сам `vault_key` (с пере-обёртыванием всех `wrapped_item_key` под новый vault_key — дорого, но семантически правильно).
3. Минимум: invalid-date `recovery_used_at` после recovery и требовать явного `RegenerateRecoveryCode` перед тем как `recovery_proof_hash` снова становится валидным.

**Серьёзность:** High. Это идёт против всего zero-knowledge нарратива.

---

### 1.2. Audit-anchor не проверяется на «чистом» проходе — защита от tampering фиктивна

**Где:** [internal/jobs/audit_chain_verify.go:62-86](../internal/jobs/audit_chain_verify.go#L62-L86)

```go
if res.OK() {
    // ...
    return nil  // ← anchor НЕ проверяется
}
// only on chain MISMATCH:
if err := w.verifyAnchor(ctx, res.Head); err != nil { ... }
```

Логика worker'а: если SHA-256 chain согласована с `system_state.audit_chain_head` → выйти без проверки anchor. Anchor проверяется **только** когда chain уже расходится.

Но цель anchor — ловить атакующего, который **согласованно** переписал и строки `audit_log`, и `audit_chain_head`. В таком сценарии:

- chain hash == stored_head → `res.OK() == true` → выходим.
- Anchor никогда не консультируется.
- Атакующий полностью замёл следы.

Это та самая атака, против которой anchor нужен. Текущая реализация ловит только некогерентные правки (которые и старый chain без anchor поймал бы).

Дополнительно [internal/audit/verify.go:67-119](../internal/audit/verify.go#L67-L119) — анкор не учитывает high-water-mark: в `audit_chain_anchors` хранится только `head`, без `audit_log.id`, до которого он подписан. Поэтому даже исправленная логика не сможет различить «легитимно ушли вперёд от анкора» и «переписали историю».

**Эксплуатация (model: внутренний оператор / DBA или RCE на DB-хосте).**

1. Получить SQL-доступ к `audit_log` и `system_state`.
2. Удалить/изменить N последних строк (например, `entry_view` для записи с паролем от банка).
3. Пересчитать `self_hash` для оставшихся.
4. Записать новый `audit_chain_head`.
5. Audit verify job на следующем прогоне: chain согласован, OK, anchor не проверяется. Tampering не обнаружено.

**Как чинить.**

1. `AuditChainAnchorWorker.Work` должен записывать `(head, last_audit_id, signature, signer_id)` — фиксируя высоту якоря.
2. `AuditChainVerifyWorker.Work` должен **всегда** загружать последний anchor и:
   - Перепроверять chain до `last_audit_id` (батчами), сравнивать с `anchor.head`.
   - Если `current_head != anchor.head`, всё равно убеждаться, что rows `[1..anchor.last_audit_id]` дают `anchor.head` (т.е. история до момента подписи неизменна; вперёд можно идти).
   - Проверять `ed25519.Verify(pub, anchor.head || anchor.last_audit_id, anchor.signature)` — id должен входить в подпись.
3. Alarm на: signature invalid; `anchor.head != computed_hash_at_anchor_height`.

**Серьёзность:** High. Эта защита заявлена как защита от DB-доступного атакующего; сейчас она не работает.

---

### 1.3. Permanent account lockout DoS — пять провальных попыток никогда не сбрасывают `failed_attempts`

**Где:** [sql/queries/user_auth/user_auth.sql:12-20](../sql/queries/user_auth/user_auth.sql#L12-L20)

```sql
SET failed_attempts = failed_attempts + 1,
    locked_until    = CASE
        WHEN failed_attempts + 1 >= 5 THEN now() + interval '15 minutes'
        ELSE locked_until
    END
```

`failed_attempts` сбрасывается **только** при `ResetFailedLogin` (вызывается на успешном login) или `UpsertUserAuth` (recovery / change password). Сам счётчик никогда не уменьшается со временем.

**Сценарий вечной блокировки.** Атакующий знает email жертвы.

1. Шлёт 5 wrong-password Authorize → `failed_attempts=5`, lockout 15 min.
2. Жертва ждёт 15 мин — может зайти? Нет: атакующий снова шлёт 1 wrong-password каждые 15 мин. Условие `failed_attempts(6) + 1 >= 5` всегда true → `locked_until = now + 15min`. Каждый wrong-password продлевает lockout, пока жертва не сделает успешный login. Жертва не может сделать успешный login, потому что `locked_until.After(time.Now())` всегда true.

Per-email rate-limit (5/min для Authorize в `rate_limit.go`) **не помогает** — атакующему нужна одна попытка раз в 15 минут (1/900 запросов в секунду), это глубоко под любым rate-лимитом.

**Стоимость атаки:** один HTTP-запрос каждые 15 минут навечно блокирует выбранный email.

**Как чинить.**

1. Сбрасывать `failed_attempts` если `locked_until IS NOT NULL AND locked_until < now()`:

   ```sql
   SET failed_attempts = CASE
       WHEN locked_until IS NOT NULL AND locked_until < now() THEN 1
       ELSE failed_attempts + 1
   END,
   locked_until = CASE
       WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until < now()
                  THEN 1 ELSE failed_attempts + 1 END) >= 5
       THEN now() + interval '15 minutes'
       ELSE NULL
   END
   ```

2. Дополнительно: задавать TTL для `failed_attempts` (например, скользящее окно 1 час) или экспоненциальный backoff (`5min, 15min, 1h, 4h, capped`).
3. И вообще для unauthenticated DoS-blocker'а account-level lockout — антипаттерн. Лучше rate-limit per-IP + per-email + CAPTCHA после N неудач, без блокировки самого аккаунта.

**Серьёзность:** High (DoS-vector конкретно против выбранного пользователя).

---

### 1.4. `dummyAuthHash` использует неправильные Argon2-параметры — user-enumeration через тайминг

**Где:** [internal/api/auth/service.go:1147-1166](../internal/api/auth/service.go#L1147-L1166)

```go
h, err := auth.HashAuthKey(seed, auth.Argon2Params{T: 3, MKiB: 65536, P: 1})
```

Dummy hash считается с `m=64 MiB, p=1`. Реальный пользователь хранит PHC с параметрами `s.argon2 = {T:3, MKiB:131072, P:4}` (из `Argon2Server` config). При `VerifyAuthKey` параметры берутся из PHC-строки → реальная проверка занимает ~100-200ms (128 MiB, 4 потока), фиктивная ~30-50ms (64 MiB, 1 поток).

Разница 50-150ms через TLS-стенку измеряется при N≥30 запросах. Это **возвращает** user-enumeration timing channel, который anti-enumeration ветка `dummyAuthHash` должна была закрыть.

Кроме того:

- Для несуществующего email `Authorize` пропускает `GetUserAuth` + lockout-check (это +1 DB round-trip = ещё ~3-10ms разницы).
- При locked аккаунте `Authorize` возвращается **мгновенно** до VerifyAuthKey — locked-vs-unknown-vs-unlocked различимы тривиально.

**Как чинить.**

1. `dummyAuthHash` лениво считать с **теми же** параметрами, что `s.argon2`. Лучше — передать в `NewService` и оставить в поле структуры.
2. На locked-ветке всё равно вызывать `auth.VerifyAuthKey(authKey, dummyAuthHash())` (или sleep до общей wall-clock).
3. На unknown-email-ветке выровнять DB-roundtrip: сделать пустой `SELECT 1` или просто пропустить lookup и сразу dummy-verify.

**Серьёзность:** Medium-High. У вас явно стоит anti-enumeration goal, и три отдельных побочных канала его рушат.

---

### 1.5. `rotateLoginTOTPInTx` молча сбрасывает TOTP при частичных данных

**Где:** [internal/api/auth/service.go:986-1012](../internal/api/auth/service.go#L986-L1012)

```go
if len(newEncrypted) > 0 && len(newNonce) > 0 {
    return repo.UpsertUserLoginTOTP(...)
}
// Empty bytes → drop the row if it exists.
return repo.DeleteUserLoginTOTP(ctx, userID)
```

Если клиент по любому багу отправил `newEncrypted != ""` но `newNonce == ""` (или наоборот) — оба значения должны быть либо непустыми, либо пустыми, но код просто падает в `DELETE`. У пользователя **тихо удаляется второй фактор**, причём операцию инициировал не он, а его клиент при `ChangeMasterPassword`/`RecoveryComplete`.

Дополнительно: я смотрю на схему `user_login_totp` — там колонка `nonce` хранится отдельно. Но `OpenLoginTOTPSecret` ([internal/auth/login_totp.go:67-80](../internal/auth/login_totp.go#L67-L80)) и `AESGCMOpen` ([internal/crypto/aead.go:31-56](../internal/crypto/aead.go#L31-L56)) ожидают envelope `version(1) || nonce(12) || ct+tag` — нонс **уже в составе** `encrypted_secret`. Колонка `nonce` мёртвая, никогда не читается для расшифровки.

Это означает:

- Сам факт того, что rotateLoginTOTPInTx разделяет `newEncrypted` и `newNonce` — артефакт устаревшей схемы.
- На клиенте при ChangeMasterPassword/RecoveryComplete нужно следить, чтобы оба поля заполнялись согласованно — это лишний инвариант, который легко нарушить.

**Как чинить.**

1. Удалить колонку `user_login_totp.nonce` (миграция-down: оставить, для миграции — игнорировать).
2. Убрать `nonce` из `Setup`/`Enable`/`Disable`/`RotateLoginTOTP` proto-полей.
3. `rotateLoginTOTPInTx`: явная ошибка `InvalidArgument` при `len(newEncrypted) > 0 != len(newNonce) > 0` (если nonce пока что не дропнули из API).
4. Лучше — заменить на единственный параметр `envelope []byte`: пустой == drop, непустой == upsert.

**Серьёзность:** Medium (тихая потеря 2FA после рутинной операции).

---

## 2. Архитектурные предложения

### 2.1. SQLite + Litestream вместо Postgres — серьёзный кандидат

**Проблема в текущей архитектуре.** Self-hosted менеджер на единственного пользователя содержит:

- pgxpool, миграции через golang-migrate с iofs, RLS с custom GUC, FOR UPDATE для audit chain, LISTEN/NOTIFY для SSE.
- Конфигурация Postgres (`verify-full`, TLS-сертификаты, pgaudit, бэкап через wal-g/pgBackRest).
- В docker-compose: оператор должен поднимать ещё один контейнер с PG, заботиться о volume, секретах БД, миграциях.

При том, что 99% пользователей — это один человек на инстанс, и **все ценное всё равно зашифровано клиентом**. То есть SQL фактически используется как KV-store с индексами.

**Альтернатива.** SQLite + WAL + Litestream (continuous replication в S3-совместимый бакет с object lock).

| Что приобретаем                                                | Что теряем                                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Один бинарь + один файл — `oblivio start` на bare VPS работает | LISTEN/NOTIFY — заменяется на in-process pub/sub (один процесс)                             |
| Бэкап = `cp` файла (или Litestream point-in-time)              | Multi-instance HA — нужно либо primary/replica на уровне SQLite, либо отказ                 |
| Нет network attack surface на БД                               | Concurrent writes сериализуются (single writer) — но это и так наш bottleneck в audit chain |
| Восстановление = поставить файл и стартовать                   | RLS — заменяется на тривиальный `WHERE user_id = ?` (уже есть везде)                        |
| Тесты быстрее на порядок                                       | Конкурентные writes не масштабируются — но для self-hosted это не задача                    |

Стоимость миграции: pgx → `mattn/go-sqlite3` или `modernc.org/sqlite`, переписать ~15 миграций (SQL-диалект почти совпадает), убрать River (см. 2.3), убрать LISTEN/NOTIFY (см. 2.4), убрать RLS-помощники. ~3-5 человеко-дней.

**Рекомендация:** не делать прямо сейчас, но осознанно проверить: «если у нас 1 vault на пользователя и data зашифрована — зачем нам Postgres?». Если ответа кроме «привычка/опыт» нет — рассмотреть.

---

### 2.2. Audit-chain с external anchor — overkill; либо упростить, либо переделать

**Проблема.** Anchor Ed25519 живёт на той же машине, что и сам сервер ([internal/audit/anchor.go:60-115](../internal/audit/anchor.go#L60-L115)). Приватный ключ в файле `data/secrets/audit_signer.json` под 0600. Атакующий с RCE на хост получает:

- DB-доступ (через тот же процесс).
- Приватный ключ.
- → может переподписать любую chain.

То есть anchor защищает только от атакующего с **DB-only** доступом (например, утечка дампа БД). А если DB живёт на той же машине что и приложение, такой атакующий редок.

В §17.4 написано, что это «целевая модель — local signer для single-node, Vault transit для multi-node». Но Vault transit пока не подключён.

Кроме того, в текущей реализации anchor не работает корректно (см. 1.2). Чтобы починить, нужно ещё разработать корректную схему high-water-mark.

**Альтернатива A: упростить.** Убрать external anchor целиком. Хэш-цепочка в `audit_log + system_state.audit_chain_head` ловит инциденты `1) случайной порчи`, `2) частичной правки таблицы аудита через SQL без обновления head`. Это уже хорошее свойство. Если ОС-уровень безопасности достаточен (нет shared DB-доступа), anchor ничего не добавляет.

**Альтернатива B: переделать на Vault transit.** Подписи производит Vault, приватный ключ никогда не покидает Vault. Это реальная DB-only защита. ~2 дня работы.

**Альтернатива C: transparency log.** Раз в час публиковать `(head, height)` на внешний WORM-стор (например, `s3://oblivio-anchors/2026-05-12T14:00:00.json`) с Object Lock. Это даёт неоспоримый внешний witness — атакующий с DB-доступом не может ретроактивно подписать прошлый head.

**Рекомендация.** Для single-user self-hosted: убрать. Для multi-tenant SaaS: Vault transit. Гибридная local-signer-on-disk схема — худшее из обоих миров.

**Дополнительно — переусложнение модели угроз.** В однопользовательском менеджере паролей audit-log читает только сам user, и сам же все мутации делает. Атакующий, который пишет в его audit_log — это атакующий, который уже владеет аккаунтом. Защита `prev_hash → self_hash` нужна для compliance/forensics, а не для блокировки атак. Целевые ограничения: «sysadmin не может тихо стереть свои действия» — но sysadmin одновременно и user, и DBA в self-hosted. То есть chain — для feature, не для security. Сократить и не подавать как security boundary.

---

### 2.3. River jobs — overkill для 8 периодических задач

**Проблема.** [internal/jobs/service.go:42-132](../internal/jobs/service.go#L42-L132) поднимает River client с 8 worker'ами:

- audit_chain_verify (1/day)
- audit_chain_anchor (1/hour)
- sessions_gc, auth_tokens_gc, idempotency_gc, mfa_gc, recovery_gc, rate_limit_gc

Все — TTL-cleanup'ы и periodic alarms. Ни одна не retry-чувствительна (если sessions_gc упал, следующий прогон через час всё подметёт).

River приносит:

- ~10 таблиц в БД для своего state (`river_job`, `river_leader`, и т.д.).
- Lock-based leader election.
- Backoff politicies, retry logic.

Для 8 cron-like задач без бизнес-результата это лютый overkill. Если бы был хоть один user-triggered job (email sending, password import, etc) — оправдано. Здесь — нет.

**Альтернатива.** `internal/jobs/service.go` ~50 строк:

```go
go func() {
    t := time.NewTicker(cfg.AuditChainVerifyInterval)
    defer t.Stop()
    for { select { case <-ctx.Done(): return; case <-t.C: runVerify(ctx) } }
}()
// ... 7 раз
```

Или `xutils/scheduler`/`robfig/cron` если хочется crontab-нотацию.

**Стоимость:** -3 миграций (River-схема), -50 строк wiring, минус транзитивная зависимость от `river/riverdriver/riverpgxv5`.

**Что теряем:** persistent retry (но эти задачи и так idempotent), distributed leader-election (single-node deploy её не использует).

**Серьёзность:** Low (работает, просто тяжелее необходимого). Имеет смысл при следующем рефакторинге.

---

### 2.4. SSE через LISTEN/NOTIFY — реальный риск; вполне можно заменить

**Проблема.** [internal/api/subscriptions/service.go:51-104](../internal/api/subscriptions/service.go#L51-L104) — на каждый активный SSE-stream держится **отдельное PG-соединение** (LISTEN bind to session). Pool ёмкостью K соединений = максимум K одновременных подписчиков. При reconnect-шторме (deploy, network blip) клиенты гонят retry → пул выгребается → новые login'ы залипают.

Дополнительные риски:

- `pg_notify` payload ограничен **8000 байт** (асимптотически). Если когда-то добавите детальный payload — придёте к лимиту.
- Если канал переполнен (`max_locks_per_transaction` или backlog), сообщения **молча теряются**.
- Один LISTEN connection на стрим = `conn.Acquire(ctx)` блокирующий, без таймаута → DoS-вектор: открыть 100 streams, выгрести пул, после чего все API-запросы стопаются.

Heartbeat каждые 25 секунд (`heartbeatInterval`) хорошо, но `WaitForNotification` с `context.WithTimeout` создаёт **новый таймер на каждый цикл** — не очень дёшево при тысячах подключений.

**Альтернатива A: long-polling.** Клиент шлёт `Poll` каждые 10-30 секунд. Сервер отвечает мгновенно если что-то изменилось (cached counter в Redis или in-process), иначе ждёт до таймаута. **Не нужны** LISTEN/NOTIFY, не нужен дополнительный пул соединений, не нужен heartbeat.

Для single-user менеджера паролей это нормально — нет real-time-критики, изменения происходят редко (на каждый Create/Update).

**Альтернатива B: in-process pub/sub.** Если перейти на single-process (SQLite, см. 2.1), publish напрямую в in-memory bus → SSE-stream. Никаких DB connections, ничего.

**Альтернатива C: оставить SSE, но через in-process broker.** Каждый mutation handler делает `broker.Publish(userID, kind)`. Каждый Subscribe слушает `broker.Subscribe(userID)`. Cross-instance — отдельная задача (см. multi-instance ниже).

**Рекомендация.** Для self-hosted: long-poll или in-process. Для multi-instance: оставить LISTEN/NOTIFY, но **отслеживать** утечку соединений через прометей-метрику `subscriptions_active_connections` и ограничивать.

---

### 2.5. Rate-limit через Postgres ConsumeRateLimit — корректно, но болезненно

**Где:** [sql/queries/rate_limit_buckets/rate_limit_buckets.sql:11-27](../sql/queries/rate_limit_buckets/rate_limit_buckets.sql#L11-L27)

Каждый анонимный запрос делает `INSERT ... ON CONFLICT DO UPDATE`. Это:

- Полная транзакция со записью в WAL.
- Row-level lock на бакете.
- Round-trip в БД.

При запросах 100 req/sec на `GetKDFParams` это 100 WAL-записей в секунду только для rate-limit. На любом не-минимальном инстансе Postgres это нагрузка, плюс генерирует мусор в bloat'е.

Fail-open на DB-ошибке ([internal/api/middleware/rate_limit.go:105-110](../internal/api/middleware/rate_limit.go#L105-L110)) — **усиливает атаку**: атакующий, который заодно нагрузит DB параллельной нагрузкой, отключит rate-limit (запросы будут долгие, таймаут 500ms сработает, fail-open вернёт true → Argon2-amplification).

**Альтернатива A: вернуться к in-memory с честным single-node-only.** Для self-hosted это норма; multi-instance явно требует sticky session. ~30 строк кода `golang.org/x/time/rate.Limiter`.

**Альтернатива B: Redis с TTL-keys + Lua.** Стандартная схема, не требует WAL.

**Альтернатива C: оставить Postgres, но с unlogged table и fail-closed.** `CREATE UNLOGGED TABLE rate_limit_buckets ...` — нет WAL-writes; перезапуск БД теряет состояние (это для rate-limit допустимо). Fail-closed: если DB не отвечает за 500ms — return 503, не пропускать. Это устраняет amplification-вектор за счёт временного user-impact'а во время DB-outage'а.

**Рекомендация.** Для текущей нагрузки (self-hosted) — В (unlogged). Для масштаба — Redis.

---

### 2.6. ConnectRPC — ценность только для streaming, который один. REST + EventSource проще

**Текущая ситуация.** Используется ConnectRPC + buf-generated stubs для Go и TS. Из всех сервисов streaming используется только в `SubscriptionsService.Subscribe`. Остальное — unary.

ConnectRPC даёт:

- Auto-generated клиент в TS.
- Proto-versioning (но `oblivio/v1` пока единственная, миграция вне роадмапа).
- Бинарный wire-format для бэкап-эффективности (но трафик в основном это encrypted_blob, который у нас уже raw bytes).

Альтернатива — REST + JSON + OpenAPI-spec. Каждая ручка явная, легче дебажить, нет proto-toolchain в CI.

**Я не рекомендую переходить** (стоимость > выгоды; ConnectRPC работает). Но это honest tradeoff в roadmap-стиле «если бы делал с нуля». Для отдельного browser extension или mobile-клиента — proto-stubs реально полезны; через 1-2 года это окупит инвестиции.

---

### 2.7. MFAKEK — три источника, два неверных пути; упростить до одного обязательного

**Где:** [internal/auth/mfa_kek.go:42-79](../internal/auth/mfa_kek.go#L42-L79)

Три источника:

1. Seed из аргумента (предположительно из Vault).
2. `OBLIVIO_MFA_KEK_SEED` env-var (caller resolve).
3. Per-instance random fallback.

(3) делает multi-instance deploy **тихо неработающим** для cross-instance MFA challenge: challenge созданный на инстансе A не расшифровывается на инстансе B (разные KEK). `IsInstanceLocal()` экспонируется, но операторы могут забыть проверить и боль обнаружат продакшн-пользователи.

Аналогично в audit anchor: `LocalSigner` на диск vs hypothetical VaultTransitSigner — но второй пока не реализован.

**Альтернатива.** При старте сервера если `OBLIVIO_MFA_KEK_SEED` (или Vault path) не задан — **отказать в старте** с явной ошибкой. Не пытаться быть «полезным» через random fallback. Документировать: «для dev-режима задайте сид-нибудь, для прода — настоящий sealed seed».

Аналогичный подход к `OBLIVIO_MASTER_SEED` (JWT signing) — там [internal/auth/secrets.go:97-145](../internal/auth/secrets.go#L97-L145) тоже падает в on-disk `secrets.json` с big WARN. Это менее опасно (single-node deploy в норме работает), но всё ещё surprise-shaped.

**Стоимость:** -30 строк, +1 строка в `start.go` (документация при ошибке).

---

### 2.8. Vault интеграция — пока неоплачиваемая ценность

Из docs: «HashiCorp Vault (опционально) для серверных секретов». В коде реальной Vault-интеграции нет (видел упоминание `xconfigvault` в config layer). Все три «защищаемых» сидов (jwt-access, jwt-refresh, MFA KEK) спокойно поднимаются из `OBLIVIO_MASTER_SEED` / `OBLIVIO_MFA_KEK_SEED` env-var через HKDF. Это лучшее из обоих миров: env-var-friendly (12-factor), и при необходимости env подгружается из Vault Agent / sealed-secrets.

**Рекомендация.** Убрать Vault из roadmap'а как обязательный (или вообще как поддерживаемый mode). Документировать «12-factor secrets» как канон. Если кто-то использует Vault — пусть прокидывает через Vault Agent sidecar в env-vars.

---

## 3. Переусложнённое

### 3.1. `internal/audit/chain.go` canonicalJSON

[internal/audit/chain.go:208-267](../internal/audit/chain.go#L208-L267) — 60 строк ручного сортированного JSON-кодировщика (`marshalSorted`, `encodeSorted`, `sortStrings` insertion-sort) ради детерминизма SHA-256 над `audit_log.metadata`.

Стандарт Go (`encoding/json`) уже **гарантирует** сортировку ключей для `map[string]X` с 1.12. Гарантирует только верхний уровень — но `metadata` в audit это пользовательский JSON произвольной вложенности, поэтому ручной обход нужен.

Альтернатива: использовать [`github.com/gibson042/canonicaljson-go`](https://github.com/gibson042/canonicaljson-go) (RFC 8785) или просто `json.Marshal(any)` после `json.Unmarshal → map[string]any` рекурсивно (что и делается, но криво).

Стоимость замены: ~5 строк, минус 60 строк кастомного кода. Дополнительный бонус — соответствие RFC 8785, можно потом тривиально верифицировать сторонним инструментом.

### 3.2. `internal/audit/chain.go` insertion-sort

`sortStrings` ([line 271-277](../internal/audit/chain.go#L271-L277)) — собственный insertion-sort строк. В standard library есть `slices.Sort`. -7 строк.

### 3.3. `pseudoSaltSecret` / `pseudoBlindPepper` / `dummyAuthHash` — три отдельных anti-enumeration механизма

[internal/api/auth/service.go:1101-1166](../internal/api/auth/service.go#L1101-L1166) держит три отдельных fallback'a:

- `pseudoSalt(email)` — HMAC от секрета процесса, для GetKDFParams.
- `pseudoBlindPepper(email)` — HMAC с префиксом, для того же.
- `dummyAuthHash()` — фиксированный Argon2id PHC, для Authorize.

Унифицировать: один helper `pseudoCredentials(email) → (salt, blind_pepper, argon_params)` плюс один `dummyVerifyTime()` для тайминга. Семантика остаётся, экономия 30 строк.

### 3.4. `audit_chain_anchor` + `audit_chain_verify` + Ed25519 LocalSigner

В сумме ~250 строк ([internal/audit/anchor.go](../internal/audit/anchor.go) + [internal/jobs/audit_chain_anchor.go](../internal/jobs/audit_chain_anchor.go) + anchor-handling в verify) для функциональности, которая в текущей реализации ничего не защищает (см. 1.2). Если решаем не чинить, эти 250 строк можно удалить целиком вместе с миграцией 010, репозиторием `repo_audit_chain_anchors`, и `Signer` интерфейсом.

### 3.5. Параллельные KEK-источники для разных целей

`MFAKEK` ([internal/auth/mfa_kek.go](../internal/auth/mfa_kek.go)) — отдельный KEK ровно для одного use-case: шифрование `auth_key` в `mfa_challenges`. Audit anchor использует свой Ed25519 ключ. JWT signing — свой пара. Email-verification токены — SHA-256 без ключа.

Можно унифицировать: единый process-wide `KEK` (производится из `OBLIVIO_MASTER_SEED` через HKDF с разными info-метками). Тогда:

- `K_mfa_at_rest = HKDF(seed, "oblivio/mfa-kek/v1")` — то же что сейчас.
- `K_audit_signer = HKDF(seed, "oblivio/audit-signer/v1")` → детерминированный seed для Ed25519. Не нужен `audit_signer.json` на диск.
- `JWT_access = HKDF(seed, "oblivio/jwt-access/v1")` — уже так.

Удаляется отдельный файл `audit_signer.json`, отдельная функция `NewMFAKEK`, отдельный fallback с random per-instance.

Стоимость: ~3 часа работы. Экономия — упрощение mental model: один сид, всё остальное детерминировано.

---

## 4. Quick wins (час-два каждое)

**4.1.** [internal/auth/argon2.go:32](../internal/auth/argon2.go#L32) — `argon2Sem` инициализируется глобально при init пакета через `runtime.NumCPU()`. Это вызывается ДО загрузки конфигурации; конфиг затем перезаписывает через `SetArgon2Concurrency`. Между моментами init и Set возможен Hash/Verify (если что-то очень рано). Лучше — явный конструктор и инстанс в Manager, без глобала.

**4.2.** [internal/auth/argon2.go:59-71](../internal/auth/argon2.go#L59-L71) — `acquireArgon2` использует `context.Background()`. Если запрос отменён клиентом во время ожидания в очереди — мы всё равно ждём слот, тратим CPU, потом считаем Argon2 и отбрасываем. Принимать `ctx` параметром и пробрасывать в `Acquire`.

**4.3.** [internal/audit/chain.go:79-83](../internal/audit/chain.go#L79-L83) — `Append` использует `IsoLevel: pgx.ReadCommitted` + `FOR UPDATE`. RR/Serializable не нужны, ReadCommitted OK. Но `defer tx.Rollback` после Commit — это всегда вызывает Rollback на закоммиченной транзакции и возвращает ошибку (pgx логирует). Стандартный паттерн — `committed bool` (как в [internal/api/middleware/rls.go:52-57](../internal/api/middleware/rls.go#L52-L57)).

**4.4.** [internal/api/subscriptions/service.go:67](../internal/api/subscriptions/service.go#L67) — `conn.Exec(ctx, fmt.Sprintf("LISTEN %s", quoteIdent(channel)))`. `quoteIdent` хороший, но `fmt.Sprintf` с user-derived строкой в SQL остаётся code-smell. Если когда-то ChannelName начнёт принимать что-то кроме UUID, легко уронить безопасность. Добавить assert или вынести whitelist символов.

**4.5.** [internal/api/middleware/idempotency.go:117](../internal/api/middleware/idempotency.go#L117) — `InsertIdempotencyEntry` без `ON CONFLICT DO NOTHING`. При концурентной гонке за тем же ключом будет PK-violation и операция выполнится дважды (см. также в разделе 5). Изменить на `INSERT ... ON CONFLICT (user_id, key) DO NOTHING`.

**4.6.** [internal/audit/anchor.go:96-110](../internal/audit/anchor.go#L96-L110) — `NewLocalSigner` создаёт файл с правами 0600, но не проверяет существующий файл на достаточную приватность. Если по ошибке `chmod 0644` — мы доверяем readable-ko файлу. Добавить `os.Stat` + проверку `Mode().Perm() == 0o600`.

**4.7.** [internal/auth/secrets.go:32-41](../internal/auth/secrets.go#L32-L41) — `AccessSecret()` возвращает `string(s.access.Bytes())` — `string()` копирует в иммутабельную heap-память, обнулить нельзя. Это противоречит обещанию memguard. Лучше — передавать `[]byte` дальше; tokenmanager должен принимать `[]byte`.

**4.8.** [internal/audit/chain.go:130-138](../internal/audit/chain.go#L130-L138) — `audit_chain_head` хранится как JSON-encoded hex-string в JSONB. Лишний слой кодирования: JSONB вокруг `"deadbeef..."` вместо просто BYTEA. Дополнительные `json.Marshal`/`Unmarshal` на каждый append. Поменять column type на BYTEA или хотя бы TEXT, убрать round-trip.

**4.9.** [sql/queries/audit_chain_anchors/audit_chain_anchors.sql:6-9](../sql/queries/audit_chain_anchors/audit_chain_anchors.sql#L6-L9) — `GetLatestAuditChainAnchor` по `ORDER BY signed_at DESC`. Если две подписи в один момент времени (clock-microsecond), порядок недетерминирован. Лучше `ORDER BY signed_at DESC, id DESC LIMIT 1` (id — BIGSERIAL).

**4.10.** [internal/api/auth/service.go:1106-1114](../internal/api/auth/service.go#L1106-L1114) — `pseudoSaltSecret` использует fallback на all-zeros при `rand.Read` error. Никогда не должно случиться, но если случилось — все unknown email возвращают **одинаковый** salt = `HMAC(zeros, email)`, который в принципе предсказуем (атакующему достаточно знать секрет = zeros). Лучше `panic(err)` чем silent zero.

**4.11.** [internal/api/auth/service.go:329](../internal/api/auth/service.go#L329) — после успешного `auth_key`-verify CompleteMFA проверяет TOTP через `s.mfa.Peek` (а не `Take`). Если TOTP fails, challenge не consumed, можно brute-force. Per-IP rate-limit для CompleteMFA отсутствует ([rate_limit.go:170-196](../internal/api/middleware/rate_limit.go#L170-L196) — нет в списке). 6 цифр = 10^6 = миллион, при ~3000 req/sec можно сбрутить за 5 минут (как раз TTL). Добавить CompleteMFA в rate-limit map + consume challenge на N неудачных попыток.

**4.12.** Метрика `failed_attempts` (per-account lockout) и `RateLimitDropsTotal` (per-IP/email) дают нам **два** механизма. Они могут противоречить (rate-limit пропустил, account-lockout заблокировал) и оба требуют отдельной настройки. Унифицировать в `auth_login_attempts(email, ip, at)` логе с скользящим окном; lockout — следствие политики, а не побочный counter.

**4.13.** [internal/api/middleware/rate_limit.go:54](../internal/api/middleware/rate_limit.go#L54) — `proceduresWithRateLimit` не включает `/oblivio.v1.AuthService/CompleteMFA`. Добавить.

---

## 5. Что не трогать

**5.1. AAD-binding на entries/projects ([frontend/src/lib/vault-crypto.ts:112-148](../frontend/src/lib/vault-crypto.ts#L112-L148)).** Структура `${itemId}|${version}|${vaultId}|item` корректно защищает от swap-атаки даже на уровне честного сервера: подменить запись пользователя A под пользователя B невозможно (vault_id = user_id различен, AAD не валидируется). Verifier при подмене получит ошибку AES-GCM tag.

**5.2. RLS политика и FORCE ROW LEVEL SECURITY ([sql/migrations/005_rls_policies.up.sql](../sql/migrations/005_rls_policies.up.sql)).** Использование двух GUC (`app.current_user_id` для пер-юзера, `app.bypass_rls` для системы), `app_is_system()` и `app_current_user_id()` через `current_setting(..., true)` — sound. FORCE RLS правильно поставлен. Audit_log read-only для пользователя, insert только для system — корректно.

**5.3. Envelope-формат `version(1) || nonce(12) || ct+tag` ([internal/crypto/aead.go](../internal/crypto/aead.go), [frontend/packages/crypto/src/aead.ts](../frontend/packages/crypto/src/aead.ts)).** Go и TS реализации идентичны, версионный байт даёт upgrade path. Само AAD на v1 не покрывает version byte, но decode rejects unknown version до AEAD-операции — этого достаточно.

**5.4. Refresh-token reuse-detection ([internal/auth/manager.go:188-209](../internal/auth/manager.go#L188-L209)).** Подход с `current_refresh_key` стампом и `bytes.Equal` для определения reuse корректен. Есть гонка (см. mini-finding в разделе 4), но базовая идея верная.

**5.5. tokenmanager + PG-backed store.** Отделение access/refresh ключей с разными TTL и хранение `SessionData` per-session в PG — solid. Sessions UI работает.

**5.6. Argon2 semaphore ([internal/auth/argon2.go:30-71](../internal/auth/argon2.go#L30-L71)).** Логика правильная (acquire/release вокруг IDKey). Comments объясняют почему context.Background — окей. SetArgon2Concurrency safe для startup-only wiring.

**5.7. MFAStore.Take = атомарный DELETE RETURNING ([internal/auth/mfa_store.go:130-152](../internal/auth/mfa_store.go#L130-L152)).** SQL уровень гарантирует, что только один caller получит row. Peek + Take в WebAuthn flow — корректный паттерн для гонки assertion-validation и cleanup.

**5.8. memguard в DeriveLoginTOTPKey ([internal/auth/login_totp.go:44-56](../internal/auth/login_totp.go#L44-L56)).** `NewBufferFromBytes` стирает source, defer Destroy на буфер — правильно. Замена `string(secret)` на byte-slice вариант (ValidateTOTPCodeBytes) — реальное улучшение.

**5.9. Anti-enumeration с pseudoSalt для GetKDFParams ([internal/api/auth/service.go:236-242](../internal/api/auth/service.go#L236-L242)).** Концепция верная (стабильные псевдо-параметры для unknown email). Реализация имеет два issue (см. 1.4 и 4.10), но переделывать «с нуля» не нужно.

**5.10. ConnectRPC interceptor chain.** Anonymous allowlist + Bearer-token middleware + RLS interceptor + audit-log interceptor + idempotency middleware — раскладка слоёв корректная.

**5.11. memguard покрытие на server-side keys ([internal/auth/secrets.go](../internal/auth/secrets.go)).** Использование `NewBufferFromBytes` для access/refresh seeds правильно. Один issue с `string()` копией (4.7) — мелочь.

---

## 6. Что сделал бы по-другому с нуля

День времени, такой же ТЗ — zero-knowledge password manager на single-user self-hosted базовый сценарий, mobile/extension в будущем.

**Стек.**

- **Хранилище:** SQLite + WAL + Litestream → S3 с Object Lock. Один файл, бэкап тривиальный, нет network attack surface.
- **Транспорт:** REST + JSON + OpenAPI-spec. С OpenAPI генерируется TS-клиент. Streaming — single SSE endpoint `/events` с long-poll fallback.
- **Server framework:** Go + chi/echo + standard library `database/sql`. Без mx-launcher (overkill для одного бинаря).
- **Криптомодель:** идентичная текущей. Argon2id master_key, HKDF auth_key, vault_key/item_key/blind_index — этот пласт у вас отличный.
- **2FA:** только WebAuthn в MVP. Login-TOTP добавляет огромную сложность (server-side secret derived from auth_key, ChangeMasterPassword rotation, recovery rotation) ради совместимости с Google Authenticator. Современный flow — passkeys, и пользователь начинает с регистрации passkey'а; TOTP добавляется опционально как low-tech backup. **В MVP — пропустить, добавить во второй спринт.**

**Что выкидываем.**

- **Postgres.** SQLite single-writer достаточен для single-user.
- **RLS.** Один user-bound query — `WHERE user_id = ?`. Не нужен GUC + interceptor + bypass.
- **River jobs.** Goroutine + ticker × 4 (verify, sessions GC, idempotency GC, mfa GC). Хватает.
- **Audit external anchor.** В single-user self-hosted нет threat-model'и, где он реально помогает. Hash chain в DB остаётся.
- **MFAKEK.** MFA challenge живёт в in-memory store (как было до миграции на PG). TTL 5 минут, sticky session не нужен (один процесс).
- **Postgres LISTEN/NOTIFY.** In-process pub/sub broker. SSE подключён напрямую.
- **Rate-limit в Postgres.** `golang.org/x/time/rate` per-IP + per-email, in-memory. Single-node only задокументировано.
- **Vault.** Только env-vars. `OBLIVIO_SEED` (32+ bytes hex/base64) обязателен при старте; всё остальное (JWT, MFAKEK если будет, anchor) выводится через HKDF.
- **ConnectRPC.** REST + OpenAPI-codegen.
- **memguard на сервере.** Реально защищает только JWT seed и K_login_totp (если TOTP остаётся). Для остального — обычный Go GC. Honestly документировать "memguard для JWT seed only".

**Что добавляем.**

- **Recovery code rotation на RecoveryComplete + ChangeMasterPassword** (см. 1.1).
- **Audit-chain без external anchor** — но с **append-only** уровня файловой системы: SQLite таблица audit_log на дополнительной WORM-FS (`overlayfs` поверх read-only nfs/s3-mount, или просто `chattr +a` на ext4-файле). Это даёт honest «нельзя удалить строку, не алертив».
- **External witness через append-to-file**: каждую N-ю строку дублировать в plain-text лог `audit.log` в WORM-папке. По периметру — Litestream бэкап с object-lock.

**Структура proto-style (но JSON).**

```text
POST /v1/auth/register       (anonymous, rate-limited)
POST /v1/auth/kdf-params     (anonymous, rate-limited)
POST /v1/auth/authorize      (anonymous, rate-limited)
POST /v1/auth/refresh
POST /v1/auth/logout
POST /v1/auth/change-password
GET  /v1/me                  (auth)
GET  /v1/projects            (auth)
... entries, audit, sessions
GET  /v1/events              (auth, SSE, long-poll)
```

**Скорость разработки.** Меньше пайплайна (buf + protoc + Connect TS-stubs + Vite), быстрее change cycle. Один бинарь — деплой через `scp + systemd`, оператор-friendly.

**Чего лишаемся.** Multi-instance, multi-tenant SaaS — не масштабируемся без рефакторинга. Это сознательный выбор: «self-hosted менеджер на одного человека / на семью» ≠ «cloud SaaS как Bitwarden».

**Длина MVP.** ~10к строк Go + ~5к строк TS, против текущих ~30к + 10к. Снижение площади атаки и поверхности поддержки в 2-3 раза.

---

## Summary

Текущая реализация — добротная zero-knowledge архитектура с правильным разделением «крипта на клиенте, ciphertext + metadata на сервере». Криптографические примитивы корректны, AEAD-envelopes согласованы Go↔TS, HKDF-info-метки версионированы, RLS правильно подключён.

Главные дефекты — **не в крипте, а в политиках вокруг неё**:

1. Recovery code как permanent backdoor (§1.1).
2. Audit anchor, который не запускается на «чистом» chain (§1.2).
3. DoS-vector через permanent account lockout (§1.3).
4. Timing-сайдканалы в anti-enumeration (§1.4).
5. Тихий drop TOTP при частичных данных в rotation (§1.5).

И «честный архитектурный накладной налог» — комбинация Postgres + River + LISTEN/NOTIFY + Vault + memguard + ConnectRPC даёт хорошую защиту, но **для текущей цели** (self-hosted single-user менеджер) overkill ровно в той части, где он сделан красиво.

Документ §17 «known limitations» честный, но **должен пополниться** позициями §1.1, §1.2, §1.3, §1.4 — это не reified compromises, это найденные баги.
