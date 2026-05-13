-- name: GetUserKDFParams :one
SELECT * FROM user_kdf_params WHERE user_id = $1;

-- name: UpsertUserKDFParams :exec
INSERT INTO user_kdf_params (user_id, salt_user, argon2_t, argon2_m_kib, argon2_p, algo, blind_pepper)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (user_id) DO UPDATE
SET salt_user    = EXCLUDED.salt_user,
    argon2_t     = EXCLUDED.argon2_t,
    argon2_m_kib = EXCLUDED.argon2_m_kib,
    argon2_p     = EXCLUDED.argon2_p,
    algo         = EXCLUDED.algo,
    blind_pepper = EXCLUDED.blind_pepper;
