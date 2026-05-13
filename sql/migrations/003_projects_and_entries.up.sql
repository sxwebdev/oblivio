-- Projects: logical groupings of entries. All metadata is encrypted client-side;
-- the server only stores ciphertext + a wrapped item key + a blind name hash.
CREATE TABLE projects (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

-- Entries cover all kinds of secret records, including notes (kind='note').
-- There is no separate notes table — UI filters by kind.
CREATE TYPE entry_kind AS ENUM ('login', 'totp', 'card', 'identity', 'ssh_key', 'note');

CREATE TABLE entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id          UUID REFERENCES projects(id) ON DELETE SET NULL,
    kind                entry_kind NOT NULL DEFAULT 'login',
    encrypted_blob      BYTEA NOT NULL,
    wrapped_item_key    BYTEA NOT NULL,
    title_hash          BYTEA NOT NULL,
    domain_hash         BYTEA,
    has_totp            BOOLEAN NOT NULL DEFAULT FALSE,
    is_favorite         BOOLEAN NOT NULL DEFAULT FALSE,
    version             INT  NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_entries_user_id     ON entries(user_id);
CREATE INDEX idx_entries_project_id  ON entries(project_id);
CREATE INDEX idx_entries_kind        ON entries(user_id, kind);
CREATE INDEX idx_entries_title_hash  ON entries(user_id, title_hash);
CREATE INDEX idx_entries_domain_hash ON entries(user_id, domain_hash) WHERE domain_hash IS NOT NULL;
CREATE INDEX idx_entries_updated_at  ON entries(user_id, updated_at DESC);
CREATE INDEX idx_entries_favorite    ON entries(user_id, is_favorite) WHERE is_favorite;
