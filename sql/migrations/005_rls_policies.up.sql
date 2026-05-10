-- Row Level Security as defence-in-depth. The application layer is the
-- primary authorization boundary; RLS catches mistakes such as a missing
-- WHERE user_id clause and prevents cross-tenant reads even if a query
-- forgets the predicate.
--
-- Each request executes `SET LOCAL app.current_user_id = '<uuid>'` before
-- touching any table. Calls without that GUC return zero rows.

CREATE OR REPLACE FUNCTION app_current_user_id() RETURNS UUID
    LANGUAGE plpgsql STABLE
AS $$
BEGIN
    RETURN current_setting('app.current_user_id', true)::uuid;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

ALTER TABLE projects                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE entries                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions             ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log                 ENABLE ROW LEVEL SECURITY;

CREATE POLICY projects_owner ON projects
    USING (user_id = app_current_user_id())
    WITH CHECK (user_id = app_current_user_id());

CREATE POLICY entries_owner ON entries
    USING (user_id = app_current_user_id())
    WITH CHECK (user_id = app_current_user_id());

CREATE POLICY auth_sessions_owner ON auth_sessions
    USING (user_id = app_current_user_id())
    WITH CHECK (user_id = app_current_user_id());

-- audit_log: a user can read only their own records; writes happen via a
-- service path that bypasses RLS (the audit writer uses an internal role
-- that has BYPASSRLS or runs without the GUC set).
CREATE POLICY audit_log_owner_read ON audit_log
    FOR SELECT
    USING (user_id = app_current_user_id());
