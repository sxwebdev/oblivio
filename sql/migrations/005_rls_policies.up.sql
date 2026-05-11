-- Row Level Security as defence-in-depth. The application layer is the
-- primary authorization boundary; RLS catches mistakes such as a missing
-- WHERE user_id clause and prevents cross-tenant reads even if a query
-- forgets the predicate.
--
-- Each per-user request executes
--     SET LOCAL app.current_user_id = '<uuid>'
-- before touching any table. Trusted system paths (audit-writer, chain
-- verifier, GC jobs, auth Manager) instead set
--     SET LOCAL app.bypass_rls = 'true'
-- — bypass disables RLS for that tx but does NOT widen authorization;
-- callers still filter by user_id explicitly.
--
-- FORCE ROW LEVEL SECURITY is required: the migration owner role is
-- otherwise exempt from policies, which would make RLS decorative.

CREATE OR REPLACE FUNCTION app_current_user_id() RETURNS UUID
    LANGUAGE plpgsql STABLE
AS $$
BEGIN
    RETURN current_setting('app.current_user_id', true)::uuid;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app_is_system() RETURNS BOOLEAN
    LANGUAGE plpgsql STABLE
AS $$
BEGIN
    RETURN current_setting('app.bypass_rls', true) = 'true';
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$;

ALTER TABLE projects                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects                  FORCE  ROW LEVEL SECURITY;
ALTER TABLE entries                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE entries                   FORCE  ROW LEVEL SECURITY;
ALTER TABLE auth_sessions             ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions             FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_log                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log                 FORCE  ROW LEVEL SECURITY;

CREATE POLICY projects_owner ON projects
    USING       (app_is_system() OR user_id = app_current_user_id())
    WITH CHECK  (app_is_system() OR user_id = app_current_user_id());

CREATE POLICY entries_owner ON entries
    USING       (app_is_system() OR user_id = app_current_user_id())
    WITH CHECK  (app_is_system() OR user_id = app_current_user_id());

CREATE POLICY auth_sessions_owner ON auth_sessions
    USING       (app_is_system() OR user_id = app_current_user_id())
    WITH CHECK  (app_is_system() OR user_id = app_current_user_id());

-- audit_log: a user can only read their own records; the audit writer
-- runs with bypass and inserts under any user_id.
CREATE POLICY audit_log_owner_read ON audit_log
    FOR SELECT
    USING (app_is_system() OR user_id = app_current_user_id());

CREATE POLICY audit_log_system_insert ON audit_log
    FOR INSERT
    WITH CHECK (app_is_system());
