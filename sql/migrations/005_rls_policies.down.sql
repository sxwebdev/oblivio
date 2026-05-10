DROP POLICY IF EXISTS audit_log_owner_read ON audit_log;
DROP POLICY IF EXISTS auth_sessions_owner  ON auth_sessions;
DROP POLICY IF EXISTS entries_owner        ON entries;
DROP POLICY IF EXISTS projects_owner       ON projects;

ALTER TABLE audit_log     DISABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE entries       DISABLE ROW LEVEL SECURITY;
ALTER TABLE projects      DISABLE ROW LEVEL SECURITY;

DROP FUNCTION IF EXISTS app_current_user_id();
