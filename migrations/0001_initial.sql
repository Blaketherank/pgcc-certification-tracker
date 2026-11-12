PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, full_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('student','reviewer','admin')),
 password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, password_iterations INTEGER NOT NULL,
 must_change_password INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS certifications (
 id TEXT PRIMARY KEY, student_id TEXT NOT NULL REFERENCES users(id),
 title TEXT NOT NULL, issuer TEXT NOT NULL, credential_id TEXT NOT NULL DEFAULT '',
 verification_url TEXT NOT NULL DEFAULT '', earned_on TEXT NOT NULL, expires_on TEXT,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','needs_revision')),
 notes TEXT NOT NULL DEFAULT '', reviewed_by TEXT REFERENCES users(id), reviewed_at TEXT,
 proof_key TEXT, proof_name TEXT, proof_type TEXT,
 created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cert_student ON certifications(student_id);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certifications(status);
CREATE TABLE IF NOT EXISTS audit_log (
 id TEXT PRIMARY KEY, actor_id TEXT REFERENCES users(id), event TEXT NOT NULL,
 target_id TEXT, metadata TEXT NOT NULL DEFAULT '{}', occurred_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(occurred_at);
CREATE TABLE IF NOT EXISTS login_attempts (
 key TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0, window_start TEXT NOT NULL
);
