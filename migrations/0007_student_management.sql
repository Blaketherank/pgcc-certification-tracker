-- V7 additive: optional staff-maintained fictional student profile metadata.
-- Existing user IDs, emails, credentials, sessions, and certification records are retained.
CREATE TABLE IF NOT EXISTS student_profiles (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 department TEXT NOT NULL DEFAULT '',
 cohort TEXT NOT NULL DEFAULT '',
 advisor TEXT NOT NULL DEFAULT '',
 internal_reference TEXT NOT NULL DEFAULT '',
 staff_notes TEXT NOT NULL DEFAULT '',
 updated_by TEXT REFERENCES users(id),
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_profiles_cohort ON student_profiles(cohort);
CREATE INDEX IF NOT EXISTS idx_profiles_department ON student_profiles(department);
