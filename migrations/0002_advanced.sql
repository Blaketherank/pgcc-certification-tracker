-- Safe additive upgrade: retains all existing records and accounts.
CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL,
 message TEXT NOT NULL,
 certification_id TEXT REFERENCES certifications(id) ON DELETE SET NULL,
 is_read INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cert_expiry ON certifications(status,expires_on);
CREATE INDEX IF NOT EXISTS idx_cert_created ON certifications(created_at);
CREATE INDEX IF NOT EXISTS idx_cert_reviewer ON certifications(reviewed_by);
