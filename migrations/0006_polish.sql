-- V6 additive performance indexes only; no data or authentication changes.
CREATE INDEX IF NOT EXISTS idx_users_role_active_name ON users(role, active, full_name);
CREATE INDEX IF NOT EXISTS idx_cert_issuer_status ON certifications(issuer, status);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_log(actor_id, occurred_at DESC);
