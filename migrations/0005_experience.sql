-- V5 additive only; preserves existing accounts, credentials, sessions, and IDs.
CREATE TABLE IF NOT EXISTS workflow_rules (
 id TEXT PRIMARY KEY,
 event TEXT NOT NULL CHECK(event IN ('submitted','needs_revision')),
 action TEXT NOT NULL CHECK(action IN ('task','notify')),
 priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high')),
 days_due INTEGER NOT NULL DEFAULT 3 CHECK(days_due BETWEEN 1 AND 30),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS workflow_tasks (
 id TEXT PRIMARY KEY,
 event_key TEXT NOT NULL UNIQUE,
 certification_id TEXT NOT NULL REFERENCES certifications(id) ON DELETE CASCADE,
 title TEXT NOT NULL,
 priority TEXT NOT NULL CHECK(priority IN ('low','normal','high')),
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','completed')),
 assigned_to TEXT REFERENCES users(id),
 due_at TEXT NOT NULL,
 created_by TEXT REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_workflow_tasks_status ON workflow_tasks(status,assigned_to,due_at);
INSERT OR IGNORE INTO workflow_rules(id,event,action,priority,days_due) VALUES
 ('seed-review-rule','submitted','task','normal',3);
