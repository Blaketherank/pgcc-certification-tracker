-- Additive enterprise demo features, existing records untouched.
CREATE TABLE IF NOT EXISTS catalog (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, issuer TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT 'General', level TEXT NOT NULL DEFAULT 'Foundational',
 description TEXT NOT NULL DEFAULT '', verification_url TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS student_goals (
 id TEXT PRIMARY KEY, student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 catalog_id TEXT REFERENCES catalog(id) ON DELETE SET NULL,
 title TEXT NOT NULL, target_date TEXT, status TEXT NOT NULL DEFAULT 'planned'
 CHECK(status IN ('planned','in_progress','completed')),
 notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_student_goals_owner ON student_goals(student_id,status);
CREATE TABLE IF NOT EXISTS announcements (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
 audience TEXT NOT NULL DEFAULT 'all' CHECK(audience IN ('all','student','reviewer','admin')),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 author_id TEXT REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_announcements_recent ON announcements(active,created_at DESC);
INSERT OR IGNORE INTO catalog (id,title,issuer,category,level,description) VALUES
 ('seed-comptia-a','CompTIA A+','CompTIA','IT Support','Foundational','Core hardware, software and troubleshooting'),
 ('seed-comptia-n','CompTIA Network+','CompTIA','Networking','Intermediate','Networking concepts, operations and troubleshooting'),
 ('seed-comptia-s','CompTIA Security+','CompTIA','Security','Intermediate','Security fundamentals and risk management'),
 ('seed-ccna','CCNA','Cisco','Networking','Intermediate','Routing, switching, IP services and security'),
 ('seed-aws-cp','AWS Certified Cloud Practitioner','Amazon Web Services','Cloud','Foundational','Cloud concepts, security, pricing and core services'),
 ('seed-az900','Microsoft Azure Fundamentals','Microsoft','Cloud','Foundational','Azure cloud fundamentals and governance');
