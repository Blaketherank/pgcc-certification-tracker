-- Ultimate v4: additive program pathways and reviewer checklists.
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS programs (
 id TEXT PRIMARY KEY,
 title TEXT NOT NULL,
 department TEXT NOT NULL DEFAULT 'Technology',
 description TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS program_requirements (
 id TEXT PRIMARY KEY,
 program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
 catalog_id TEXT NOT NULL REFERENCES catalog(id),
 required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0,1)),
 UNIQUE(program_id,catalog_id)
);
CREATE INDEX IF NOT EXISTS idx_program_req_program ON program_requirements(program_id);
CREATE TABLE IF NOT EXISTS student_programs (
 student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
 joined_at TEXT NOT NULL DEFAULT (datetime('now')),
 PRIMARY KEY(student_id,program_id)
);
CREATE INDEX IF NOT EXISTS idx_student_program_program ON student_programs(program_id);
CREATE TABLE IF NOT EXISTS verification_checks (
 certification_id TEXT PRIMARY KEY REFERENCES certifications(id) ON DELETE CASCADE,
 issuer_checked INTEGER NOT NULL DEFAULT 0 CHECK(issuer_checked IN (0,1)),
 identifier_checked INTEGER NOT NULL DEFAULT 0 CHECK(identifier_checked IN (0,1)),
 dates_checked INTEGER NOT NULL DEFAULT 0 CHECK(dates_checked IN (0,1)),
 evidence_reviewed INTEGER NOT NULL DEFAULT 0 CHECK(evidence_reviewed IN (0,1)),
 reviewer_notes TEXT NOT NULL DEFAULT '',
 checked_by TEXT REFERENCES users(id),
 checked_at TEXT
);
INSERT OR IGNORE INTO programs(id,title,department,description) VALUES
 ('path-network','Networking & Infrastructure','Information Technology','Demonstration pathway for core networking credentials and infrastructure skills.'),
 ('path-cyber','Cybersecurity Fundamentals','Information Technology','Demonstration pathway for foundational security credentials.'),
 ('path-cloud','Cloud Foundations','Information Technology','Demonstration pathway for introductory cloud-platform credentials.');
INSERT OR IGNORE INTO program_requirements(id,program_id,catalog_id,required) VALUES
 ('req-net-plus','path-network','seed-comptia-n',1),
 ('req-net-ccna','path-network','seed-ccna',1),
 ('req-cyber-sec','path-cyber','seed-comptia-s',1),
 ('req-cyber-net','path-cyber','seed-comptia-n',1),
 ('req-cloud-aws','path-cloud','seed-aws-cp',1),
 ('req-cloud-az','path-cloud','seed-az900',1);
