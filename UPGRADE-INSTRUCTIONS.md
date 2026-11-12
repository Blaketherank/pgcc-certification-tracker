# Enterprise Free v3 — Upgrade your existing deployment

**For Elevate Systems Consulting's fictional-data PGCC Certification Tracker demonstration.** This adds functionality to the existing working site. It does not require a paid service, new database or new administrator account. Free service limits apply; real protected records must not be entered.

## Features

Previous v1/v2 features stay: student/administrator/reviewer roles, login, credential submissions, fictional evidence descriptions, approval/rejection/revision flow, searchable registry, reporting, CSV export, audit logs, notification inbox, reviewer queue, expiry watchlist and analytics.

V3 adds:
- **Certification Catalog:** six seeded sample credentials and expandable admin-maintained catalog; category/level/search filtering.
- **Student Development Plans:** milestones, target dates and progress statuses; catalog-to-goal action; goals are private to each student.
- **Role-targeted Announcements:** administrators can publish or archive notices; students/reviewers see applicable notices.
- **Certification History:** ownership-checked activity timeline from audit events.
- **Polished enterprise interface:** responsive catalog cards, learning-plan progress cards, announcement feed, activity timelines.

Catalog content is illustrative; it is not a guarantee of current certification requirements or an official PGCC offering. Notifications are in-app only; the free edition does not upload or store proof documents.

## Safest upgrade (Mac Terminal)

1. **Back up your live Cloudflare D1 database** using Cloudflare's dashboard or Wrangler. Check that the export exists. Do not skip this because migrations change the live database.
2. Download and extract this ZIP into Downloads or Desktop.
3. Open Terminal, change to the **extracted v3 folder** (the one containing `install-upgrade.sh`), and run:

```bash
bash install-upgrade.sh "$HOME/Desktop/pgcc-certification-tracker"
```

The script copies updated code into your existing project, creates a timestamped local source backup, and does **not** replace your working `wrangler.toml`, `frontend/config.js`, database ID, domain or GitHub settings.

4. In Terminal run:

```bash
cd "$HOME/Desktop/pgcc-certification-tracker"
npm run db:remote
npm run deploy:api
git add worker/index.js frontend/app.js frontend/styles.css migrations/0002_advanced.sql migrations/0003_enterprise.sql UPGRADE-INSTRUCTIONS.md
git commit -m "Advanced free v3 upgrade"
git push origin main
```

If a command fails, **stop** and review the message rather than advancing to the next command. The database operation applies pending 0002 and 0003 migrations (or only 0003 if v2 is already installed). **Never** recreate D1 or run `/api/setup` again.

5. Check GitHub Actions. When deployment finishes, hard-refresh the existing GitHub Pages URL. Sign in with your existing account.

## Verification / demo walkthrough

1. Administrator: open Certification Catalog; add an entry; post an announcement for students.
2. Administrator: create a **fictional** student and reviewer account (strong temporary password, private handoff).
3. Student: see the announcement; open Certification Catalog; choose “Plan this certification”; open My Development Plan; set a milestone status.
4. Student: submit a fictional certificate and record a **description**, not a file.
5. Reviewer: use Review Queue; approve or request revision; open registry certification History to see activity.
6. Student: open Inbox to view the decision and mark it read.
7. Administrator: inspect Analytics, Reports, certification expiry watchlist and Audit Log.
8. Confirm a student cannot read another student's records/goals and cannot use admin APIs.

## Rollback and important caveats

- The upgrade script makes a timestamped local backup of the previous frontend/worker code. To roll back UI and Worker, restore those files from the backup, redeploy the Worker and push the frontend. **Do not remove the new database tables** just to roll back code; additive tables can remain harmlessly.
- Do not overwrite `wrangler.toml`, `frontend/config.js`, or use the included placeholder configuration file to deploy.
- `npm run check` covers JavaScript syntax, not every functional/security workflow. Live Cloudflare integration was not tested here. Password hashing is compatible with the previously observed Cloudflare PBKDF2 ceiling but is not independently audited.
- GitHub Pages site files are public; backend secrets must remain in Wrangler secrets. Free Workers/D1 limits may affect availability.
- This is a production-style **demo**, not production-approved for real student records, FERPA compliance or actual proof-file verification.
