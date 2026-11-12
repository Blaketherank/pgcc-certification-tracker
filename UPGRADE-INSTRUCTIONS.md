# Ultimate FREE v4 — Upgrade the existing certification tracker

This is a **fictional-data demo** developed by Elevate Systems Consulting. It is not a certified PGCC production system. The v4 upgrade preserves your **existing D1 database, Cloudflare Worker URL, GitHub repository, authentication accounts and passwords, `wrangler.toml`, and `frontend/config.js`**.

## What you get

- All previous features: secure role-based login, student submissions, manual approval/rejection/revisions, notifications, searchable credential registry, catalog, learning goals, announcements, historical activity, audit log, reporting, CSV exports, analytics, expiration monitoring, and user administration.
- **Program Pathways:** administrators create pathways and map catalog certifications to each; students join pathways and see indicative requirement coverage based on approved credential title/issuer matches.
- **Verification Desk:** staff can save checklists covering issuer, ID/link, dates, and fictional demo evidence, with reviewer notes and audit events. This **does not** call external verification services.
- **Operations Command Center:** reviewer backlog and aging, credentials approaching expiry, program enrollments, and recent logged events.
- **Portfolio:** students can print/save an *unofficial* portfolio with approved records and personal goals.
- **Role-tailored Demo Guide**, enhanced responsive layout and accessibility styling.

## Your Mac setup (minimal commands)

**Step 1: Extract ZIP into Downloads.** Open Terminal in the extracted package directory (the directory containing `install-upgrade.sh`). Example:

```bash
cd "$HOME/Downloads/PGCC-Certification-Tracker-ULTIMATE-FREE-v4"
```

If the extracted folder has a different name, drag the folder from Finder into Terminal after typing `cd `.

**Step 2: Install into your existing working project.** The previously established path was `~/Downloads/pgcc-certification-tracker`:

```bash
bash install-upgrade.sh "$HOME/Downloads/pgcc-certification-tracker"
```

The installer makes a local code backup. It does not recreate accounts or change Cloudflare configuration.

**Step 3: Export D1, then migrate/deploy/push with confirmation.**

```bash
bash deploy-upgrade.sh "$HOME/Downloads/pgcc-certification-tracker"
```

The script exports the **live** D1 database to `~/Desktop/pgcc-cloudflare-backups/`, verifies the backup file exists and is nonempty, then asks you to type `DEPLOY`. Only then does it run `npm run db:remote`, `npm run deploy:api`, commit the updated source files, and `git push origin main`. **Stop if any command fails**. Do not run `/api/setup` again or create a new D1 database.

**Step 4: Verify.** After GitHub Actions succeeds, open `https://blaketherank.github.io/pgcc-certification-tracker/` and hard refresh. Log in with your existing administrator account.

## Suggested demo sequence

1. Admin adds a certification to the Catalog, creates a Program Pathway and maps that certification to the program.
2. Admin creates fictional student/reviewer users and a role-targeted announcement.
3. Student joins a pathway, sets a learning goal, submits fictional certification information and adds a demo evidence *description*.
4. Reviewer sees the record in the Review Queue, saves the manual verification checklist, then approves or requests revisions in the Certification Registry.
5. Student views in-app notification, updated pathway coverage, and an unofficial printable portfolio.
6. Admin visits Operations and Analytics to show backlog, risk, trends, audit log and CSV reports.
7. Verify student accounts cannot see other student records, checklists, or admin dashboards.

## Safety, privacy and limitations

- No real certificate file upload/storage. Do not enter actual student records or institutional secrets.
- Pathway progress is a **demonstration heuristic** matching *approved* certificate title + issuer to catalog entries; it is not official credit articulation, program completion or third-party certification verification.
- Reviewer checklist is an attestation written into D1; it does not automatically authenticate credentials.
- This upgrade uses **free tier** GitHub Pages + Cloudflare Worker/D1 without adding R2, billing or subscription dependencies. Stay within free limits; available quotas and terms may change.
- Existing Worker authentication remains intact; PBKDF2 100,000 iterations is a known Cloudflare compatibility workaround, not evidence of security-audit readiness.
- Code syntax and SQLite migration checks pass; **live Cloudflare integration and comprehensive security tests have not been performed**.

## Rollback

- Installer backup: `YOUR_PROJECT/.local-backups/pre-v4-TIMESTAMP` (ignored from Git).
- D1 export backup: `~/Desktop/pgcc-cloudflare-backups/pgcc-d1-pre-v4-TIMESTAMP.sql`.
- To roll back UI/API, restore `worker/index.js`, `frontend/app.js`, `frontend/styles.css`, and `frontend/index.html` from the local backup, redeploy Worker, commit and push. Additive v4 tables may safely remain unused. Do **not** blindly import an old D1 backup over new live data.
