# Upgrade v5 → v6 without recreating accounts

**Requires a working v5 installation.** Your last confirmed existing project folder was `~/Downloads/pgcc-certification-tracker`. This ZIP has safe placeholder configuration and MUST be installed into the existing configured repository, not deployed as an independent project.

1. Download and extract this ZIP into Downloads (folder `PGCC-Certification-Tracker-ENTERPRISE-POLISH-v6`).
2. In Mac Terminal:
   ```bash
   cd "$HOME/Downloads/PGCC-Certification-Tracker-ENTERPRISE-POLISH-v6"
   bash install-upgrade.sh "$HOME/Downloads/pgcc-certification-tracker"
   ```
3. The install script checks for v5, backs up your local source under `.local-backups/`, preserves `wrangler.toml`, `frontend/config.js`, `.git`, previous migrations, and tests the new code. **It does not touch your live database.**
4. Then **only after the install script succeeds**, run:
   ```bash
   bash deploy-upgrade.sh "$HOME/Downloads/pgcc-certification-tracker"
   ```
5. The deploy script first runs syntax and integration tests, exports the live D1 database to `~/Desktop/pgcc-cloudflare-backups/`, checks backup existence, and asks for explicit `DEPLOY`. It then runs migration, deploys the existing Worker, and pushes the frontend to the existing GitHub repository.
6. Confirm GitHub Actions shows a green check, then sign in at `https://blaketherank.github.io/pgcc-certification-tracker/` with your **existing** administrator account. You may need to sign in again if your browser session expires.

## Functional verification

- Login as administrator. Open Global Search, Student 360, Reporting Studio, Security Center and Demo Lab.
- Create the fictional demo accounts with Demo Lab if not created previously; securely retain passwords shown once. Never send them in chat or add them to Git.
- In Demo Lab click **Add Fictional Sample Records** after provisioning the demo student accounts. This calls the administrator-only demo scenario endpoint, is idempotent, and does not delete or overwrite existing records.
- Open Report Studio and export aggregated CSV; do not treat aggregate demo metrics as real college outcomes.
- Verify that student accounts cannot access Student 360, Reporting Studio, or Security Center; reviewers can access Student 360 and reports but not Security Center.
- Confirm legacy submission/approval flows and notifications continue working.

## If the upgrade fails

Stop on any error. The installer keeps a local source backup, and the deploy script exports a D1 backup before migration. Do not delete the live D1 database, call `/api/setup`, or attempt to regenerate the administrator account. If migration or Worker deployment fails, inspect output before re-running; backups alone are not automatic rollback.

## Limitations

The v6 code passes offline unit/integration testing but has **not** been deployed to your Cloudflare account in this environment. Cloudflare free-tier CPU and query quotas still apply. Password hashing stays at the supported 100,000 PBKDF2 iterations; this is a prototype compatibility compromise, not a claim of production-grade credential storage. Secure cookies, MFA, password resets, complete record-level authorization analysis, and professional vulnerability testing remain future work.
