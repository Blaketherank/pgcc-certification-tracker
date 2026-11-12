# v6 → v7 — Install without resetting authentication

Use your existing working repository at `~/Downloads/pgcc-certification-tracker`.

1. Download and extract the v7 ZIP into Downloads.
2. Run:
   ```bash
   cd "$HOME/Downloads/PGCC-Certification-Tracker-STUDENT360-REPORTING-v7"
   bash install-upgrade.sh "$HOME/Downloads/pgcc-certification-tracker"
   ```
   This validates the v6 migration, creates a local source-code backup under `.local-backups/`, and installs v7 locally. It runs JavaScript syntax checks and four integration tests. It does not alter Cloudflare or the live database.
3. To back up and deploy:
   ```bash
   bash deploy-upgrade.sh "$HOME/Downloads/pgcc-certification-tracker"
   ```
   The script exports your actual D1 database under `~/Desktop/pgcc-cloudflare-backups/`, verifies the file is nonempty, and asks you to type `DEPLOY` before applying migration 0007, updating the existing Worker, and pushing to your GitHub repository. **Stop if any step fails.** Never rerun `/api/setup`.
4. Check [GitHub Actions](https://github.com/blaketherank/pgcc-certification-tracker/actions) for a green deployment and then open [the site](https://blaketherank.github.io/pgcc-certification-tracker/). Hard-refresh if necessary.

## Acceptance checklist

- Admin login still works; reviewer and student logins still work.
- Admin opens Student 360 > a student > Account & Profile, changes a fictional cohort and saves. Reload and verify persisted values.
- Reviewer can open the same profile but sees read-only details. Student cannot open staff directory/profile APIs.
- Admin changes a fictional student's account email, confirms the previous email cannot sign in, and that the new email can.
- Admin uses Reset password with a fictional account; existing sessions are revoked, new password works, and the student is required to change it.
- Admin can deactivate/reactivate a fictional student; inactive student cannot log in.
- Reporting Studio filters by issuer, status, date and program; chart totals and exported CSV match the selected filters.
- Test legacy submission, evidence description, verification checklist, approval and notifications.
- Check Developer Tools for console/network errors; check Worker's logs for any 500 errors.

## Limits of validation

Offline integration tests cover key server workflows. The Playwright browser smoke test couldn't run in the build environment because browser navigation was blocked by its administrator policy. Therefore no claim is made that every browser control has been exercised. Perform the acceptance checklist on your live test environment using fictional data before presenting.

Do not enter real student records or confidential personal information into this prototype.
