# PGCC Certification Tracker — Free Demo Edition

**Elevate Systems Consulting | $0 hosting architecture | DEMO DATA ONLY**

This is the **no-R2** edition. It uses GitHub Pages for public static frontend hosting, Cloudflare Workers Free for the API, and Cloudflare D1 Free for the database. **There is NO file upload or document storage.** Students record a fictional evidence description as text, which reviewers can use during the demo. Do not present this as real document verification. Do not enter real student or protected data. This is a deployment candidate, not a certified production system.

## Files
- `frontend/`: static site (HTML, CSS, JS); change only the public Worker URL in `frontend/config.js`
- `worker/index.js`: authentication, user, submissions, reviews, reporting and demo evidence API
- `migrations/0001_initial.sql`: D1 schema
- `wrangler.toml`: Worker name, CORS origin, D1 binding; **NO R2 binding**
- `.github/workflows/pages.yml`: GitHub Pages deployment
- `.dev.vars.example`: sample local-only secret, not real credentials

## What you need
Free GitHub account, free Cloudflare account, Node.js 20+ LTS, Git, Terminal. Use free tiers only and do not enable paid services or submit billing information if you wish to avoid charges. Check service limits and eligibility before creating resources.

## A. Create a database and configure the backend

```bash
cd ~/Desktop/pgcc-certification-tracker
npm install
npx wrangler login
npx wrangler d1 create pgcc-cert-tracker
```

Copy the **actual `database_id`** from Wrangler into `wrangler.toml` under `[[d1_databases]]` (replace `REPLACE_WITH_YOUR_D1_DATABASE_ID`). Keep the `binding = "DB"` and `database_name = "pgcc-cert-tracker"` unchanged.

## B. Prepare GitHub Pages origin

Before production deployment, create a public GitHub repository named `pgcc-certification-tracker`. If your GitHub username is `YOUR-USERNAME`, your frontend origin is **`https://YOUR-USERNAME.github.io`** (no trailing slash, no repository pathname). Change the `ALLOWED_ORIGINS` value in `wrangler.toml` to:

```toml
ALLOWED_ORIGINS = "https://YOUR-USERNAME.github.io,http://localhost:5173"
```

This setting is for the **origin** only. Use your actual username. A different repository name changes the website PATH but does not change the origin.

## C. Apply the D1 schema

```bash
npm run db:remote
```

Confirm when asked. (For local-only development: `npm run db:local`.)

## D. Bootstrap an administrator securely

Create a secret and add it to the Cloudflare Worker:

```bash
openssl rand -hex 32
npx wrangler secret put BOOTSTRAP_TOKEN
npm run deploy:api
```

The first command displays a random value; safely copy it, paste it when Wrangler prompts for `BOOTSTRAP_TOKEN`, and do not commit it or send it to anyone. Wrangler deploy outputs a Worker URL, e.g. `https://pgcc-cert-tracker-api.YOUR-SUBDOMAIN.workers.dev`. Test it at `https://YOUR-WORKER-URL/api/health`.

For the one-time account creation, avoid including the password or bootstrap token in your shell history. In Terminal use:

```bash
read -s BOOTSTRAP_TOKEN; echo
read -s ADMIN_PASSWORD; echo
export BOOTSTRAP_TOKEN ADMIN_PASSWORD
export WORKER_URL='https://YOUR-ACTUAL-WORKER-URL'
node -e 'const u=process.env.WORKER_URL;const headers={"Content-Type":"application/json","X-Bootstrap-Token":process.env.BOOTSTRAP_TOKEN};const body=JSON.stringify({full_name:"Demo Administrator",email:"admin@example.test",password:process.env.ADMIN_PASSWORD});fetch(u+"/api/setup",{method:"POST",headers,body}).then(async r=>console.log(r.status,await r.text())).catch(console.error)'
```

Enter your own strong (12+ chars including letters and numbers) password when prompted; replace `admin@example.test` with an email that you control **in the node command** before running it. A `201` response indicates administrator creation. **Immediately remove the bootstrap secret**:

```bash
npx wrangler secret delete BOOTSTRAP_TOKEN
npm run deploy:api
unset BOOTSTRAP_TOKEN ADMIN_PASSWORD
```

## E. Connect the frontend

Edit `frontend/config.js`:

```javascript
export const API_BASE_URL = 'https://YOUR-ACTUAL-WORKER-URL';
```

The Worker URL is public; NEVER place private tokens, passwords, or Cloudflare account secrets in this file.

## F. Upload to GitHub

Create a **public** GitHub repository `pgcc-certification-tracker` without initial README, using the GitHub website. In the local project directory:

```bash
git init
git branch -M main
git add .
git status
git commit -m "Deploy free demo certification tracker"
git remote add origin https://github.com/YOUR-USERNAME/pgcc-certification-tracker.git
git push -u origin main
```

Substitute your GitHub username. Check `git status` and staged files for secrets before pushing. In GitHub repository **Settings > Pages**, set **Build and deployment > Source: GitHub Actions**. The included workflow publishes the `frontend/` directory on push to `main`. Find the deployed URL in **Actions** or **Settings > Pages**:

`https://YOUR-USERNAME.github.io/pgcc-certification-tracker/`

## G. Full demonstration test

1. Open the GitHub Pages URL and sign in with the initial admin credentials.
2. In User Management, create fictional student and reviewer accounts using unique temporary passwords. Their first sign-in requires a password change.
3. Sign out; sign in as student; submit a fictional credential.
4. Open Details and **record demo evidence description** (not an uploaded file).
5. Sign out; sign in as reviewer; approve the pending credential.
6. Sign in as student; confirm status changed to Approved.
7. Sign in as admin; inspect reports, export CSV, and view the audit trail.
8. Confirm a student cannot view another student's credentials or admin endpoints.

## Local development (optional)

Create `.dev.vars` with `BOOTSTRAP_TOKEN=<your-private-token>`; see `.dev.vars.example`. `npm run db:local`, `npm run dev:api`. From another Terminal tab run `cd frontend && python3 -m http.server 5173`. Local config defaults to `http://localhost:8787` in `frontend/config.js`, so switch it back while testing locally.

## Troubleshooting

- **npm missing**: Install Node.js LTS and reopen Terminal.
- **DB error**: Check the real D1 `database_id` in `wrangler.toml`; run `npm run db:remote`.
- **Browser CORS / login error**: Make sure `ALLOWED_ORIGINS` includes the exact GitHub Pages **origin**, deploy Worker again, and set the exact Worker URL in `frontend/config.js`.
- **GitHub Pages 404**: Select GitHub Actions as Pages source; check repo Actions logs and Pages URL.
- **Setup 404**: Bootstrap secret may be missing; deploy with it first.
- **Setup 409**: An admin already exists; don't repeat setup.
- **Can't approve**: Student must enter a fictional demo evidence description first.
- **No upload button**: Expected; this free demo has no file storage.

## Cost and security notes

Cloudflare Workers Free has a daily request limit. D1 also has free-tier limits; when exceeded, the app may stop responding until quotas reset. Stay on free plans. This architecture avoids R2 altogether. The website is public, but private records require a login through the Worker. This implementation has not passed a production security assessment, automated penetration testing, or institutional approvals. Use fictional demo accounts and data only.
