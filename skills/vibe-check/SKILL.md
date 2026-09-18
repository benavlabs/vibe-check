---
name: vibe-check
description: Security audit for web apps, especially AI-built ("vibe coded") ones. Scans the running app for exposed .env/.git files, public source maps, weak CSP/HSTS/security headers, wildcard CORS, insecure cookies, and public debug/API-docs endpoints, then audits the codebase across 17 vulnerability categories (RLS, auth middleware, IDOR, secrets, SSRF, CSRF, SQLi, XSS, Stripe webhooks, uploads, password hashing, dependencies). Use when the user asks for a security audit or review, asks to check headers/CSP/CORS, or is about to deploy.
---

# vibe-check

Two parts:

1. **Live scan**: `scripts/check.py` (in this skill's directory) sends read-only requests to the running app and reports PASS/FAIL/WARN per check. It covers categories 1, 5, 7, 8, 9, and 15 from the outside, including things the code can't show you, like headers and CORS added by the host or CDN.
2. **Code audit**: `references/AI-CHECKLIST.md` covers all 17 categories by reading the codebase, writing reports and fix plans, fixing, and verifying.

## Workflow

### 1. Get a target

Ask the user for the production or staging URL, plus the API's URL if it's on a different origin (e.g. `https://api.example.com/health`). Only scan apps the user owns or is authorized to test. If they say it isn't deployed, offer to start the dev server and scan `http://localhost:<port>`, but tell them local results are incomplete (no HSTS, dev servers serve source maps, host/CDN headers are missing).

### 2. Run the live scan

```bash
python3 <skill-dir>/scripts/check.py https://app.example.com --api https://api.example.com/health --json
```

- Python 3.8+ standard library only; nothing to install.
- Exit code 0 = no failures, 1 = at least one FAIL, 2 = target unreachable (report the error; don't guess results).
- `--only headers,cors` limits the categories (`secrets,frontend,csrf,headers,cors,errors`). `--insecure` skips TLS verification for self-signed staging certs.
- Leave out `--json` when you want to show the user the readable report directly.

Treat the scan as evidence, not as the audit. Every FAIL has `evidence`, `url`, and `fix` fields. Confirm each one against the code before changing anything, and find where the problem really comes from: app middleware, framework config, or hosting config (`vercel.json`, `netlify.toml`, `_headers`, `nginx.conf`, `Caddyfile`, `firebase.json`, `wrangler.toml`).

If a sensitive file (`.env`, `.git/config`, a key or a dump) is reported as exposed, tell the user **immediately**, before anything else, that those credentials must be rotated. Don't print the secret values.

### 3. Run existing tools if they're installed

Don't reimplement these; run them and include their results:

- `gitleaks detect --source . --verbose`: secrets in git history
- `npm audit` / `pnpm audit` / `yarn npm audit`, or `pip-audit`: vulnerable dependencies
- `semgrep --config auto` (optional): code patterns

If a tool isn't installed, say so in the report and give the install command. Don't install anything without asking.

### 4. Audit the code

Follow `references/AI-CHECKLIST.md` category by category. For categories 1, 5, 7, 8, 9, and 15, start from the scan results; the rest need reading the code. Write reports to `security/reports/`, plans to `security/plans/`, and the summary to `security/AUDIT_SUMMARY.md`, as the checklist describes.

### 5. Re-scan after fixing

After fixing and deploying, run `check.py` again and put the before and after counts in `AUDIT_SUMMARY.md`. If a fix only exists locally, say it's unverified until it's deployed.

## Interpreting results

- **CSP**: the scanner parses each directive. A header that's present with only `frame-ancestors` fails most checks, and that's correct. Roll out a new CSP as `Content-Security-Policy-Report-Only` first so it doesn't break the app. `'unsafe-inline'` in `style-src` is tolerated.
- **HSTS `preload`** is reported as optional. Don't add it unless the user confirms every subdomain is HTTPS-only.
- **Cookies**: only cookies set on the landing page are visible. Session cookies set after login need the manual check (DevTools → Application → Cookies).
- **WARN** means worth fixing, but not a vulnerability on its own (e.g. `*` CORS on a public JS file, version headers, GraphQL introspection on a public API).
- **Not covered by the scan**: RLS, auth middleware, IDOR, SSRF, rate limiting, SQLi, XSS, webhooks, uploads, password hashing, dependencies. Never report these as passing based on the scan.
