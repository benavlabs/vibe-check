# AI Security Audit

This is a prompt for your AI coding assistant. Give it this file and tell it to run the audit.

```
Run the security audit defined in AI-CHECKLIST.md against this project. Go through each vulnerability one at a time.
```

## How this works

For each vulnerability category below, you will:

1. **Investigate** the codebase thoroughly. Search every file that could be related to this problem. Check configs, routes, middleware, database schemas, environment files, frontend code, package files. Do not skim. Do not assume.
2. **Create a report** at `security/reports/{CATEGORY}_REPORT.md` documenting exactly what you found: what's vulnerable, what's safe, what's missing entirely, and severity (CRITICAL / HIGH / MEDIUM / LOW / PASS).
3. **Create a fix plan** at `security/plans/{CATEGORY}_PLAN.md` with the specific changes needed and verification goals that prove the fix works.
4. **Implement** the fixes.
5. **Verify** against every goal in the plan. Update the report with results.

Do each category fully before moving to the next. Do not batch them.

Create the `security/reports/` and `security/plans/` directories if they don't exist.

**Check the deployed app too, not just the code.** Headers, CORS, and publicly served files are often decided by the host or CDN (Vercel, Netlify, Cloudflare, nginx), not by your app code. Before starting, ask the human for the production (or staging) URL. If they give one, then for categories 1, 5, 7, 8, 9, and 15, check the live responses and report any mismatch between what the code sets and what is actually served. If the vibe-check scanner is available (`scripts/check.py` in the vibe-check skill, or `skills/vibe-check/scripts/check.py` in the vibe-check repo), run `python3 check.py <url> --json` first and use its findings as evidence. Otherwise use `curl -sI` / `curl -s`. Also read hosting config files: `vercel.json`, `netlify.toml`, `_headers`, `nginx.conf`, `Caddyfile`, `firebase.json`, `wrangler.toml`.

---

## Report format

Every report should follow this structure:

```markdown
# {Category} Security Report

## Status: CRITICAL / HIGH / MEDIUM / LOW / PASS

## Findings

What you found. Be specific. List every file, every route, every config that's relevant.
Include code snippets showing the actual vulnerable code.

## What's at risk

What an attacker could do with this vulnerability. Be concrete.

## What's already secure

Anything that's correctly implemented. Give credit where it's due.

## Recommendations

What needs to change, in priority order.
```

## Plan format

Every plan should follow this structure:

```markdown
# {Category} Fix Plan

## Changes

List every file that needs to change and what the change is.

- `path/to/file.ts` — description of change
- `path/to/other.py` — description of change

## New files

Any new files that need to be created (middleware, configs, tests).

## Verification goals

After implementation, ALL of these must be true:

- [ ] Goal 1 (specific, testable)
- [ ] Goal 2
- [ ] ...

## Manual verification (for the human)

Steps the human needs to test that can't be verified in code:

- Step 1
- Step 2
```

---

## Vulnerability categories

Run these in order. The first 5 are the most critical.

### 1. SECRETS_EXPOSURE

Investigate: .env files, .gitignore, all source files, git history, environment variable usage, frontend env vars (NEXT_PUBLIC_*, VITE_*, REACT_APP_*), hardcoded credentials, default passwords, config files.

Search for patterns: `sk_live_`, `sk_test_`, `AKIA`, `password =`, `secret =`, `token =`, `Bearer`, connection strings with credentials, any long alphanumeric string assigned to a variable in frontend code.

Check: Is .env in .gitignore? Is .env tracked by git? Are there secrets in any source file? Are any "public" env vars actually holding secret keys? Does .env.example contain real values?

Also check what the web server publicly serves: Is the public/static root only the build output directory, or could it serve the project root? Are `.env`, `.git/`, `*.sql`, `*.bak`, `*.log`, `backup/` reachable over HTTP? Is directory listing enabled (nginx `autoindex`, Apache `Indexes`, Express `serve-index`, public buckets with listing)?

Verification goals after fix:
- `git ls-files .env` returns nothing
- `grep -rn` for secret patterns across all source files returns nothing
- No env var prefixed with NEXT_PUBLIC_, VITE_, or REACT_APP_ contains a secret key
- .env.example exists with placeholder values only
- `/.env`, `/.git/config`, and common backup/dump paths return 404 or 403 on the deployed app
- Directory listing is disabled (`/uploads/`, `/static/`, `/backup/` don't return a file index)

### 2. DATABASE_ACCESS

Investigate: Supabase config, Firebase rules, RLS policies, database migrations, schema files, any direct database client usage.

Check: Is RLS enabled on every table? Are there policies on every table? Do any policies use `USING (true)` or grant unrestricted access? Can the anon key read data it shouldn't? For Firebase: do rules require auth?

Verification goals after fix:
- Every table has RLS enabled
- Every table has explicit policies scoped to auth.uid()
- No policy uses USING (true) without a proper condition
- A curl request with just the anon key to any table returns empty or 403

### 3. AUTH_MIDDLEWARE

Investigate: Every API route/endpoint in the project. All middleware. Route definitions. How authentication is checked. Where session/token validation happens.

Check: Does every protected route have auth middleware that runs BEFORE the handler? Are there any routes that return user data without checking authentication? Are admin routes checking for admin role?

List every route and whether it's protected or not. Be exhaustive.

Verification goals after fix:
- Every route that returns or modifies user data has auth middleware
- Auth middleware runs before the handler, not inside it
- Unauthenticated requests to protected routes return 401
- Non-admin requests to admin routes return 403
- No route accidentally serves data without session validation

### 4. ACCESS_CONTROL

Investigate: Every route that takes a resource ID (in URL path, query params, or request body). How ownership is verified. Whether auth check and ownership check are separate.

Check: After authentication, does the handler verify the current user owns the requested resource? Is this check present on both read (GET) and write (PUT/PATCH/DELETE) operations?

Verification goals after fix:
- Every route with a resource ID parameter checks current_user.id == resource.owner_id
- This check exists on GET, PUT, PATCH, and DELETE operations
- Failing the ownership check returns 403
- Auth and ownership are separate checks (passing auth doesn't imply ownership)

### 5. FRONTEND_SECRETS

Investigate: All files under src/, app/, pages/, components/, public/. All client-side API calls. All env vars with public prefixes. Network requests made from the browser.

Check: Are any secret API keys in frontend code? Are sensitive API calls going directly from the browser to third-party services with secret credentials?

Also check source maps: Does the production build emit `.js.map` files that are served publicly (Vite `build.sourcemap`, Next.js `productionBrowserSourceMaps`, webpack `devtool`)? Public source maps hand anyone your full, readable frontend source, including comments and internal API routes.

Verification goals after fix:
- No secret keys in any frontend file
- All sensitive API calls proxy through backend routes
- Only publishable/public keys are in client-side code
- No public env var (NEXT_PUBLIC_*, VITE_*, REACT_APP_*) holds a secret
- Production build does not serve `.js.map` files (requesting `<bundle>.js.map` returns 404)

### 6. SSRF

Investigate: Any code that fetches a URL based on user input. Link preview features, image proxies, URL validators, webhook URL testing, import-from-URL features.

Check: Is there any URL validation before fetching? Are internal/private IP ranges blocked? Is DNS resolution checked before the request?

If the app has no user-supplied URL fetching, mark as PASS and note why.

Verification goals after fix:
- All user-supplied URL fetching validates the URL before requesting
- Private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1) are blocked
- Only http and https schemes are allowed
- Hostname is resolved and IP checked before the request is made

### 7. CSRF

Investigate: Session/cookie configuration. CSRF token implementation. SameSite cookie settings. All state-changing endpoints (POST, PUT, PATCH, DELETE).

Check: Are session cookies set with SameSite=Lax or Strict? If not, are CSRF tokens required on all state-changing endpoints? Do any GET routes change state? Check every cookie that carries auth or session data (including refresh tokens), not just the main one.

Verification goals after fix:
- Session cookies have SameSite set to Lax or Strict, OR
- All state-changing endpoints validate a CSRF token
- No GET route changes state
- Every auth/session cookie has HttpOnly, Secure, and SameSite set (SameSite=None only with Secure)
- A cross-origin form POST to any state-changing endpoint fails

### 8. SECURITY_HEADERS

Investigate: Middleware configuration, response headers, framework config files (next.config.js, etc.), helmet usage, hosting/CDN config (vercel.json, netlify.toml, _headers, nginx.conf). If a deployed URL is available, fetch the real headers from both the HTML page and a static asset.

Check: Are Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy set on all responses, including static files served by the host?

Don't stop once you see a CSP header. Many apps ship a partial CSP (e.g. only `frame-ancestors 'none'`) that blocks framing but does nothing against XSS. Parse the policy and check each directive:
- `default-src` is declared (`'self'` or `'none'`). Undeclared fetch directives (`script-src`, `style-src`, `img-src`, `connect-src`, `font-src`, `frame-src`, `media-src`) fall back to it, so without it they are unrestricted
- `script-src` (or its `default-src` fallback) has no `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`, `blob:`, `http:`, bare `https:`, or wildcard subdomains. Inline scripts use nonces or hashes
- `object-src 'none'`
- `base-uri`, `form-action`, and `frame-ancestors` are declared explicitly (they do NOT fall back to `default-src`) and none of them is `*`
- `connect-src` and `frame-src` are not `*`
- `style-src 'unsafe-inline'` is acceptable; `*` is not

HSTS: `max-age` is at least 31536000 and includes `includeSubDomains`. Mention `preload` as optional in the report. Only recommend it if the human confirms every subdomain is HTTPS-only, because removing a domain from the preload list takes months.

Verification goals after fix:
- All five headers present on every response, including static assets served by the host
- Headers set via a single global middleware (not per-route), mirrored in hosting config for static files
- CSP declares `default-src`, `script-src` (or safe fallback), `object-src 'none'`, `base-uri`, `form-action`, `frame-ancestors`
- No `'unsafe-inline'` / `'unsafe-eval'` / `*` in `script-src`
- Strict-Transport-Security has `max-age>=31536000; includeSubDomains`
- App still works with the CSP enforced (no console CSP violations on core pages). Consider shipping as `Content-Security-Policy-Report-Only` first

### 9. CORS

Investigate: CORS configuration in middleware, framework config, or server setup. Also hosting/CDN config and storage buckets: static hosts and CDNs often add `Access-Control-Allow-Origin: *` on their own, even when the app code never sets it. If a deployed URL is available, check the actual response headers.

Check: Is origin set to `*`? Is origin a dynamic reflection of the request? Is `credentials: true` combined with a wildcard? Are allowed methods declared explicitly, or is every method allowed?

Verification goals after fix:
- CORS origin is an explicit allowlist of actual domains
- No wildcard origin, in the app code or in the deployed response headers
- Origin is never echoed back unless it's on the allowlist
- credentials: true only paired with specific origins
- Allowed methods list only what the API uses

### 10. RATE_LIMITING

Investigate: Login, registration, password reset endpoints. Any expensive or sensitive endpoints. Rate limiting middleware.

Check: Is there rate limiting on auth endpoints? What's the limit? Can it be bypassed via X-Forwarded-For?

Verification goals after fix:
- Login, registration, and password reset have rate limiting
- Rate limit triggers after N failed attempts (recommend 10 per 15 minutes)
- Rate limiter cannot be bypassed by spoofing X-Forwarded-For
- Rate-limited requests return 429

### 11. SQL_INJECTION

Investigate: Every database query in the codebase. Any raw SQL. ORM usage. Query builders.

Search for patterns: f-strings with SQL keywords, string concatenation in queries, template literals in SQL, .format() with SQL, `${}` inside query strings.

Check: Are all queries parameterized? Are there any raw SQL queries with user input concatenated in?

Verification goals after fix:
- Every database query uses parameterized placeholders or ORM methods
- No string concatenation, f-strings, or template literals in SQL with user input
- grep for dangerous patterns returns nothing

### 12. XSS

Investigate: All rendering of user-supplied content. Usage of dangerouslySetInnerHTML, v-html, innerHTML. Server-side template rendering. Autoescaping settings.

Check: Is any user input rendered as raw HTML without sanitization? Is DOMPurify (or equivalent) used where raw HTML is needed?

Verification goals after fix:
- No dangerouslySetInnerHTML/v-html/innerHTML with unsanitized user content
- Where raw HTML rendering is required, DOMPurify is used
- Server-side templates have autoescaping enabled

### 13. PAYMENT_WEBHOOKS

Investigate: Stripe webhook endpoint(s). Signature verification. Event processing. Idempotency handling. Which event types are handled.

If the app doesn't use Stripe/payments, mark as N/A.

Check: Is the Stripe signature verified on every request? Are processed event IDs tracked? Are failure events handled (not just success)?

Verification goals after fix:
- stripe.Webhook.construct_event (or equivalent) validates signature on every request
- Invalid or missing signatures return 400
- Processed event IDs are stored and duplicates are skipped
- Handlers exist for `payment_intent.succeeded`, `invoice.payment_failed`, `customer.subscription.updated` (acting on `status: past_due` / `unpaid`), and `customer.subscription.deleted`

### 14. FILE_UPLOADS

Investigate: All upload endpoints. How file type is validated. How files are named and stored. Size limits.

If the app has no file uploads, mark as N/A.

Check: Is file type checked by magic bytes or just extension? Are files renamed? Are they stored on a separate domain? Are size limits enforced server-side?

Verification goals after fix:
- File type validated by magic bytes, not extension
- Files renamed to UUIDs server-side
- Files stored on separate domain/bucket (S3, R2, GCS)
- Size limits enforced server-side

### 15. ERROR_HANDLING

Investigate: Error handling middleware. Exception handlers. Try/catch blocks. What gets returned to the client on errors. Debug/development mode settings.

Check: Do error responses expose stack traces, SQL queries, file paths, or library names? Is there a global error handler? Is debug mode off in production config?

Also check debug and documentation endpoints that frameworks turn on by default: FastAPI `/docs`, `/redoc`, `/openapi.json`; Swagger UI / `api-docs`; GraphQL Playground, GraphiQL, and introspection; Spring Boot Actuator (`/actuator/env`); `phpinfo`, `/server-status`; Werkzeug debugger (which allows remote code execution); Django `DEBUG=True`; ELMAH. Are they disabled or put behind auth in production?

Verification goals after fix:
- Global error handler catches all unhandled exceptions
- Client responses contain only generic error messages
- Full error details logged server-side only
- No stack traces, SQL errors, or file paths in any API response
- Debug/development mode is off in production config
- API docs, GraphQL playgrounds/introspection, and framework debug endpoints return 404 or require auth in production

### 16. PASSWORD_HASHING

Investigate: Where passwords are hashed. Which algorithm is used. How passwords are verified.

If the app uses a third-party auth provider (Auth0, Supabase Auth, Firebase Auth, Clerk), mark as N/A with note.

Check: Is bcrypt, Argon2, or scrypt used? Is there any MD5, SHA-1, or plain SHA-256 on passwords?

Verification goals after fix:
- Passwords hashed with bcrypt, Argon2, or scrypt only
- No MD5, SHA-1, or SHA-256 used for passwords
- Existing weak hashes migrated or users forced to reset

### 17. DEPENDENCIES

Investigate: package.json, requirements.txt, pyproject.toml, lock files. All dependencies.

Check: Does every package exist on the official registry with reasonable download history? Are versions pinned? Are lock files committed? Are there known vulnerabilities?

Verification goals after fix:
- Every dependency verified as legitimate on its registry
- No packages with suspiciously low downloads or recent publish dates
- Exact versions pinned (no ^ or ~ in production)
- Lock files committed
- `npm audit` / `pip audit` shows no critical or high vulnerabilities

---

## After the audit

When all 17 categories are done, create a summary at `security/AUDIT_SUMMARY.md`:

```markdown
# Security Audit Summary

Date: {date}

## Results

| # | Category | Status | Report | Plan |
|---|----------|--------|--------|------|
| 1 | SECRETS_EXPOSURE | CRITICAL/HIGH/MEDIUM/LOW/PASS/N/A | [report](reports/SECRETS_EXPOSURE_REPORT.md) | [plan](plans/SECRETS_EXPOSURE_PLAN.md) |
| 2 | DATABASE_ACCESS | ... | ... | ... |
| ... | ... | ... | ... | ... |

## Critical issues

List anything rated CRITICAL that needs immediate attention.

## Remaining manual verification

List the manual steps from each plan that the human still needs to do.
```
