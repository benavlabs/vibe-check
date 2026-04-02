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

Verification goals after fix:
- `git ls-files .env` returns nothing
- `grep -rn` for secret patterns across all source files returns nothing
- No env var prefixed with NEXT_PUBLIC_, VITE_, or REACT_APP_ contains a secret key
- .env.example exists with placeholder values only

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

Verification goals after fix:
- No secret keys in any frontend file
- All sensitive API calls proxy through backend routes
- Only publishable/public keys are in client-side code
- No public env var (NEXT_PUBLIC_*, VITE_*, REACT_APP_*) holds a secret

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

Check: Are session cookies set with SameSite=Lax or Strict? If not, are CSRF tokens required on all state-changing endpoints?

Verification goals after fix:
- Session cookies have SameSite set to Lax or Strict, OR
- All state-changing endpoints validate a CSRF token
- A cross-origin form POST to any state-changing endpoint fails

### 8. SECURITY_HEADERS

Investigate: Middleware configuration, response headers, framework config files (next.config.js, etc.), helmet usage.

Check: Are Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy set on all responses?

Verification goals after fix:
- All five headers present on every response
- Headers set via a single global middleware (not per-route)

### 9. CORS

Investigate: CORS configuration in middleware, framework config, or server setup.

Check: Is origin set to `*`? Is origin a dynamic reflection of the request? Is `credentials: true` combined with a wildcard?

Verification goals after fix:
- CORS origin is an explicit allowlist of actual domains
- No wildcard origin
- credentials: true only paired with specific origins

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
- Handlers exist for payment_intent.succeeded, invoice.payment_failed, customer.subscription.deleted

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

Verification goals after fix:
- Global error handler catches all unhandled exceptions
- Client responses contain only generic error messages
- Full error details logged server-side only
- No stack traces, SQL errors, or file paths in any API response
- Debug/development mode is off in production config

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
