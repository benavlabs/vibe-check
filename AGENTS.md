# Security Rules

These rules apply to all code generated in this project. They are non-negotiable.

## Secrets

- NEVER put API keys, database credentials, or tokens in frontend code (anything under src/, app/, pages/, components/, public/)
- NEVER put secret keys in environment variables prefixed with NEXT_PUBLIC_, VITE_, or REACT_APP_ (these are bundled into the client)
- NEVER hardcode credentials in source files. Use environment variables loaded server-side only
- The .env file MUST be in .gitignore before the first commit. Verify this before creating any .env file
- Use .env.example with placeholder values only, never real credentials

## Database

- Enable Row Level Security on EVERY Supabase table before deployment. Default policy: deny all. Write explicit policies scoped to auth.uid()
- NEVER set a Supabase RLS policy to `USING (true)` or `FOR ALL` without a WHERE condition
- Firebase Security Rules MUST require `request.auth != null` and scope access to `request.auth.uid`
- NEVER use `pickle.loads`, `pickle.load`, or any deserialization on user-supplied data. Use JSON for all network data exchange

## Authentication and Authorization

- EVERY API route that returns or modifies user data MUST have authentication middleware that runs BEFORE the handler, not inside it
- Unauthenticated requests to protected endpoints MUST return 401
- EVERY route that takes a resource ID MUST verify the authenticated user owns that resource: `current_user.id == resource.owner_id`. This is a SEPARATE check from authentication
- Admin endpoints MUST verify admin role and return 403 for non-admin users
- Session cookies MUST set `httpOnly: true`, `secure: true`, and `sameSite: 'lax'`

## Input and Output

- NEVER concatenate user input into SQL queries. ALWAYS use parameterized queries or ORM methods
- NEVER use `dangerouslySetInnerHTML`, `v-html`, or `innerHTML` with user-supplied content unless it is first sanitized with DOMPurify
- ALL user input MUST be validated server-side. Client-side validation is for UX only
- File uploads MUST validate file type by reading magic bytes, not by checking the filename extension. Rename all uploads to UUIDs server-side. Store on a separate domain (S3, R2, GCS), never on the app origin

## URL Fetching (SSRF Prevention)

- If the application fetches URLs provided by users (link previews, image proxies, URL validators), it MUST:
  - Block all private/internal IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1
  - Allow only http and https schemes
  - Resolve the hostname and check the IP BEFORE making the request

## Security Headers

- Set these headers on ALL responses via a single global middleware:
  - `Content-Security-Policy` (see CSP rules below)
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- In Express, use the `helmet` package. In Next.js, set headers in next.config.js
- If the app is served by a host or CDN (Vercel, Netlify, Cloudflare, nginx), set the same headers in that layer's config (vercel.json, netlify.toml, _headers, nginx.conf) for static files, since those responses never pass through your app middleware

## Content Security Policy

- A CSP header that exists is not enough. Start from this baseline and add only the origins your app actually uses:
  `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`
- ALWAYS declare `default-src`. Every fetch directive that isn't declared (script-src, style-src, img-src, connect-src, font-src, frame-src, media-src) falls back to it
- ALWAYS declare `base-uri`, `form-action`, and `frame-ancestors` explicitly. They do NOT fall back to `default-src`
- NEVER use `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`, `http:`, or bare `https:` in `script-src`. For inline scripts, use nonces or hashes
- NEVER use `*` in `connect-src`, `frame-src`, or `form-action`
- `'unsafe-inline'` is tolerated in `style-src` only (many CSS-in-JS and Tailwind setups need it)
- Roll out a new policy as `Content-Security-Policy-Report-Only` first, fix what it reports, then switch it to enforcing

## CORS

- NEVER set CORS origin to `*` (wildcard). Use an explicit allowlist of your actual domains
- NEVER reflect the request's `Origin` header back without checking it against the allowlist
- NEVER combine `origin: '*'` with `credentials: true`
- Declare allowed methods explicitly (only the ones the API uses) instead of allowing all methods

## CSRF

- Every state-changing endpoint (POST, PUT, PATCH, DELETE) that uses cookie-based auth MUST be protected by SameSite=Lax/Strict session cookies, a CSRF token, or both
- NEVER perform state changes on GET requests (SameSite=Lax still sends cookies on top-level GET navigations)
- Set cookie flags on EVERY cookie that carries auth or session data, not just the main session cookie

## Rate Limiting

- Login, registration, and password reset endpoints MUST have rate limiting (block after N failed attempts per IP within a time window)
- Do NOT trust X-Forwarded-For for rate limiting unless behind a trusted reverse proxy

## Payments

- Stripe webhook endpoints MUST verify the signature using `stripe.Webhook.construct_event` (or equivalent) on every request. Reject any request with an invalid or missing signature
- Webhook handlers MUST track processed event IDs and skip duplicates (idempotency)
- Handle the full event lifecycle: `payment_intent.succeeded`, `invoice.payment_failed`, `customer.subscription.updated` (check `status` for `past_due` / `unpaid`), `customer.subscription.deleted`

## Error Handling

- NEVER expose stack traces, SQL errors, file paths, or library names in API responses
- Production error responses MUST return only generic messages: `{"error": "Something went wrong"}`
- Full error details go to server-side logs only
- Debug mode / development error pages MUST be disabled in production

## Production Exposure

- Disable or put behind auth these endpoints in production: API docs (FastAPI `/docs`, `/redoc`, `/openapi.json`; Swagger UI), GraphQL playgrounds/GraphiQL and introspection, Spring Boot Actuator, phpinfo, server-status, Werkzeug debugger
- NEVER serve source maps (`.js.map`) publicly in production. Disable them in the build config (e.g. Vite `build.sourcemap: false`, Next.js `productionBrowserSourceMaps: false`) or upload them privately to your error tracker
- NEVER let the web server serve `.env`, `.git/`, database dumps, backups, or log files. Only the build output directory is publicly served
- Directory listing MUST be disabled on the web server and on any public bucket

## Password Hashing

- ALWAYS use bcrypt, Argon2, or scrypt for password hashing
- NEVER use MD5, SHA-1, or plain SHA-256 for passwords

## Dependencies

- Before installing any package, verify it exists on the official registry with a reasonable download count and history
- Pin exact versions in package.json / requirements.txt (no ^ or ~ in production)
- Commit lock files (package-lock.json, poetry.lock, yarn.lock)
