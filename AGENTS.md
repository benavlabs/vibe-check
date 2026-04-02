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
  - `Content-Security-Policy: default-src 'self'` (adjust as needed for your app)
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- In Express, use the `helmet` package. In Next.js, set headers in next.config.js

## CORS

- NEVER set CORS origin to `*` (wildcard). Use an explicit allowlist of your actual domains
- NEVER combine `origin: '*'` with `credentials: true`

## Rate Limiting

- Login, registration, and password reset endpoints MUST have rate limiting (block after N failed attempts per IP within a time window)
- Do NOT trust X-Forwarded-For for rate limiting unless behind a trusted reverse proxy

## Payments

- Stripe webhook endpoints MUST verify the signature using `stripe.Webhook.construct_event` (or equivalent) on every request. Reject any request with an invalid or missing signature
- Webhook handlers MUST track processed event IDs and skip duplicates (idempotency)
- Handle the full event lifecycle: payment_intent.succeeded, invoice.payment_failed, customer.subscription.deleted, customer.subscription.past_due

## Error Handling

- NEVER expose stack traces, SQL errors, file paths, or library names in API responses
- Production error responses MUST return only generic messages: `{"error": "Something went wrong"}`
- Full error details go to server-side logs only
- Debug mode / development error pages MUST be disabled in production

## Password Hashing

- ALWAYS use bcrypt, Argon2, or scrypt for password hashing
- NEVER use MD5, SHA-1, or plain SHA-256 for passwords

## Dependencies

- Before installing any package, verify it exists on the official registry with a reasonable download count and history
- Pin exact versions in package.json / requirements.txt (no ^ or ~ in production)
- Commit lock files (package-lock.json, poetry.lock, yarn.lock)
