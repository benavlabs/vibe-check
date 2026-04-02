# Manual Security Checklist

These are the checks that can't be enforced by rules alone. You need to actually test them.
Go through each one before deploying to real users.

---

## 1. Database is not publicly queryable

Take your Supabase project URL and anon key (both are in your frontend code). Make a direct REST call from outside your app:

```bash
curl https://YOUR_PROJECT.supabase.co/rest/v1/users?select=* \
  -H "apikey: YOUR_ANON_KEY"
```

PASS: Empty array or permission error.
FAIL: Returns actual user data.

For Firebase: try reading a collection without being authenticated.

---

## 2. API routes reject unauthenticated requests

Log in and copy a request to a protected endpoint from browser DevTools (Network tab). Log out. Replay that exact request without the session cookie or auth header.

PASS: Returns 401.
FAIL: Returns data.

Also test: call an admin-only endpoint with a regular user session.

PASS: Returns 403.
FAIL: Returns admin data.

---

## 3. No secrets in git

```bash
# Is .env tracked?
git ls-files .env
# PASS: No output

# Is .env in .gitignore?
grep "\.env" .gitignore
# PASS: Shows a match

# Are there secrets in source code?
grep -rn "sk_live_\|sk_test_\|AKIA\|password\s*=\s*['\"]" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.jsx" --include="*.tsx" \
  ./src ./app ./pages ./api 2>/dev/null
# PASS: No output

# Are there secrets in git history?
# (install gitleaks: https://github.com/gitleaks/gitleaks)
gitleaks detect --source . --verbose
# PASS: No leaks found
```

---

## 4. Can't access another user's data by changing an ID

Create two test accounts (User A and User B). As User A:

1. Find a resource ID that belongs to User B
2. Request `GET /api/resources/{user_b_resource_id}` with User A's session

PASS: Returns 403.
FAIL: Returns User B's data.

Also test writes: `PUT /api/resources/{user_b_resource_id}` with User A's session should also return 403.

Test every endpoint that takes a user-scoped ID: documents, payments, profile data, orders.

---

## 5. No secret keys visible in the browser

Open your app in a browser. Open DevTools.

1. Go to Sources tab. Search all files for: `sk_`, `AKIA`, `Bearer`, `secret`, `private_key`
2. Go to Network tab. Watch outbound requests. Check headers for auth tokens being sent from the client to third-party APIs

PASS: No secret keys found.
FAIL: Any match.

---

## 6. SSRF: internal URLs are blocked

If your app has any feature that fetches a URL from user input (link previews, image proxies, URL validators), submit these:

```
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://10.0.0.1/
http://[::1]/
```

PASS: All rejected before any request is made.
FAIL: Any returns content.

If your app doesn't fetch user-supplied URLs, skip this.

---

## 7. CSRF: cross-origin form submissions are blocked

Create this HTML file and open it in a browser where you're logged into your app:

```html
<form action="https://yourapp.com/api/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

Replace the URL with any state-changing endpoint in your app.

PASS: Action fails (403 or no effect).
FAIL: The action actually executes.

---

## 8. Security headers are present

```bash
curl -I https://yourapp.com 2>/dev/null | grep -i "content-security-policy\|strict-transport\|x-frame-options\|x-content-type"
```

PASS: All four headers present.
FAIL: Any missing.

Or go to https://securityheaders.com and enter your URL.

---

## 9. CORS isn't wide open

```bash
curl -I -H "Origin: https://evil.com" https://yourapp.com/api/anything 2>/dev/null | grep -i "access-control-allow-origin"
```

PASS: No header, or shows your specific domain only.
FAIL: Shows `*` or echoes back `https://evil.com`.

---

## 10. Login can't be brute-forced

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://yourapp.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
done
```

PASS: Starts returning 429 after a few attempts.
FAIL: All 50 return 401 without being blocked.

---

## 11. SQL injection doesn't work

Submit these in every input that likely touches the database (login, search, filters):

```
' OR '1'='1
'; DROP TABLE users; --
```

PASS: No unexpected data, no database errors exposed.
FAIL: Returns unexpected data, shows a SQL error, or breaks.

---

## 12. XSS doesn't execute

Submit in every text input (names, comments, bios, search, URL params):

```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

PASS: Displayed as plain text. No alert fires.
FAIL: Alert appears.

---

## 13. Stripe webhooks reject fake requests

```bash
curl -X POST https://yourapp.com/api/webhook \
  -H "Content-Type: application/json" \
  -d '{"type":"payment_intent.succeeded","data":{"object":{"id":"pi_fake"}}}'
```

PASS: Returns 400 or signature error.
FAIL: Returns 200 and processes the event.

Also send the same valid event twice (same event ID). If it processes both times, idempotency is missing.

---

## 14. File uploads reject disguised files

Create a file named `test.jpg` with this content:

```
<script>alert('XSS')</script>
```

Upload it through the normal flow. Navigate to the uploaded file's URL.

PASS: Rejected, or served as download, or on a different domain.
FAIL: Content renders/executes on the same origin as your app.

---

## 15. Errors don't leak internals

Submit deliberately bad data: invalid JSON, non-existent IDs, a single `'` character in text fields.

PASS: Responses say "Something went wrong" with no technical details.
FAIL: Response contains stack traces, SQL queries, file paths, or library names.

---

## 16. Passwords are hashed properly

Check your codebase:

```bash
grep -rn "hashlib.md5\|hashlib.sha1\|MD5\|SHA1\|createHash.*md5\|createHash.*sha1" \
  --include="*.py" --include="*.js" --include="*.ts" ./
```

PASS: No matches.
FAIL: Any match means passwords may be using a broken algorithm. Should be bcrypt, Argon2, or scrypt only.

If you can access your database, check the stored hash format. bcrypt hashes start with `$2b$`. MD5 is 32 hex characters. SHA-1 is 40.

---

## 17. Dependencies are real

For every package your AI suggested that you haven't used before:

1. Search for it on npmjs.com or pypi.org
2. Check: does it exist? How many weekly downloads? When was it first published? Who maintains it?

Red flags: fewer than 1,000 weekly downloads, published in the last 30 days, single unnamed maintainer, name is suspiciously similar to a popular package.

```bash
npm audit
# or
pip audit
```

PASS: No critical or high vulnerabilities.

---

## Quick priority

If you only test 5 things, test these:

- [ ] #1 (database not publicly queryable)
- [ ] #2 (API routes reject unauthenticated requests)
- [ ] #3 (no secrets in git)
- [ ] #4 (can't access other users' data)
- [ ] #5 (no secret keys in browser)

Then come back and do the rest.
