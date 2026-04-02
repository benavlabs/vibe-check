# vibe-check

Security checklist for vibe coded apps.

AI optimizes for making your code work, not for making it safe. Carnegie Mellon tested this: 61% of AI-generated code is functionally correct, only 10.5% is secure.

This repo has three things:

1. **AGENTS.md** — Security rules your AI coding tool reads and follows while it writes code. This prevents vulnerabilities from being created.
2. **AI-CHECKLIST.md** — A prompt that tells your AI to audit your entire project for vulnerabilities. It investigates your codebase, writes reports for each category, creates fix plans, implements them, and verifies.
3. **manual-checklist.md** — Tests you run yourself to verify the things AI can't catch.

## Setup

### Step 1: Copy the rules file into your project

This file tells your AI tool to follow security best practices while generating code.

**If you use Cursor, Copilot, Codex, Windsurf, or Gemini CLI:**
```bash
cp AGENTS.md /path/to/your/project/AGENTS.md
```

**If you use Claude Code:**
```bash
cp AGENTS.md /path/to/your/project/CLAUDE.md
```

**If you're not sure, copy both:**
```bash
cp AGENTS.md /path/to/your/project/AGENTS.md
cp AGENTS.md /path/to/your/project/CLAUDE.md
```

Commit it to your repo. Your AI tool will read it automatically from now on.

### Step 2: Run the AI security audit

Give [AI-CHECKLIST.md](AI-CHECKLIST.md) to your AI coding assistant and tell it:

```
Run the security audit defined in AI-CHECKLIST.md against this project. Go through each vulnerability one at a time.
```

It will investigate your codebase for each of the 17 vulnerability categories, create reports documenting what it found, write fix plans, implement fixes, and verify them. Results go in a `security/` folder in your project.

### Step 3: Run the manual checks before deploying

Open [manual-checklist.md](manual-checklist.md) and go through each test. These are things you need to verify yourself: trying to access another user's data, checking if your .env is exposed, testing if login can be brute-forced, etc.

If you only do 5, do the first 5. They cover what took down every company in the list.

## What this covers

17 most common vulnerabilities found in vibe coded apps, based on documented breaches and security research:

1. Misconfigured database (no Row Level Security)
2. Unprotected API routes (no auth middleware)
3. Committed secrets (.env on GitHub)
4. Broken access control (IDOR)
5. Secret API keys in frontend code
6. Server-Side Request Forgery (SSRF)
7. Missing CSRF protection
8. Missing security headers
9. Wildcard CORS
10. No rate limiting
11. SQL injection
12. Cross-site scripting (XSS)
13. Unverified Stripe webhooks
14. Insecure file uploads
15. Verbose error messages
16. Weak password hashing
17. Hallucinated packages (slopsquatting)

## This will not make your app bulletproof

It covers the basics that have actually taken down vibe coded apps in production. When you have real traction and real user data, hire a pentester. No checklist replaces someone actively trying to break your stuff.

## Sources

Based on documented incidents and security research:

- Escape.tech scan of 5,600 vibe coded apps (2,000+ vulnerabilities, 400+ exposed secrets)
- Tenzai study of 5 major AI coding tools (69 vulnerabilities across 15 apps)
- Carnegie Mellon SusVibes benchmark (61% functional, 10.5% secure)
- Georgia Tech Vibe Security Radar (74+ CVEs from AI-generated code)
- Veracode GenAI Code Security Report 2025

## Skip the checklist entirely

This repo helps you fix what you already built. If you're starting something new, consider starting from a foundation that already passes all 17 checks out of the box.

[FastroAI](https://fastro.ai/vibe-coders) is a production-ready full-stack template (FastAPI + Astro + Stripe + PydanticAI) built by the same team behind this checklist. Auth with CSRF and rate limiting, Stripe webhooks with signature verification and idempotency, security headers, parameterized queries, production validation that blocks deployment if your secrets are weak or debug mode is on. 90%+ test coverage. You vibe-code the product on top of it, not the foundation.

## Contributing

Found something that should be on this list? Open a PR. Include what the vulnerability is, how to test for it, and how to fix it.

## License

MIT
