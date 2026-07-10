<p align="center">
  <img src="logo.svg" alt="vibe-check" width="35%" height="auto">
</p>
<p align="center" markdown=1>
  <i>Security checklist for vibe coded apps.</i>
</p>
<p align="center" markdown=1>
<a href="https://github.com/benavlabs/vibe-check/blob/main/LICENSE">
  <img src="https://img.shields.io/badge/license-MIT-34D058" alt="License"/>
</a>
</p>
<hr>
<p align="justify">
AI optimizes for making your code work, not for making it safe. Carnegie Mellon tested this: 61% of AI-generated code is functionally correct, only 10.5% is secure. This repo exists to close that gap.
</p>

<hr>

## How it works

Three layers, no overlap:

1. **`AGENTS.md`** — Security rules your AI tool reads while it writes code. Copy into your project root. Prevents vulnerabilities from being created.
2. **`AI-CHECKLIST.md`** — A prompt that tells your AI to audit your entire project. It investigates your codebase, writes reports, creates fix plans, implements them, and verifies.
3. **`manual-checklist.md`** — Tests you run yourself for the things AI can't catch.

## Setup

### Step 1: Copy the rules file into your project

**Cursor, Copilot, Codex, Windsurf, or Gemini CLI:**
```bash
cp AGENTS.md /path/to/your/project/AGENTS.md
```

**Claude Code:**
```bash
cp AGENTS.md /path/to/your/project/CLAUDE.md
```

**Not sure? Copy both:**
```bash
cp AGENTS.md /path/to/your/project/AGENTS.md
cp AGENTS.md /path/to/your/project/CLAUDE.md
```

Commit it. Your AI tool reads it automatically from now on.

### Step 2: Run the AI security audit

Give [AI-CHECKLIST.md](AI-CHECKLIST.md) to your AI coding assistant:

```
Run the security audit defined in AI-CHECKLIST.md against this project.
Go through each vulnerability one at a time.
```

It will investigate your codebase for each of the 17 vulnerability categories, create reports, write fix plans, implement fixes, and verify. Results go in a `security/` folder in your project.

### Step 3: Run the manual checks

Open [manual-checklist.md](manual-checklist.md) and go through each test. These verify things like: can you access another user's data, is your `.env` exposed, can login be brute-forced.

If you only do 5, do the first 5. They cover what took down every company on the list.

## What this covers

17 most common vulnerabilities found in vibe coded apps, based on documented breaches and security research:

| # | Vulnerability | Severity |
|---|--------------|----------|
| 1 | Misconfigured database (no Row Level Security) | Critical |
| 2 | Unprotected API routes (no auth middleware) | Critical |
| 3 | Committed secrets (.env on GitHub) | Critical |
| 4 | Broken access control (IDOR) | Critical |
| 5 | Secret API keys in frontend code | Critical |
| 6 | Server-Side Request Forgery (SSRF) | High |
| 7 | Missing CSRF protection | High |
| 8 | Missing security headers | Medium |
| 9 | Wildcard CORS | High |
| 10 | No rate limiting | Medium |
| 11 | SQL injection | High |
| 12 | Cross-site scripting (XSS) | High |
| 13 | Unverified Stripe webhooks | High |
| 14 | Insecure file uploads | Medium |
| 15 | Verbose error messages | Low |
| 16 | Weak password hashing | Medium |
| 17 | Hallucinated packages (slopsquatting) | High |

Items 1–5 are what took down every real company on this list. None required a sophisticated attack.

> **⚠️ Warning:**
> This will not make your app bulletproof. It covers the basics that have actually taken down vibe coded apps in production. When you have real traction and real user data, hire a pentester. No checklist replaces someone actively trying to break your stuff.

## Skip the checklist entirely

This repo helps you fix what you already built. If you're starting something new, consider starting from a foundation that already passes all 17 checks out of the box.

[FastroAI](https://fastro.ai/for/vibe-coders) is a production-ready full-stack template (FastAPI + Astro + Stripe + PydanticAI) built by the same team behind this checklist. Auth with CSRF and rate limiting, Stripe webhooks with signature verification and idempotency, security headers, parameterized queries, production validation that blocks deployment if your secrets are weak or debug mode is on. 90%+ test coverage. You vibe-code the product on top of it, not the foundation.

<p align="center">
  <a href="https://fastro.ai/for/vibe-coders">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://github.com/benavlabs/fastcrud/raw/main/docs/assets/fastroai-card-dark.png">
      <img src="https://github.com/benavlabs/fastcrud/raw/main/docs/assets/fastroai-card-light.png" alt="FastroAI - the complete FastAPI SaaS template: auth, Stripe payments, entitlements, email, frontend and AI" width="100%">
    </picture>
  </a>
</p>

<p align="center"><b><a href="https://fastro.ai/for/vibe-coders">Start from a foundation that passes all 17 checks →</a></b></p>

## Sources

Based on documented incidents and security research:

- [Escape.tech](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/) — 5,600 vibe coded apps scanned (2,000+ vulnerabilities, 400+ exposed secrets)
- [Tenzai](https://blog.tenzai.com/bad-vibes-comparing-the-secure-coding-capabilities-of-popular-coding-agents/) — 5 major AI coding tools compared (69 vulnerabilities across 15 apps)
- [Carnegie Mellon SusVibes](https://arxiv.org/abs/2512.03262) — 61% functional, 10.5% secure
- [Georgia Tech Vibe Security Radar](https://www.infosecurity-magazine.com/news/ai-generated-code-vulnerabilities/) — 74+ CVEs from AI-generated code
- [Veracode](https://www.veracode.com/) — GenAI Code Security Report 2025

## Contributing

Found something that should be on this list? Open a PR. Include what the vulnerability is, how to test for it, and how to fix it.

## License

[`MIT`](LICENSE)

## Contact

Benav Labs – [benav.io](https://benav.io)
[github.com/benavlabs](https://github.com/benavlabs/)
