# Security policy

## Reporting a vulnerability

Please report security issues privately via GitHub's **Report a vulnerability**
feature (Security → Advisories) on this repository. Do not open a public issue
with exploit details, tokens or personal data.

Please include:

- a short description and impact
- steps to reproduce, if possible
- affected file or endpoint
- suggested fix, if you have one

## Scope

This repository contains a self-hosted dashboard and a network scanner agent.

- **Do not** use the agent against networks you do not own or have explicit
  permission to scan. Active scanning of third-party networks is illegal in
  many jurisdictions.
- The operator is responsible for the Cloudflare account, D1 database, secrets
  and the machine running the agent.
- Tokens, `.dev.vars`, `wrangler.jsonc` and `worker-configuration.d.ts` are
  intentionally excluded from version control.

## Known limitations

A full review with the current status is in
[`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md). The main deliberate
trade-offs are:

- The agent runs as root because nmap needs raw sockets/ARP.
- CSP still allows `'unsafe-inline'` for scripts because Astro inlines small
  page scripts at build time.
- Uptime targets are validated syntactically; DNS-based SSRF is left to
  Cloudflare's network policy.
- PBKDF2 is capped at 100,000 iterations by the Workers Web Crypto runtime.

## Good practices for operators

- Keep `ALLOW_BOOTSTRAP=false` after creating your account.
- Restrict `send_email` to your own address in `wrangler.jsonc`.
- Rotate agent tokens if one is exposed.
- Use Cloudflare Rate Limiting / WAF in front of `/api/auth/login` for extra
  protection.
