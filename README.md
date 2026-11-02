# Web Vulnerability Scanner

A Flask web app that scans websites for common security weaknesses and reports them with OWASP Top 10 categories and fix advice.

> **For authorized security testing and education only.** Only scan systems you own or have written permission to test. Unauthorized scanning may be illegal.

## Features
- **Passive scan (any site):** missing security headers, weak CSP, version leaks, insecure cookies (Secure / HttpOnly / SameSite), HTTP-only sites, TLS certificate expiry and protocol checks
- **Active scan (verified sites only):** same-site crawler, reflected-input detection, SQL error detection, missing CSRF tokens, password forms over HTTP, permissive CORS, exposed `.git` / `.env` / `phpinfo` / `server-status`
- **Ownership verification:** active tests unlock only if you serve a token file or meta tag on the target (localhost is trusted automatically)
- **Safety controls:** blocks cloud-metadata and link-local IPs, never probes other hosts, request cap, rate limiting
- **Reports:** severity-ranked findings, OWASP category, fix advice, scan history (SQLite), JSON export

## Tech stack
Python, Flask, Requests, SQLite, HTML/CSS/JavaScript

## Setup