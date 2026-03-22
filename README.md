<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,40:06b6d4,100:6366f1&height=200&section=header&text=webcheck&fontSize=80&fontColor=ffffff&fontAlignY=40&desc=HTTP%20Security%20Auditor&descSize=22&descAlignY=62&descColor=94a3b8&animation=fadeIn" width="100%"/>

<br>

[![Version](https://img.shields.io/badge/version-1.1.0-06b6d4?style=for-the-badge&labelColor=0d1117)](https://github.com/wavegxz-design/webcheck/releases)
[![Shell](https://img.shields.io/badge/Bash-5.0+-4ade80?style=for-the-badge&logo=gnubash&logoColor=white&labelColor=0d1117)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/MIT-8b5cf6?style=for-the-badge&labelColor=0d1117)](LICENSE)
[![Platform](https://img.shields.io/badge/Kali%20·%20Parrot%20·%20Ubuntu-f97316?style=for-the-badge&logo=linux&logoColor=white&labelColor=0d1117)](https://github.com/wavegxz-design/webcheck)
[![BugBounty](https://img.shields.io/badge/Bug%20Bounty-Ready-ef4444?style=for-the-badge&labelColor=0d1117)](https://github.com/wavegxz-design/webcheck)

<br>

**Single-script HTTP security auditor for pentesters and bug bounty hunters.**
No Python. No npm. No Docker. Just `curl` + `openssl`.**

<br>

[Features](#-features) · [Install](#-install) · [Usage](#-usage) · [Modules](#-modules) · [Scoring](#-scoring) · [Roadmap](#-roadmap) · [Author](#-author)

</div>

---

## 🔍 What is webcheck?

**webcheck** audits the security posture of any HTTP/HTTPS target in seconds. It runs five focused modules — headers, cookies, TLS, redirects, and information disclosure — and outputs a color-coded terminal report with a 0–100 risk score and letter grade.

Built to work anywhere Kali/Parrot/Ubuntu runs. Zero extra dependencies.

---

## ✨ Features

| | Feature | What it does |
|--|---------|-------------|
| 🔀 | **HTTP → HTTPS** | Validates redirect chain and destination |
| 🛡️ | **Security Headers** | Audits 9 headers with value-level analysis |
| 🕵️ | **Info Disclosure** | Detects server versions, CMS leaks, CORS wildcards |
| 🍪 | **Cookies** | Per-cookie Secure / HttpOnly / SameSite analysis |
| 🔒 | **TLS / SSL** | Protocols, ciphers, expiry, self-signed detection |
| 📊 | **Risk Score** | 0–100 score with A+→F grade, deducted per finding |
| 🎨 | **Colored Output** | CRITICAL · HIGH · MEDIUM · LOW · OK |
| 🧹 | **Safe Cleanup** | `trap` ensures temp files always removed |

---

## ⚡ Install

```bash
git clone https://github.com/wavegxz-design/webcheck.git
cd webcheck
chmod +x webcheck.sh
```

**Requirements** — pre-installed on Kali, Parrot, Ubuntu:
```
curl   openssl   grep   awk   sed
```

---

## 🚀 Usage

```
webcheck.sh <target> [options]

Usage:
  ./webcheck.sh example.com
  ./webcheck.sh -t https://example.com
  ./webcheck.sh --target http://192.168.1.1

Target formats:
  example.com
  https://example.com
  http://192.168.1.1
  http://localhost:8080

Options:
  -t, --target <url>   Target URL or domain
  -h, --help           Show help
  -v, --version        Print version

Examples:
  ./webcheck.sh testphp.vulnweb.com
  ./webcheck.sh -t https://juice-shop.example.com
  ./webcheck.sh --target http://dvwa.local

⚠  Authorized targets only.
```

---

## 📋 Modules

### 🔀 HTTP → HTTPS Redirect

Checks whether HTTP automatically redirects to HTTPS, validates the redirect code and destination.

```
[OK]       HTTP redirects to HTTPS [301]
[HIGH]     HTTP redirects but NOT to HTTPS
[MEDIUM]   HTTP responds directly — no redirect configured
[INFO]     HTTP port unreachable (HTTPS-only or firewalled)
```

---

### 🛡️ Security Headers

Audits 9 response headers. Checks not just presence but also correctness of values.

| Header | What is checked |
|--------|----------------|
| `Strict-Transport-Security` | Presence, `max-age` value, `preload` directive |
| `Content-Security-Policy` | Presence, `unsafe-inline`, `unsafe-eval`, wildcards |
| `X-Frame-Options` | `DENY` / `SAMEORIGIN` / deprecated `ALLOW-FROM` |
| `X-Content-Type-Options` | Must be `nosniff` |
| `Referrer-Policy` | Value risk level |
| `Permissions-Policy` | Presence |
| `X-XSS-Protection` | Should be `0` (deprecated — rely on CSP) |
| `Cross-Origin-Opener-Policy` | Presence |
| `Cross-Origin-Resource-Policy` | Presence |

---

### 🕵️ Information Disclosure

```
[HIGH]     Server: nginx/1.18.0             ← version exposed
[HIGH]     X-Powered-By: PHP/8.1.2          ← remove this header
[HIGH]     X-AspNet-Version: 4.0.30319      ← .NET version leak
[HIGH]     CORS: Access-Control-Allow-Origin: *
[MEDIUM]   X-Generator: WordPress 6.4       ← CMS fingerprint
[OK]       X-Powered-By absent
[OK]       Server absent or genericized
```

---

### 🍪 Cookies

Each `Set-Cookie` header is analyzed individually:

```
Cookie 1: session_id
  ✓ Secure
  ✗ [HIGH]   Missing HttpOnly flag
  ✗ [MEDIUM] Missing SameSite attribute
  → Persistent (has expiry)
```

---

### 🔒 TLS / SSL

```
[OK]       Certificate valid for 213 more days
[OK]       TLS 1.2 supported
[OK]       TLS 1.3 supported
[CRITICAL] Weak protocol: TLS 1.0 enabled
[CRITICAL] Weak cipher: RC4-MD5
[HIGH]     Self-signed certificate
[LOW]      HSTS preload missing
```

---

## 📊 Scoring

Score starts at **100**. Each finding deducts points:

| Severity | Deduction |
|----------|-----------|
| 🔴 CRITICAL | −20 pts |
| 🔴 HIGH | −15 pts |
| 🟡 MEDIUM | −8 pts |
| 🔵 LOW | −3 pts |
| ✅ PASSED | 0 pts |

**Grades:**

| Grade | Score |
|-------|-------|
| **A+** | 90–100 |
| **A** | 80–89 |
| **B** | 70–79 |
| **C** | 60–69 |
| **D** | 50–59 |
| **F** | 0–49 |

---

## 🛣️ Roadmap

**v1.2**
- [ ] `--output json` — machine-readable report
- [ ] `--output md` — save Markdown report to file
- [ ] `--timeout` flag — custom timeout per request
- [ ] HSTS preload list lookup (hstspreload.org API)

**v2.0**
- [ ] Batch scanning: `--file targets.txt`
- [ ] recon-kit integration — pipe subdomain list directly
- [ ] `--fail-on HIGH` — non-zero exit for CI/CD pipelines
- [ ] Nuclei template generation from findings

---

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [**recon-kit**](https://github.com/wavegxz-design/recon-kit) | Modular recon — WHOIS, DNS, subdomains, ports, SSL |
| [**NEXORA-TOOLKIT**](https://github.com/wavegxz-design/NEXORA-TOOLKIT) | Advanced ADB toolkit for Android |

---

## ⚖️ Legal

MIT License. Use on systems you own or have written authorization to test. Unauthorized use is illegal.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:6366f1,60:8b5cf6,100:0d1117&height=140&section=footer" width="100%"/>

<br>

**[krypthane](https://github.com/wavegxz-design)** · Red Team Operator & Open Source Developer

<br>

[![Site](https://img.shields.io/badge/krypthane.workernova.workers.dev-06b6d4?style=flat-square&logo=cloudflare&logoColor=white)](https://krypthane.workernova.workers.dev)
[![Telegram](https://img.shields.io/badge/@Skrylakk-06b6d4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/Skrylakk)
[![Email](https://img.shields.io/badge/Workernova@proton.me-06b6d4?style=flat-square&logo=protonmail&logoColor=white)](mailto:Workernova@proton.me)
[![GitHub](https://img.shields.io/badge/wavegxz--design-06b6d4?style=flat-square&logo=github&logoColor=white)](https://github.com/wavegxz-design)

<br>

<sub>⭐ Star if webcheck found something on your target</sub>

</div>
