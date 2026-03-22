<div align="center">

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗██╗████████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ██║ ██╔╝██║╚══██╔══╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗█████╔╝ ██║   ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════╝██╔═██╗ ██║   ██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ██║  ██╗██║   ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝╚═╝   ╚═╝
```

### Modular Reconnaissance Toolkit for Authorized Penetration Testing

[![Version](https://img.shields.io/badge/version-2.0.0-blueviolet?style=flat-square)](https://github.com/wavegxz-design/recon-kit/releases)
[![Platform](https://img.shields.io/badge/platform-Linux-blue?style=flat-square&logo=linux)](https://github.com/wavegxz-design/recon-kit)
[![Shell](https://img.shields.io/badge/shell-bash-green?style=flat-square&logo=gnubash)](https://github.com/wavegxz-design/recon-kit)
[![Distros](https://img.shields.io/badge/distros-8_supported-orange?style=flat-square)](https://github.com/wavegxz-design/recon-kit)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-krypthane-9cf?style=flat-square)](https://github.com/wavegxz-design)

</div>

---

## What is recon-kit?

**recon-kit** is a senior-level modular reconnaissance toolkit built entirely in Bash.

It auto-detects your Linux distribution, installs any missing dependencies using your distro's package manager, runs 6 independent recon modules with live visual feedback, and generates a structured Markdown report — all from a single script.

No manual setup. No broken dependencies. No silent failures.

---

## Key Features

- **Distro-aware auto-install** — detects your distro and installs deps with the correct package manager
- **AUTOFIX engine** — 4-step recovery: reinstall → fix permissions → suggest alternative → retry
- **Plugin system** — drop `.sh` files into `~/.recon-kit/plugins/` to extend any module
- **Visual feedback** — spinner, progress bars, color-coded severity output
- **Structured report** — Markdown report auto-generated after every scan
- **Background scans** — full TCP and UDP run in background while other modules execute
- **Zero config** — works out of the box on any supported distro

---

## Supported Distributions

| Distro | Family | Package Manager |
|--------|--------|-----------------|
| Kali Linux | Debian | `apt` |
| Parrot OS | Debian | `apt` |
| Ubuntu / Mint / Pop!_OS | Debian | `apt` |
| Debian | Debian | `apt` |
| Arch Linux | Arch | `pacman` |
| Manjaro / EndeavourOS | Arch | `pacman` |
| BlackArch | Arch | `pacman` |
| Fedora / CentOS / RHEL | RHEL | `dnf` |

---

## Modules

| # | Module | Tools Used | What It Does |
|---|--------|-----------|--------------|
| 1 | `whois` | whois | Registrar, creation/expiry dates, nameservers |
| 2 | `dns` | dig | A, AAAA, MX, NS, TXT, SOA, SRV, CAA, DMARC + zone transfer |
| 3 | `subdomains` | subfinder, dig | Active discovery + 35-entry common brute force |
| 4 | `portscan` | nmap | Quick top 1000 + Full TCP background + UDP top 100 |
| 5 | `web` | curl, httpx, whatweb | Security headers audit, tech stack, robots.txt, live hosts |
| 6 | `cert` | openssl | Subject, issuer, SANs, expiry countdown |

---

## AUTOFIX Engine

When a tool fails or is missing, recon-kit recovers in 4 steps before skipping:

```
Step 1 — Reinstall via package manager / go install / gem
Step 2 — Fix binary permissions (chmod +x)
Step 3 — Suggest and use an available alternative tool
Step 4 — Retry with --fix-missing (Debian) or equivalent
```

Every failure is logged. No silent skips.

---

## Installation

```bash
git clone https://github.com/wavegxz-design/recon-kit
cd recon-kit
chmod +x recon-kit.sh
```

**Optional — extend with ProjectDiscovery tools:**
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## Usage

```bash
# Interactive mode — menu on launch
./recon-kit.sh -t example.com

# All modules
./recon-kit.sh -t example.com -m all

# Specific modules
./recon-kit.sh -t example.com -m whois,dns,portscan

# Full scan with UDP (requires root)
sudo ./recon-kit.sh -t example.com -m all

# List installed plugins
./recon-kit.sh -p
```

---

## Output Structure

```
~/.recon-kit/output/
└── example_com_20260321_143000/
    ├── REPORT.md               ← Summary report
    ├── recon.log               ← Full timestamped log
    ├── nmap/
    │   ├── quick.txt           ← Top 1000 ports + versions
    │   ├── quick.xml           ← Machine-readable XML
    │   ├── full.txt            ← All 65535 TCP (background)
    │   └── udp.txt             ← UDP top 100 (root only)
    ├── dns/
    │   ├── records.txt         ← All record types
    │   └── axfr.txt            ← Zone transfer result
    ├── whois/
    │   └── whois.txt
    ├── subdomains/
    │   ├── subfinder.txt
    │   ├── bruteforce.txt
    │   └── all.txt             ← Deduplicated master list
    ├── web/
    │   ├── whatweb.txt         ← Tech fingerprint
    │   └── live_hosts.txt      ← Live hosts (httpx)
    ├── headers/
    │   ├── https.txt
    │   ├── http.txt
    │   └── security_audit.txt  ← Missing headers report
    └── cert/
        └── cert.txt            ← Full certificate info
```

---

## Plugin System

Drop any `.sh` file into `~/.recon-kit/plugins/` — loaded automatically on launch.

**Plugin template:**
```bash
# PLUGIN: my-plugin
# DESC: What this plugin does

plugin_myplugin() {
  log "Running on $TARGET"
  # use log() info() warn() err() for consistent output
}
```

Run it: `./recon-kit.sh -t example.com -m myplugin`

---

## Roadmap v3.0

- [ ] Shodan / Censys API integration
- [ ] Nuclei vulnerability scan module
- [ ] HTML report with charts
- [ ] Screenshot capture via gowitness
- [ ] Telegram notification on scan complete
- [ ] Docker container release

---

## Legal Notice

> **Use only on systems you own or have explicit written authorization to test.**

Unauthorized use may violate the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws in your jurisdiction. The author is not responsible for misuse.

---

## Contributing

PRs are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) before opening one.

```bash
git checkout -b feat/your-feature
git commit -m "feat: description"
git push origin feat/your-feature
# → Open PR
```

---

## Related Projects

- [NEXORA-TOOLKIT](https://github.com/wavegxz-design/NEXORA-TOOLKIT) — Advanced ADB Toolkit for Android

---

<div align="center">

Made with focus by **[krypthane](https://github.com/wavegxz-design)**

[krypthane.dev](https://krypthane.dev) · [Telegram](https://t.me/Skrylakk) · [Workernova@proton.me](mailto:Workernova@proton.me)

</div>
