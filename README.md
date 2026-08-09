# KnockSphere

`knocksphere` is an asynchronous Python 3 tool designed for subdomain discovery, active HTTP/HTTPS probing, wildcard DNS filtering, and TLS posture auditing.

## Key Features

- ⚡ **Asynchronous Core:** Built with `asyncio`, `aiohttp`, and `dnspython` for fast multi-threaded operations.
- 🔍 **Hybrid Recon:** Combines passive APIs (CRT.sh, HackerTarget, AlienVault, VirusTotal, Shodan) with DNS bruteforcing.
- 🛡️ **Wildcard Detection:** Detects wildcard DNS and prevents false-positive spam.
- 🔒 **TLS Auditor:** Inspects certificates, retrieves expiration dates, and flags legacy TLS versions (TLS 1.0 / 1.1).
- 💾 **SQLite Storage:** Persistent storage for searching, reviewing, and managing historical scans.
- 📊 **Export Options:** Generates standalone HTML dashboards and CSV files.

---

## Installation

```bash
git clone [https://github.com/username/knocksphere.git](https://github.com/username/knocksphere.git)
cd knocksphere
pip install -e .
