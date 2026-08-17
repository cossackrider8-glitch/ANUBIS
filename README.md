<p align="center">
  <img src="https://raw.githubusercontent.com/cossackrider8-glitch/ANUBIS/main/Anubis_v2.1.webp" alt="ANUBIS Banner" width="800">
</p>

<h1 align="center">🏛️ ANUBIS Recon Engine v2.1 🏛️</h1>

<p align="center">
  <strong>Crafted by Obito Uchiha</strong><br>
  Bug Hunter | Red Teamer | Open-Source Enthusiast
</p>

---

# ☥ ANUBIS — Shadow Scanning. Absolute Precision.

**ANUBIS** is a **40-phase automated reconnaissance engine** designed for bug bounty hunting and Vulnerability Assessment & Penetration Testing (VAPT). It streamlines the entire reconnaissance pipeline—from WHOIS lookups to SSL/TLS analysis, CORS misconfigurations, JWT weaknesses, and email security—delivering a prioritized attack surface in minutes.

---

## ✨ Features — 40 Phases Explained

| Phase                             | Description                                                  | Impact                                       |
| --------------------------------- | ------------------------------------------------------------ | -------------------------------------------- |
| **1 — WHOIS**                     | Retrieves domain registration details                        | Identify domain ownership                    |
| **2 — ASN & Netblock**            | Discovers hosting provider and IP ranges                     | Map surrounding infrastructure               |
| **3 — Passive Subdomains**        | Queries Subfinder and crt.sh                                 | Uncover hidden applications silently         |
| **4 — Active Brute-Force**        | Enumerates common subdomains                                 | Find subdomains absent from public logs      |
| **5 — DNS Permutations**          | Mutates discovered subdomains                                | Expand subdomain coverage                    |
| **6 — Certificate Logs**          | Inspects SSL certificate transparency logs                   | Catch subdomains early via certificate data  |
| **7 — DNS + Takeover**            | Resolves subdomains and checks for takeover risks            | Identify dangling subdomains for hijacking   |
| **8 — Cloud Buckets**             | Scans S3, Azure Blob, and GCP Storage                        | Detect exposed cloud storage                 |
| **9 — GitHub Search**             | Searches GitHub for secrets and configurations               | Surface hardcoded credentials                |
| **10 — Emails**                   | Enumerates email addresses                                   | Support phishing simulations and OSINT       |
| **11 — Port Scanning**            | Probes top 25 TCP ports                                      | Reveal unconventional entry points           |
| **12 — Virtual Hosts**            | Tests Host header manipulation                               | Access internal or virtual services          |
| **13 — HTTP Probing**             | Validates host availability                                  | Separate live targets from dead ones         |
| **14 — Tech Fingerprinting**      | Detects web servers, frameworks, and languages               | Select appropriate exploits                  |
| **15 — Takeover Confirmation**    | Verifies CNAME takeover risks                                | Capture easy bug bounty wins                 |
| **16 — CVE Recon**                | Matches discovered technologies against CVE databases        | Identify known vulnerabilities               |
| **17 — CORS / GraphQL / Favicon** | Detects misconfigurations, introspection, and favicon hashes | Expose API risks and session theft vectors   |
| **18 — Wayback URLs**             | Retrieves historical URLs from archives                      | Discover old, forgotten endpoints            |
| **18.5 — Katana** *(Optional)*    | Actively crawls target applications                          | Find fresh, dynamic URLs                     |
| **19 — JS Deep Dive**             | Parses JavaScript for endpoints and secrets                  | Reveal hidden routes and API keys            |
| **20 — Sourcemaps**               | Fetches `.js.map` files                                      | Recover unminified source code               |
| **21 — URL Fuzzing**              | Brute-forces common paths and files                          | Locate hidden dashboards and sensitive files |
| **22 — Parameter Discovery**      | Extracts GET and POST parameters                             | Identify injection points                    |
| **23 — Screenshots**              | Captures visual snapshots via GoWitness                      | Enable visual inspection of targets          |
| **24 — Live Validation**          | Filters dead links and flags high-priority findings          | Focus on actionable results                  |
| **25 — Deduplication**            | Merges datasets and removes duplicates                       | Maintain clean, organized output             |
| **26 — Enrichment Loop**          | Re-runs Phases 18–24                                         | Catch anything missed in the first pass      |
| **27 — Report Generation**        | Exports findings to JSON, Markdown, and HTML                 | Share and document results                   |
| **28 — Audit Trail**              | Generates SHA-256 hashes of all output files                 | Ensure integrity and non-repudiation         |
| **29 — Nuclei** *(Optional)*      | Runs active exploit scanning                                 | Detect critical vulnerabilities              |
| **30 — SSL/TLS Deep Scan**        | Checks certificate expiry, weak ciphers, and Heartbleed      | Surface SSL/TLS misconfigurations            |
| **31 — Security Headers**         | Analyzes HSTS, CSP, X-Frame-Options, and more                | Identify clickjacking and XSS risks          |
| **32 — DNS AXFR**                 | Attempts DNS zone transfers                                  | Classic win if successful                    |
| **33 — Cloud Metadata**           | Probes `169.254.169.254`                                     | Attempt IAM credential extraction            |
| **34 — Git Leak**                 | Checks for exposed `.git` directories                        | Prevent full source code leaks               |
| **35 — S3 Permissions**           | Tests bucket accessibility                                   | Detect public or misconfigured buckets       |
| **36 — GraphQL Introspection**    | Extracts full GraphQL schemas                                | Identify dangerous queries                   |
| **37 — JWT Weakness**             | Tests `alg=none` and weak secrets                            | Bypass authentication controls               |
| **38 — CORS Reflection**          | Sends `Origin: evil.com` probes                              | Detect session theft via XSS                 |
| **39 — Rate Limiting**            | Sends 10 rapid requests to login/OTP endpoints               | Identify brute-force opportunities           |
| **40 — Email Security**           | Validates SPF, DKIM, and DMARC records                       | Assess email spoofing risks                  |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/cossackrider8-glitch/ANUBIS.git

# Navigate into the repository
cd ANUBIS

# Create a Python virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Optional: Global Command

To run `anubis` from anywhere in your terminal:

```bash
cat << 'EOF' > ~/anubis
#!/bin/bash
cd ~/ANUBIS && source venv/bin/activate && python3 anubis.py "$@"
EOF

chmod +x ~/anubis
sudo mv ~/anubis /usr/local/bin/anubis
```

Now you can run:

```bash
#  from any folder in the terminal.
anubis -d target.com
```

---

## 🚀 Usage

### Full Pipeline (All 40 Phases)

```bash
python3 anubis.py -d target.com
# Or, if you configured the global alias:
anubis -d target.com
```

### Run a Single Phase

```bash
python3 anubis.py -d target.com --phase 5
```

### Enable Nuclei (Phase 29)

During the scan, you will be prompted:

```
Continue to Phase 29? (y/N):
```

Type `y` to run Nuclei. **Note:** This sends real exploit payloads—only use on authorized targets.

---

## ⚠️ Warnings

- **Nuclei (Phase 29)** sends real exploit payloads (LFI, SQLi, RCE). Only run against targets you own or have **explicit written permission** to test.
- Running this tool against production systems without authorization is **illegal and unethical**.
- By default, ANUBIS uses public APIs and DNS resolution—it does **not** send intrusive payloads unless explicitly enabled.

---

## 📂 Output Structure

All results are saved as human-readable `.txt` files in `output/<target>/`:

```
output/
└── target.com/
    ├── phase_01_whois_*.txt
    ├── phase_02_asn_*.txt
    ├── ...
    ├── phase_40_email_*.txt
    ├── report_*.txt
    ├── audit_*.txt
    └── nuclei_results_*.txt (if enabled)
```

---

## 🤝 Contributing

Pull requests and issues are welcome. Please follow the existing code style and test your changes before submitting.

---

## 📄 License

MIT License see [LICENSE](LICENSE) for details.

---

<p align="center">
  <em>"Shadow scanning. Absolute precision."</em><br>
  <strong>Obito Uchiha</strong><br>
  Bug Hunter | Red Teamer | Open-Source Enthusiast
</p>

---

## 📢 Feedback & Future Improvements

ANUBIS v2.1 is actively maintained with a focus on accuracy, clarity, and performance optimization. If you encounter issues, have suggestions, or want to report a bug, please [open an issue](https://github.com/cossackrider8-glitch/ANUBIS/issues).

Your honest feedback is highly appreciated.

> *"Shadow scanning. Absolute precision."*