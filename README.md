# ☥ ANUBIS – Shadow Scanning. Absolute Precision.

![ANUBIS Banner](anubis_v2.webp)

**ANUBIS is a 40‑phase reconnaissance engine for Bug Bounty & VAPT.**  
It automates the entire recon pipeline – from WHOIS to SSL/TLS, CORS, JWT, email security, and more – giving you a prioritized attack surface in minutes.

🚀 **Built for speed, precision, and stealth.**  
🔍 **Covers 100% of the modern recon workflow** – 40 phases, no skips.

---

## ✨ Features – 40 Phases Explained (Like You're 5)

Every phase builds on the last one, slowly revealing the target's secrets. Here's exactly what ANUBIS does, step-by-step:

| Phase | What It Does | Why It Matters |
|-------|--------------|----------------|
| **1 – WHOIS** | Fetches domain registration details (who owns it, when it expires). | Find out who is behind the domain and when it might drop. |
| **2 – ASN & Netblock** | Finds the hosting provider (e.g., AWS, Google Cloud) and IP range. | Know where the target lives so you can hunt nearby infrastructure. |
| **3 – Passive Subdomains** | Uses Subfinder and crt.sh to find subdomains without touching the target. | Discover hidden apps (like `admin.target.com`) silently. |
| **4 – Active Brute‑Force** | Guesses common subdomains (like `mail`, `api`, `dev`) using a huge wordlist. | Find subdomains that are not in public logs. |
| **5 – DNS Permutations** | Mutates found subdomains (e.g., `admin` → `dev-admin`). | Catch even more hidden subdomains. |
| **6 – Certificate Logs** | Checks public SSL certificate logs for subdomains. | Subdomains often show up in SSL certs before they go live. |
| **7 – DNS + Takeover** | Resolves all subdomains to IPs and checks if any are vulnerable to takeover. | Find "dangling" subdomains you can hijack (critical bug). |
| **8 – Cloud Buckets** | Scans for open cloud storage (S3, Azure, GCP) linked to the domain. | Exposed buckets often leak confidential files. |
| **9 – GitHub Search** | Searches GitHub for secrets, configs, and internal code references. | Hardcoded passwords and API keys are a goldmine. |
| **10 – Emails** | Enumerates emails associated with the domain. | Use these for phishing tests or to find employee accounts. |
| **11 – Port Scanning** | Scans for open TCP ports (top 1000) on all discovered IPs. | Find unconventional entry points (SSH, FTP, databases). |
| **12 – Virtual Hosts** | Tests the Host header on IP:Port to find hidden virtual hosts. | Access internal services that aren't linked to a subdomain. |
| **13 – HTTP Probing** | Sends HTTP/S requests to every subdomain/IP to check if they are alive. | Separate live targets from dead ones. |
| **14 – Tech Fingerprinting** | Detects web servers, languages (PHP, Python), and frameworks (WordPress, React). | Know the tech stack to pick the right exploits. |
| **15 – Takeover Confirm** | Verifies if the takeover risk is real (CNAME points to a dead service). | Confirmed takeovers are easy bug bounty wins. |
| **16 – CVE Recon** | Matches detected tech against a lightweight CVE database. | Find known vulnerabilities in the software they use. |
| **17 – CORS/GraphQL/Favicon** | Checks CORS misconfigurations, enables GraphQL introspection, and grabs favicon hashes. | CORS misconfigs steal sessions; GraphQL exposes the whole API schema. |
| **18 – Wayback URLs** | Pulls historical URLs from the Wayback Machine. | Find old, forgotten endpoints that are still alive and vulnerable. |
| **18.5 – Katana** | *(Optional)* Actively crawls the target to find fresh, dynamic URLs. | Discover endpoints not archived anywhere else. |
| **19 – JS Deep Dive** | Downloads and parses JavaScript files to find endpoints, secrets, and parameters. | JS files are full of hidden API routes and keys. |
| **20 – Sourcemaps** | Fetches `.js.map` files to reveal original, unminified source code. | Read the original code to find bugs easily. |
| **21 – URL Fuzzing** | Bruteforces common paths (`/admin`, `/api`, `/env`, `/.git`). | Find hidden dashboards and sensitive files. |
| **22 – Parameter Discovery** | Extracts GET/POST parameters from URLs. | Parameters are where injection bugs (SQLi, XSS) live. |
| **23 – Screenshots** | Takes screenshots of live pages (requires `gowitness`). | Visually inspect targets without opening a browser. |
| **24 – Live Validation** | Filters out dead links and flags high‑priority targets. | Focus only on what's actually working. |
| **25 – Deduplication** | Merges all the collected data and removes duplicates. | Clean, organized data is easier to analyze. |
| **26 – Enrichment Loop** | Re‑runs enrichment phases (18–24) to catch anything missed the first time. | Ensure you haven't missed any low-hanging fruit. |
| **27 – Report Generation** | Generates reports in JSON, Markdown, and HTML. | Share findings with your team or clients easily. |
| **28 – Audit Trail** | Creates SHA‑256 hashes of all output files for integrity checks. | Prove your reports haven't been tampered with. |
| **29 – Nuclei** | *(Optional)* Runs active exploit payloads (LFI, SQLi, RCE) on discovered URLs. | Find critical vulnerabilities automatically (use with permission!). |
| **30 – SSL/TLS Deep Scan** | Checks certificate expiry, weak ciphers, and the Heartbleed vulnerability. | Find SSL misconfigurations that lead to MITM attacks. |
| **31 – Security Headers** | Audits HSTS, CSP, X‑Frame‑Options, and other security headers. | Missing headers make the site vulnerable to clickjacking and XSS. |
| **32 – DNS AXFR** | Attempts a DNS zone transfer against all NS servers. | If it works, you get the entire DNS database in one shot (classic win). |
| **33 – Cloud Metadata** | Probes the internal cloud metadata endpoint (169.254.169.254). | If the target is in the cloud, you might steal IAM credentials. |
| **34 – Git Leak** | Checks for exposed `.git` folders (`/.git/config`, `/.git/HEAD`). | Leak the entire source code of the website. |
| **35 – S3 Permissions** | Tests if S3 buckets are publicly readable or writable. | Public write permissions mean you can deface the site or host malware. |
| **36 – GraphQL Introspection** | Extracts the full GraphQL schema. | Understand the entire API and find dangerous queries. |
| **37 – JWT Weakness** | Tests JWT tokens for `alg=none`, weak HMAC secrets, and `kid` injection. | Bypass authentication completely. |
| **38 – CORS Reflection** | Sends requests with `Origin: evil.com` and checks if it's reflected. | Steal user sessions via XSS if CORS is misconfigured. |
| **39 – Rate Limiting** | Sends 10 rapid requests to login/OTP endpoints. | If no 429/403, the endpoint is vulnerable to brute‑force attacks. |
| **40 – Email Security** | Queries SPF, DKIM, and DMARC records. | Misconfigured email policies allow attackers to spoof emails from your domain. |

---

## 📦 Installation

```bash
git clone https://github.com/cossackrider8-glitch/ANUBIS.git
cd ANUBIS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Optional tools (for enhanced results):
subfinder, katana, nuclei, theHarvester, waybackurls, gowitness – install them via go install or apt as needed.

🚀 Usage
Full pipeline (all 40 phases)
bash
python anubis.py -d target.com
Run a single phase (for testing/debugging)
bash
python anubis.py -d target.com --phase 5
Enable Nuclei scan (Phase 29 – you'll be prompted)
bash
python anubis.py -d target.com --nuclei
Note: Nuclei sends real exploit payloads – you'll be asked to confirm before it runs.

⚠️ Warnings
Nuclei scan sends real payloads (LFI, SQLi, RCE). Only run on targets you own or have explicit permission to test.

Running this tool against production systems without authorization is illegal and unethical.

The tool uses public APIs and DNS resolution – it does not send intrusive payloads by default.

📂 Output Structure
All results are saved to output/<target>/:

text
output/
└── target.com/
    ├── phase_01_whois_*.json
    ├── phase_02_asn_*.json
    ├── ...
    ├── phase_40_email_*.json
    ├── report_*.txt
    ├── audit_*.txt
    └── nuclei_results_*.txt (if run)
🤝 Contributing
Pull requests and issues are welcome. Please ensure your code follows the existing style and passes basic tests.

📄 License
MIT License – see LICENSE for details.

⚡ Crafted by
Obito Uchiha [ h4ck3r ] – Bug Hunter | Red Teamer | Open‑Source Enthusiast

"Shadow scanning. Absolute precision."

📢 Feedback & Future Improvements
This is ANUBIS v2.0 – we're actively working on more accuracy, clarity, and optimization.

If you encounter any issues, have suggestions, or want to report a bug, please open an issue.
Your honest feedback is highly appreciated and will help shape the next versions.

"Shadow scanning. Absolute precision."
Your honest feedback is highly appreciated and will help shape the next versions.

"Shadow scanning. Absolute precision."
