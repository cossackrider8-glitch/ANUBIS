<p align="center">
  <img src="https://raw.githubusercontent.com/cossackrider8-glitch/ANUBIS/main/Anubis_v2.1.webp" alt="ANUBIS Banner" width="800">
</p>

🏛️ ANUBIS RECON ENGINE v2.1 🏛️
⚡ Crafted by: Obito Uchiha [ h4ck3r ] | ANUBIS Protocol ⚡

text

# ☥ ANUBIS – Shadow Scanning. Absolute Precision.

**ANUBIS** is a **40‑phase reconnaissance engine** for Bug Bounty & VAPT.  
It automates the entire recon pipeline – from WHOIS to SSL/TLS, CORS, JWT, email security – giving you a prioritized attack surface in minutes.

---

## ✨ Features – 40 Phases Explained

| Phase | What It Does | Why It Matters |
|-------|--------------|----------------|
| 1 – WHOIS | Fetches domain registration details | Find out who owns the domain |
| 2 – ASN & Netblock | Finds hosting provider and IP range | Hunt nearby infrastructure |
| 3 – Passive Subdomains | Subfinder + crt.sh | Discover hidden apps silently |
| 4 – Active Brute‑Force | Guesses common subdomains | Find subdomains not in public logs |
| 5 – DNS Permutations | Mutates found subdomains | Catch even more |
| 6 – Certificate Logs | Checks SSL cert logs | Subdomains appear in certs early |
| 7 – DNS + Takeover | Resolves subdomains, checks takeover | Find dangling subdomains you can hijack |
| 8 – Cloud Buckets | Scans S3, Azure, GCP | Exposed buckets leak files |
| 9 – GitHub Search | Searches GitHub for secrets/configs | Hardcoded passwords are gold |
| 10 – Emails | Enumerates emails | For phishing or employee accounts |
| 11 – Port Scanning | Top 25 TCP ports | Find unconventional entry points |
| 12 – Virtual Hosts | Tests Host header | Access internal services |
| 13 – HTTP Probing | Checks if hosts are alive | Separate live from dead |
| 14 – Tech Fingerprinting | Detects web servers, languages | Pick the right exploits |
| 15 – Takeover Confirm | Verifies CNAME takeover risks | Easy bug bounty wins |
| 16 – CVE Recon | Matches tech against CVE DB | Known vulnerabilities |
| 17 – CORS/GraphQL/Favicon | Misconfigs, introspection, favicon hashes | Steal sessions or expose APIs |
| 18 – Wayback URLs | Pulls historical URLs | Old, forgotten endpoints |
| 18.5 – Katana | (Optional) Active crawl | Discover fresh, dynamic URLs |
| 19 – JS Deep Dive | Parses JavaScript for endpoints/secrets | Hidden routes and keys |
| 20 – Sourcemaps | Fetches .js.map files | Read unminified code |
| 21 – URL Fuzzing | Bruteforces common paths | Hidden dashboards, sensitive files |
| 22 – Parameter Discovery | Extracts GET/POST parameters | Injection bugs live here |
| 23 – Screenshots | Takes screenshots (gowitness) | Visual inspection |
| 24 – Live Validation | Filters dead links, flags high‑priority | Focus on what matters |
| 25 – Deduplication | Merges and removes duplicates | Clean, organised data |
| 26 – Enrichment Loop | Re‑runs phases 18–24 | Catch anything missed |
| 27 – Report Generation | JSON, Markdown, HTML | Share findings |
| 28 – Audit Trail | SHA‑256 hashes of all output | Prove integrity |
| 29 – Nuclei | (Optional) Active exploit scanning | Critical vulnerabilities |
| 30 – SSL/TLS Deep Scan | Certificate expiry, weak ciphers, Heartbleed | SSL misconfigurations |
| 31 – Security Headers | HSTS, CSP, X‑Frame‑Options, etc. | Missing headers = clickjacking/XSS |
| 32 – DNS AXFR | Attempts zone transfer | Classic win if successful |
| 33 – Cloud Metadata | Probes 169.254.169.254 | Steal IAM credentials |
| 34 – Git Leak | Checks exposed .git folders | Leak entire source code |
| 35 – S3 Permissions | Tests if buckets are public | Deface or host malware |
| 36 – GraphQL Introspection | Extracts full schema | Find dangerous queries |
| 37 – JWT Weakness | Tests alg=none, weak secrets | Bypass authentication |
| 38 – CORS Reflection | Sends Origin: evil.com | Steal sessions via XSS |
| 39 – Rate Limiting | 10 rapid requests to login/OTP | If no 429/403 → brute‑force |
| 40 – Email Security | SPF, DKIM, DMARC | Prevent email spoofing |

---

## 📦 Installation

```bash
git clone https://github.com/cossackrider8-glitch/ANUBIS.git
cd ANUBIS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
(Optional) Global command – run anubis from anywhere
bash
echo '#!/bin/bash' > ~/anubis
echo 'cd ~/ANUBIS && source venv/bin/activate && python3 anubis.py "$@"' >> ~/anubis
chmod +x ~/anubis
sudo mv ~/anubis /usr/local/bin/anubis
Now you can run:

bash
anubis -d target.com
from any folder in the terminal.

🚀 Usage
Full pipeline (all 40 phases)
bash
python3 anubis.py -d target.com
or (if you set up the global alias):

bash
anubis -d target.com
Run a single phase
bash
python3 anubis.py -d target.com --phase 5
Enable Nuclei (Phase 29)
You'll be prompted during the scan:

text
Continue to Phase 29? (y/N):
Type y to run Nuclei (sends real payloads – use with permission).

⚠️ Warnings
Nuclei sends real exploit payloads (LFI, SQLi, RCE). Only run on targets you own or have explicit permission.

Running this tool against production systems without authorisation is illegal and unethical.

The tool uses public APIs and DNS resolution – it does not send intrusive payloads by default.

📂 Output Structure
All results are saved as human‑readable TXT files in output/<target>/:

text
output/
└── target.com/
    ├── phase_01_whois_*.txt
    ├── phase_02_asn_*.txt
    ├── ...
    ├── phase_40_email_*.txt
    ├── report_*.txt
    ├── audit_*.txt
    └── nuclei_results_*.txt (if run)
🤝 Contributing
Pull requests and issues are welcome. Please follow the existing code style and test your changes.

📄 License
MIT License – see LICENSE for details.

⚡ Crafted byYour honest feedback is highly appreciated.

"Shadow scanning. Absolute precision."
Obito Uchiha [ h4ck3r ] – Bug Hunter | Red Teamer | Open‑Source Enthusiast

"Shadow scanning. Absolute precision."

📢 Feedback & Future Improvements
This is ANUBIS v2.1 – we're actively working on more accuracy, clarity, and optimisation.

If you encounter any issues, have suggestions, or want to report a bug, please open an issue.

Your honest feedback is highly appreciated.

"Shadow scanning. Absolute precision."
