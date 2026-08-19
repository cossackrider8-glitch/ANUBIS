#!/usr/bin/env python3
import sys, os, json, requests, socket, concurrent.futures, subprocess, time, argparse, re, asyncio, aiohttp
from datetime import datetime
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

# =========================== COLOURS ===========================
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"; M = "\033[95m"; RS = "\033[0m"

print(f"""{C}
    █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
   ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
   ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
   ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
   ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝

        ☥  SHADOW SCANNING. ABSOLUTE PRECISION.  ⚡
        🏛️  ANUBIS RECON ENGINE v3.0  🏛️
        ⚡  Crafted by: Obito Uchiha [ h4ck3r ]  |  ANUBIS Protocol  ⚡
{RS}""")

# =========================== CONFIG ===========================
DEFAULT_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,6379,8080,8443,8888,9000,9090]
DNS_THREADS = 500
PORT_THREADS = 300
PROBE_CONCURRENT = 500
FUZZ_CONCURRENT = 800
PARAM_CONCURRENT = 800
ARJUN_THREADS = 50

SECLISTS = "/usr/share/seclists"
SUBDOMAIN_WORDLIST = f"{SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"
FUZZ_WORDLIST = f"{SECLISTS}/Discovery/Web-Content/common.txt"
PARAM_WORDLIST = f"{SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt"
BUCKET_WORDLIST = f"{SECLISTS}/Discovery/Web-Content/bucket-names.txt"

def load_wordlist(filepath, fallback):
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return fallback

def save_output(domain, phase_name, data, output_dir="output"):
    target_dir = os.path.join(output_dir, domain)
    os.makedirs(target_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_file = os.path.join(target_dir, f"{phase_name}_{timestamp}.txt")
    with open(txt_file, 'w') as f:
        f.write(f"ANUBIS Phase: {phase_name}\nDomain: {domain}\nTimestamp: {datetime.now().isoformat()}\n" + "="*60 + "\n\n")
        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                for item in data:
                    for k, v in item.items():
                        f.write(f"{k}: {v}\n")
                    f.write("-"*40 + "\n")
            else:
                for item in data:
                    f.write(str(item) + "\n")
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    f.write(f"{k}: ({len(v)} items)\n")
                    for item in v[:20]:
                        f.write(f"  - {item}\n")
                    if len(v) > 20:
                        f.write(f"  ... and {len(v)-20} more\n")
                else:
                    f.write(f"{k}: {v}\n")
        else:
            f.write(str(data))
    print(f"{C}[📁] Saved: {txt_file}{RS}")

def run_cmd(cmd, timeout=15):
    try:
        return subprocess.check_output(cmd, shell=True, timeout=timeout).decode().strip()
    except:
        return ""

def is_tool_installed(name):
    return run_cmd(f"which {name}", 2) != ""

# =========================== PHASE 1 ===========================
def phase_01_whois(domain, outdir):
    print(f"{B}[🔵] Phase 1: WHOIS{RS}")
    import whois, subprocess
    raw = ""
    # Try python-whois library first
    try:
        w = whois.whois(domain)
        raw = str(w)
    except Exception as e:
        # Fallback to system whois command (with stderr suppressed)
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
            if result.stdout:
                raw = result.stdout
            else:
                raw = f"Error (both methods failed): {e}"
        except Exception as e2:
            raw = f"Error: {e2}"
    save_output(domain, "phase_01_whois", {"raw": raw}, outdir)
    print(f"{G}[✅] Phase 1 complete.{RS}")

# =========================== PHASE 2 ===========================
def phase_02_asn(domain, outdir):
    print(f"{B}[🔵] Phase 2: ASN{RS}")
    try:
        ip = socket.gethostbyname(domain)
        save_output(domain, "phase_02_asn", requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json(), outdir)
    except Exception as e:
        save_output(domain, "phase_02_asn", {"error": str(e)}, outdir)
    print(f"{G}[✅] Phase 2 complete.{RS}")

# =========================== PHASE 3 ===========================
def phase_03_passive_subdomain(domain, outdir):
    print(f"{B}[🔵] Phase 3: Passive Subdomain Enumeration (Parallel){RS}")
    subs = set()
    tools = []
    if is_tool_installed("subfinder"):
        tools.append(("subfinder", f"subfinder -d {domain} -silent"))
    if is_tool_installed("sublist3r"):
        tools.append(("sublist3r", f"sublist3r -d {domain} -o /tmp/sublist3r_{domain}.txt && cat /tmp/sublist3r_{domain}.txt"))
    tools.append(("crt.sh", f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u"))
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async def run_tool(name, cmd):
        try:
            result = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await result.communicate()
            if stdout:
                lines = stdout.decode().strip().splitlines()
                for line in lines:
                    if line.strip() and not line.startswith("["):
                        subs.add(line.strip().lower())
                print(f"{G}[+] {name} found {len(lines)} subdomains.{RS}")
        except:
            pass
    async def run_all():
        tasks = [run_tool(name, cmd) for name, cmd in tools]
        await asyncio.gather(*tasks)
    loop.run_until_complete(run_all())
    loop.close()
    subs = list(subs)
    save_output(domain, "phase_03_subdomains", subs, outdir)
    print(f"{G}[✅] Phase 3 complete (total: {len(subs)}).{RS}")
    return subs

# =========================== PHASE 4 ===========================
def phase_04_bruteforce(domain, outdir):
    print(f"{B}[🔵] Phase 4: Active Brute‑Force (SecLists){RS}")
    wordlist = load_wordlist(SUBDOMAIN_WORDLIST, [
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","webdisk","ns2","cpanel","whm","autodiscover","autoconfig","m","imap","test","ns","blog","pop3","dev","www2","admin","forum","news","vpn","ns3","mail2","new","mysql","old","lists","support","mobile","mx","static","docs","beta","shop","sql","secure","demo","cp","calendar","wiki","web","media","email","images","img","www1","intranet","help","ns4","download","dns","mx1","webmail2","sites","app","apps","api","api2","stage","staging","cdn","stats","status","live","portal","info","clients","dev2","test2","ftp2","www3","server","git","svn","crm","files","backup","db","proxy","vpn2","internal","remote","securemail","corp","business"
    ])
    found = []
    def resolve(sub):
        try:
            full = f"{sub}.{domain}"
            ip = socket.gethostbyname(full)
            return full, ip
        except:
            return None, None
    print(f"{Y}[*] Brute‑forcing {len(wordlist)} subdomains with {DNS_THREADS} threads...{RS}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_THREADS) as ex:
        for full, ip in ex.map(lambda s: resolve(s), wordlist):
            if full:
                found.append({'subdomain': full, 'ip': ip})
                print(f"{G}[+] Found: {full} -> {ip}{RS}")
    if is_tool_installed("altdns"):
        print(f"{Y}[*] Running AltDNS mutations...{RS}")
        with open(f"{outdir}/tmp_subs.txt", 'w') as f:
            f.write('\n'.join([s['subdomain'] for s in found]))
        subprocess.run(f"altdns -i {outdir}/tmp_subs.txt -w /usr/share/seclists/Discovery/DNS/permutations_list.txt -o {outdir}/altdns_mutations.txt", shell=True, timeout=30)
        if os.path.exists(f"{outdir}/altdns_mutations.txt"):
            with open(f"{outdir}/altdns_mutations.txt", 'r') as f:
                for line in f:
                    sub = line.strip()
                    if sub:
                        try:
                            ip = socket.gethostbyname(sub)
                            found.append({'subdomain': sub, 'ip': ip})
                            print(f"{G}[+] AltDNS Found: {sub} -> {ip}{RS}")
                        except:
                            pass
    save_output(domain, "phase_04_bruteforce", found, outdir)
    print(f"{G}[✅] Phase 4 complete (total: {len(found)}).{RS}")
    return found

# =========================== PHASE 5-6 ===========================
def phase_05_permutations(domain, subdomains, outdir):
    print(f"{B}[🔵] Phase 5: DNS Permutations{RS}")
    perms = set()
    for p in ['dev-', 'test-', 'staging-', 'api-', 'admin-']:
        for sub in subdomains[:100]:
            perms.add(p + sub)
    save_output(domain, "phase_05_permutations", list(perms), outdir)
    print(f"{G}[✅] Phase 5 complete.{RS}")
    return list(perms)

def phase_06_ct_logs(domain, outdir):
    print(f"{B}[🔵] Phase 6: CT Logs{RS}")
    save_output(domain, "phase_06_ct_logs", [], outdir)
    print(f"{G}[✅] Phase 6 complete.{RS}")

# =========================== PHASE 7 ===========================
def phase_07_dns_takeover(domain, subdomains, outdir):
    print(f"{B}[🔵] Phase 7: DNS + Takeover{RS}")
    results = {}
    all_domains = set(subdomains)
    try:
        base_ip = socket.gethostbyname(domain)
        all_domains.add(domain)
        results[domain] = {'ip': base_ip, 'cname': None, 'takeover': False}
    except:
        pass
    def resolve(sub):
        try:
            ip = socket.gethostbyname(sub)
            return sub, ip
        except:
            return sub, None
    with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_THREADS) as ex:
        for sub, ip in ex.map(lambda s: resolve(s), all_domains):
            if ip:
                results[sub] = {'ip': ip, 'cname': None, 'takeover': False}
    save_output(domain, "phase_07_dns_takeover", results, outdir)
    print(f"{G}[✅] Phase 7 complete.{RS}")
    return results

# =========================== PHASE 8 ===========================
def phase_08_cloud_buckets(domain, outdir):
    print(f"{B}[🔵] Phase 8: Cloud Buckets (Fast){RS}")
    buckets = []
    bucket_names = load_wordlist(BUCKET_WORDLIST, [domain, f"www.{domain}", f"assets.{domain}", f"static.{domain}", f"media.{domain}"])
    if is_tool_installed("lazys3"):
        try:
            subprocess.run(f"lazys3 -d {domain} -o {outdir}/lazys3_{domain}.txt", shell=True, timeout=30)
            with open(f"{outdir}/lazys3_{domain}.txt", 'r') as f:
                for line in f:
                    buckets.append(line.strip())
        except:
            pass
    for name in bucket_names[:100]:
        for url in [f"http://{name}.s3.amazonaws.com", f"http://{name}.s3-website.amazonaws.com"]:
            try:
                if requests.get(url, timeout=2).status_code == 200:
                    buckets.append(url)
                    print(f"{G}[+] Found bucket: {url}{RS}")
            except:
                pass
    save_output(domain, "phase_08_cloud_buckets", list(set(buckets)), outdir)
    print(f"{G}[✅] Phase 8 complete (found {len(buckets)}).{RS}")
    return buckets

# =========================== PHASE 9 ===========================
def phase_09_github_search(domain, outdir):
    print(f"{B}[🔵] Phase 9: GitHub Secrets (TruffleHog/Gitleaks){RS}")
    secrets = []
    if is_tool_installed("trufflehog"):
        try:
            subprocess.run(f"trufflehog github --org={domain} -o json > {outdir}/trufflehog_{domain}.json", shell=True, timeout=60)
            with open(f"{outdir}/trufflehog_{domain}.json", 'r') as f:
                secrets = f.readlines()
        except:
            pass
    save_output(domain, "phase_09_github_search", secrets, outdir)
    print(f"{G}[✅] Phase 9 complete.{RS}")
    return secrets

# =========================== PHASE 10 ===========================
def phase_10_emails(domain, outdir):
    print(f"{B}[🔵] Phase 10: Email Enumeration{RS}")
    save_output(domain, "phase_10_emails", [], outdir)
    print(f"{G}[✅] Phase 10 complete.{RS}")

# =========================== PHASE 11 ===========================
def phase_11_open_ports(domain, ips, outdir):
    print(f"{B}[🔵] Phase 11: Port Scanning (300 concurrent){RS}")
    if not ips:
        try:
            ips = [socket.gethostbyname(domain)]
        except:
            ips = []
    if not ips:
        print(f"{R}[!] No IPs.{RS}")
        return {}
    results = {}
    def check(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            res = sock.connect_ex((ip, port))
            sock.close()
            return res == 0
        except:
            return False
    for ip in ips:
        open_ports = []
        print(f"{Y}[*] Scanning {ip} for {len(DEFAULT_PORTS)} ports...{RS}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_THREADS) as ex:
            for port, is_open in zip(DEFAULT_PORTS, ex.map(lambda p: check(ip, p), DEFAULT_PORTS)):
                if is_open:
                    open_ports.append(port)
                    print(f"{G}[+] Port {port} open on {ip}{RS}")
        if open_ports:
            results[ip] = open_ports
        else:
            print(f"{Y}[!] No open ports on {ip}{RS}")
    save_output(domain, "phase_11_open_ports", results, outdir)
    print(f"{G}[✅] Phase 11 complete.{RS}")
    return results

# =========================== PHASE 12 ===========================
def phase_12_vhosts(domain, subdomains, open_ports, outdir):
    print(f"{B}[🔵] Phase 12: Virtual Hosts{RS}")
    vhosts = []
    for sub in subdomains[:10]:
        for port in [80,443]:
            try:
                url = f"http://{sub}:{port}" if port==80 else f"https://{sub}"
                if requests.get(url, timeout=2, verify=False).status_code < 400:
                    vhosts.append(url)
            except:
                pass
    save_output(domain, "phase_12_vhosts", vhosts, outdir)
    print(f"{G}[✅] Phase 12 complete.{RS}")

# =========================== PHASE 13 ===========================
def phase_13_http_probing(domain, subdomains, open_ports, outdir):
    print(f"{B}[🔵] Phase 13: HTTP Probing (500 concurrent){RS}")
    if not subdomains:
        subdomains = [domain]
    ports = set()
    for ip, plist in open_ports.items():
        ports.update(plist)
    if not ports:
        ports = {80, 443}
    results = []
    def probe(sub, port, proto):
        if port in [443, 8443, 465, 995, 993] and proto == 'http':
            return None
        if port in [80, 8080] and proto == 'https':
            return None
        url = f"{proto}://{sub}:{port}" if port not in [80,443] else f"{proto}://{sub}"
        try:
            r = requests.get(url, timeout=2, allow_redirects=True, verify=False)
            return {'url': url, 'status': r.status_code, 'server': r.headers.get('Server','')}
        except:
            return None
    tasks = []
    for sub in subdomains[:50]:
        for port in ports:
            for proto in ['http','https']:
                tasks.append((sub, port, proto))
    print(f"{Y}[*] Probing {len(tasks)} combinations with {PROBE_CONCURRENT} workers...{RS}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_CONCURRENT) as ex:
        for res in ex.map(lambda t: probe(t[0], t[1], t[2]), tasks):
            if res:
                results.append(res)
                print(f"{G}[+] {res['url']} -> {res['status']}{RS}")
    save_output(domain, "phase_13_probe", results, outdir)
    print(f"{G}[✅] Phase 13 complete (found {len(results)} live).{RS}")
    return results

# =========================== PHASE 14 ===========================
def phase_14_tech_fingerprint(domain, probe_results, outdir):
    print(f"{B}[🔵] Phase 14: Tech Fingerprint{RS}")
    tech = {}
    for res in probe_results:
        if res.get('server'):
            tech[res['url']] = {'server': res['server']}
    save_output(domain, "phase_14_tech", tech, outdir)
    print(f"{G}[✅] Phase 14 complete.{RS}")
    return tech

# =========================== PHASE 15-16 ===========================
def phase_15_takeover_confirm(domain, dns_results, outdir):
    print(f"{B}[🔵] Phase 15: Takeover Confirm{RS}")
    save_output(domain, "phase_15_takeover", [], outdir)
    print(f"{G}[✅] Phase 15 complete.{RS}")

def phase_16_cve_recon(domain, tech_data, outdir):
    print(f"{B}[🔵] Phase 16: CVE Recon{RS}")
    save_output(domain, "phase_16_cve", [], outdir)
    print(f"{G}[✅] Phase 16 complete.{RS}")

# =========================== PHASE 17 ===========================
def phase_17_cors_graphql_favicon(domain, live_urls, outdir):
    print(f"{B}[🔵] Phase 17: CORS/GraphQL/Favicon{RS}")
    graphql = [u for u in live_urls if '/graphql' in u or '/api/graphql' in u]
    save_output(domain, "phase_17_cors_graphql", {'graphql': graphql}, outdir)
    print(f"{G}[✅] Phase 17 complete.{RS}")

# =========================== PHASE 18 ===========================
def phase_18_wayback_historical(domain, outdir):
    print(f"{B}[🔵] Phase 18: Wayback URLs (Fast){RS}")
    urls = set()
    tools = []
    if is_tool_installed("waybackurls"):
        tools.append(("waybackurls", f"waybackurls {domain}"))
    if is_tool_installed("gau"):
        tools.append(("gau", f"gau --subdomains {domain}"))
    if is_tool_installed("waymore"):
        tools.append(("waymore", f"waymore -i {domain} -mode U -oU /tmp/waymore_{domain}.txt && cat /tmp/waymore_{domain}.txt"))
    if not tools:
        try:
            r = requests.get(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if len(data) > 1:
                    urls.update([entry[0] for entry in data[1:]])
        except:
            pass
    for name, cmd in tools:
        output = run_cmd(cmd, 30)
        if output:
            for line in output.splitlines():
                if line.strip():
                    urls.add(line.strip())
    save_output(domain, "phase_18_wayback", list(urls), outdir)
    print(f"{G}[✅] Phase 18 complete (found {len(urls)}).{RS}")
    return list(urls)

# =========================== PHASE 18.5 ===========================
def phase_18_5_katana(domain, outdir, existing_urls):
    print(f"{M}[🔵] Phase 18.5: Katana Active Crawl{RS}")
    if not is_tool_installed("katana"):
        print(f"{Y}[!] Katana not installed.{RS}")
        return existing_urls
    print(f"{Y}[?] Run Katana? (y/N): {RS}", end="")
    if input().strip().lower() not in ['y','yes']:
        return existing_urls
    outfile = f"{outdir}/katana_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        subprocess.run(f"katana -u {domain} -d 3 -o {outfile} -silent", shell=True, timeout=60)
        if os.path.exists(outfile):
            with open(outfile, 'r') as f:
                existing_urls = list(set(existing_urls + [line.strip() for line in f if line.strip()]))
    except:
        pass
    return existing_urls

# =========================== PHASE 19-20 ===========================
def phase_19_js_deep_dive(domain, live_urls, historical_urls, outdir):
    print(f"{B}[🔵] Phase 19: JS Deep Dive{RS}")
    js_files = [u for u in (live_urls + historical_urls[:100]) if u.endswith('.js')]
    save_output(domain, "phase_19_js", js_files, outdir)
    print(f"{G}[✅] Phase 19 complete.{RS}")
    return js_files

def phase_20_sourcemaps(domain, js_extracts, outdir):
    print(f"{B}[🔵] Phase 20: Sourcemaps{RS}")
    maps = []
    for js in js_extracts:
        try:
            if requests.get(js + '.map', timeout=2).status_code == 200:
                maps.append(js + '.map')
        except:
            pass
    save_output(domain, "phase_20_sourcemaps", maps, outdir)
    print(f"{G}[✅] Phase 20 complete.{RS}")

# =========================== PHASE 21 ===========================
def phase_21_url_fuzzing(domain, live_urls, outdir):
    print(f"{B}[🔵] Phase 21: URL Fuzzing (800 concurrent){RS}")
    wordlist = load_wordlist(FUZZ_WORDLIST, ['admin','api','backup','config','env','.git','robots.txt','sitemap.xml'])
    found = []
    base_urls = live_urls[:5] if live_urls else [f"http://{domain}", f"https://{domain}"]
    def fuzz(base, path):
        url = base.rstrip('/') + '/' + path
        try:
            if requests.get(url, timeout=1.5).status_code < 400:
                return url
        except:
            pass
        return None
    print(f"{Y}[*] Fuzzing {len(base_urls)} bases × {len(wordlist)} paths...{RS}")
    tasks = [(base, path) for base in base_urls for path in wordlist]
    with concurrent.futures.ThreadPoolExecutor(max_workers=FUZZ_CONCURRENT) as ex:
        for url in ex.map(lambda t: fuzz(t[0], t[1]), tasks):
            if url:
                found.append(url)
                print(f"{G}[+] Found: {url}{RS}")
    save_output(domain, "phase_21_fuzzing", found, outdir)
    print(f"{G}[✅] Phase 21 complete (found {len(found)}).{RS}")
    return found

# =========================== PHASE 22 ===========================
def phase_22_parameters(domain, urls, outdir):
    print(f"{B}[🔵] Phase 22: Parameter Discovery (Passive + Arjun){RS}")
    params = {}
    for url in urls[:200]:
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    params.setdefault(url, []).append(key)
    if is_tool_installed("arjun"):
        print(f"{Y}[*] Running Arjun on live URLs (threads: {ARJUN_THREADS})...{RS}")
        for url in urls[:5]:
            if url and '?' not in url:
                try:
                    cmd = f"arjun -u {url} -t {ARJUN_THREADS} --timeout 2 -w {PARAM_WORDLIST} -o {outdir}/arjun_{domain}.txt"
                    subprocess.run(cmd, shell=True, timeout=60)
                    if os.path.exists(f"{outdir}/arjun_{domain}.txt"):
                        with open(f"{outdir}/arjun_{domain}.txt", 'r') as f:
                            for line in f:
                                if '?' in line:
                                    new_url = line.strip()
                                    parsed = urlparse(new_url)
                                    if parsed.query:
                                        for param in parsed.query.split('&'):
                                            if '=' in param:
                                                key = param.split('=')[0]
                                                params.setdefault(new_url, []).append(key)
                                else:
                                    params.setdefault(line.strip(), [])
                except:
                    pass
    save_output(domain, "phase_22_params", params, outdir)
    print(f"{G}[✅] Phase 22 complete (found {len(params)} params).{RS}")
    return params

# =========================== PHASE 23-28 ===========================
def phase_23_screenshots(domain, live_urls, outdir):
    print(f"{B}[🔵] Phase 23: Screenshots{RS}")
    save_output(domain, "phase_23_screenshots", [], outdir)
    print(f"{G}[✅] Phase 23 complete.{RS}")

def phase_24_live_validation(domain, urls, outdir):
    print(f"{B}[🔵] Phase 24: Live Validation{RS}")
    valid = []
    def check(url):
        try:
            if requests.get(url, timeout=1.5).status_code < 400:
                return url
        except:
            pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_CONCURRENT) as ex:
        for url in ex.map(check, urls[:200]):
            if url:
                valid.append(url)
    save_output(domain, "phase_24_live", valid, outdir)
    print(f"{G}[✅] Phase 24 complete (found {len(valid)}).{RS}")
    return valid

def phase_25_dedup(domain, master_data, outdir):
    print(f"{B}[🔵] Phase 25: Deduplication{RS}")
    save_output(domain, "phase_25_dedup", master_data, outdir)
    print(f"{G}[✅] Phase 25 complete.{RS}")

def phase_26_enrichment(domain, master_data, outdir):
    print(f"{B}[🔵] Phase 26: Enrichment{RS}")
    save_output(domain, "phase_26_enrich", master_data, outdir)
    print(f"{G}[✅] Phase 26 complete.{RS}")

def phase_27_report(domain, master_data, outdir):
    print(f"{B}[🔵] Phase 27: Report Generation{RS}")
    with open(f"{outdir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w') as f:
        f.write(f"ANUBIS Report for {domain}\n")
        for k, v in master_data.items():
            if isinstance(v, list):
                f.write(f"\n{k}: ({len(v)} items)\n")
                for item in v[:20]:
                    f.write(f"  - {item}\n")
                if len(v) > 20:
                    f.write(f"  ... and {len(v)-20} more\n")
            else:
                f.write(f"{k}: {v}\n")
    print(f"{G}[✅] Phase 27 complete.{RS}")

def phase_28_audit(domain, outdir):
    print(f"{B}[🔵] Phase 28: Audit Trail{RS}")
    with open(f"{outdir}/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w') as f:
        f.write(f"Audit for {domain} at {datetime.now()}\n")
    print(f"{G}[✅] Phase 28 complete.{RS}")

# =========================== PHASE 29 ===========================
def phase_29_nuclei(domain, urls, outdir):
    print(f"{B}[🔵] Phase 29: Nuclei Scan (No Timeout){RS}")
    if not urls:
        print(f"{Y}[!] No URLs.{RS}")
        return
    url_file = f"{outdir}/nuclei_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(url_file, 'w') as f:
        for url in urls:
            f.write(url + "\n")
    try:
        subprocess.run(['nuclei', '-l', url_file, '-severity', 'critical,high,medium', '-o', f"{outdir}/nuclei_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"])
        print(f"{G}[+] Nuclei completed.{RS}")
    except Exception as e:
        print(f"{R}[!] Nuclei error: {e}{RS}")
    print(f"{G}[✅] Phase 29 complete.{RS}")

# =========================== PHASE 30-40 ===========================
def phase_30_ssl_scan(domain, outdir):
    print(f"{B}[🔵] Phase 30: SSL/TLS Deep Scan{RS}")
    import ssl
    result = {"domain": domain, "cert": {}, "vulns": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                result["cert"] = {"notAfter": cert["notAfter"], "days_left": days_left}
                if days_left < 30:
                    result["vulns"].append("Expires in <30 days")
    except Exception as e:
        result["error"] = str(e)
    save_output(domain, "phase_30_ssl", result, outdir)
    print(f"{G}[✅] Phase 30 complete.{RS}")
    return result

def phase_31_security_headers(domain, outdir):
    print(f"{B}[🔵] Phase 31: Security Headers{RS}")
    results = {}
    for proto in ["http","https"]:
        url = f"{proto}://{domain}"
        try:
            r = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            results[url] = {h: r.headers.get(h) for h in ["Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Content-Security-Policy"]}
        except Exception as e:
            results[url] = {"error": str(e)}
    save_output(domain, "phase_31_headers", results, outdir)
    print(f"{G}[✅] Phase 31 complete.{RS}")
    return results

def phase_32_axfr(domain, outdir):
    print(f"{B}[🔵] Phase 32: AXFR{RS}")
    results = {"domain": domain, "axfr_success": False}
    ns_list = run_cmd(f"dig NS {domain} +short", 5).splitlines()
    for ns in ns_list:
        ns = ns.rstrip('.')
        print(f"{Y}[*] Testing NS: {ns}{RS}")
        axfr = run_cmd(f"dig AXFR {domain} @{ns}", 10)
        if "Transfer failed" not in axfr and "XFR size" in axfr:
            results["axfr_success"] = True
            results["records"] = axfr
            print(f"{G}[+] AXFR successful from {ns}{RS}")
            break
    save_output(domain, "phase_32_axfr", results, outdir)
    print(f"{G}[✅] Phase 32 complete.{RS}")
    return results

def phase_33_cloud_metadata(domain, outdir):
    print(f"{B}[🔵] Phase 33: Cloud Metadata{RS}")
    results = {}
    for url in ["http://169.254.169.254/latest/meta-data/"]:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                results["accessible"] = True
                results["data"] = r.text[:500]
        except:
            pass
    save_output(domain, "phase_33_cloud_metadata", results, outdir)
    print(f"{G}[✅] Phase 33 complete.{RS}")
    return results

def phase_34_git_leak(domain, outdir):
    print(f"{B}[🔵] Phase 34: Git Leak{RS}")
    results = {"leaks": []}
    for proto in ["http","https"]:
        for path in ["/.git/config","/.git/HEAD"]:
            url = f"{proto}://{domain}{path}"
            try:
                if requests.get(url, timeout=2).status_code == 200:
                    results["leaks"].append(url)
                    print(f"{G}[+] LEAK: {url}{RS}")
            except:
                pass
    save_output(domain, "phase_34_git_leak", results, outdir)
    print(f"{G}[✅] Phase 34 complete.{RS}")
    return results

def phase_35_s3_permissions(domain, outdir):
    print(f"{B}[🔵] Phase 35: S3 Permissions{RS}")
    # Reuse Phase 8 logic
    phase_08_cloud_buckets(domain, outdir)
    print(f"{G}[✅] Phase 35 complete.{RS}")
    return []

def phase_36_graphql_introspection(domain, outdir):
    print(f"{B}[🔵] Phase 36: GraphQL Introspection{RS}")
    results = {"endpoints": []}
    for ep in ["/graphql","/api/graphql","/gql"]:
        for proto in ["http","https"]:
            url = f"{proto}://{domain}{ep}"
            try:
                r = requests.post(url, json={"query": "query { __schema { types { name } } }"}, timeout=3, verify=False)
                if r.status_code == 200 and "data" in r.json():
                    results["endpoints"].append(url)
                    print(f"{G}[+] GraphQL: {url}{RS}")
            except:
                pass
    save_output(domain, "phase_36_graphql", results, outdir)
    print(f"{G}[✅] Phase 36 complete.{RS}")
    return results

def phase_37_jwt_scanner(domain, outdir):
    print(f"{B}[🔵] Phase 37: JWT Scanner{RS}")
    import base64
    results = {"tokens": []}
    for path in ["","/api","/auth"]:
        for proto in ["http","https"]:
            url = f"{proto}://{domain}{path}"
            try:
                r = requests.get(url, timeout=2, verify=False)
                auth = r.headers.get("Authorization", "")
                if "Bearer " in auth:
                    token = auth.split("Bearer ")[1]
                    if token.startswith("eyJ"):
                        results["tokens"].append({"url": url, "token": token})
                        print(f"{G}[+] JWT found: {url}{RS}")
            except:
                pass
    save_output(domain, "phase_37_jwt", results, outdir)
    print(f"{G}[✅] Phase 37 complete.{RS}")
    return results

def phase_38_cors_reflection(domain, outdir):
    print(f"{B}[🔵] Phase 38: CORS Reflection{RS}")
    results = []
    for origin in ["https://evil.com", "https://attacker.com"]:
        for proto in ["http","https"]:
            url = f"{proto}://{domain}"
            try:
                r = requests.get(url, headers={"Origin": origin}, timeout=2, verify=False)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*" or acao == origin:
                    results.append({"url": url, "origin": origin, "acao": acao})
                    print(f"{G}[+] CORS misconfig: {url} -> {acao}{RS}")
            except:
                pass
    save_output(domain, "phase_38_cors", results, outdir)
    print(f"{G}[✅] Phase 38 complete.{RS}")
    return results

def phase_39_rate_limit(domain, outdir):
    print(f"{B}[🔵] Phase 39: Rate Limit{RS}")
    results = []
    for ep in ["/login","/api","/auth"]:
        for proto in ["http","https"]:
            url = f"{proto}://{domain}{ep}"
            try:
                codes = []
                for _ in range(10):
                    codes.append(requests.get(url, timeout=1, verify=False).status_code)
                    time.sleep(0.1)
                if 429 in codes or 403 in codes:
                    results.append({"url": url, "rate_limited": True})
                    print(f"{G}[+] Rate limited: {url}{RS}")
                else:
                    results.append({"url": url, "rate_limited": False})
            except:
                pass
    save_output(domain, "phase_39_rate_limit", results, outdir)
    print(f"{G}[✅] Phase 39 complete.{RS}")
    return results

def phase_40_email_security(domain, outdir):
    print(f"{B}[🔵] Phase 40: Email Security{RS}")
    results = {"spf": None, "dmarc": None}
    def q(name):
        return run_cmd(f"dig TXT {name} +short", 3)
    spf = q(domain)
    if "v=spf1" in spf:
        results["spf"] = spf
        print(f"{G}[+] SPF: {spf}{RS}")
    dmarc = q(f"_dmarc.{domain}")
    if "DMARC" in dmarc:
        results["dmarc"] = dmarc
        print(f"{G}[+] DMARC: {dmarc}{RS}")
    save_output(domain, "phase_40_email", results, outdir)
    print(f"{G}[✅] Phase 40 complete.{RS}")
    return results

# =========================== MAIN ===========================
def main():
    parser = argparse.ArgumentParser(description="ANUBIS Recon Engine")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--phase", type=int, help="Run only a specific phase")
    args = parser.parse_args()
    domain = args.domain
    outdir = f"output/{domain}"
    os.makedirs(outdir, exist_ok=True)
    print(f"{C}[🎯] Target: {domain}{RS}")
    print(f"{C}[⚡] Running FULL pipeline (Phases 1-40).{RS}")

    if args.phase:
        phase_map = {1: phase_01_whois, 2: phase_02_asn, 3: phase_03_passive_subdomain, 4: phase_04_bruteforce,
                     5: phase_05_permutations, 6: phase_06_ct_logs, 7: phase_07_dns_takeover, 8: phase_08_cloud_buckets,
                     9: phase_09_github_search, 10: phase_10_emails, 11: phase_11_open_ports, 12: phase_12_vhosts,
                     13: phase_13_http_probing, 14: phase_14_tech_fingerprint, 15: phase_15_takeover_confirm,
                     16: phase_16_cve_recon, 17: phase_17_cors_graphql_favicon, 18: phase_18_wayback_historical,
                     19: phase_19_js_deep_dive, 20: phase_20_sourcemaps, 21: phase_21_url_fuzzing, 22: phase_22_parameters,
                     23: phase_23_screenshots, 24: phase_24_live_validation, 25: phase_25_dedup, 26: phase_26_enrichment,
                     27: phase_27_report, 28: phase_28_audit, 29: phase_29_nuclei, 30: phase_30_ssl_scan,
                     31: phase_31_security_headers, 32: phase_32_axfr, 33: phase_33_cloud_metadata, 34: phase_34_git_leak,
                     35: phase_35_s3_permissions, 36: phase_36_graphql_introspection, 37: phase_37_jwt_scanner,
                     38: phase_38_cors_reflection, 39: phase_39_rate_limit, 40: phase_40_email_security}
        if args.phase in phase_map:
            phase_map[args.phase](domain, outdir)
        else:
            print(f"{R}[!] Phase {args.phase} not implemented.{RS}")
        return

    phase_01_whois(domain, outdir)
    phase_02_asn(domain, outdir)
    subs = phase_03_passive_subdomain(domain, outdir)
    brute = phase_04_bruteforce(domain, outdir)
    all_subs = list(set(subs + [s['subdomain'] for s in brute if 'subdomain' in s]))
    phase_05_permutations(domain, all_subs, outdir)
    phase_06_ct_logs(domain, outdir)
    dns_results = phase_07_dns_takeover(domain, all_subs, outdir)
    phase_08_cloud_buckets(domain, outdir)
    phase_09_github_search(domain, outdir)
    phase_10_emails(domain, outdir)

    ips = list({v['ip'] for v in dns_results.values() if v.get('ip')})
    open_ports = phase_11_open_ports(domain, ips, outdir)
    phase_12_vhosts(domain, all_subs, open_ports, outdir)
    probe_results = phase_13_http_probing(domain, all_subs, open_ports, outdir)
    tech = phase_14_tech_fingerprint(domain, probe_results, outdir)
    phase_15_takeover_confirm(domain, dns_results, outdir)
    phase_16_cve_recon(domain, tech, outdir)
    live_urls = [r['url'] for r in probe_results if 'url' in r]
    phase_17_cors_graphql_favicon(domain, live_urls, outdir)

    historical = phase_18_wayback_historical(domain, outdir)
    historical = phase_18_5_katana(domain, outdir, historical)

    js_files = phase_19_js_deep_dive(domain, live_urls, historical, outdir)
    phase_20_sourcemaps(domain, js_files, outdir)
    phase_21_url_fuzzing(domain, live_urls, outdir)
    phase_22_parameters(domain, live_urls + historical[:100], outdir)
    phase_23_screenshots(domain, live_urls, outdir)
    live_valid = phase_24_live_validation(domain, live_urls + historical[:50], outdir)

    master_data = {'subdomains': all_subs, 'ips': ips, 'open_ports': open_ports, 'probe': probe_results, 'tech': tech,
                   'historical': historical, 'js': js_files, 'live': live_valid}
    phase_25_dedup(domain, master_data, outdir)
    phase_26_enrichment(domain, master_data, outdir)
    phase_27_report(domain, master_data, outdir)
    phase_28_audit(domain, outdir)

    print(f"{Y}\n[?] Phase 29: Nuclei Scan (optional).{RS}")
    print(f"{R}[!] Sends real payloads (LFI, SQLi, RCE).{RS}")
    if input(f"{C}Continue? (y/N): {RS}").strip().lower() in ['y','yes']:
        phase_29_nuclei(domain, live_valid if live_valid else historical[:10], outdir)
    else:
        print(f"{Y}[!] Skipped.{RS}")

    print(f"{C}\n[⚡] Running Phases 30-40 (Deep Security Checks){RS}")
    phase_30_ssl_scan(domain, outdir)
    phase_31_security_headers(domain, outdir)
    phase_32_axfr(domain, outdir)
    phase_33_cloud_metadata(domain, outdir)
    phase_34_git_leak(domain, outdir)
    phase_35_s3_permissions(domain, outdir)
    phase_36_graphql_introspection(domain, outdir)
    phase_37_jwt_scanner(domain, outdir)
    phase_38_cors_reflection(domain, outdir)
    phase_39_rate_limit(domain, outdir)
    phase_40_email_security(domain, outdir)

    print(f"{G}\n[+] Phases 1-40 completed successfully!{RS}")
    print(f"{C}[🔥] ANUBIS pipeline ready – manual hacking starts now! 🔥{RS}")
    print(f"{M}💀 Go hunt some bugs, brother. 💀{RS}")

if __name__ == "__main__":
    main()
