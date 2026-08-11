#!/usr/bin/env python3
import sys, os, json, requests, socket, concurrent.futures, subprocess, time, argparse, re
from datetime import datetime
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

# Colours
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"; M = "\033[95m"; RS = "\033[0m"

print(f"""{C}
    █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
   ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
   ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
   ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
   ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝

        ☥  SHADOW SCANNING. ABSOLUTE PRECISION.  ⚡
        🏛️  ANUBIS RECON ENGINE v2.0  🏛️
        ⚡  Crafted by: Obito Uchiha [ h4ck3r ]  |  ANUBIS Protocol  ⚡
{RS}""")

DEFAULT_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,6379,8080,8443,8888,9000,9090]
DNS_THREADS = 200; PORT_THREADS = 100

def save_json(data, fname):
    with open(fname, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def run_cmd(cmd, timeout=15):
    try:
        return subprocess.check_output(cmd, shell=True, timeout=timeout).decode().strip()
    except:
        return ""

# ---------- Phase 1 ----------
def phase_01_whois(domain, outdir):
    print(f"{B}[🔵] Phase 1: WHOIS{RS}")
    save_json({"raw": run_cmd(f"whois {domain}", 10)}, f"{outdir}/phase_01_whois_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 1 complete.{RS}")

# ---------- Phase 2 ----------
def phase_02_asn(domain, outdir):
    print(f"{B}[🔵] Phase 2: ASN{RS}")
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        save_json(resp.json(), f"{outdir}/phase_02_asn_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    except Exception as e:
        save_json({"error": str(e)}, f"{outdir}/phase_02_asn_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 2 complete.{RS}")

# ---------- Phase 3 ----------
def phase_03_passive_subdomain(domain, outdir):
    print(f"{B}[🔵] Phase 3: Passive Subdomain Enumeration{RS}")
    subs = set()
    try:
        r = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.strip():
                    subs.add(line.strip().lower())
            print(f"{G}[+] Subfinder found {len(subs)} subdomains.{RS}")
    except:
        pass
    if not subs:
        print(f"{Y}[!] Falling back to crt.sh...{RS}")
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub and sub.endswith('.' + domain):
                                subs.add(sub)
                print(f"{G}[+] crt.sh found {len(subs)} subdomains.{RS}")
        except Exception as e:
            print(f"{R}[!] crt.sh error: {e}{RS}")
    subs = list(subs)
    save_json(subs, f"{outdir}/phase_03_subdomains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 3 complete.{RS}")
    return subs

# ---------- Phase 4 ----------
def phase_04_bruteforce(domain, outdir):
    print(f"{B}[🔵] Phase 4: Active Brute‑Force Subdomains{RS}")
    common = [
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","webdisk","ns2","cpanel","whm","autodiscover","autoconfig","m","imap","test","ns","blog","pop3","dev","www2","admin","forum","news","vpn","ns3","mail2","new","mysql","old","lists","support","mobile","mx","static","docs","beta","shop","sql","secure","demo","cp","calendar","wiki","web","media","email","images","img","www1","intranet","help","ns4","download","dns","mx1","webmail2","sites","app","apps","api","api2","stage","staging","cdn","stats","status","live","portal","info","clients","dev2","test2","ftp2","www3","server","git","svn","crm","files","backup","db","proxy","vpn2","internal","remote","securemail","corp","business","admin2","blog2","forum2","shop2","pay","payment","gateway","store","catalog","cart","checkout","user","login","signup","register","profile","dashboard","manage","control","panel","console","auth","oauth","sso","identity","dev-api","test-api","staging-api","rest","graphql","ws","socket","chat","message","notification","alert","monitor","metrics","logs","audit","trace","debug","health","status","cdn2","static2","media2","img2","video","audio","upload","share","file","doc","docs2","knowledge","kb","wiki2","faq","helpdesk","support2","contact","about","careers","jobs","partners","vendors","suppliers","distributors","dealer","reseller","affiliate","referral","campaign","promo","newsletter","subscription","billing","invoice","quote","order","tracking","shipment","delivery","warehouse","inventory","stock","supply","procurement","purchase","finance","accounting","tax","reports","analytics","insights"
    ]
    found = []
    def resolve(sub):
        try:
            full = f"{sub}.{domain}"
            ip = socket.gethostbyname(full)
            return full, ip
        except:
            return None, None
    print(f"{Y}[*] Brute‑forcing {len(common)} subdomains...{RS}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_THREADS) as ex:
        future_to_sub = {ex.submit(resolve, sub): sub for sub in common}
        for future in concurrent.futures.as_completed(future_to_sub):
            full, ip = future.result()
            if full:
                found.append({'subdomain': full, 'ip': ip})
                print(f"{G}[+] Found: {full} -> {ip}{RS}")
    save_json(found, f"{outdir}/phase_04_bruteforce_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 4 complete.{RS}")
    return found

# ---------- Phase 5 ----------
def phase_05_permutations(domain, subdomains, outdir):
    print(f"{B}[🔵] Phase 5: DNS Permutations{RS}")
    perms = set()
    for p in ['dev-', 'test-', 'staging-', 'api-', 'admin-']:
        for sub in subdomains:
            perms.add(p + sub)
    perms = list(perms)
    save_json(perms, f"{outdir}/phase_05_permutations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 5 complete.{RS}")
    return perms

# ---------- Phase 6 ----------
def phase_06_ct_logs(domain, outdir):
    print(f"{B}[🔵] Phase 6: CT Logs{RS}")
    save_json([], f"{outdir}/phase_06_ct_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 6 complete.{RS}")

# ---------- Phase 7 ----------
def phase_07_dns_takeover(domain, subdomains, outdir):
    print(f"{B}[🔵] Phase 7: DNS + Takeover{RS}")
    results = {}
    all_domains = set(subdomains)
    try:
        base_ip = socket.gethostbyname(domain)
        all_domains.add(domain)
        results[domain] = {'ip': base_ip, 'cname': None, 'takeover': False}
        print(f"{G}[+] Added base domain {domain} -> {base_ip}{RS}")
    except:
        pass
    for sub in all_domains:
        try:
            ip = socket.gethostbyname(sub)
            results[sub] = {'ip': ip, 'cname': None, 'takeover': False}
        except:
            pass
    save_json(results, f"{outdir}/phase_07_dns_takeover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 7 complete.{RS}")
    return results

# ---------- Phase 8 ----------
def phase_08_cloud_buckets(domain, outdir):
    print(f"{B}[🔵] Phase 8: Cloud Buckets{RS}")
    buckets = []
    for name in ['s3', 'aws', 'azure', 'gcp']:
        try:
            url = f"http://{name}.{domain}"
            r = requests.get(url, timeout=3)
            if r.status_code != 404:
                buckets.append(url)
        except:
            pass
    save_json(buckets, f"{outdir}/phase_08_cloud_buckets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 8 complete.{RS}")

# ---------- Phase 9 ----------
def phase_09_github_search(domain, outdir):
    print(f"{B}[🔵] Phase 9: GitHub Search{RS}")
    save_json([], f"{outdir}/phase_09_github_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 9 complete.{RS}")

# ---------- Phase 10 ----------
def phase_10_emails(domain, outdir):
    print(f"{B}[🔵] Phase 10: Email Enumeration{RS}")
    save_json([], f"{outdir}/phase_10_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 10 complete.{RS}")

# ---------- Phase 11 ----------
def phase_11_open_ports(domain, ips, outdir):
    print(f"{B}[🔵] Phase 11: Port Scanning{RS}")
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
            sock.settimeout(3)
            res = sock.connect_ex((ip, port))
            sock.close()
            return res == 0
        except:
            return False
    for ip in ips:
        open_ports = []
        print(f"{Y}[*] Scanning {ip} for {len(DEFAULT_PORTS)} ports...{RS}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_THREADS) as ex:
            futs = {ex.submit(check, ip, port): port for port in DEFAULT_PORTS}
            for f in concurrent.futures.as_completed(futs):
                port = futs[f]
                if f.result():
                    open_ports.append(port)
                    print(f"{G}[+] Port {port} open on {ip}{RS}")
        if open_ports:
            results[ip] = sorted(open_ports)
        else:
            print(f"{Y}[!] No open ports on {ip}{RS}")
    save_json(results, f"{outdir}/phase_11_open_ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 11 complete.{RS}")
    return results

# ---------- Phase 12 ----------
def phase_12_vhosts(domain, subdomains, open_ports, outdir):
    print(f"{B}[🔵] Phase 12: Virtual Hosts{RS}")
    vhosts = []
    for sub in subdomains[:5]:
        for port in [80,443]:
            try:
                url = f"http://{sub}:{port}" if port==80 else f"https://{sub}"
                r = requests.get(url, timeout=3)
                if r.status_code < 400:
                    vhosts.append(url)
            except:
                pass
    save_json(vhosts, f"{outdir}/phase_12_vhosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 12 complete.{RS}")

# ---------- Phase 13 ----------
def phase_13_http_probing(domain, subdomains, open_ports, outdir):
    print(f"{B}[🔵] Phase 13: HTTP Probing{RS}")
    if not subdomains:
        subdomains = [domain]
    ports = set()
    for ip, plist in open_ports.items():
        ports.update(plist)
    if not ports:
        ports = {80, 443}
    results = []
    for sub in subdomains[:20]:
        for port in ports:
            for proto in ['http','https']:
                if port == 443 and proto == 'http': continue
                if port == 80 and proto == 'https': continue
                url = f"{proto}://{sub}:{port}" if port not in [80,443] else f"{proto}://{sub}"
                try:
                    r = requests.get(url, timeout=3, allow_redirects=True, verify=False)
                    results.append({'url': url, 'status': r.status_code, 'server': r.headers.get('Server','')})
                    print(f"{G}[+] {url} -> {r.status_code}{RS}")
                except:
                    pass
    save_json(results, f"{outdir}/phase_13_probe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 13 complete.{RS}")
    return results

# ---------- Phase 14 ----------
def phase_14_tech_fingerprint(domain, probe_results, outdir):
    print(f"{B}[🔵] Phase 14: Tech Fingerprint{RS}")
    tech = {}
    for res in probe_results:
        if res.get('server'):
            tech[res['url']] = {'server': res['server']}
    save_json(tech, f"{outdir}/phase_14_tech_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 14 complete.{RS}")
    return tech

# ---------- Phase 15 ----------
def phase_15_takeover_confirm(domain, dns_results, outdir):
    print(f"{B}[🔵] Phase 15: Takeover Confirm{RS}")
    save_json([], f"{outdir}/phase_15_takeover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 15 complete.{RS}")

# ---------- Phase 16 ----------
def phase_16_cve_recon(domain, tech_data, outdir):
    print(f"{B}[🔵] Phase 16: CVE Recon{RS}")
    save_json([], f"{outdir}/phase_16_cve_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 16 complete.{RS}")

# ---------- Phase 17 ----------
def phase_17_cors_graphql_favicon(domain, live_urls, outdir):
    print(f"{B}[🔵] Phase 17: CORS/GraphQL/Favicon{RS}")
    graphql = [u for u in live_urls if '/graphql' in u or '/api/graphql' in u]
    save_json({'graphql': graphql}, f"{outdir}/phase_17_cors_graphql_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 17 complete.{RS}")

# ---------- Phase 18 ----------
def phase_18_wayback_historical(domain, outdir):
    print(f"{B}[🔵] Phase 18: Wayback URLs{RS}")
    urls = []
    try:
        r = requests.get(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:
                urls = [entry[0] for entry in data[1:]]
                print(f"{G}[+] Found {len(urls)} historical URLs{RS}")
    except:
        pass
    save_json(urls, f"{outdir}/phase_18_wayback_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 18 complete.{RS}")
    return urls

# ---------- Phase 18.5: Katana ----------
def phase_18_5_katana(domain, outdir, existing_urls):
    print(f"{M}[🔵] Phase 18.5: Katana Active Crawl{RS}")
    if run_cmd("which katana", 2) == "":
        print(f"{Y}[!] Katana not installed. Skipping.{RS}")
        return existing_urls
    print(f"{Y}[?] Run Katana active crawl? (y/N): {RS}", end="")
    choice = input().strip().lower()
    if choice not in ['y','yes']:
        print(f"{Y}[!] Katana skipped.{RS}")
        return existing_urls
    print(f"{Y}[*] Running Katana (depth 3)...{RS}")
    outfile = f"{outdir}/katana_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        subprocess.run(f"katana -u {domain} -d 3 -o {outfile} -silent", shell=True, timeout=60)
        if os.path.exists(outfile):
            with open(outfile, 'r') as f:
                new_urls = [line.strip() for line in f if line.strip()]
            print(f"{G}[+] Katana found {len(new_urls)} new URLs.{RS}")
            existing_urls = list(set(existing_urls + new_urls))
        else:
            print(f"{Y}[!] Katana produced no output.{RS}")
    except subprocess.TimeoutExpired:
        print(f"{R}[!] Katana timed out.{RS}")
    except Exception as e:
        print(f"{R}[!] Katana error: {e}{RS}")
    save_json(existing_urls, f"{outdir}/phase_18_combined_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    return existing_urls

# ---------- Phase 19 ----------
def phase_19_js_deep_dive(domain, live_urls, historical_urls, outdir):
    print(f"{B}[🔵] Phase 19: JS Deep Dive{RS}")
    js_files = [u for u in (live_urls + historical_urls[:100]) if u.endswith('.js')]
    save_json(js_files, f"{outdir}/phase_19_js_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 19 complete.{RS}")
    return js_files

# ---------- Phase 20 ----------
def phase_20_sourcemaps(domain, js_extracts, outdir):
    print(f"{B}[🔵] Phase 20: Sourcemaps{RS}")
    maps = []
    for js in js_extracts:
        try:
            if requests.get(js + '.map', timeout=3).status_code == 200:
                maps.append(js + '.map')
        except:
            pass
    save_json(maps, f"{outdir}/phase_20_sourcemaps_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 20 complete.{RS}")

# ---------- Phase 21 ----------
def phase_21_url_fuzzing(domain, live_urls, outdir):
    print(f"{B}[🔵] Phase 21: URL Fuzzing{RS}")
    common_paths = ['admin','api','backup','config','env','.git','robots.txt','sitemap.xml']
    found = []
    base_urls = live_urls if live_urls else [f"http://{domain}", f"https://{domain}"]
    for base in base_urls[:5]:
        for path in common_paths:
            url = base.rstrip('/') + '/' + path
            try:
                if requests.get(url, timeout=3).status_code < 400:
                    found.append(url)
                    print(f"{G}[+] Found: {url}{RS}")
            except:
                pass
    save_json(found, f"{outdir}/phase_21_fuzzing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 21 complete.{RS}")

# ---------- Phase 22 ----------
def phase_22_parameters(domain, urls, outdir):
    print(f"{B}[🔵] Phase 22: Parameter Discovery{RS}")
    params = {}
    for url in urls[:100]:
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    params.setdefault(url, []).append(key)
    save_json(params, f"{outdir}/phase_22_params_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 22 complete.{RS}")

# ---------- Phase 23 ----------
def phase_23_screenshots(domain, live_urls, outdir):
    print(f"{B}[🔵] Phase 23: Screenshots{RS}")
    save_json([], f"{outdir}/phase_23_screenshots_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 23 complete.{RS}")

# ---------- Phase 24 ----------
def phase_24_live_validation(domain, urls, outdir):
    print(f"{B}[🔵] Phase 24: Live Validation{RS}")
    valid = []
    for url in urls[:50]:
        try:
            if requests.get(url, timeout=3).status_code < 400:
                valid.append(url)
        except:
            pass
    save_json(valid, f"{outdir}/phase_24_live_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 24 complete.{RS}")

# ---------- Phase 25 ----------
def phase_25_dedup(domain, master_data, outdir):
    print(f"{B}[🔵] Phase 25: Deduplication{RS}")
    save_json(master_data, f"{outdir}/phase_25_dedup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 25 complete.{RS}")

# ---------- Phase 26 ----------
def phase_26_enrichment(domain, master_data, outdir):
    print(f"{B}[🔵] Phase 26: Enrichment{RS}")
    save_json(master_data, f"{outdir}/phase_26_enrich_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 26 complete.{RS}")

# ---------- Phase 27 ----------
def phase_27_report(domain, master_data, outdir):
    print(f"{B}[🔵] Phase 27: Report Generation{RS}")
    with open(f"{outdir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w') as f:
        f.write(f"ANUBIS Report for {domain}\n{json.dumps(master_data, indent=2)}")
    print(f"{G}[✅] Phase 27 complete.{RS}")

# ---------- Phase 28 ----------
def phase_28_audit(domain, outdir):
    print(f"{B}[🔵] Phase 28: Audit Trail{RS}")
    with open(f"{outdir}/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w') as f:
        f.write(f"Audit for {domain} at {datetime.now()}\n")
    print(f"{G}[✅] Phase 28 complete.{RS}")

# ---------- Phase 29 ----------
def phase_29_nuclei(domain, urls, outdir):
    print(f"{B}[🔵] Phase 29: Nuclei Scan{RS}")
    if not urls:
        print(f"{Y}[!] No URLs for Nuclei.{RS}")
        return
    url_file = f"{outdir}/nuclei_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(url_file, 'w') as f:
        f.write('\n'.join(urls[:10]))
    try:
        subprocess.run(['nuclei', '-l', url_file, '-severity', 'critical,high,medium', '-o', f"{outdir}/nuclei_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"], timeout=60)
        print(f"{G}[+] Nuclei scan completed.{RS}")
    except Exception as e:
        print(f"{R}[!] Nuclei error: {e}{RS}")
    print(f"{G}[✅] Phase 29 complete.{RS}")

# ---------- Phase 30 ----------
def phase_30_ssl_scan(domain, outdir):
    print(f"{B}[🔵] Phase 30: SSL/TLS Deep Scan{RS}")
    import ssl
    result = {"domain": domain, "cert": {}, "ciphers": [], "vulns": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["cert"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "SAN": cert.get("subjectAltName", [])
                }
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                result["cert"]["days_left"] = days_left
                if days_left < 30:
                    result["vulns"].append("Certificate expires in less than 30 days")
    except Exception as e:
        result["cert"]["error"] = str(e)
    # ciphers
    output = run_cmd(f"openssl s_client -connect {domain}:443 -ciphers 'ALL:eNULL' -tls1_2 </dev/null 2>/dev/null | grep -E 'Cipher|Protocol'", 10)
    if output:
        result["ciphers"] = output.strip().splitlines()
    # heartbeat
    if "heartbeat" in run_cmd(f"openssl s_client -connect {domain}:443 -heartbeat -tlsextdebug </dev/null 2>&1 | grep -i heartbeat", 10).lower():
        result["vulns"].append("Heartbleed may be present")
    save_json(result, f"{outdir}/phase_30_ssl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 30 complete.{RS}")
    return result

# ---------- Phase 31 ----------
def phase_31_security_headers(domain, outdir):
    print(f"{B}[🔵] Phase 31: Security Headers{RS}")
    results = {}; grades = {"A":0,"B":0,"C":0,"D":0,"F":0}
    headers_to_check = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]
    for proto in ["http","https"]:
        url = f"{proto}://{domain}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=True, verify=False)
            found = {h: r.headers[h] for h in headers_to_check if h in r.headers}
            results[url] = found
            present = len(found)
            grade = "A" if present >= 5 else "B" if present >= 4 else "C" if present >= 3 else "D" if present >= 2 else "F"
            grades[grade] += 1
            print(f"{G}[+] {url} -> Grade: {grade} (Headers: {present}/6){RS}")
        except Exception as e:
            results[url] = {"error": str(e)}
            print(f"{R}[!] {url} failed: {e}{RS}")
    output = {"domain": domain, "results": results, "grades": grades}
    save_json(output, f"{outdir}/phase_31_headers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 31 complete.{RS}")
    return output

# ---------- Phase 32 ----------
def phase_32_axfr(domain, outdir):
    print(f"{B}[🔵] Phase 32: AXFR{RS}")
    results = {"domain": domain, "ns_servers": [], "axfr_success": False, "records": {}}
    try:
        ns_list = run_cmd(f"dig NS {domain} +short", 10).strip().splitlines()
        for ns in ns_list:
            ns = ns.rstrip('.')
            results["ns_servers"].append(ns)
            print(f"{Y}[*] Testing NS: {ns}{RS}")
            axfr = run_cmd(f"dig AXFR {domain} @{ns}", 15)
            if "Transfer failed" not in axfr and "XFR size" in axfr:
                results["axfr_success"] = True
                results["records"][ns] = axfr.strip().splitlines()
                print(f"{G}[+] AXFR successful from {ns}{RS}")
            else:
                print(f"{Y}[!] AXFR failed from {ns}{RS}")
    except Exception as e:
        results["error"] = str(e)
    save_json(results, f"{outdir}/phase_32_axfr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 32 complete.{RS}")
    return results

# ---------- Phase 33 ----------
def phase_33_cloud_metadata(domain, outdir):
    print(f"{B}[🔵] Phase 33: Cloud Metadata{RS}")
    results = {"domain": domain, "metadata": {}, "accessible": False}
    endpoints = {"AWS": "http://169.254.169.254/latest/meta-data/", "GCP": "http://169.254.169.254/computeMetadata/v1/", "Azure": "http://169.254.169.254/metadata/instance?api-version=2017-08-01", "OVH": "http://169.254.169.254/ovh/"}
    for prov, url in endpoints.items():
        try:
            h = {"Metadata-Flavor": "Google"} if prov == "GCP" else {}
            r = requests.get(url, headers=h, timeout=3)
            if r.status_code == 200:
                results["metadata"][prov] = r.text[:500]
                results["accessible"] = True
                print(f"{G}[+] {prov} metadata accessible{RS}")
            else:
                print(f"{Y}[!] {prov} not accessible (status {r.status_code}){RS}")
        except Exception as e:
            print(f"{R}[!] {prov} error: {e}{RS}")
    save_json(results, f"{outdir}/phase_33_cloud_metadata_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 33 complete.{RS}")
    return results

# ---------- Phase 34 ----------
def phase_34_git_leak(domain, outdir):
    print(f"{B}[🔵] Phase 34: Git Leak{RS}")
    results = {"domain": domain, "leaks": []}
    for proto in ["http","https"]:
        for path in ["/.git/config","/.git/HEAD","/.git/index"]:
            url = f"{proto}://{domain}{path}"
            try:
                r = requests.get(url, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    results["leaks"].append({"url": url, "status": 200, "size": len(r.text)})
                    print(f"{G}[+] LEAK FOUND: {url}{RS}")
                else:
                    print(f"{Y}[-] {url} -> {r.status_code}{RS}")
            except Exception as e:
                print(f"{R}[!] {url} error: {e}{RS}")
    save_json(results, f"{outdir}/phase_34_git_leak_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 34 complete.{RS}")
    return results

# ---------- Phase 35 ----------
def phase_35_s3_permissions(domain, outdir):
    print(f"{B}[🔵] Phase 35: S3 Permissions{RS}")
    results = {"domain": domain, "buckets": []}
    names = [domain, f"www.{domain}", f"assets.{domain}", f"static.{domain}", f"media.{domain}", f"files.{domain}", f"cdn.{domain}", domain.replace(".", "-")]
    for name in names:
        url = f"http://{name}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                if "ListBucketResult" in r.text or "Contents" in r.text:
                    print(f"{G}[+] BUCKET PUBLIC: {url} (listable){RS}")
                    results["buckets"].append({"bucket": name, "url": url, "status": "public_listable"})
                else:
                    print(f"{G}[+] BUCKET PUBLIC: {url} (accessible){RS}")
                    results["buckets"].append({"bucket": name, "url": url, "status": "public_accessible"})
            elif r.status_code == 403:
                print(f"{Y}[-] {url} -> 403 (Access Denied){RS}")
                results["buckets"].append({"bucket": name, "url": url, "status": "access_denied"})
            else:
                print(f"{Y}[-] {url} -> {r.status_code}{RS}")
                results["buckets"].append({"bucket": name, "url": url, "status": f"http_{r.status_code}"})
        except Exception as e:
            print(f"{R}[!] {url} error: {e}{RS}")
            results["buckets"].append({"bucket": name, "url": url, "status": "error", "error": str(e)})
    save_json(results, f"{outdir}/phase_35_s3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 35 complete.{RS}")
    return results

# ---------- Phase 36 ----------
def phase_36_graphql_introspection(domain, outdir):
    print(f"{B}[🔵] Phase 36: GraphQL Introspection{RS}")
    results = {"domain": domain, "endpoints": []}
    endpoints = ["/graphql","/api/graphql","/gql","/v1/graphql","/graphiql"]
    query = "query IntrospectionQuery { __schema { types { name kind description fields { name type { name kind } } } } }"
    for ep in endpoints:
        for proto in ["http","https"]:
            url = f"{proto}://{domain}{ep}"
            try:
                r = requests.post(url, json={"query": query}, timeout=10, verify=False, headers={"Content-Type": "application/json"})
                if r.status_code == 200 and "data" in r.json():
                    print(f"{G}[+] GraphQL introspection enabled at {url}{RS}")
                    results["endpoints"].append({"url": url, "status": "enabled", "schema": r.json().get("data", {})})
                else:
                    r2 = requests.get(url, params={"query": query}, timeout=10, verify=False)
                    if r2.status_code == 200 and "data" in r2.json():
                        print(f"{G}[+] GraphQL introspection enabled at {url} (GET){RS}")
                        results["endpoints"].append({"url": url, "status": "enabled", "schema": r2.json().get("data", {})})
                    else:
                        print(f"{Y}[-] {url} -> {r.status_code} (no introspection){RS}")
            except Exception as e:
                print(f"{R}[!] {url} error: {e}{RS}")
    save_json(results, f"{outdir}/phase_36_graphql_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 36 complete.{RS}")
    return results

# ---------- Phase 37 ----------
def phase_37_jwt_scanner(domain, outdir):
    print(f"{B}[🔵] Phase 37: JWT Scanner{RS}")
    import base64
    results = {"domain": domain, "tokens": []}
    paths = ["","/api","/auth","/login"]
    for proto in ["http","https"]:
        for path in paths:
            url = f"{proto}://{domain}{path}"
            try:
                r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                # Header
                auth = r.headers.get("Authorization", "")
                if "Bearer " in auth:
                    token = auth.split("Bearer ")[1].strip()
                    if token.startswith("eyJ"):
                        results["tokens"].append({"url": url, "source": "Authorization header", "token": token})
                        print(f"{G}[+] JWT in Authorization header at {url}{RS}")
                # Cookie
                for cookie in r.cookies:
                    if "eyJ" in cookie.value:
                        results["tokens"].append({"url": url, "source": "Cookie", "token": cookie.value})
                        print(f"{G}[+] JWT in cookie at {url}{RS}")
                # Body
                matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", r.text)
                for token in matches:
                    results["tokens"].append({"url": url, "source": "Response body", "token": token})
                    print(f"{G}[+] JWT in response body at {url}{RS}")
            except Exception as e:
                print(f"{R}[!] {url} error: {e}{RS}")
    # Decode
    for entry in results["tokens"]:
        try:
            parts = entry["token"].split(".")
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
                entry["header"] = header
                entry["payload"] = payload
                entry["algorithm"] = header.get("alg", "unknown")
                if entry["algorithm"] == "none":
                    entry["weakness"] = "alg=none (critical)"
                    print(f"{R}[!] Critical: alg=none found in token from {entry['url']}{RS}")
        except Exception as e:
            entry["decode_error"] = str(e)
    save_json(results, f"{outdir}/phase_37_jwt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 37 complete.{RS}")
    return results

# ---------- Phase 38 ----------
def phase_38_cors_reflection(domain, outdir):
    print(f"{B}[🔵] Phase 38: CORS Reflection{RS}")
    results = {"domain": domain, "endpoints": []}
    for proto in ["http","https"]:
        for path in ["", "/api", "/graphql", "/auth", "/login"]:
            url = f"{proto}://{domain}{path}"
            for origin in ["https://evil.com", "https://attacker.com"]:
                try:
                    r = requests.get(url, headers={"Origin": origin}, timeout=5, verify=False, allow_redirects=True)
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    if acao == "*" or acao == origin:
                        print(f"{G}[+] CORS misconfiguration at {url} (ACAO: {acao}){RS}")
                        results["endpoints"].append({"url": url, "origin": origin, "Access-Control-Allow-Origin": acao, "vulnerable": True})
                    else:
                        print(f"{Y}[-] {url} -> ACAO: {acao} (not reflecting){RS}")
                        results["endpoints"].append({"url": url, "origin": origin, "Access-Control-Allow-Origin": acao, "vulnerable": False})
                except Exception as e:
                    print(f"{R}[!] {url} error: {e}{RS}")
    save_json(results, f"{outdir}/phase_38_cors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 38 complete.{RS}")
    return results

# ---------- Phase 39 ----------
def phase_39_rate_limit(domain, outdir):
    print(f"{B}[🔵] Phase 39: Rate Limit{RS}")
    results = {"domain": domain, "endpoints": []}
    for proto in ["http","https"]:
        for ep in ["/login","/api","/auth","/signup"]:
            url = f"{proto}://{domain}{ep}"
            print(f"{Y}[*] Testing {url} for rate limiting{RS}")
            codes = []
            for _ in range(10):
                try:
                    codes.append(requests.get(url, timeout=3, verify=False).status_code)
                except:
                    codes.append(None)
                time.sleep(0.1)
            if 429 in codes or 403 in codes:
                print(f"{G}[+] Rate limiting detected at {url} (statuses: {set(codes)}){RS}")
                results["endpoints"].append({"url": url, "statuses": codes, "rate_limited": True})
            else:
                print(f"{Y}[-] No rate limiting at {url} (statuses: {set(codes)}){RS}")
                results["endpoints"].append({"url": url, "statuses": codes, "rate_limited": False})
    save_json(results, f"{outdir}/phase_39_rate_limit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"{G}[✅] Phase 39 complete.{RS}")
    return results

# ---------- Phase 40 ----------
def phase_40_email_security(domain, outdir):
    print(f"{B}[🔵] Phase 40: Email Security{RS}")
    results = {"domain": domain, "spf": None, "dkim": {}, "dmarc": None}
    def q(name):
        return [rec.strip('"') for rec in run_cmd(f"dig TXT {name} +short", 5).splitlines() if rec]
    spf = [r for r in q(domain) if 'v=spf1' in r]
    if spf:
        results["spf"] = spf[0]
        print(f"{G}[+] SPF record found: {spf[0]}{RS}")
    else:
        print(f"{Y}[-] SPF not found{RS}")
    dmarc = q(f"_dmarc.{domain}")
    if dmarc:
        results["dmarc"] = dmarc[0]
        print(f"{G}[+] DMARC record found: {dmarc[0]}{RS}")
    else:
        print(f"{Y}[-] DMARC not found{RS}")
    for sel in ["default","google","selector1","selector2","k1","k2","dkim"]:
        dkim = q(f"{sel}._domainkey.{domain}")
        if dkim:
            results["dkim"][sel] = dkim[0]
            print(f"{G}[+] DKIM found for selector {sel}: {dkim[0]}{RS}")
        else:
            print(f"{Y}[-] No DKIM for selector {sel}{RS}")
    save_json(results, f"{outdir}/phase_40_email_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
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

    # If single phase requested
    if args.phase:
        phase_map = {
            1: phase_01_whois, 2: phase_02_asn, 3: phase_03_passive_subdomain, 4: phase_04_bruteforce,
            5: phase_05_permutations, 6: phase_06_ct_logs, 7: phase_07_dns_takeover, 8: phase_08_cloud_buckets,
            9: phase_09_github_search, 10: phase_10_emails, 11: phase_11_open_ports, 12: phase_12_vhosts,
            13: phase_13_http_probing, 14: phase_14_tech_fingerprint, 15: phase_15_takeover_confirm,
            16: phase_16_cve_recon, 17: phase_17_cors_graphql_favicon, 18: phase_18_wayback_historical,
            19: phase_19_js_deep_dive, 20: phase_20_sourcemaps, 21: phase_21_url_fuzzing, 22: phase_22_parameters,
            23: phase_23_screenshots, 24: phase_24_live_validation, 25: phase_25_dedup, 26: phase_26_enrichment,
            27: phase_27_report, 28: phase_28_audit, 29: phase_29_nuclei, 30: phase_30_ssl_scan,
            31: phase_31_security_headers, 32: phase_32_axfr, 33: phase_33_cloud_metadata, 34: phase_34_git_leak,
            35: phase_35_s3_permissions, 36: phase_36_graphql_introspection, 37: phase_37_jwt_scanner,
            38: phase_38_cors_reflection, 39: phase_39_rate_limit, 40: phase_40_email_security
        }
        if args.phase in phase_map:
            phase_map[args.phase](domain, outdir)
        else:
            print(f"{R}[!] Phase {args.phase} not implemented.{RS}")
        return

    # ---- Full pipeline ----
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
    phase_24_live_validation(domain, live_urls + historical[:50], outdir)

    master_data = {
        'subdomains': all_subs,
        'ips': ips,
        'open_ports': open_ports,
        'probe': probe_results,
        'tech': tech,
        'historical': historical,
        'js': js_files,
        'live': live_urls
    }
    phase_25_dedup(domain, master_data, outdir)
    phase_26_enrichment(domain, master_data, outdir)
    phase_27_report(domain, master_data, outdir)
    phase_28_audit(domain, outdir)

    # Phase 29 – prompt
    print(f"{Y}\n[?] Phase 29: Nuclei Scan (optional).{RS}")
    print(f"{R}[!] WARNING: Sends real payloads (LFI, SQLi, RCE). May trigger WAF or violate bug bounty rules.{RS}")
    resp = input(f"{C}Continue to Phase 29? (y/N): {RS}").strip().lower()
    if resp in ['y','yes']:
        print(f"{G}[!] Continuing...{RS}")
        phase_29_nuclei(domain, live_urls if live_urls else historical[:10], outdir)
    else:
        print(f"{Y}[!] Phase 29 skipped.{RS}")

    # Phase 30-40
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
