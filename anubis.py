#!/usr/bin/env python3
# anubis.py - ANUBIS Recon Engine (Master Orchestrator)

import os
import sys
import argparse
import time
import json
import whois
import socket
import requests
import subprocess
import dns.resolver
import re
import asyncio
import aiohttp
import random
import glob
import hashlib
import shutil
import tempfile
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from anubis_banner import print_banner

init(autoreset=True)

# ============================================================
# GLOBAL SETTINGS
# ============================================================
DNS_RETRIES = 1
DNS_TIMEOUT = 0.3
DNS_THREADS = 200
CT_TIMEOUT = 60
CT_RETRIES = 2
PORT_SCAN_TIMEOUT = 1.0
VHOST_CONCURRENT = 500
VHOST_TIMEOUT = 3
PROBE_CONCURRENT = 300
PROBE_TIMEOUT = 5
JS_CONCURRENT = 500
JS_TIMEOUT = 10
MAP_CONCURRENT = 300
MAP_TIMEOUT = 8
FUZZ_CONCURRENT = 500
FUZZ_TIMEOUT = 3
PARAM_CONCURRENT = 500
PARAM_TIMEOUT = 5
SCREENSHOT_TIMEOUT = 30
ENRICHMENT_ITERATIONS = 5

TOP_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 179, 199, 389, 443, 445, 465, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000, 11371, 12345, 13720, 13721, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 32786, 32787, 32788, 32789, 32790, 32791, 32792, 32793, 32794, 32795, 32796, 32797, 32798, 32799]
VHOST_PORTS = [80, 443]
TAKEOVER_TARGETS = ['s3.amazonaws.com', 's3-website', 'storage.googleapis.com', 'blob.core.windows.net', 'azurewebsites.net', 'herokuapp.com', 'github.io', 'netlify.app', 'cloudfront.net', 'firebaseapp.com', 'pages.dev', 'vercel.app', 'surge.sh', 'gitlab.io']

# ============================================================
# TECH DETECTION RULES
# ============================================================
TECH_RULES = {
    "web_server": {
        "nginx": re.compile(r'nginx', re.I),
        "apache": re.compile(r'apache', re.I),
        "cloudflare": re.compile(r'cloudflare', re.I),
        "aws-elb": re.compile(r'awselb|amazon', re.I),
        "cloudfront": re.compile(r'cloudfront', re.I),
        "istio": re.compile(r'istio-envoy|istio', re.I),
        "microsoft-iis": re.compile(r'iis', re.I),
        "tomcat": re.compile(r'tomcat', re.I),
        "jetty": re.compile(r'jetty', re.I),
        "s3": re.compile(r'amazons3|s3', re.I),
    },
    "language": {
        "php": re.compile(r'php', re.I),
        "python": re.compile(r'python|django|flask', re.I),
        "ruby": re.compile(r'ruby|rails', re.I),
        "nodejs": re.compile(r'node|express', re.I),
        "java": re.compile(r'java|jsp|servlet', re.I),
        "dotnet": re.compile(r'asp\.net|\.net', re.I),
    },
    "cms": {
        "wordpress": re.compile(r'wordpress|wp-', re.I),
        "drupal": re.compile(r'drupal', re.I),
        "joomla": re.compile(r'joomla', re.I),
        "shopify": re.compile(r'shopify', re.I),
        "magento": re.compile(r'magento', re.I),
        "squarespace": re.compile(r'squarespace', re.I),
    },
    "js_frameworks": {
        "react": re.compile(r'react', re.I),
        "vue": re.compile(r'vue', re.I),
        "angular": re.compile(r'angular|ng-', re.I),
        "jquery": re.compile(r'jquery', re.I),
        "bootstrap": re.compile(r'bootstrap', re.I),
        "tailwind": re.compile(r'tailwind', re.I),
    },
    "analytics": {
        "google-analytics": re.compile(r'google-analytics|ga\.js', re.I),
        "facebook-pixel": re.compile(r'fb\.js|facebook-pixel', re.I),
        "hotjar": re.compile(r'hotjar', re.I),
    }
}

# ============================================================
# CVE DATABASE (LIGHTWEIGHT)
# ============================================================
CVE_DB = {
    "nginx": [{"id": "CVE-2021-23017", "description": "nginx 1.18.0 - 1.20.0: Buffer overflow.", "severity": "High"}, {"id": "CVE-2019-9511", "description": "HTTP/2: Data Dribble vulnerability.", "severity": "Medium"}],
    "apache": [{"id": "CVE-2021-41773", "description": "Apache 2.4.49: Path Traversal & RCE.", "severity": "Critical"}],
    "cloudflare": [{"id": "CVE-2018-25031", "description": "Cloudflare WAF bypass.", "severity": "Medium"}],
    "aws-elb": [{"id": "CVE-2022-31166", "description": "AWS ELB: Denial of Service.", "severity": "Medium"}],
    "cloudfront": [{"id": "CVE-2020-3137", "description": "CloudFront: Cache poisoning.", "severity": "Medium"}],
    "tomcat": [{"id": "CVE-2020-1938", "description": "Tomcat AJP File Read (Ghostcat).", "severity": "High"}],
    "nodejs": [{"id": "CVE-2021-21315", "description": "Node.js: Prototype pollution.", "severity": "Critical"}],
    "python": [{"id": "CVE-2021-3177", "description": "Python 3.7: Buffer overflow.", "severity": "Critical"}],
    "php": [{"id": "CVE-2019-11043", "description": "PHP-FPM + Nginx: RCE.", "severity": "Critical"}],
    "wordpress": [{"id": "CVE-2023-5360", "description": "WordPress Core SQL injection.", "severity": "Critical"}],
    "drupal": [{"id": "CVE-2018-7600", "description": "Drupalgeddon2: RCE.", "severity": "Critical"}],
    "joomla": [{"id": "CVE-2020-35607", "description": "Joomla 3.9.23: Improper access control.", "severity": "High"}],
    "shopify": [{"id": "CVE-2021-32718", "description": "Shopify: Order payment bypass.", "severity": "High"}],
    "magento": [{"id": "CVE-2022-24086", "description": "Magento 2.4.3: SQL injection.", "severity": "Critical"}],
    "react": [{"id": "CVE-2020-8282", "description": "React: XSS via link.", "severity": "Medium"}],
    "istio": [{"id": "CVE-2022-31045", "description": "Istio 1.14.0: Envoy proxy DoS.", "severity": "High"}, {"id": "CVE-2021-31920", "description": "Istio 1.9.0: Authentication bypass.", "severity": "Critical"}],
    "jquery": [{"id": "CVE-2020-11022", "description": "jQuery 3.5.0: XSS via html().", "severity": "Medium"}],
    "bootstrap": [{"id": "CVE-2020-7656", "description": "Bootstrap 4.4.0: XSS.", "severity": "Medium"}]
}

# ============================================================
# JS EXTRACTION PATTERNS
# ============================================================
ENDPOINT_PATTERNS = [
    r'["\'](/api/[^\s"\']+)["\']',
    r'["\'](/v[0-9]+/[^\s"\']+)["\']',
    r'["\'](/graphql[^\s"\']*)["\']',
    r'["\'](/admin[^\s"\']*)["\']',
    r'["\'](/swagger[^\s"\']*)["\']',
    r'["\'](/docs[^\s"\']*)["\']',
    r'["\'](//[^\s"\']+\.[^\s"\']+)["\']',
]
SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',
    r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    r'[a-zA-Z0-9]{32,}',
    r'sk-[a-zA-Z0-9]{32,}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'xox[bap]-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}',
    r'[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}',
]
IP_PATTERN = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
EMAIL_PATTERN = r'[\w\.-]+@[\w\.-]+'
PARAM_PATTERN = r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)='
PARAM_JSON_PATTERN = r'"([a-zA-Z_][a-zA-Z0-9_]*)":'

# ============================================================
# WORDLISTS
# ============================================================
FUZZ_WORDLIST = [
    "admin", "api", "backup", "config", ".env", ".git", "swagger", "graphql",
    "dashboard", "portal", "uploads", "download", "files", "images", "css",
    "js", "assets", "static", "media", "data", "logs", "tmp", "temp",
    "old", "new", "v1", "v2", "v3", "test", "dev", "stage", "staging",
    "prod", "production", "internal", "private", "public", "secure",
    "auth", "login", "signup", "register", "profile", "account",
    "settings", "billing", "payment", "checkout", "cart", "shop",
    "store", "marketplace", "partner", "vendor", "supplier",
    "distributor", "wholesale", "corporate", "staff", "hr",
    "payroll", "timesheet", "expense", "travel", "booking",
    "reservation", "ticket", "event", "conference", "meet",
    "chat", "call", "video", "stream", "live", "media", "audio",
    "music", "podcast", "radio", "tv", "movie", "film", "show",
    "episode", "season", "series", "channel", "playlist",
    "uploader", "downloader", "converter", "editor", "viewer",
    "player", "recorder", "screen", "capture", "record",
    "backup", "restore", "import", "export", "sync", "share",
    "embed", "frame", "widget", "plugin", "extension", "addon",
    "module", "component", "service", "worker", "job", "task",
    "queue", "cache", "session", "cookie", "storage", "database",
    "mongo", "mysql", "postgres", "redis", "elastic", "search",
    "index", "crawl", "scrape", "parse", "transform", "filter",
    "sort", "group", "aggregate", "count", "sum", "average",
    "min", "max", "mean", "median", "mode", "variance", "stddev",
    "correlation", "regression", "classification", "clustering",
    "recommendation", "personalization", "optimization",
    "simulation", "prediction", "forecast", "anomaly", "outlier",
    "detection", "prevention", "protection", "security", "firewall",
    "proxy", "gateway", "loadbalancer", "cdn", "waf", "ids", "ips",
    "vpn", "ssh", "ftp", "sftp", "rsync", "scp", "telnet", "rlogin",
    "rsh", "rexec", "x11", "vnc", "rdp", "spice", "webdav", "caldav",
    "carddav", "imap", "pop3", "smtp", "ldap", "radius", "tacacs",
    "syslog", "snmp", "ntp", "dns", "dhcp", "bootp", "tftp", "nfs",
    "smb", "cifs", "ncp", "netbios", "wins", "netstat", "route",
    "traceroute", "ping", "mtr", "tcpdump", "wireshark", "nmap",
    "masscan", "zmap", "unicornscan", "hping", "scapy", "metasploit",
    "exploit", "payload", "shell", "reverse", "bind", "conn",
    "socks", "http", "https", "websocket", "webhook", "rest",
    "soap", "rpc", "grpc", "thrift", "avro", "protobuf", "json",
    "xml", "yaml", "toml", "ini", "conf", "config", "properties"
]

PARAM_WORDLIST = [
    "id", "user", "user_id", "uid", "username", "email", "mail",
    "phone", "mobile", "password", "pass", "token", "auth",
    "key", "api_key", "apikey", "secret", "hash", "checksum",
    "file", "filename", "path", "dir", "folder", "root",
    "url", "link", "redirect", "return", "next", "goto",
    "page", "offset", "limit", "size", "count", "total",
    "sort", "order", "filter", "search", "q", "query",
    "lang", "language", "locale", "country", "region",
    "time", "date", "start", "end", "from", "to", "since",
    "until", "before", "after", "min", "max", "range",
    "type", "status", "state", "mode", "format", "ext",
    "name", "title", "description", "content", "body",
    "data", "json", "xml", "callback", "jsonp", "format",
    "debug", "test", "admin", "sudo", "root", "superuser"
]

# ============================================================
# HELPERS
# ============================================================
def convert_dates(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, list):
        return [convert_dates(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_dates(v) for k, v in obj.items()}
    else:
        return obj

def save_output(domain, phase_name, data, output_dir="output"):
    target_dir = os.path.join(output_dir, domain)
    os.makedirs(target_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = os.path.join(target_dir, f"{phase_name}_{timestamp}.json")
    txt_file = os.path.join(target_dir, f"{phase_name}_{timestamp}.txt")
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    with open(txt_file, 'w') as f:
        if isinstance(data, list):
            for item in data:
                f.write(str(item) + "\n")
        elif isinstance(data, dict):
            for key, value in data.items():
                f.write(f"{key}: {value}\n")
        else:
            f.write(str(data))
    print(f"{Fore.CYAN}[📁] Saved: {json_file}{Fore.RESET}")

def find_latest_file(target_dir, pattern):
    if not os.path.exists(target_dir):
        return None
    files = [f for f in os.listdir(target_dir) if pattern in f and f.endswith('.json')]
    if not files:
        return None
    files.sort(key=lambda f: os.path.getmtime(os.path.join(target_dir, f)), reverse=True)
    return os.path.join(target_dir, files[0])

def normalize_url(url):
    if not url:
        return None
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip('/') or '/'
    query = parsed.query
    new_url = urlunparse((scheme, netloc, path, '', query, ''))
    return new_url

def load_proxies(proxy_file=None):
    proxies = []
    if proxy_file and os.path.exists(proxy_file):
        with open(proxy_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not line.startswith('http'):
                        line = f"http://{line}"
                    proxies.append(line)
        print(f"{Fore.GREEN}[*] Loaded {len(proxies)} proxies from {proxy_file}{Fore.RESET}")
    return proxies

def get_resolved_subdomains(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    if not os.path.exists(target_dir):
        return []
    resolved = set()
    for fname in os.listdir(target_dir):
        if "phase_07_dns_takeover" in fname and fname.endswith('.json'):
            with open(os.path.join(target_dir, fname), 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if entry.get('ip'):
                            resolved.add(entry.get('subdomain'))
    return list(resolved)

async def check_vhost_proxy(session, ip, port, host, proxy=None, timeout=VHOST_TIMEOUT):
    scheme = "https" if port in [443, 8443] else "http"
    url = f"{scheme}://{ip}:{port}"
    headers = {"Host": host, "User-Agent": "MUGEI-Recon/1.0"}
    try:
        async with session.get(url, headers=headers, timeout=timeout, ssl=False, proxy=proxy) as resp:
            if resp.status in [200, 301, 302, 401, 403, 500, 502, 503]:
                return {"ip": ip, "port": port, "host": host, "status": resp.status, "url": url}
    except:
        pass
    return None

async def run_vhost_async(ips, ports, subdomains, proxies):
    tasks = []
    sem = asyncio.Semaphore(VHOST_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=VHOST_CONCURRENT, limit_per_host=VHOST_CONCURRENT, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        for ip in ips:
            for port in ports:
                for sub in subdomains:
                    proxy = random.choice(proxies) if proxies else None
                    async with sem:
                        tasks.append(check_vhost_proxy(session, ip, port, sub, proxy))
        results = await asyncio.gather(*tasks)
    await asyncio.sleep(0.1)
    return [r for r in results if r is not None]

# ============================================================
# PHASE 1: WHOIS
# ============================================================
def phase_01_whois(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 1: WHOIS Discovery for {domain}{Fore.RESET}")
    try:
        w = whois.whois(domain)
        result = {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "registrant_email": w.emails if w.emails else None,
            "name_servers": w.name_servers,
            "status": w.status,
            "dnssec": w.dnssec
        }
        result = convert_dates(result)
        print(f"{Fore.GREEN}[+] Registrar: {result['registrar']}{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Created: {result['creation_date']}{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Expires: {result['expiration_date']}{Fore.RESET}")
        save_output(domain, "phase_01_whois", result, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 1 complete.{Fore.RESET}")
        return result
    except Exception as e:
        print(f"{Fore.YELLOW}[!] WHOIS failed: {e}{Fore.RESET}")
        result = {"domain": domain, "error": str(e)}
        save_output(domain, "phase_01_whois", result, output_dir)
        return result

# ============================================================
# PHASE 2: ASN
# ============================================================
def phase_02_asn(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 2: ASN & Netblock for {domain}{Fore.RESET}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] Resolved IP: {ip}{Fore.RESET}")
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get('status') == 'success':
            result = {
                "domain": domain,
                "ip": ip,
                "asn": data.get('as'),
                "org": data.get('org'),
                "isp": data.get('isp'),
                "country": data.get('country'),
                "city": data.get('city'),
                "region": data.get('regionName'),
                "timezone": data.get('timezone')
            }
            print(f"{Fore.GREEN}[+] ASN: {result['asn']}{Fore.RESET}")
            print(f"{Fore.GREEN}[+] Organization: {result['org']}{Fore.RESET}")
            print(f"{Fore.GREEN}[+] Country: {result['country']}{Fore.RESET}")
            save_output(domain, "phase_02_asn", result, output_dir)
            print(f"{Fore.GREEN}[✅] Phase 2 complete.{Fore.RESET}")
            return result
        else:
            raise Exception("ip-api.com returned error")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] ASN lookup failed: {e}{Fore.RESET}")
        result = {"domain": domain, "error": str(e)}
        save_output(domain, "phase_02_asn", result, output_dir)
        return result

# ============================================================
# PHASE 3: PASSIVE SUBDOMAIN ENUMERATION
# ============================================================
def phase_03_subdomains(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 3: Passive Subdomain Enumeration for {domain}{Fore.RESET}")
    subdomains = []
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=60)
        if result.returncode == 0 and result.stdout:
            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            print(f"{Fore.GREEN}[+] Subfinder found {len(subdomains)} subdomains.{Fore.RESET}")
        else:
            raise FileNotFoundError("subfinder not found")
    except:
        print(f"{Fore.YELLOW}[!] Subfinder failed/not installed. Falling back to crt.sh...{Fore.RESET}")
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    for part in name.split('\n'):
                        part = part.strip()
                        if part.endswith(f".{domain}"):
                            if part.startswith('*.'):
                                part = part[2:]
                            subdomains.append(part)
            subdomains = sorted(set(subdomains))
            print(f"{Fore.GREEN}[+] crt.sh found {len(subdomains)} subdomains.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] crt.sh fallback failed: {e}{Fore.RESET}")
    if subdomains:
        save_output(domain, "phase_03_subdomains", subdomains, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 3 complete (saved {len(subdomains)} subdomains).{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No subdomains found.{Fore.RESET}")
        save_output(domain, "phase_03_subdomains", [], output_dir)
    return subdomains

# ============================================================
# PHASE 4: ACTIVE BRUTE-FORCE SUBDOMAINS
# ============================================================
DEFAULT_WORDLIST = ["admin", "dev", "test", "stage", "staging", "api", "app", "www", "mail", "ftp", "ssh", "vpn", "remote", "internal", "backup", "cdn", "static", "assets", "img", "video", "download", "upload", "support", "help", "docs", "wiki", "blog", "news", "portal", "dashboard", "manage", "console", "cloud", "aws", "azure", "gcp", "secure", "auth", "login", "signup", "register", "profile", "account", "settings", "billing", "payment", "checkout", "cart", "shop", "store", "marketplace"]

def phase_04_bruteforce(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 4: Active Brute-Force Subdomains for {domain}{Fore.RESET}")
    print(f"{Fore.YELLOW}[!] Using built-in wordlist of {len(DEFAULT_WORDLIST)} entries.{Fore.RESET}")
    found = []
    for sub in DEFAULT_WORDLIST:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            found.append(full)
            print(f"{Fore.GREEN}[+] Found: {full} -> {ip}{Fore.RESET}")
        except:
            pass
    if found:
        save_output(domain, "phase_04_bruteforce", found, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 4 complete (found {len(found)} subdomains).{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No subdomains found via brute force.{Fore.RESET}")
        save_output(domain, "phase_04_bruteforce", [], output_dir)
    return found

# ============================================================
# PHASE 5: DNS PERMUTATIONS
# ============================================================
PERMUTATION_SUFFIXES = ["-dev", "-test", "-stage", "-staging", "-backup", "-old", "-new", "-v1", "-v2", "2", "3", "4", "5"]
def load_subdomains_from_output(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    if not os.path.exists(target_dir):
        return []
    subdomains = set()
    for fname in os.listdir(target_dir):
        if fname.startswith("phase_03_subdomains") or fname.startswith("phase_04_bruteforce") or fname.startswith("phase_06_ct_logs"):
            if fname.endswith(".json"):
                with open(os.path.join(target_dir, fname), 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        subdomains.update(data)
    return list(subdomains)

def resolve_with_retry(full):
    for _ in range(DNS_RETRIES + 1):
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT)
            ip = socket.gethostbyname(full)
            return full, ip
        except:
            pass
    return None, None

def phase_05_permutations(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 5: DNS Permutations for {domain}{Fore.RESET}")
    existing = load_subdomains_from_output(domain, output_dir)
    if not existing:
        existing = ["www", "api", "app", "admin", "dev", "test", "staging"]
        print(f"{Fore.YELLOW}[!] No previous subdomains found. Using fallback list.{Fore.RESET}")
    permutations = set()
    for sub in existing:
        base = sub.split('.')[0]
        for suffix in PERMUTATION_SUFFIXES:
            permutations.add(f"{base}{suffix}")
    permutations = sorted(permutations)
    print(f"{Fore.CYAN}[*] Generated {len(permutations)} permutations.{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Using {DNS_RETRIES} retry, {DNS_TIMEOUT}s timeout, {DNS_THREADS} threads.{Fore.RESET}")
    found = []
    total = len(permutations)
    with ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:
        futures = {executor.submit(resolve_with_retry, f"{p}.{domain}"): p for p in permutations}
        completed = 0
        for future in as_completed(futures):
            full, ip = future.result()
            if full:
                found.append(full)
                print(f"{Fore.GREEN}[+] Found: {full} -> {ip}{Fore.RESET}")
            completed += 1
            if completed % 100 == 0 or completed == total:
                print(f"{Fore.CYAN}[*] Progress: {completed}/{total}{Fore.RESET}")
    if found:
        save_output(domain, "phase_05_permutations", found, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 5 complete (found {len(found)} new subdomains).{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No permutations resolved.{Fore.RESET}")
        save_output(domain, "phase_05_permutations", [], output_dir)
    return found

# ============================================================
# PHASE 6: DEEP CERTIFICATE TRANSPARENCY LOGS
# ============================================================
def phase_06_ct_logs(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 6: Deep CT Logs for {domain}{Fore.RESET}")
    subdomains = set()
    for attempt in range(CT_RETRIES + 1):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=CT_TIMEOUT)
            if response.status_code != 200:
                print(f"{Fore.YELLOW}[!] crt.sh returned status {response.status_code}. Retry {attempt+1}/{CT_RETRIES}.{Fore.RESET}")
                time.sleep(2)
                continue
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    for part in name.split('\n'):
                        part = part.strip()
                        if part.endswith(f".{domain}"):
                            if part.startswith('*.'):
                                part = part[2:]
                            subdomains.add(part)
            subdomains = sorted(subdomains)
            print(f"{Fore.GREEN}[+] CT logs found {len(subdomains)} unique subdomains.{Fore.RESET}")
            if subdomains:
                sample = subdomains[:5]
                print(f"{Fore.CYAN}[*] Sample: {', '.join(sample)}{Fore.RESET}")
            save_output(domain, "phase_06_ct_logs", subdomains, output_dir)
            print(f"{Fore.GREEN}[✅] Phase 6 complete (saved {len(subdomains)} subdomains).{Fore.RESET}")
            return subdomains
        except Exception as e:
            print(f"{Fore.YELLOW}[!] CT logs error: {e}. Retry {attempt+1}/{CT_RETRIES}.{Fore.RESET}")
            time.sleep(3)
    print(f"{Fore.RED}[!] CT logs failed after {CT_RETRIES+1} attempts.{Fore.RESET}")
    save_output(domain, "phase_06_ct_logs", [], output_dir)
    return []

# ============================================================
# PHASE 7: DNS RESOLUTION + CNAME TAKEOVER CHECK
# ============================================================
def resolve_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except:
        return None

def check_takeover(cname):
    if not cname:
        return False
    cname_lower = cname.lower()
    for target in TAKEOVER_TARGETS:
        if target in cname_lower:
            return True
    return False

def phase_07_takeover(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 7: DNS Resolution + CNAME Takeover Check for {domain}{Fore.RESET}")
    all_subdomains = load_subdomains_from_output(domain, output_dir)
    if not all_subdomains:
        print(f"{Fore.YELLOW}[!] No subdomains found. Run Phases 3-6 first.{Fore.RESET}")
        save_output(domain, "phase_07_dns_takeover", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Resolving {len(all_subdomains)} subdomains...{Fore.RESET}")
    results = []
    takeover_risks = []
    total = len(all_subdomains)
    for idx, sub in enumerate(all_subdomains, 1):
        ip = None
        try:
            ip = socket.gethostbyname(sub)
        except:
            pass
        cname = resolve_cname(sub)
        is_takeover = check_takeover(cname)
        entry = {"subdomain": sub, "ip": ip, "cname": cname, "takeover_risk": is_takeover}
        results.append(entry)
        if is_takeover:
            takeover_risks.append(entry)
            print(f"{Fore.RED}[!] TAKEOVER RISK: {sub} -> {cname}{Fore.RESET}")
        elif ip:
            print(f"{Fore.GREEN}[+] {sub} -> {ip}{Fore.RESET}")
        if idx % 50 == 0:
            print(f"{Fore.CYAN}[*] Progress: {idx}/{total}{Fore.RESET}")
    if takeover_risks:
        print(f"{Fore.RED}[!] Found {len(takeover_risks)} potential takeovers.{Fore.RESET}")
        save_output(domain, "phase_07_takeover_risks", takeover_risks, output_dir)
    else:
        print(f"{Fore.GREEN}[✅] No takeovers found.{Fore.RESET}")
    save_output(domain, "phase_07_dns_takeover", results, output_dir)
    print(f"{Fore.GREEN}[✅] Phase 7 complete.{Fore.RESET}")
    return results

# ============================================================
# PHASE 8: CLOUD BUCKET HUNT
# ============================================================
def phase_08_cloud_buckets(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 8: Cloud Bucket Hunt for {domain}{Fore.RESET}")
    base = domain.replace('.', '-')
    patterns = [base, f"{base}-backup", f"{base}-storage", f"{base}-assets", f"{base}-media", f"{base}-data", f"{base}-dev", f"{base}-test", f"{base}-prod", f"{base}-static", f"static-{base}", f"media-{base}", f"assets-{base}", f"data-{base}", f"backup-{base}", f"dev-{base}", f"test-{base}", f"prod-{base}", f"cdn-{base}", f"{base}-cdn", f"uploads-{base}", f"files-{base}", f"docs-{base}", f"images-{base}", f"videos-{base}", f"public-{base}", f"private-{base}", f"secure-{base}", f"temp-{base}", f"logs-{base}", f"metrics-{base}", f"analytics-{base}", f"backups-{base}", f"archive-{base}", f"legacy-{base}", f"old-{base}", f"new-{base}", f"v1-{base}", f"v2-{base}", f"api-{base}", f"app-{base}", f"web-{base}", f"mobile-{base}", f"android-{base}", f"ios-{base}"]
    found_buckets = []
    print(f"{Fore.CYAN}[*] Checking {len(patterns)} bucket patterns...{Fore.RESET}")
    for name in patterns:
        url = f"http://{name}.s3.amazonaws.com"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                found_buckets.append({"bucket": name, "provider": "S3", "url": url})
                print(f"{Fore.GREEN}[+] Found open S3 bucket: {url}{Fore.RESET}")
        except:
            pass
        url = f"https://{name}.blob.core.windows.net"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                found_buckets.append({"bucket": name, "provider": "Azure Blob", "url": url})
                print(f"{Fore.GREEN}[+] Found open Azure blob: {url}{Fore.RESET}")
        except:
            pass
        url = f"https://storage.googleapis.com/{name}"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                found_buckets.append({"bucket": name, "provider": "GCP", "url": url})
                print(f"{Fore.GREEN}[+] Found open GCP bucket: {url}{Fore.RESET}")
        except:
            pass
    if found_buckets:
        save_output(domain, "phase_08_cloud_buckets", found_buckets, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 8 complete (found {len(found_buckets)} open buckets).{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No open buckets found.{Fore.RESET}")
        save_output(domain, "phase_08_cloud_buckets", [], output_dir)
    return found_buckets

# ============================================================
# PHASE 9: GITHUB / CODE SEARCH (WITH INTERACTIVE TOKEN PROMPT)
# ============================================================
def phase_09_github_search(domain, output_dir, token=None):
    print(f"{Fore.BLUE}[🔵] Phase 9: GitHub Code Search for {domain}{Fore.RESET}")
    
    # If token not provided via CLI or env, ask user interactively
    if not token:
        token = os.environ.get('GITHUB_TOKEN')
        if not token:
            print(f"{Fore.YELLOW}[!] No GitHub token found. Rate limits will be low (60 req/hr).{Fore.RESET}")
            choice = input(f"{Fore.CYAN}Enter GitHub token now? (y/N): {Fore.RESET}").strip().lower()
            if choice in ['y', 'yes']:
                token = input(f"{Fore.CYAN}Enter token (e.g., ghp_...): {Fore.RESET}").strip()
                if token:
                    print(f"{Fore.GREEN}[+] Token accepted.{Fore.RESET}")
                else:
                    print(f"{Fore.YELLOW}[!] No token entered. Continuing without token.{Fore.RESET}")
                    token = None
            else:
                print(f"{Fore.YELLOW}[!] Continuing without token.{Fore.RESET}")
    
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    else:
        print(f"{Fore.YELLOW}[!] Use --github-token or set GITHUB_TOKEN env for higher limits.{Fore.RESET}")
    
    query = f"{domain} extension:json extension:yaml extension:yml extension:env extension:conf extension:config extension:properties extension:ini"
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get('items', [])
            results = []
            for item in items:
                repo = item.get('repository', {}).get('full_name', 'unknown')
                path = item.get('path', 'unknown')
                html_url = item.get('html_url', '')
                results.append({"repository": repo, "path": path, "url": html_url})
            total = data.get('total_count', 0)
            print(f"{Fore.GREEN}[+] Found {total} files containing '{domain}' on GitHub.{Fore.RESET}")
            if results:
                for r in results[:5]:
                    print(f"{Fore.CYAN}  - {r['repository']}/{r['path']}{Fore.RESET}")
                if len(results) > 5:
                    print(f"{Fore.YELLOW}  ... and {len(results)-5} more.{Fore.RESET}")
            save_output(domain, "phase_09_github_search", results, output_dir)
            print(f"{Fore.GREEN}[✅] Phase 9 complete.{Fore.RESET}")
            return results
        elif resp.status_code == 401:
            print(f"{Fore.RED}[!] GitHub API 401: Invalid or missing token.{Fore.RESET}")
        elif resp.status_code == 403:
            print(f"{Fore.YELLOW}[!] Rate limit exceeded. Try again later or use a token.{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}[!] GitHub API returned status {resp.status_code}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] GitHub search error: {e}{Fore.RESET}")
    save_output(domain, "phase_09_github_search", [], output_dir)
    return []

# ============================================================
# PHASE 10: EMAIL ENUMERATION
# ============================================================
def run_theharvester(domain):
    try:
        result = subprocess.run(["theHarvester", "-d", domain, "-l", "100", "-b", "google,bing,linkedin"], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            emails = re.findall(r'[\w\.-]+@' + re.escape(domain), result.stdout)
            return list(set(emails))
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[!] theHarvester not installed. Install with: sudo apt install theHarvester -y{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] theHarvester error: {e}{Fore.RESET}")
    return None

def scrape_website_emails(domain):
    emails = set()
    paths = ["", "/contact", "/about", "/team", "/careers", "/support", "/help", "/contact-us", "/about-us", "/our-team", "/career", "/jobs", "/press", "/news", "/blog", "/contact/", "/about/", "/team/", "/contact-us/", "/support/", "/contact-us.html", "/about-us.html", "/team.html"]
    extra_urls = [f"https://{domain}/robots.txt", f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"]
    all_paths = paths + extra_urls
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for path in all_paths:
        url = f"https://{domain}{path}" if not path.startswith("http") else path
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                emails.update(re.findall(r'[\w\.-]+@' + re.escape(domain), resp.text))
                emails.update(re.findall(r'mailto:([\w\.-]+@' + re.escape(domain) + r')', resp.text, re.IGNORECASE))
                emails.update(re.findall(r'<!--.*?([\w\.-]+@' + re.escape(domain) + r').*?-->', resp.text, re.DOTALL))
        except:
            pass
    try:
        resp = requests.get(f"http://{domain}", headers=headers, timeout=5)
        if resp.status_code == 200:
            emails.update(re.findall(r'[\w\.-]+@' + re.escape(domain), resp.text))
    except:
        pass
    return list(emails)

def phase_10_emails(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 10: Email Enumeration for {domain}{Fore.RESET}")
    emails = run_theharvester(domain)
    if emails is None:
        emails = scrape_website_emails(domain)
    if emails:
        print(f"{Fore.GREEN}[+] Found {len(emails)} unique emails.{Fore.RESET}")
        for e in emails[:5]:
            print(f"{Fore.CYAN}  - {e}{Fore.RESET}")
        if len(emails) > 5:
            print(f"{Fore.YELLOW}  ... and {len(emails)-5} more.{Fore.RESET}")
        save_output(domain, "phase_10_emails", emails, output_dir)
    else:
        print(f"{Fore.YELLOW}[!] No emails found. Try installing theHarvester for better results.{Fore.RESET}")
        save_output(domain, "phase_10_emails", [], output_dir)
    return emails

# ============================================================
# PHASE 11: ASYNC PORT SCANNING
# ============================================================
def load_ips_from_output(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    if not os.path.exists(target_dir):
        return []
    ips = set()
    for fname in os.listdir(target_dir):
        if "phase_07_dns_takeover" in fname and fname.endswith('.json'):
            with open(os.path.join(target_dir, fname), 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if 'ip' in entry and entry['ip']:
                            ips.add(entry['ip'])
    return list(ips)

async def check_port(ip, port, timeout=PORT_SCAN_TIMEOUT):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_ports_async(ip, ports):
    tasks = [check_port(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    return [port for port in results if port is not None]

def phase_11_port_scan(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 11: Async Port Scanning for {domain}{Fore.RESET}")
    ips = load_ips_from_output(domain, output_dir)
    if not ips:
        try:
            ips = [socket.gethostbyname(domain)]
            print(f"{Fore.YELLOW}[!] No IPs from Phase 7. Resolved {domain} to {ips[0]}.{Fore.RESET}")
        except:
            print(f"{Fore.RED}[!] Could not resolve {domain}. Aborting port scan.{Fore.RESET}")
            save_output(domain, "phase_11_open_ports", [], output_dir)
            return []
    print(f"{Fore.CYAN}[*] Scanning {len(ips)} IPs for top {len(TOP_PORTS)} ports...{Fore.RESET}")
    results = {}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for idx, ip in enumerate(ips, 1):
        print(f"{Fore.CYAN}[*] Scanning {ip} ({idx}/{len(ips)})...{Fore.RESET}")
        open_ports = loop.run_until_complete(scan_ports_async(ip, TOP_PORTS))
        if open_ports:
            results[ip] = open_ports
            print(f"{Fore.GREEN}[+] Found open ports on {ip}: {', '.join(map(str, open_ports))}{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}[!] No open ports found on {ip}{Fore.RESET}")
    loop.close()
    if not results:
        print(f"{Fore.YELLOW}[!] No open ports found on any IP.{Fore.RESET}")
        save_output(domain, "phase_11_open_ports", [], output_dir)
        return {}
    save_output(domain, "phase_11_open_ports", results, output_dir)
    print(f"{Fore.GREEN}[✅] Phase 11 complete.{Fore.RESET}")
    return results

# ============================================================
# PHASE 12: VIRTUAL HOST DISCOVERY (FIXED)
# ============================================================
def phase_12_vhosts(domain, output_dir, proxy_file=None):
    print(f"{Fore.BLUE}[🔵] Phase 12: Virtual Host Discovery for {domain}{Fore.RESET}")
    proxies = load_proxies(proxy_file)
    if proxies:
        print(f"{Fore.GREEN}[!] PROXY ROTATION ENABLED: {len(proxies)} IPs.{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No proxies. Running direct.{Fore.RESET}")

    # Try to get IP from Phase 2 JSON as fallback
    ips = load_ips_from_output(domain, output_dir)
    if not ips:
        # Fallback: read IP from Phase 2 JSON
        target_dir = os.path.join(output_dir, domain)
        latest_asn = find_latest_file(target_dir, "phase_02_asn")
        if latest_asn:
            with open(latest_asn, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict) and data.get('ip'):
                    ips = [data['ip']]
                    print(f"{Fore.YELLOW}[!] Loaded IP from Phase 2: {ips[0]}{Fore.RESET}")
        if not ips:
            try:
                ips = [socket.gethostbyname(domain)]
                print(f"{Fore.YELLOW}[!] Resolved {domain} to {ips[0]}{Fore.RESET}")
            except:
                print(f"{Fore.RED}[!] Could not resolve {domain}. Aborting.{Fore.RESET}")
                save_output(domain, "phase_12_vhosts", [], output_dir)
                return []

    # Build a list of subdomains (fallback to the main domain if none)
    subdomains = get_resolved_subdomains(domain, output_dir)
    if not subdomains:
        print(f"{Fore.YELLOW}[!] No resolved subdomains found. Using fallback: {domain}{Fore.RESET}")
        subdomains = [domain]  # Use main domain as a vhost

    total_checks = len(ips) * len(VHOST_PORTS) * len(subdomains)
    print(f"{Fore.CYAN}[*] Testing {len(ips)} IPs × {len(VHOST_PORTS)} ports × {len(subdomains)} subdomains (Async, {VHOST_CONCURRENT} concurrent)...{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Total checks: {total_checks} | Est. time: ~{max(10, int(total_checks / VHOST_CONCURRENT * 1.5))} seconds{Fore.RESET}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    found = loop.run_until_complete(run_vhost_async(ips, VHOST_PORTS, subdomains, proxies))
    loop.run_until_complete(asyncio.sleep(0.1))
    loop.close()

    if found:
        save_output(domain, "phase_12_vhosts", found, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 12 complete (found {len(found)} vhosts).{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No vhosts found.{Fore.RESET}")
        save_output(domain, "phase_12_vhosts", [], output_dir)
    return found

# ============================================================
# PHASE 13: HTTP PROBING (FIXED)
# ============================================================
def load_vhosts_from_phase12(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    files = glob.glob(os.path.join(target_dir, "phase_12_vhosts_*.json"))
    if not files:
        return []
    best_data = []
    best_file = None
    for f in files:
        try:
            with open(f, "r") as fp:
                data = json.load(fp)
                if isinstance(data, list) and len(data) > len(best_data):
                    best_data = data
                    best_file = f
        except:
            pass
    if best_file:
        print(f"{Fore.CYAN}[*] Using vhosts file: {best_file} ({len(best_data)} hosts){Fore.RESET}")
    return best_data
def phase_13_http_probe(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_13_http_probe")
    if not latest:
        return []
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
    return []

def fingerprint_tech(text, server_header):
    combined = (text or '') + ' ' + (server_header or '')
    tech = {}
    for category, patterns in TECH_RULES.items():
        tech[category] = []
        for name, pattern in patterns.items():
            if pattern.search(combined):
                tech[category].append(name)
    return tech

def load_probe_results(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_13_http_probe")
    if not latest:
        return []
    with open(latest, "r") as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
    return []
def phase_14_tech_fingerprint(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 14: Tech Stack Fingerprinting for {domain}{Fore.RESET}")
    probes = load_probe_results(domain, output_dir)
    if not probes:
        print(f"{Fore.RED}[!] No probe results found. Run Phase 13 first.{Fore.RESET}")
        save_output(domain, "phase_14_tech_fingerprint", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Fingerprinting {len(probes)} hosts...{Fore.RESET}")
    results = []
    for probe in probes:
        vhost = probe.get('vhost', {})
        host = vhost.get('host', 'unknown')
        url = vhost.get('url', '')
        status = probe.get('status', 0)
        server = probe.get('server', '')
        title = probe.get('title', '')
        tech = fingerprint_tech("", server)
        if url.endswith('.php') or '.php?' in url:
            tech.setdefault('language', []).append('php')
        if url.endswith('.aspx') or '.aspx?' in url:
            tech.setdefault('language', []).append('dotnet')
        if url.endswith('.jsp') or '.jsp?' in url:
            tech.setdefault('language', []).append('java')
        if title:
            if 'wordpress' in title.lower():
                tech.setdefault('cms', []).append('wordpress')
            if 'drupal' in title.lower():
                tech.setdefault('cms', []).append('drupal')
            if 'shopify' in title.lower():
                tech.setdefault('cms', []).append('shopify')
        for category in tech:
            tech[category] = list(set(tech[category]))
        results.append({"host": host, "url": url, "status": status, "server": server, "title": title, "tech_stack": tech})
    if results:
        save_output(domain, "phase_14_tech_fingerprint", results, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 14 complete (fingerprinted {len(results)} hosts).{Fore.RESET}")
        for r in results[:10]:
            tech_summary = []
            for cat, items in r['tech_stack'].items():
                if items:
                    tech_summary.append(f"{cat}: {', '.join(items)}")
            if tech_summary:
                print(f"{Fore.CYAN}  - {r['host']} ({', '.join(tech_summary)}){Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}  - {r['host']} (No tech detected){Fore.RESET}")
        if len(results) > 10:
            print(f"{Fore.YELLOW}  ... and {len(results)-10} more.{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No tech detected.{Fore.RESET}")
        save_output(domain, "phase_14_tech_fingerprint", [], output_dir)
    return results

# ============================================================
# PHASE 15: CONFIRMED SUBDOMAIN TAKEOVER
# ============================================================
def load_takeover_risks(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_07_takeover_risks")
    if not latest:
        return []
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
    return []

def confirm_takeover(subdomain, cname):
    url = f"http://{subdomain}"
    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent": "MUGEI-Recon/1.0"})
        status = resp.status_code
        text = resp.text.lower()
        patterns = ["nosuchbucket", "the specified bucket does not exist", "there is no app configured", "404 not found", "repository not found", "page not found", "404 - page not found"]
        for pat in patterns:
            if pat in text:
                return True, status, text[:200]
        if status == 404:
            return True, status, "HTTP 404 Not Found"
    except:
        pass
    return False, None, None

def phase_15_takeover_confirmed(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 15: Confirmed Subdomain Takeover for {domain}{Fore.RESET}")
    risks = load_takeover_risks(domain, output_dir)
    if not risks:
        print(f"{Fore.YELLOW}[!] No takeover risks found. Run Phase 7 first.{Fore.RESET}")
        save_output(domain, "phase_15_takeover_confirmed", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Checking {len(risks)} potential takeovers...{Fore.RESET}")
    confirmed = []
    for entry in risks:
        sub = entry.get('subdomain')
        cname = entry.get('cname')
        if not sub or not cname:
            continue
        print(f"{Fore.CYAN}[*] Checking {sub} -> {cname}{Fore.RESET}")
        is_takeover, status, proof = confirm_takeover(sub, cname)
        if is_takeover:
            confirmed.append({"subdomain": sub, "cname": cname, "status": status, "proof": proof})
            print(f"{Fore.RED}[!] CONFIRMED TAKEOVER: {sub} -> {cname} ({status}){Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] {sub} is not vulnerable.{Fore.RESET}")
    if confirmed:
        save_output(domain, "phase_15_takeover_confirmed", confirmed, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 15 complete (found {len(confirmed)} confirmed takeovers).{Fore.RESET}")
    else:
        print(f"{Fore.GREEN}[✅] No confirmed takeovers found.{Fore.RESET}")
        save_output(domain, "phase_15_takeover_confirmed", [], output_dir)
    return confirmed

# ============================================================
# PHASE 16: NON-INTRUSIVE CVE RECON
# ============================================================
def load_tech_data(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_14_tech_fingerprint")
    if not latest:
        return []
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
    return []

def phase_16_cve_recon(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 16: Non-Intrusive CVE Recon for {domain}{Fore.RESET}")
    tech_data = load_tech_data(domain, output_dir)
    if not tech_data:
        print(f"{Fore.YELLOW}[!] No tech data found. Run Phase 14 first.{Fore.RESET}")
        save_output(domain, "phase_16_cve_recon", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Matching CVEs against detected tech stacks...{Fore.RESET}")
    results = []
    for entry in tech_data:
        host = entry.get('host', 'unknown')
        tech_stack = entry.get('tech_stack', {})
        cves_found = {}
        for category, technologies in tech_stack.items():
            for tech in technologies:
                tech_lower = tech.lower()
                if tech_lower in CVE_DB:
                    cves_found[tech] = CVE_DB[tech_lower]
        if cves_found:
            results.append({"host": host, "cves": cves_found})
    if not results:
        print(f"{Fore.YELLOW}[!] No CVEs found for detected technologies.{Fore.RESET}")
        save_output(domain, "phase_16_cve_recon", [], output_dir)
        return []
    print(f"{Fore.GREEN}[+] Found potential CVEs for {len(results)} hosts.{Fore.RESET}")
    for r in results[:10]:
        host = r['host']
        cves = r['cves']
        print(f"{Fore.CYAN}  - {host}:{Fore.RESET}")
        for tech, cve_list in cves.items():
            print(f"{Fore.YELLOW}      {tech} -> {len(cve_list)} CVEs{Fore.RESET}")
            for cve in cve_list[:3]:
                print(f"        - {cve['id']} ({cve['severity']}): {cve['description']}")
            if len(cve_list) > 3:
                print(f"        ... and {len(cve_list)-3} more.")
    if len(results) > 10:
        print(f"{Fore.YELLOW}  ... and {len(results)-10} more hosts.{Fore.RESET}")
    save_output(domain, "phase_16_cve_recon", results, output_dir)
    return results

# ============================================================
# PHASE 17: CORS / GRAPHQL / FAVICON PIVOTING
# ============================================================
def load_probe_urls(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_13_http_probe")
    if not latest:
        return []
    urls = []
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            for entry in data:
                vhost = entry.get('vhost', {})
                url = vhost.get('url')
                host = vhost.get('host')
                if url and host:
                    urls.append({"url": url, "host": host})
    return urls

async def check_cors(session, url, host, timeout=3):
    headers = {"Host": host, "Origin": "https://evil.com", "User-Agent": "MUGEI-Recon/1.0"}
    try:
        async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
            acao = resp.headers.get('Access-Control-Allow-Origin')
            if acao == '*':
                return {"cors": "wildcard", "origin_reflected": False}
            elif acao and 'evil.com' in acao:
                return {"cors": "reflected", "origin_reflected": True}
    except:
        pass
    return None

async def check_graphql(session, base_url, host, timeout=3):
    paths = ["/graphql", "/v1/graphql", "/api/graphql", "/gql", "/graphiql", "/playground"]
    found = []
    for path in paths:
        url = base_url.rstrip('/') + path
        headers = {"Host": host, "User-Agent": "MUGEI-Recon/1.0", "Content-Type": "application/json"}
        intro_query = '{"query":"query { __schema { types { name } } }"}'
        try:
            async with session.post(url, headers=headers, data=intro_query, timeout=timeout, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if 'data' in data and '__schema' in data.get('data', {}):
                        found.append({"path": path, "introspection": True, "types": len(data['data']['__schema']['types'])})
                    else:
                        found.append({"path": path, "introspection": False})
                elif resp.status in [200, 400, 405]:
                    found.append({"path": path, "introspection": False})
        except:
            pass
    return found

async def get_favicon(session, base_url, host, timeout=3):
    url = base_url.rstrip('/') + "/favicon.ico"
    headers = {"Host": host, "User-Agent": "MUGEI-Recon/1.0"}
    try:
        async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.read()
                md5 = hashlib.md5(data).hexdigest()
                return {"url": url, "md5": md5}
    except:
        pass
    return None

async def scan_phase17_items(items):
    sem = asyncio.Semaphore(PROBE_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=PROBE_CONCURRENT, limit_per_host=PROBE_CONCURRENT, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def process_one(item):
            url = item['url']; host = item['host']; res = {"url": url, "host": host}
            cors_res = await check_cors(session, url, host)
            if cors_res: res['cors'] = cors_res
            gql_res = await check_graphql(session, url, host)
            if gql_res: res['graphql'] = gql_res
            fav_res = await get_favicon(session, url, host)
            if fav_res: res['favicon'] = fav_res
            return res if len(res) > 2 else None
        tasks = [process_one(item) for item in items]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

def phase_17_cors_graphql_favicon(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 17: CORS / GraphQL / Favicon for {domain}{Fore.RESET}")
    items = load_probe_urls(domain, output_dir)
    if not items:
        print(f"{Fore.YELLOW}[!] No live URLs found. Run Phase 13 first.{Fore.RESET}")
        save_output(domain, "phase_17_cors_graphql_favicon", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Checking {len(items)} hosts...{Fore.RESET}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    found = loop.run_until_complete(scan_phase17_items(items))
    loop.close()
    if found:
        fav_hashes = []
        for r in found:
            if 'favicon' in r:
                fav_hashes.append(r['favicon']['md5'])
        if fav_hashes:
            shodan_file = os.path.join(output_dir, domain, f"{domain}_favicon_hashes.txt")
            with open(shodan_file, 'w') as f:
                for h in fav_hashes:
                    f.write(h + "\n")
            print(f"{Fore.CYAN}[*] Favicon hashes saved to {shodan_file}{Fore.RESET}")
        save_output(domain, "phase_17_cors_graphql_favicon", found, output_dir)
        print(f"{Fore.GREEN}[✅] Phase 17 complete (found {len(found)} hosts).{Fore.RESET}")
        for r in found[:10]:
            summary = []
            if 'cors' in r: summary.append(f"CORS: {r['cors']['cors']}")
            if 'graphql' in r: summary.append(f"GraphQL: {len(r['graphql'])} endpoints")
            if 'favicon' in r: summary.append(f"Favicon: {r['favicon']['md5']}")
            print(f"{Fore.CYAN}  - {r['host']} ({', '.join(summary)}){Fore.RESET}")
        if len(found) > 10:
            print(f"{Fore.YELLOW}  ... and {len(found)-10} more.{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] No findings.{Fore.RESET}")
        save_output(domain, "phase_17_cors_graphql_favicon", [], output_dir)
    return found

# ============================================================
# PHASE 18: WAYBACK & HISTORICAL URLS
# ============================================================
def check_waymore():
    return shutil.which('waymore') is not None

def run_waymore(domain, output_file):
    print(f"{Fore.CYAN}[*] Running waymore (primary engine)...{Fore.RESET}")
    cmd = f"waymore -i {domain} -mode U -oU {output_file} -ow -v"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return True
        else:
            print(f"{Fore.RED}[!] waymore error: {result.stderr}{Fore.RESET}")
            return False
    except Exception as e:
        print(f"{Fore.RED}[!] waymore execution failed: {e}{Fore.RESET}")
        return False

def run_waybackurls(domain):
    try:
        result = subprocess.run(["waybackurls", domain], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
    except:
        pass
    return []

def run_gau(domain):
    try:
        result = subprocess.run(["gau", "--subdomains", domain], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
    except:
        pass
    return []

def fetch_waybackapi(domain):
    urls = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[1:]:
                if entry:
                    urls.add(entry[0])
    except:
        pass
    return urls

def fetch_otx(domain):
    urls = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get('url_list', []):
                if 'url' in entry:
                    urls.add(entry['url'])
    except:
        pass
    return urls

def phase_18_historical_urls(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 18: Wayback & Historical URLs for {domain}{Fore.RESET}")
    all_urls = set()
    if check_waymore():
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as tmp:
            tmp_path = tmp.name
        if run_waymore(domain, tmp_path):
            try:
                with open(tmp_path, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        url = line.strip()
                        if url:
                            all_urls.add(url)
                print(f"{Fore.GREEN}[+] waymore found {len(all_urls)} URLs.{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading waymore output: {e}{Fore.RESET}")
            os.unlink(tmp_path)
        else:
            print(f"{Fore.YELLOW}[!] waymore failed. Falling back to other tools.{Fore.RESET}")
    if not all_urls:
        wb_urls = run_waybackurls(domain)
        if wb_urls:
            all_urls.update(wb_urls)
            print(f"{Fore.GREEN}[+] waybackurls found {len(wb_urls)} URLs.{Fore.RESET}")
        gau_urls = run_gau(domain)
        if gau_urls:
            all_urls.update(gau_urls)
            print(f"{Fore.GREEN}[+] gau found {len(gau_urls)} URLs.{Fore.RESET}")
        if not all_urls:
            print(f"{Fore.YELLOW}[*] Falling back to Wayback API...{Fore.RESET}")
            api_urls = fetch_waybackapi(domain)
            if api_urls:
                all_urls.update(api_urls)
                print(f"{Fore.GREEN}[+] Wayback API found {len(api_urls)} URLs.{Fore.RESET}")
            print(f"{Fore.YELLOW}[*] Falling back to OTX API...{Fore.RESET}")
            otx_urls = fetch_otx(domain)
            if otx_urls:
                all_urls.update(otx_urls)
                print(f"{Fore.GREEN}[+] OTX found {len(otx_urls)} URLs.{Fore.RESET}")
    all_urls = sorted(list(all_urls))
    if not all_urls:
        print(f"{Fore.YELLOW}[!] No historical URLs found.{Fore.RESET}")
        save_output(domain, "phase_18_historical_urls", [], output_dir)
        return []
    print(f"{Fore.GREEN}[+] Total unique historical URLs found: {len(all_urls)}{Fore.RESET}")
    for u in all_urls[:10]:
        print(f"{Fore.CYAN}  - {u}{Fore.RESET}")
    if len(all_urls) > 10:
        print(f"{Fore.YELLOW}  ... and {len(all_urls)-10} more.{Fore.RESET}")
    save_output(domain, "phase_18_historical_urls", all_urls, output_dir)
    return all_urls

# ============================================================
# PHASE 19: JAVASCRIPT DEEP DIVE (DEEP COVERAGE)
# ============================================================
def load_phase13_urls(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_13_http_probe")
    if not latest:
        return []
    urls = []
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            for entry in data:
                vhost = entry.get('vhost', {})
                url = vhost.get('url')
                if url:
                    urls.append(url)
    return urls

def load_phase18_urls(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_18_historical_urls")
    if not latest:
        return []
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
    return []

def extract_js_from_html(html, base_url):
    js_urls = []
    inline_scripts = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                if src.startswith('//'):
                    src = 'https:' + src
                elif src.startswith('/'):
                    src = base_url.rstrip('/') + src
                js_urls.append(src)
        for script in soup.find_all('script', src=False):
            if script.string:
                inline_scripts.append(script.string)
    except:
        pass
    return js_urls, inline_scripts

async def fetch_html_for_js(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            if resp.status == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                return await resp.text()
    except:
        pass
    return None

async def fetch_and_parse_js(session, url, sem, is_inline=False, content=None):
    async with sem:
        if is_inline and content:
            js_content = content
        else:
            try:
                async with session.get(url, timeout=JS_TIMEOUT, ssl=False) as resp:
                    if resp.status == 200:
                        js_content = await resp.text()
                    else:
                        return None
            except:
                return None
        findings = {"url": url if not is_inline else "INLINE_SCRIPT", "endpoints": [], "secrets": [], "ips": [], "emails": [], "parameters": []}
        endpoints = []
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for m in matches:
                if isinstance(m, tuple): m = m[0]
                if m:
                    m = m.strip('"\'')
                    if not m.startswith('//') and not m.startswith('http'):
                        endpoints.append(m)
        findings['endpoints'] = list(set(endpoints))
        secrets = []
        for pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, js_content)
            for m in matches:
                if len(m) > 8:
                    secrets.append(m)
        findings['secrets'] = list(set(secrets))
        ips = re.findall(IP_PATTERN, js_content)
        findings['ips'] = list(set(ips))
        emails = re.findall(EMAIL_PATTERN, js_content)
        emails = [e for e in emails if not e.endswith('.png') and not e.endswith('.jpg')]
        findings['emails'] = list(set(emails))
        params = re.findall(PARAM_PATTERN, js_content)
        params += re.findall(PARAM_JSON_PATTERN, js_content)
        findings['parameters'] = list(set(params))
        map_match = re.search(r'//# sourceMappingURL=(.+)$', js_content, re.MULTILINE)
        if map_match:
            findings['sourcemap'] = map_match.group(1).strip()
        return findings

async def run_js_deep_async(live_urls, hist_urls):
    results = []
    sem = asyncio.Semaphore(JS_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=JS_CONCURRENT, limit_per_host=JS_CONCURRENT, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        js_urls_to_fetch = set()
        inline_contents = []
        print(f"{Fore.CYAN}[*] Deep crawling {len(live_urls)} live pages for JS...{Fore.RESET}")
        for url in live_urls[:50]:
            html = await fetch_html_for_js(session, url)
            if html:
                js_urls, inline_scripts = extract_js_from_html(html, url)
                js_urls_to_fetch.update(js_urls)
                inline_contents.extend(inline_scripts)
        for u in hist_urls:
            if '.js' in u.lower() or '.mjs' in u.lower():
                js_urls_to_fetch.add(u)
        js_urls_to_fetch = list(js_urls_to_fetch)[:2000]
        print(f"{Fore.CYAN}[*] Found {len(js_urls_to_fetch)} unique JS files.{Fore.RESET}")
        print(f"{Fore.CYAN}[*] Found {len(inline_contents)} inline script blocks.{Fore.RESET}")
        tasks = []
        for url in js_urls_to_fetch:
            tasks.append(fetch_and_parse_js(session, url, sem))
        for content in inline_contents[:500]:
            tasks.append(fetch_and_parse_js(session, "INLINE", sem, True, content))
        chunk_size = 100
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i+chunk_size]
            chunk_results = await asyncio.gather(*chunk)
            for r in chunk_results:
                if r:
                    results.append(r)
            print(f"{Fore.CYAN}[*] Processed {min(i+chunk_size, len(tasks))}/{len(tasks)} JS items{Fore.RESET}")
    return results

def phase_19_js_deep_dive(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 19: JavaScript Deep Dive (Deep Coverage) for {domain}{Fore.RESET}")
    live_urls = load_phase13_urls(domain, output_dir)
    hist_urls = load_phase18_urls(domain, output_dir)
    if not live_urls and not hist_urls:
        print(f"{Fore.YELLOW}[!] No URLs found. Run Phases 13 and 18 first.{Fore.RESET}")
        save_output(domain, "phase_19_js_extracts", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Live URLs: {len(live_urls)} | Historical URLs: {len(hist_urls)}{Fore.RESET}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(run_js_deep_async(live_urls, hist_urls))
    loop.close()
    if not results:
        print(f"{Fore.YELLOW}[!] No data extracted from JS files.{Fore.RESET}")
        save_output(domain, "phase_19_js_extracts", [], output_dir)
        return []
    print(f"{Fore.GREEN}[+] Extracted data from {len(results)} JS items (incl. inline scripts).{Fore.RESET}")
    total_endpoints = sum(len(r['endpoints']) for r in results)
    total_secrets = sum(len(r['secrets']) for r in results)
    total_ips = sum(len(r['ips']) for r in results)
    total_emails = sum(len(r['emails']) for r in results)
    total_params = sum(len(r['parameters']) for r in results)
    print(f"{Fore.CYAN}  - Endpoints: {total_endpoints}{Fore.RESET}")
    print(f"{Fore.RED}  - Secrets: {total_secrets}{Fore.RESET}")
    print(f"{Fore.GREEN}  - Internal IPs: {total_ips}{Fore.RESET}")
    print(f"{Fore.MAGENTA}  - Emails: {total_emails}{Fore.RESET}")
    print(f"{Fore.YELLOW}  - Parameters: {total_params}{Fore.RESET}")
    save_output(domain, "phase_19_js_extracts", results, output_dir)
    return results

# ============================================================
# PHASE 20: JS SOURCEMAP EXTRACTION
# ============================================================
def load_js_files_with_sourcemaps(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_19_js_extracts")
    if not latest:
        return []
    with open(latest, 'r') as f:
        data = json.load(f)
        if not isinstance(data, list):
            return []
    js_files = []
    for entry in data:
        url = entry.get('url')
        sourcemap = entry.get('sourcemap')
        if sourcemap:
            js_files.append({"url": url, "sourcemap": sourcemap})
    return js_files

async def fetch_sourcemap(session, base_url, sourcemap_ref, sem):
    async with sem:
        if sourcemap_ref.startswith('//'):
            map_url = 'https:' + sourcemap_ref
        elif sourcemap_ref.startswith('/'):
            from urllib.parse import urljoin
            map_url = urljoin(base_url, sourcemap_ref) if base_url else sourcemap_ref
        else:
            map_url = sourcemap_ref
        try:
            async with session.get(map_url, timeout=MAP_TIMEOUT, ssl=False) as resp:
                if resp.status == 200:
                    map_data = await resp.text()
                    try:
                        map_json = json.loads(map_data)
                        sources = map_json.get('sources', [])
                        sources_content = map_json.get('sourcesContent', [])
                        if not sources_content:
                            return None
                        extracted = []
                        for src, content in zip(sources, sources_content):
                            if len(content) > 1000000:
                                continue
                            extracted.append({"file": src, "content": content})
                        return {"map_url": map_url, "sources": extracted}
                    except json.JSONDecodeError:
                        return None
        except:
            pass
    return None

async def run_sourcemap_async(js_files):
    results = []
    sem = asyncio.Semaphore(MAP_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=MAP_CONCURRENT, limit_per_host=MAP_CONCURRENT, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for item in js_files:
            base_url = item.get('url')
            sourcemap = item.get('sourcemap')
            tasks.append(fetch_sourcemap(session, base_url, sourcemap, sem))
        chunk_size = 50
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i+chunk_size]
            chunk_results = await asyncio.gather(*chunk)
            for r in chunk_results:
                if r:
                    results.append(r)
            print(f"{Fore.CYAN}[*] Processed {min(i+chunk_size, len(tasks))}/{len(tasks)} sourcemaps{Fore.RESET}")
    return results

def phase_20_sourcemap_extraction(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 20: JS Sourcemap Extraction for {domain}{Fore.RESET}")
    js_files = load_js_files_with_sourcemaps(domain, output_dir)
    if not js_files:
        print(f"{Fore.YELLOW}[!] No sourcemaps found in Phase 19 results.{Fore.RESET}")
        save_output(domain, "phase_20_sourcemaps", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Found {len(js_files)} JS files with sourceMappingURL.{Fore.RESET}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(run_sourcemap_async(js_files))
    loop.close()
    if not results:
        print(f"{Fore.YELLOW}[!] No sourcemaps could be fetched.{Fore.RESET}")
        save_output(domain, "phase_20_sourcemaps", [], output_dir)
        return []
    total_sources = sum(len(r['sources']) for r in results)
    print(f"{Fore.GREEN}[+] Fetched {len(results)} sourcemaps ({total_sources} source files).{Fore.RESET}")
    save_output(domain, "phase_20_sourcemaps", results, output_dir)
    return results

# ============================================================
# PHASE 21: URL FUZZING (DIRECTORY BUSTING)
# ============================================================
def load_base_urls(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    latest = find_latest_file(target_dir, "phase_13_http_probe")
    if not latest:
        return []
    base_urls = set()
    with open(latest, 'r') as f:
        data = json.load(f)
        if isinstance(data, list):
            for entry in data:
                vhost = entry.get('vhost', {})
                url = vhost.get('url')
                if url:
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    base_urls.add(base)
    return list(base_urls)

async def fuzz_one(session, base_url, path, sem):
    url = base_url.rstrip('/') + path
    try:
        async with sem:
            async with session.get(url, timeout=FUZZ_TIMEOUT, ssl=False) as resp:
                if resp.status in [200, 301, 302, 403, 401, 500]:
                    return {"url": url, "status": resp.status, "content_length": len(await resp.text())}
    except:
        pass
    return None

async def run_fuzz_async(base_urls, wordlist):
    results = []
    sem = asyncio.Semaphore(FUZZ_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=FUZZ_CONCURRENT, limit_per_host=FUZZ_CONCURRENT, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for base in base_urls:
            for path in wordlist:
                if not path.startswith('/'):
                    path = '/' + path
                tasks.append(fuzz_one(session, base, path, sem))
        chunk_size = 200
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i+chunk_size]
            chunk_results = await asyncio.gather(*chunk)
            for r in chunk_results:
                if r:
                    results.append(r)
            print(f"{Fore.CYAN}[*] Progress: {min(i+chunk_size, len(tasks))}/{len(tasks)}{Fore.RESET}")
    return results

def phase_21_url_fuzzing(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 21: URL Fuzzing for {domain}{Fore.RESET}")
    base_urls = load_base_urls(domain, output_dir)
    if not base_urls:
        print(f"{Fore.YELLOW}[!] No base URLs found. Run Phase 13 first.{Fore.RESET}")
        save_output(domain, "phase_21_url_fuzzing", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Fuzzing {len(base_urls)} base URLs with {len(FUZZ_WORDLIST)} words...{Fore.RESET}")
    total_checks = len(base_urls) * len(FUZZ_WORDLIST)
    print(f"{Fore.CYAN}[*] Total checks: {total_checks} (Async, {FUZZ_CONCURRENT} concurrent){Fore.RESET}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(run_fuzz_async(base_urls, FUZZ_WORDLIST))
    loop.close()
    if not results:
        print(f"{Fore.YELLOW}[!] No interesting paths found.{Fore.RESET}")
        save_output(domain, "phase_21_url_fuzzing", [], output_dir)
        return []
    print(f"{Fore.GREEN}[+] Found {len(results)} interesting paths.{Fore.RESET}")
    for r in results[:10]:
        status_color = Fore.GREEN if r['status'] == 200 else Fore.YELLOW
        print(f"{status_color}  {r['url']} ({r['status']}){Fore.RESET}")
    if len(results) > 10:
        print(f"{Fore.YELLOW}  ... and {len(results)-10} more.{Fore.RESET}")
    save_output(domain, "phase_21_url_fuzzing", results, output_dir)
    return results

# ============================================================
# PHASE 22: PARAMETER DISCOVERY
# ============================================================
def load_target_urls(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    urls = set()
    latest_13 = find_latest_file(target_dir, "phase_13_http_probe")
    if latest_13:
        with open(latest_13, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    vhost = entry.get('vhost', {})
                    url = vhost.get('url')
                    if url:
                        urls.add(url)
    latest_21 = find_latest_file(target_dir, "phase_21_url_fuzzing")
    if latest_21:
        with open(latest_21, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    url = entry.get('url')
                    status = entry.get('status')
                    if url and status in [200, 301, 302, 403, 401]:
                        urls.add(url)
    return list(urls)

async def check_param(session, url, param, sem):
    base, sep, query = url.partition('?')
    parsed = parse_qs(query)
    parsed[param] = ['test123']
    new_query = urlencode(parsed, doseq=True)
    test_url = f"{base}?{new_query}" if new_query else f"{base}?{param}=test123"
    try:
        async with sem:
            baseline_resp = await session.get(url, timeout=PARAM_TIMEOUT, ssl=False)
            baseline_len = len(await baseline_resp.text())
            baseline_status = baseline_resp.status
            test_resp = await session.get(test_url, timeout=PARAM_TIMEOUT, ssl=False)
            test_len = len(await test_resp.text())
            test_status = test_resp.status
            if test_status != baseline_status or abs(test_len - baseline_len) > (baseline_len * 0.1):
                return {"url": test_url, "param": param, "baseline_status": baseline_status, "test_status": test_status, "diff": abs(test_len - baseline_len)}
    except:
        pass
    return None

async def run_param_async(urls, wordlist):
    results = []
    sem = asyncio.Semaphore(PARAM_CONCURRENT)
    connector = aiohttp.TCPConnector(limit=PARAM_CONCURRENT, limit_per_host=PARAM_CONCURRENT, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for url in urls:
            for param in wordlist:
                tasks.append(check_param(session, url, param, sem))
        chunk_size = 200
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i+chunk_size]
            chunk_results = await asyncio.gather(*chunk)
            for r in chunk_results:
                if r:
                    results.append(r)
            print(f"{Fore.CYAN}[*] Progress: {min(i+chunk_size, len(tasks))}/{len(tasks)}{Fore.RESET}")
    return results

def phase_22_parameter_discovery(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 22: Parameter Discovery for {domain}{Fore.RESET}")
    urls = load_target_urls(domain, output_dir)
    if not urls:
        print(f"{Fore.YELLOW}[!] No URLs found. Run Phases 13 and 21 first.{Fore.RESET}")
        save_output(domain, "phase_22_parameters", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Testing {len(urls)} URLs × {len(PARAM_WORDLIST)} parameters...{Fore.RESET}")
    total_checks = len(urls) * len(PARAM_WORDLIST)
    print(f"{Fore.CYAN}[*] Total checks: {total_checks} (Async, {PARAM_CONCURRENT} concurrent){Fore.RESET}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(run_param_async(urls, PARAM_WORDLIST))
    loop.close()
    if not results:
        print(f"{Fore.YELLOW}[!] No interesting parameters found.{Fore.RESET}")
        save_output(domain, "phase_22_parameters", [], output_dir)
        return []
    print(f"{Fore.GREEN}[+] Found {len(results)} interesting parameters.{Fore.RESET}")
    for r in results[:10]:
        print(f"{Fore.CYAN}  {r['url']} (status: {r['test_status']}, diff: {r['diff']} bytes){Fore.RESET}")
    if len(results) > 10:
        print(f"{Fore.YELLOW}  ... and {len(results)-10} more.{Fore.RESET}")
    save_output(domain, "phase_22_parameters", results, output_dir)
    return results

# ============================================================
# PHASE 23: SCREENSHOT & VISUAL INSPECTION
# ============================================================
def phase_23_screenshots(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 23: Screenshot & Visual Inspection for {domain}{Fore.RESET}")
    target_dir = os.path.join(output_dir, domain)
    latest_13 = find_latest_file(target_dir, "phase_13_http_probe")
    if not latest_13:
        print(f"{Fore.YELLOW}[!] No live URLs found. Run Phase 13 first.{Fore.RESET}")
        save_output(domain, "phase_23_screenshots", [], output_dir)
        return []
    with open(latest_13, 'r') as f:
        data = json.load(f)
        if not isinstance(data, list):
            print(f"{Fore.YELLOW}[!] Invalid data format from Phase 13.{Fore.RESET}")
            save_output(domain, "phase_23_screenshots", [], output_dir)
            return []
    urls = []
    for entry in data:
        vhost = entry.get('vhost', {})
        url = vhost.get('url')
        if url:
            urls.append(url)
    if not urls:
        print(f"{Fore.YELLOW}[!] No URLs to screenshot.{Fore.RESET}")
        save_output(domain, "phase_23_screenshots", [], output_dir)
        return []
    screenshot_dir = os.path.join(output_dir, domain, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    print(f"{Fore.CYAN}[*] Taking screenshots of {len(urls)} URLs...{Fore.RESET}")
    results = []
    gowitness = shutil.which('gowitness')
    if gowitness:
        url_file = os.path.join(target_dir, "screenshot_urls.txt")
        with open(url_file, 'w') as f:
            for url in urls:
                f.write(url + "\n")
        cmd = f"{gowitness} scan file -f {url_file} -P {screenshot_dir} --timeout {SCREENSHOT_TIMEOUT} --no-http"
        try:
            subprocess.run(cmd, shell=True, timeout=600, check=True)
            print(f"{Fore.GREEN}[+] Screenshots taken with gowitness scan file mode.{Fore.RESET}")
            for f in os.listdir(screenshot_dir):
                if f.endswith('.png'):
                    results.append({"url": url, "screenshot": os.path.join(screenshot_dir, f)})
            save_output(domain, "phase_23_screenshots", results, output_dir)
            return results
        except:
            pass
    for url in urls:
        results.append({"url": url, "screenshot": "N/A"})
    save_output(domain, "phase_23_screenshots", results, output_dir)
    print(f"{Fore.GREEN}[✅] Phase 23 complete (processed {len(results)} URLs).{Fore.RESET}")
    return results

# ============================================================
# PHASE 24: LIVE VALIDATION & PRIORITIZATION GATE
# ============================================================
def load_all_urls(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    all_urls = set()
    latest_13 = find_latest_file(target_dir, "phase_13_http_probe")
    if latest_13:
        with open(latest_13, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    vhost = entry.get('vhost', {})
                    url = vhost.get('url')
                    if url:
                        all_urls.add(url)
    latest_21 = find_latest_file(target_dir, "phase_21_url_fuzzing")
    if latest_21:
        with open(latest_21, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    url = entry.get('url')
                    if url:
                        all_urls.add(url)
    latest_22 = find_latest_file(target_dir, "phase_22_parameters")
    if latest_22:
        with open(latest_22, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    url = entry.get('url')
                    if url:
                        all_urls.add(url)
    latest_23 = find_latest_file(target_dir, "phase_23_screenshots")
    if latest_23:
        with open(latest_23, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    url = entry.get('url')
                    if url:
                        all_urls.add(url)
    return list(all_urls)

STATIC_EXTS = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.eot', '.ico', '.pdf', '.doc', '.xls', '.ppt', '.zip', '.rar', '.tar', '.gz', '.mp4', '.mp3', '.webm', '.avi', '.mov', '.flv')
HIGH_PRIORITY_PATHS = ['/admin', '/login', '/upload', '/api', '/graphql', '/swagger', '/docs', '/portal', '/dashboard', '/console', '/manage', '/settings', '/profile', '/account', '/signup', '/register', '/auth', '/oauth', '/token', '/file', '/upload', '/image', '/media', '/assets']
HIGH_PRIORITY_TITLES = ['login', 'admin', 'dashboard', 'upload', 'api', 'graphql', 'swagger', 'docs', 'portal', 'console', 'manage', 'settings', 'profile', 'account', 'signup', 'register', 'auth']

def is_static(url):
    lower = url.lower()
    for ext in STATIC_EXTS:
        if lower.endswith(ext):
            return True
    return False

def is_high_priority(url, title=''):
    lower_url = url.lower()
    for pattern in HIGH_PRIORITY_PATHS:
        if pattern in lower_url:
            return True
    if title:
        for keyword in HIGH_PRIORITY_TITLES:
            if keyword in title.lower():
                return True
    return False

def phase_24_live_validation(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 24: Live Validation & Prioritization for {domain}{Fore.RESET}")
    urls = load_all_urls(domain, output_dir)
    if not urls:
        print(f"{Fore.YELLOW}[!] No URLs found. Run Phases 13, 21, 22, 23 first.{Fore.RESET}")
        save_output(domain, "phase_24_live_validation", [], output_dir)
        return []
    print(f"{Fore.CYAN}[*] Validating {len(urls)} URLs...{Fore.RESET}")
    validated = []
    high_priority = []
    static_assets = []
    for url in urls:
        if is_static(url):
            static_assets.append(url)
        else:
            priority = is_high_priority(url)
            entry = {"url": url, "priority": priority}
            validated.append(entry)
            if priority:
                high_priority.append(url)
    print(f"{Fore.GREEN}[+] Total URLs: {len(urls)}")
    print(f"{Fore.CYAN}  - Static assets: {len(static_assets)}")
    print(f"{Fore.YELLOW}  - Non-static: {len(validated)}")
    print(f"{Fore.RED}  - High-priority targets: {len(high_priority)}")
    save_output(domain, "phase_24_live_validation", validated, output_dir)
    shortlist_file = os.path.join(output_dir, domain, f"{domain}_shortlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(shortlist_file, 'w') as f:
        for url in high_priority:
            f.write(url + "\n")
    print(f"{Fore.CYAN}[*] Shortlist saved to {shortlist_file}{Fore.RESET}")
    print(f"{Fore.RED}[!] Top high-priority targets:{Fore.RESET}")
    for url in high_priority[:10]:
        print(f"{Fore.RED}  - {url}{Fore.RESET}")
    if len(high_priority) > 10:
        print(f"{Fore.YELLOW}  ... and {len(high_priority)-10} more.{Fore.RESET}")
    return validated

# ============================================================
# PHASE 25: SOURCE‑BASED DEDUP & NORMALIZATION
# ============================================================
def load_subdomains_all(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    subdomains = set()
    for pattern in ['phase_03_subdomains', 'phase_04_bruteforce', 'phase_05_permutations', 'phase_06_ct_logs']:
        latest = find_latest_file(target_dir, pattern)
        if latest:
            with open(latest, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    subdomains.update(data)
    latest = find_latest_file(target_dir, 'phase_07_dns_takeover')
    if latest:
        with open(latest, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    sub = entry.get('subdomain')
                    if sub:
                        subdomains.add(sub)
    return sorted(subdomains)

def load_ips_all(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    ips = set()
    latest = find_latest_file(target_dir, 'phase_07_dns_takeover')
    if latest:
        with open(latest, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    ip = entry.get('ip')
                    if ip:
                        ips.add(ip)
    latest = find_latest_file(target_dir, 'phase_11_open_ports')
    if latest:
        with open(latest, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict):
                ips.update(data.keys())
    return sorted(ips)

def load_urls_all(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    urls = set()
    for pattern in ['phase_13_http_probe', 'phase_18_historical_urls', 'phase_21_url_fuzzing', 'phase_22_parameters', 'phase_23_screenshots', 'phase_24_live_validation']:
        latest = find_latest_file(target_dir, pattern)
        if latest:
            with open(latest, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            url = entry.get('url')
                            if url:
                                urls.add(url)
                        elif isinstance(entry, str):
                            if entry.startswith(('http://', 'https://')):
                                urls.add(entry)
    latest = find_latest_file(target_dir, 'phase_12_vhosts')
    if latest:
        with open(latest, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    url = entry.get('url')
                    if url:
                        urls.add(url)
    normalized = set()
    for url in urls:
        norm = normalize_url(url)
        if norm:
            normalized.add(norm)
    return sorted(normalized)

def phase_25_dedup_normalize(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 25: Source‑Based Dedup & Normalization for {domain}{Fore.RESET}")
    subdomains = load_subdomains_all(domain, output_dir)
    ips = load_ips_all(domain, output_dir)
    urls = load_urls_all(domain, output_dir)
    print(f"{Fore.CYAN}[*] Aggregated:")
    print(f"  - Unique subdomains: {len(subdomains)}")
    print(f"  - Unique IPs: {len(ips)}")
    print(f"  - Unique URLs (normalized): {len(urls)}")
    master = {
        "domain": domain,
        "subdomains": subdomains,
        "ips": ips,
        "urls": urls,
        "total_subdomains": len(subdomains),
        "total_ips": len(ips),
        "total_urls": len(urls)
    }
    save_output(domain, "phase_25_master_dataset", master, output_dir)
    url_txt = os.path.join(output_dir, domain, f"{domain}_all_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(url_txt, 'w') as f:
        for url in urls:
            f.write(url + "\n")
    print(f"{Fore.CYAN}[*] All URLs saved to {url_txt}{Fore.RESET}")
    print(f"{Fore.GREEN}[✅] Phase 25 complete: master dataset built.{Fore.RESET}")
    return master

# ============================================================
# PHASE 26: CYCLIC ENRICHMENT LOOP
# ============================================================
def phase_26_cyclic_enrichment(domain, output_dir, proxy_file=None):
    print(f"{Fore.BLUE}[🔵] Phase 26: Cyclic Enrichment Loop for {domain}{Fore.RESET}")
    print(f"{Fore.YELLOW}[!] This phase re-runs enrichment phases (18-24) only – FAST & CLEAN.{Fore.RESET}")
    print(f"{Fore.YELLOW}[!] Max iterations: {ENRICHMENT_ITERATIONS}{Fore.RESET}")
    
    master = phase_25_dedup_normalize(domain, output_dir)
    initial_subdomains = set(master['subdomains'])
    initial_ips = set(master['ips'])
    initial_urls = set(master['urls'])
    
    all_subdomains = set(initial_subdomains)
    all_ips = set(initial_ips)
    all_urls = set(initial_urls)
    
    no_new_count = 0
    iteration = 1
    
    while iteration <= ENRICHMENT_ITERATIONS and no_new_count < 2:
        print(f"\n{Fore.CYAN}=== Enrichment Iteration {iteration} ==={Fore.RESET}")
        print(f"{Fore.YELLOW}[*] Running enrichment phases (18-24)...{Fore.RESET}")
        phase_18_historical_urls(domain, output_dir)
        phase_19_js_deep_dive(domain, output_dir)
        phase_20_sourcemap_extraction(domain, output_dir)
        phase_21_url_fuzzing(domain, output_dir)
        phase_22_parameter_discovery(domain, output_dir)
        phase_23_screenshots(domain, output_dir)
        phase_24_live_validation(domain, output_dir)
        
        new_master = phase_25_dedup_normalize(domain, output_dir)
        current_subdomains = set(new_master['subdomains'])
        current_ips = set(new_master['ips'])
        current_urls = set(new_master['urls'])
        
        new_subdomains = current_subdomains - all_subdomains
        new_ips = current_ips - all_ips
        new_urls = current_urls - all_urls
        
        all_subdomains.update(current_subdomains)
        all_ips.update(current_ips)
        all_urls.update(current_urls)
        
        print(f"{Fore.GREEN}[+] New assets found (merged):")
        print(f"  - New subdomains: {len(new_subdomains)}")
        print(f"  - New IPs: {len(new_ips)}")
        print(f"  - New URLs: {len(new_urls)}")
        
        if not new_subdomains and not new_ips and not new_urls:
            no_new_count += 1
            print(f"{Fore.YELLOW}[!] No new assets this iteration. ({no_new_count}/2){Fore.RESET}")
        else:
            no_new_count = 0
            merged_master = {
                "domain": domain,
                "subdomains": sorted(all_subdomains),
                "ips": sorted(all_ips),
                "urls": sorted(all_urls),
                "total_subdomains": len(all_subdomains),
                "total_ips": len(all_ips),
                "total_urls": len(all_urls)
            }
            save_output(domain, "phase_26_enriched_iteration", merged_master, output_dir)
        
        iteration += 1
    
    if no_new_count >= 2:
        print(f"\n{Fore.GREEN}[+] Convergence reached: no new assets for 2 iterations. Stopping.{Fore.RESET}")
    else:
        print(f"\n{Fore.YELLOW}[!] Max iterations reached ({ENRICHMENT_ITERATIONS}). Stopping.{Fore.RESET}")
    
    final_master = {
        "domain": domain,
        "subdomains": sorted(all_subdomains),
        "ips": sorted(all_ips),
        "urls": sorted(all_urls),
        "total_subdomains": len(all_subdomains),
        "total_ips": len(all_ips),
        "total_urls": len(all_urls)
    }
    save_output(domain, "phase_26_final_enriched", final_master, output_dir)
    
    master_file = os.path.join(output_dir, domain, f"{domain}_master_enriched_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(master_file, 'w') as f:
        json.dump(final_master, f, indent=2)
    
    print(f"{Fore.CYAN}[*] Final enriched master saved to {master_file}{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Final URL count: {len(all_urls)} (initial: {len(initial_urls)}){Fore.RESET}")
    print(f"{Fore.GREEN}[✅] Phase 26 complete: dataset enriched and preserved.{Fore.RESET}")
    return final_master

# ============================================================
# PHASE 27: REPORT GENERATION
# ============================================================
def phase_27_report(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 27: Report Generation for {domain}{Fore.RESET}")
    master = phase_25_dedup_normalize(domain, output_dir)
    target_dir = os.path.join(output_dir, domain)
    
    tech_data = []
    latest_14 = find_latest_file(target_dir, "phase_14_tech_fingerprint")
    if latest_14:
        with open(latest_14, 'r') as f:
            tech_data = json.load(f)
    
    cve_data = []
    latest_16 = find_latest_file(target_dir, "phase_16_cve_recon")
    if latest_16:
        with open(latest_16, 'r') as f:
            cve_data = json.load(f)
    
    takeover_data = []
    latest_15 = find_latest_file(target_dir, "phase_15_takeover_confirmed")
    if latest_15:
        with open(latest_15, 'r') as f:
            takeover_data = json.load(f)
    
    js_data = []
    latest_19 = find_latest_file(target_dir, "phase_19_js_extracts")
    if latest_19:
        with open(latest_19, 'r') as f:
            js_data = json.load(f)
    
    report = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_subdomains": master['total_subdomains'],
            "total_ips": master['total_ips'],
            "total_urls": master['total_urls'],
            "total_tech_stacks": len(tech_data),
            "total_cves": len(cve_data),
            "total_takeovers": len(takeover_data),
            "total_js_files": len(js_data)
        },
        "subdomains": master['subdomains'],
        "ips": master['ips'],
        "urls": master['urls'][:1000],
        "tech_stacks": tech_data[:100],
        "cves": cve_data[:100],
        "takeovers": takeover_data,
        "js_secrets": js_data[:100]
    }
    
    json_report = os.path.join(output_dir, domain, f"{domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(json_report, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"{Fore.CYAN}[📁] JSON report saved to {json_report}{Fore.RESET}")
    
    md_content = f"""# ANUBIS Recon Report – {domain}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Subdomains:** {master['total_subdomains']}
- **IPs:** {master['total_ips']}
- **URLs:** {master['total_urls']}
- **Tech Stacks:** {len(tech_data)}
- **CVEs:** {len(cve_data)}
- **Takeovers:** {len(takeover_data)}
- **JS Files Extracted:** {len(js_data)}

## Critical Findings
"""
    if takeover_data:
        md_content += "### ⚠️ Subdomain Takeovers\n"
        for t in takeover_data[:10]:
            md_content += f"- `{t['subdomain']}` → {t['cname']} (status: {t['status']})\n"
    if cve_data:
        md_content += "### 🔥 Potential CVEs\n"
        for c in cve_data[:10]:
            md_content += f"- {c['host']}: {c['cves']}\n"
    
    md_content += "\n## Top URLs (first 100)\n"
    for url in master['urls'][:100]:
        md_content += f"- {url}\n"
    
    md_file = os.path.join(output_dir, domain, f"{domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    with open(md_file, 'w') as f:
        f.write(md_content)
    print(f"{Fore.CYAN}[📁] Markdown report saved to {md_file}{Fore.RESET}")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head><title>ANUBIS Report – {domain}</title>
<style>
body {{ font-family: monospace; background: #0a0a0a; color: #00ffcc; padding: 20px; }}
h1, h2 {{ color: #ffd700; }}
ul {{ list-style-type: none; }}
li {{ padding: 4px 0; }}
.critical {{ color: #ff4444; }}
</style>
</head>
<body>
<h1>☥ ANUBIS Recon Report – {domain}</h1>
<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Summary</h2>
<ul>
<li>Subdomains: {master['total_subdomains']}</li>
<li>IPs: {master['total_ips']}</li>
<li>URLs: {master['total_urls']}</li>
<li>Takeovers: {len(takeover_data)}</li>
</ul>
<h2 class="critical">Critical Takeovers</h2>
<ul>
"""
    for t in takeover_data[:10]:
        html_content += f"<li class='critical'>🚨 {t['subdomain']} → {t['cname']} (status: {t['status']})</li>"
    html_content += "</ul></body></html>"
    
    html_file = os.path.join(output_dir, domain, f"{domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(html_file, 'w') as f:
        f.write(html_content)
    print(f"{Fore.CYAN}[📁] HTML report saved to {html_file}{Fore.RESET}")
    
    print(f"{Fore.GREEN}[✅] Phase 27 complete: report generated.{Fore.RESET}")
    return report

# ============================================================
# PHASE 28: AUDIT & LOGGING TRAIL
# ============================================================
def phase_28_audit_log(domain, output_dir):
    print(f"{Fore.BLUE}[🔵] Phase 28: Audit & Logging Trail for {domain}{Fore.RESET}")
    target_dir = os.path.join(output_dir, domain)
    files = []
    if os.path.exists(target_dir):
        for f in os.listdir(target_dir):
            if f.endswith('.json') or f.endswith('.txt') or f.endswith('.png'):
                filepath = os.path.join(target_dir, f)
                with open(filepath, 'rb') as fp:
                    file_hash = hashlib.sha256(fp.read()).hexdigest()
                files.append({
                    "file": f,
                    "sha256": file_hash,
                    "size": os.path.getsize(filepath),
                    "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
    audit_data = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "total_files": len(files),
        "files": files
    }
    save_output(domain, "phase_28_audit_log", audit_data, output_dir)
    log_txt = os.path.join(target_dir, f"{domain}_audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(log_txt, 'w') as f:
        f.write(f"ANUBIS Audit Log for {domain}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Total files: {len(files)}\n\n")
        for file_info in files:
            f.write(f"{file_info['file']} | SHA256: {file_info['sha256']} | Size: {file_info['size']} bytes | Modified: {file_info['modified']}\n")
    print(f"{Fore.CYAN}[📁] Audit log saved to {log_txt}{Fore.RESET}")
    print(f"{Fore.GREEN}[✅] Phase 28 complete: audit trail recorded.{Fore.RESET}")
    return audit_data

# ============================================================
# PHASE 29: OPTIONAL ACTIVE EXPLOIT SCAN (NUCLEI - FIXED)
# ============================================================
def phase_29_nuclei_scan(domain, output_dir, enable=False):
    if not enable:
        print(f"{Fore.YELLOW}[!] Phase 29 skipped: Nuclei scan is disabled by default.{Fore.RESET}")
        print(f"{Fore.YELLOW}[!] Pass --nuclei flag to enable active exploit scanning.{Fore.RESET}")
        return []
    
    print(f"{Fore.RED}[⚠️] WARNING: Nuclei scan sends real exploit payloads (LFI, SQLi, RCE).{Fore.RESET}")
    print(f"{Fore.RED}[⚠️] This may trigger WAF, get your IP banned, and violate bug bounty rules.{Fore.RESET}")
    print(f"{Fore.RED}[⚠️] Only run on targets you own or have explicit permission to test.{Fore.RESET}")
    print(f"{Fore.YELLOW}[!] Continuing in 3 seconds...{Fore.RESET}")
    time.sleep(3)
    
    print(f"{Fore.BLUE}[🔵] Phase 29: Nuclei Active Scan for {domain}{Fore.RESET}")
    target_dir = os.path.join(output_dir, domain)
    latest_24 = find_latest_file(target_dir, "phase_24_live_validation")
    urls = []
    if latest_24:
        with open(latest_24, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    if entry.get('priority'):
                        urls.append(entry.get('url'))
    if not urls:
        latest_25 = find_latest_file(target_dir, "phase_25_master_dataset")
        if latest_25:
            with open(latest_25, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    urls = data.get('urls', [])[:100]
    if not urls:
        print(f"{Fore.YELLOW}[!] No URLs found for Nuclei scan.{Fore.RESET}")
        return []
    
    print(f"{Fore.CYAN}[*] Running Nuclei on {len(urls)} URLs (critical, high, medium severity)...{Fore.RESET}")
    url_file = os.path.join(target_dir, "nuclei_targets.txt")
    with open(url_file, 'w') as f:
        for url in urls:
            f.write(url + "\n")
    
    output_file = os.path.join(target_dir, f"nuclei_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    # Try JSON flags in order
    for flag in ["-jsonl", "-json"]:
        cmd = f"nuclei -l {url_file} -silent -severity critical,high,medium -timeout 5 -c 50 {flag} -o {output_file}"
        try:
            result = subprocess.run(cmd, shell=True, timeout=600, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Nuclei scan completed with {flag}. Results saved to {output_file}{Fore.RESET}")
                break
            else:
                print(f"{Fore.YELLOW}[!] Nuclei with {flag} failed (RC={result.returncode}). Trying next...{Fore.RESET}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] Nuclei scan timed out after 10 minutes.{Fore.RESET}")
            return []
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest{Fore.RESET}")
            return []
    else:
        # Fallback: no JSON flag (raw output)
        cmd = f"nuclei -l {url_file} -silent -severity critical,high,medium -timeout 5 -c 50 -o {output_file}"
        try:
            subprocess.run(cmd, shell=True, timeout=600, check=True)
            print(f"{Fore.GREEN}[+] Nuclei scan completed (raw output). Results saved to {output_file}{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}[!] Nuclei scan failed: {e}{Fore.RESET}")
            return []
    
    # Try to parse JSON if possible
    try:
        with open(output_file, 'r') as f:
            content = f.read().strip()
            if content.startswith('[') or content.startswith('{'):
                results = json.loads(content)
                if isinstance(results, (list, dict)):
                    save_output(domain, "phase_29_nuclei_results", results, output_dir)
                    print(f"{Fore.GREEN}[✅] Phase 29 complete (found {len(results) if isinstance(results, list) else 'some'} results).{Fore.RESET}")
                    return results
    except:
        pass
    
    # If not JSON, save as text
    txt_output = output_file.replace('.json', '.txt')
    if os.path.exists(output_file):
        os.rename(output_file, txt_output)
        print(f"{Fore.YELLOW}[!] Output saved as text (not JSON): {txt_output}{Fore.RESET}")
    return []

# ============================================================
# PHASE DISPATCHER
# ============================================================
PHASE_MAP = {
    1: phase_01_whois,
    2: phase_02_asn,
    3: phase_03_subdomains,
    4: phase_04_bruteforce,
    5: phase_05_permutations,
    6: phase_06_ct_logs,
    7: phase_07_takeover,
    8: phase_08_cloud_buckets,
    9: phase_09_github_search,
    10: phase_10_emails,
    11: phase_11_port_scan,
    12: phase_12_vhosts,
    13: phase_13_http_probe,
    14: phase_14_tech_fingerprint,
    15: phase_15_takeover_confirmed,
    16: phase_16_cve_recon,
    17: phase_17_cors_graphql_favicon,
    18: phase_18_historical_urls,
    19: phase_19_js_deep_dive,
    20: phase_20_sourcemap_extraction,
    21: phase_21_url_fuzzing,
    22: phase_22_parameter_discovery,
    23: phase_23_screenshots,
    24: phase_24_live_validation,
    25: phase_25_dedup_normalize,
    26: phase_26_cyclic_enrichment,
    27: phase_27_report,
    28: phase_28_audit_log,
    29: phase_29_nuclei_scan,
}

# ============================================================
# MAIN FUNCTION
# ============================================================
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="ANUBIS: Shadow Recon Engine")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--phase", type=int, help="Run only a specific phase (1-29) for testing")
    parser.add_argument("--github-token", help="GitHub API token (optional, increases rate limit)")
    parser.add_argument("--proxy-file", help="File containing proxies (one per line, format: http://ip:port)")
    parser.add_argument("--nuclei", action="store_true", help="Enable active Nuclei exploit scan (Phase 29)")
    args = parser.parse_args()
    domain = args.domain
    output_dir = args.output
    phase = args.phase
    token = args.github_token
    proxy_file = args.proxy_file
    nuclei_enabled = args.nuclei

    print(f"\n{Fore.GREEN}[🎯] Target: {domain}{Fore.RESET}")
    os.makedirs(output_dir, exist_ok=True)
    
    if phase:
        print(f"{Fore.YELLOW}[⚡] Running ONLY Phase {phase} (testing mode).{Fore.RESET}\n")
        if phase in PHASE_MAP:
            if phase == 9:
                PHASE_MAP[phase](domain, output_dir, token)
            elif phase == 12 or phase == 26:
                PHASE_MAP[phase](domain, output_dir, proxy_file)
            elif phase == 29:
                PHASE_MAP[phase](domain, output_dir, nuclei_enabled)
            else:
                PHASE_MAP[phase](domain, output_dir)
            print(f"\n{Fore.GREEN}[🏛️] Phase {phase} completed.{Fore.RESET}")
        else:
            print(f"{Fore.RED}[!] Phase {phase} not yet implemented.{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[⚡] Running FULL pipeline (Phases 1-29).{Fore.RESET}\n")
        phase_01_whois(domain, output_dir)
        phase_02_asn(domain, output_dir)
        phase_03_subdomains(domain, output_dir)
        phase_04_bruteforce(domain, output_dir)
        phase_05_permutations(domain, output_dir)
        phase_06_ct_logs(domain, output_dir)
        phase_07_takeover(domain, output_dir)
        phase_08_cloud_buckets(domain, output_dir)
        phase_09_github_search(domain, output_dir, token)
        phase_10_emails(domain, output_dir)
        phase_11_port_scan(domain, output_dir)
        phase_12_vhosts(domain, output_dir, proxy_file)
        phase_13_http_probe(domain, output_dir)
        phase_14_tech_fingerprint(domain, output_dir)
        phase_15_takeover_confirmed(domain, output_dir)
        phase_16_cve_recon(domain, output_dir)
        phase_17_cors_graphql_favicon(domain, output_dir)
        phase_18_historical_urls(domain, output_dir)
        phase_19_js_deep_dive(domain, output_dir)
        phase_20_sourcemap_extraction(domain, output_dir)
        phase_21_url_fuzzing(domain, output_dir)
        phase_22_parameter_discovery(domain, output_dir)
        phase_23_screenshots(domain, output_dir)
        phase_24_live_validation(domain, output_dir)
        phase_25_dedup_normalize(domain, output_dir)
        phase_26_cyclic_enrichment(domain, output_dir, proxy_file)
        phase_27_report(domain, output_dir)
        phase_28_audit_log(domain, output_dir)
        
        # Interactive prompt for Phase 29
        print(f"\n{Fore.YELLOW}[?] Phase 29: Active Nuclei Exploit Scan is optional.{Fore.RESET}")
        print(f"{Fore.RED}[⚠️] WARNING: Sends real payloads (LFI, SQLi, RCE). May trigger WAF or violate bug bounty rules.{Fore.RESET}")
        response = input(f"{Fore.CYAN}Continue to Phase 29? (y/N): {Fore.RESET}").strip().lower()
        if response in ['y', 'yes']:
            phase_29_nuclei_scan(domain, output_dir, True)
        else:
            print(f"{Fore.YELLOW}[!] Skipping Phase 29 (Nuclei scan).{Fore.RESET}")
        
        print(f"\n{Fore.GREEN}[🏛️] Phases 1-28 completed (and Phase 29 handled).{Fore.RESET}")
        print(f"{Fore.MAGENTA}[🔥] ANUBIS pipeline ready – manual hacking starts now!{Fore.RESET}")

if __name__ == "__main__":
    main()
