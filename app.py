#!/usr/bin/env python3
"""
WebsiteGrandMaster Telegram Bot
Advanced website scanner bot with user management, rate limiting, and admin controls.
"""

import os
import sys
import time
import json
import sqlite3
import threading
import random
import string
import logging
from datetime import datetime, date, timedelta
from urllib.parse import urlparse
import requests
import whois
import socket
import ssl
import re
import concurrent.futures
from collections import defaultdict
from bs4 import BeautifulSoup
import telebot
from telebot import types
import dns.resolver
import builtwith
from Wappalyzer import Wappalyzer, WebPage
from flask import Flask, render_template_string

# ----------------------------- Configuration -----------------------------
TOKEN = "8770219645:AAE8Hf4pVg13CW7jezJ-TMtmCW8mDof0kz4"  # Replace with your bot token
ADMIN_IDS = [8373846582]  # List of admin user IDs (telegram user IDs)
DB_FILE = "bot_data.db"
SCAN_TIMEOUT = 30  # seconds for each request
SCAN_THREADS = 12  # number of threads for directory brute
DAILY_LIMIT_FREE = 10  # max scans per day for free users
COOLDOWN_SECONDS = 60  # 1 minute cooldown between scans for a user

# ----------------------------- Database Setup -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    role TEXT DEFAULT 'free',
                    scans_today INTEGER DEFAULT 0,
                    last_scan_date TEXT,
                    last_scan_time REAL
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS vip_keys (
                    key TEXT PRIMARY KEY,
                    used_by INTEGER DEFAULT NULL,
                    created_at TEXT,
                    used_at TEXT DEFAULT NULL
                 )''')
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT role, scans_today, last_scan_date, last_scan_time FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {'role': row[0], 'scans_today': row[1], 'last_scan_date': row[2], 'last_scan_time': row[3]}
    else:
        # new user
        today = date.today().isoformat()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (user_id, role, scans_today, last_scan_date) VALUES (?, ?, ?, ?)",
                  (user_id, 'free', 0, today))
        conn.commit()
        conn.close()
        return {'role': 'free', 'scans_today': 0, 'last_scan_date': today, 'last_scan_time': None}

def update_user_scan(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    today = date.today().isoformat()
    now = time.time()
    # Reset daily count if new day
    c.execute("SELECT last_scan_date FROM users WHERE user_id = ?", (user_id,))
    last_date = c.fetchone()
    if last_date and last_date[0] != today:
        scans_today = 0
    else:
        c.execute("SELECT scans_today FROM users WHERE user_id = ?", (user_id,))
        scans_today = c.fetchone()[0] + 1
    c.execute("UPDATE users SET scans_today = ?, last_scan_date = ?, last_scan_time = ? WHERE user_id = ?",
              (scans_today, today, now, user_id))
    conn.commit()
    conn.close()

def set_user_role(user_id, role):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, user_id))
    conn.commit()
    conn.close()

def generate_vip_key():
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO vip_keys (key, created_at) VALUES (?, ?)", (key, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return key

def use_vip_key(key, user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT used_by FROM vip_keys WHERE key = ?", (key,))
    row = c.fetchone()
    if row and row[0] is None:
        c.execute("UPDATE vip_keys SET used_by = ?, used_at = ? WHERE key = ?", (user_id, datetime.now().isoformat(), key))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

def can_scan(user_id):
    user = get_user(user_id)
    # Check cooldown
    if user['last_scan_time']:
        if time.time() - user['last_scan_time'] < COOLDOWN_SECONDS:
            return False, f"Please wait {int(COOLDOWN_SECONDS - (time.time() - user['last_scan_time']))} seconds before scanning again."
    # Check daily limit
    if user['role'] == 'free':
        today = date.today().isoformat()
        if user['last_scan_date'] != today:
            user['scans_today'] = 0
        if user['scans_today'] >= DAILY_LIMIT_FREE:
            return False, f"You have reached your daily scan limit ({DAILY_LIMIT_FREE} scans). Upgrade to VIP for unlimited scans."
    return True, None

# ----------------------------- Scanner Class -----------------------------
class WebsiteGrandMasterPro:
    def __init__(self, target, timeout=SCAN_TIMEOUT, threads=SCAN_THREADS):
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc
        self.base_url = f"{self.parsed.scheme}://{self.domain}"
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = {
            'target': self.domain,
            'scan_time': datetime.now().isoformat(),
            'info': [],
            'vulns': [],
            'credentials': [],
            'admin_panels': [],
            'subdomains': [],
            'directories': [],
            'emails': [],
            'technologies': [],
            'ports': []
        }

        # Common subdomains
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'download', 'mssql', 'mail1',
            'panel', 'server', 'staging', 'my', 'api', 'app', 'portal', 'stats',
            'backup', 'dns', 'store', 'help', 'crm', 'office', 'info', 'bbs', 'sip',
            'vps', 'gw', 'live', 'remote', 'video', 'sms', 'exchange', 'cloud'
        ]

        # Common paths
        self.common_paths = [
            '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin', '/mysql',
            '/backup', '/backups', '/.env', '/.git/config', '/.svn/entries', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/server-status', '/phpinfo.php', '/test.php',
            '/config.php', '/wp-config.php', '/config.inc.php', '/.htaccess', '/.htpasswd',
            '/web.config', '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql',
            '/old', '/old_site', '/temp', '/tmp', '/uploads', '/download', '/files',
            '/css', '/js', '/images', '/img', '/assets', '/static', '/media', '/wp-content/uploads',
            '/wp-config.php.bak', '/wp-config.php.save', '/wp-config.old', '/config.php.bak',
            '/config.inc.php.bak', '/database.php', '/db.php', '/settings.php', '/local.xml',
            '/app/etc/local.xml', '/configuration.php', '/includes/configure.php', '/includes/config.php',
            '/include/config.php', '/inc/config.php', '/conf/config.php', '/config/database.php',
            '/protected/config/database.php', '/application/config/database.php', '/system/config/database.php',
            '/api', '/v1', '/v2', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/swagger-ui',
            '/adminer.php', '/adminer', '/admin/index.php', '/admin/login', '/administrator/index.php',
            '/dashboard', '/controlpanel', '/cp', '/cpanel', '/panel', '/manage', '/manager',
            '/console', '/setup', '/install', '/maint', '/maintenance', '/debug', '/info', '/status'
        ]

        # Ports to scan
        self.ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP (submission)', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB', 6379: 'Redis',
            11211: 'Memcached', 9200: 'Elasticsearch'
        }

    def run_scan(self):
        # Run all scan functions
        self.get_domain_hosting_intel()
        self.get_dns_records()
        self.get_geo_location()
        self.get_ssl_certificate()
        self.get_http_headers_security()
        self.detect_cms()
        self.get_backend_tech()
        self.scan_ports()
        self.enumerate_subdomains()
        self.enumerate_directories_files()
        self.crawl_links()
        self.extract_emails()
        self.check_sensitive_files()
        self.check_admin_panels()
        self.check_exposed_credentials()
        self.check_vulnerabilities()
        return self.results

    def log(self, message, category='info'):
        if category in self.results:
            self.results[category].append(message)

    def get_domain_hosting_intel(self):
        try:
            w = whois.whois(self.domain)
            self.log(f"Registrar: {w.registrar}")
            creation = w.creation_date
            if isinstance(creation, list): creation = creation[0]
            self.log(f"Creation Date: {creation}")
            expiry = w.expiration_date
            if isinstance(expiry, list): expiry = expiry[0]
            self.log(f"Expiry Date: {expiry}")
            self.log(f"Admin Email: {w.emails if w.emails else 'Private/Not Found'}")
            self.log(f"Name Servers: {w.name_servers}")
        except Exception as e:
            self.log(f"Domain Intel failed: {e}")

    def get_dns_records(self):
        try:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
            for rec in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, rec)
                    self.log(f"{rec} Records: {', '.join(str(r) for r in answers)}")
                except:
                    pass
        except Exception as e:
            self.log(f"DNS failed: {e}")

    def get_geo_location(self):
        try:
            ip = socket.gethostbyname(self.domain)
            self.log(f"Server IP: {ip}")
            try:
                geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.timeout).json()
                if geo.get('status') == 'success':
                    self.log(f"Country: {geo.get('country')} ({geo.get('countryCode')})")
                    self.log(f"Region/City: {geo.get('regionName')}, {geo.get('city')}")
                    self.log(f"ISP/Hosting: {geo.get('isp')}")
            except:
                pass
        except Exception as e:
            self.log(f"Geo failed: {e}")

    def get_ssl_certificate(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            self.log(f"Issuer: {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
            self.log(f"Subject: {subject.get('commonName', 'N/A')}")
            self.log(f"Valid From: {cert['notBefore']}")
            self.log(f"Valid To: {cert['notAfter']}")
            self.log(f"SAN: {cert.get('subjectAltName', 'N/A')}")
        except Exception as e:
            self.log(f"SSL failed: {e}")

    def get_http_headers_security(self):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout, allow_redirects=True)
            headers = resp.headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS filter',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy'
            }
            for header, desc in security_headers.items():
                value = headers.get(header)
                if value:
                    self.log(f"{desc}: {value}")
                else:
                    self.log(f"{desc}: Not set")
            server = headers.get('Server')
            if server:
                self.log(f"Server Software: {server}")
            cookies = resp.cookies
            if cookies:
                self.log("Cookies:")
                for cookie in cookies:
                    flags = []
                    if cookie.secure: flags.append('Secure')
                    if cookie.has_nonstandard_attr('HttpOnly'): flags.append('HttpOnly')
                    if cookie.has_nonstandard_attr('SameSite'): flags.append(f"SameSite={cookie.get_nonstandard_attr('SameSite')}")
                    self.log(f"  - {cookie.name}: {' '.join(flags) if flags else 'no flags'}")
        except Exception as e:
            self.log(f"Headers failed: {e}")

    def detect_cms(self):
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wp-login.php'],
            'Joomla': ['joomla', 'media/jui', 'components/com_content'],
            'Drupal': ['drupal', 'sites/default', 'core/misc'],
            'Magento': ['magento', 'skin/frontend', 'Mage_Core'],
            'PrestaShop': ['prestashop', 'modules/blockcart', 'js/jquery/plugins'],
            'OpenCart': ['catalog/view/theme', 'index.php?route=common/home'],
            'Shopify': ['cdn.shopify.com', 'shopify'],
            'Wix': ['wix.com', 'static.wixstatic.com'],
            'Weebly': ['weebly.com', 'weebly-static'],
            'Squarespace': ['squarespace.com', 'static.squarespace']
        }
        detected = []
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            html = resp.text.lower()
            for cms, indicators in cms_indicators.items():
                for ind in indicators:
                    if ind in html:
                        detected.append(cms)
                        break
            if detected:
                self.log(f"Possible CMS(s): {', '.join(set(detected))}")
            else:
                self.log("No common CMS detected.")
        except Exception as e:
            self.log(f"CMS detection failed: {e}")

    def get_backend_tech(self):
        try:
            tech = builtwith.parse(self.base_url)
            for cat, apps in tech.items():
                self.log(f"{cat.title()}: {', '.join(apps)}")
                self.results['technologies'].extend(apps)
        except Exception as e:
            self.log(f"BuiltWith failed: {e}")
        try:
            webpage = WebPage.new_from_url(self.base_url, verify=False)
            wapp = Wappalyzer.latest()
            detected = wapp.analyze(webpage)
            if detected:
                self.log("Wappalyzer Analysis:")
                for tech in detected:
                    self.log(f"  - {tech}")
                    self.results['technologies'].append(tech)
        except Exception as e:
            self.log(f"Wappalyzer failed: {e}")

    def scan_ports(self):
        try:
            ip = socket.gethostbyname(self.domain)
        except:
            self.log("Could not resolve IP for port scan.")
            return
        open_ports = []
        for port, service in self.ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                self.log(f"Port {port} ({service}): OPEN")
                open_ports.append(f"{port}:{service}")
            sock.close()
        self.results['ports'] = open_ports

    def enumerate_subdomains(self):
        # crt.sh
        try:
            crt_url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = requests.get(crt_url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            if sub.endswith(f".{self.domain}"):
                                subdomains.add(sub.rstrip('.'))
                if subdomains:
                    self.log(f"Found {len(subdomains)} subdomains from crt.sh:")
                    for sub in list(subdomains)[:30]:
                        self.log(f"  {sub}")
                        self.results['subdomains'].append(sub)
        except Exception as e:
            self.log(f"crt.sh failed: {e}")
        # Brute
        found = []
        def check(sub):
            try:
                socket.gethostbyname(f"{sub}.{self.domain}")
                return sub
            except:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_sub = {executor.submit(check, sub): sub for sub in self.common_subdomains}
            for future in concurrent.futures.as_completed(future_to_sub):
                result = future.result()
                if result:
                    found.append(result)
        if found:
            self.log(f"Found {len(found)} subdomains via brute:")
            for sub in found:
                self.log(f"  {sub}.{self.domain}")
                self.results['subdomains'].append(f"{sub}.{self.domain}")

    def enumerate_directories_files(self):
        found = []
        def check(path):
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403]:
                    return (path, resp.status_code)
            except:
                pass
            return (path, None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(check, path): path for path in self.common_paths}
            for future in concurrent.futures.as_completed(future_to_path):
                path, status = future.result()
                if status:
                    found.append((path, status))
        if found:
            self.log(f"Found {len(found)} directories/files:")
            for path, status in found:
                self.log(f"  {self.base_url}{path} (HTTP {status})")
                self.results['directories'].append(f"{path} ({status})")
        else:
            self.log("No common directories/files found.")

    def crawl_links(self):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                src = tag.get('href') or tag.get('src')
                if src:
                    absolute = urljoin(self.base_url, src)
                    parsed = urlparse(absolute)
                    if parsed.netloc == self.domain or parsed.netloc == '':
                        links.add(absolute)
            if links:
                self.log(f"Found {len(links)} internal links (first 20):")
                for link in list(links)[:20]:
                    self.log(f"  {link}")
        except Exception as e:
            self.log(f"Crawling failed: {e}")

    def extract_emails(self):
        emails = set()
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            emails.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            sitemap_url = urljoin(self.base_url, '/sitemap.xml')
            try:
                sitemap_resp = self.session.get(sitemap_url, timeout=self.timeout)
                if sitemap_resp.status_code == 200:
                    emails.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', sitemap_resp.text))
            except:
                pass
            if emails:
                self.log(f"Found {len(emails)} unique emails:")
                for email in emails:
                    self.log(f"  {email}")
                    self.results['emails'].append(email)
            else:
                self.log("No emails found.")
        except Exception as e:
            self.log(f"Email extraction failed: {e}")

    def check_sensitive_files(self):
        sensitive = [
            '/.env', '/.git/config', '/.svn/entries', '/wp-config.php.bak',
            '/config.php.bak', '/.htpasswd', '/.htaccess', '/web.config',
            '/backup.sql', '/dump.sql', '/error_log', '/debug.log',
            '/config.php', '/wp-config.php', '/configuration.php', '/settings.php',
            '/db.php', '/database.php', '/composer.json', '/composer.lock',
            '/package.json', '/package-lock.json', '/requirements.txt'
        ]
        found = []
        for path in sensitive:
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if any(kw in content for kw in ['mysql', 'password', 'secret', 'api_key', 'database', 'dbuser', 'dbpass']):
                        found.append(f"{url} (contains sensitive data)")
                    else:
                        found.append(url)
            except:
                pass
        if found:
            self.log("Sensitive files found:")
            for item in found:
                self.log(f"  {item}")
                self.results['vulns'].append(f"Sensitive file: {item}")
        else:
            self.log("No sensitive files exposed.")

    def check_admin_panels(self):
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/admin.php', '/login',
            '/admin/login', '/admin/index.php', '/backend', '/cp', '/cpanel',
            '/dashboard', '/manager', '/control', '/user', '/auth', '/signin',
            '/admincp', '/adminarea', '/admin_panel', '/adminpanel', '/manage'
        ]
        found = []
        for path in admin_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in [200, 403, 401]:
                    found.append(f"{url} (HTTP {resp.status_code})")
            except:
                pass
        if found:
            self.log("Admin panels found:")
            for item in found:
                self.log(f"  {item}")
                self.results['admin_panels'].append(item)
        else:
            self.log("No admin panels detected.")

    def check_exposed_credentials(self):
        patterns = [
            (r'(?:DB_PASSWORD|DB_PASS|DB_PWD|PASSWORD|PASS|SECRET_KEY|API_KEY)\s*=\s*[\'"]([^\'"]+)[\'"]', 'database'),
            (r'(?:mysql|database)\.connect\(\s*[\'"]([^\'"]+)[\'"]', 'database'),
            (r'password\s*:\s*[\'"]([^\'"]+)[\'"]', 'JSON'),
            (r'\$db_password\s*=\s*[\'"]([^\'"]+)[\'"]', 'PHP'),
            (r'PASSWORD\s*=\s*([^\s]+)', 'INI'),
            (r'<password>([^<]+)</password>', 'XML'),
            (r'api_key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Secret')
        ]
        credential_files = [
            '/.env', '/wp-config.php', '/config.php', '/configuration.php',
            '/app/etc/local.xml', '/includes/configure.php', '/settings.php',
            '/db.php', '/database.php', '/.env.local', '/.env.production'
        ]
        found_creds = []
        for f in credential_files:
            url = urljoin(self.base_url, f)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    content = resp.text
                    for pattern, source in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            for match in matches:
                                cred_str = f"{url} -> {source}: {match}"
                                found_creds.append(cred_str)
                                self.results['credentials'].append(cred_str)
            except:
                pass
        if found_creds:
            self.log("Possible credentials found:")
            for cred in found_creds:
                self.log(f"  {cred}")
        else:
            self.log("No obvious credentials found.")

    def check_vulnerabilities(self):
        # XSS
        xss_payload = "<script>alert('XSS')</script>"
        try:
            parsed = urlparse(self.base_url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for key in params:
                    test_url = f"{self.base_url}?{key}={xss_payload}"
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if xss_payload in resp.text:
                        self.log(f"Possible XSS at {test_url}")
                        self.results['vulns'].append(f"XSS at {test_url}")
        except:
            pass
        # SQLi
        sqli_payloads = ["'", "\"", "1' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
        try:
            for payload in sqli_payloads:
                test_url = f"{self.base_url}?id={payload}"
                resp = self.session.get(test_url, timeout=self.timeout)
                if "mysql" in resp.text.lower() or "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                    self.log(f"Possible SQLi at {test_url} (error message)")
                    self.results['vulns'].append(f"SQLi at {test_url}")
        except:
            pass
        # Open redirect
        redirect_url = "https://evil.com"
        test_url = f"{self.base_url}?redirect={redirect_url}"
        try:
            resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code in [301, 302] and redirect_url in resp.headers.get('Location', ''):
                self.log(f"Open redirect at {test_url}")
                self.results['vulns'].append(f"Open redirect at {test_url}")
        except:
            pass

# ----------------------------- Bot Handlers -----------------------------
bot = telebot.TeleBot(TOKEN, threaded=False)

@bot.message_handler(commands=['start'])
def start(message):
    user_id = message.from_user.id
    user = get_user(user_id)
    text = f"Welcome to WebsiteGrandMaster Bot!\nYour role: {user['role']}\nToday's scans: {user['scans_today']}/{DAILY_LIMIT_FREE if user['role']=='free' else '∞'}\n\nUse /help to see available commands."
    bot.reply_to(message, text)

@bot.message_handler(commands=['help'])
def help_command(message):
    text = (
        "Available commands:\n"
        "/start - Show your status\n"
        "/help - Show this help\n"
        "/search <url> - Scan a website (e.g., /search https://example.com)\n"
        "/use <key> - Activate a VIP key\n"
        "/admin - Admin panel (admins only)\n"
        "/getkey - Generate a new VIP key (admins only)"
    )
    bot.reply_to(message, text)

@bot.message_handler(commands=['search'])
def search(message):
    user_id = message.from_user.id
    # Check cooldown and limit
    can, msg = can_scan(user_id)
    if not can:
        bot.reply_to(message, msg)
        return
    # Parse URL
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "Please provide a URL. Usage: /search https://example.com")
        return
    url = args[1].strip()
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError
    except:
        bot.reply_to(message, "Invalid URL. Please include domain name.")
        return
    # Start scan in background
    bot.reply_to(message, f"🔍 Scanning {url}... This may take a few minutes. I'll send the report when done.")
    # Use threading to avoid blocking
    threading.Thread(target=run_scan_thread, args=(message, user_id, url)).start()

def run_scan_thread(message, user_id, url):
    try:
        # Create scanner instance
        scanner = WebsiteGrandMasterPro(url, timeout=SCAN_TIMEOUT, threads=SCAN_THREADS)
        results = scanner.run_scan()
        # Update user scan count
        update_user_scan(user_id)
        # Generate report text
        report = f"🌐 Scan Report for {results['target']}\n"
        report += f"Scan Time: {results['scan_time']}\n\n"
        for category, items in results.items():
            if category in ['target', 'scan_time']:
                continue
            if items:
                report += f"📌 {category.upper()}:\n"
                for item in items:
                    report += f"  - {item}\n"
                report += "\n"
        # Create a file
        filename = f"scan_{results['target']}_{int(time.time())}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        # Send report as file
        with open(filename, 'rb') as f:
            bot.send_document(message.chat.id, f, caption=f"Scan completed for {url}")
        os.remove(filename)
    except Exception as e:
        bot.send_message(message.chat.id, f"Scan failed: {str(e)}")

@bot.message_handler(commands=['use'])
def use_key(message):
    user_id = message.from_user.id
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "Please provide a key. Usage: /use KEY")
        return
    key = args[1].strip()
    if use_vip_key(key, user_id):
        set_user_role(user_id, 'vip')
        bot.reply_to(message, "🎉 Congratulations! You are now a VIP user. Unlimited scans unlocked.")
    else:
        bot.reply_to(message, "Invalid or already used key.")

@bot.message_handler(commands=['admin'])
def admin_panel(message):
    user_id = message.from_user.id
    if user_id not in ADMIN_IDS:
        bot.reply_to(message, "You are not authorized to use this command.")
        return
    # Show admin panel
    text = "Admin Panel\n\n"
    text += "Commands:\n"
    text += "/getkey - Generate a new VIP key\n"
    text += "/stats - Show bot statistics\n"
    bot.reply_to(message, text)

@bot.message_handler(commands=['getkey'])
def getkey(message):
    user_id = message.from_user.id
    if user_id not in ADMIN_IDS:
        bot.reply_to(message, "You are not authorized to use this command.")
        return
    key = generate_vip_key()
    bot.reply_to(message, f"New VIP key generated:\n`{key}`\n\nShare this key with users. They can use it with /use KEY", parse_mode='Markdown')

@bot.message_handler(commands=['stats'])
def stats(message):
    user_id = message.from_user.id
    if user_id not in ADMIN_IDS:
        bot.reply_to(message, "You are not authorized to use this command.")
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE role='vip'")
    vip_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM vip_keys WHERE used_by IS NOT NULL")
    used_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM vip_keys WHERE used_by IS NULL")
    unused_keys = c.fetchone()[0]
    conn.close()
    text = f"Bot Statistics:\n\nTotal Users: {total_users}\nVIP Users: {vip_users}\nVIP Keys Used: {used_keys}\nUnused Keys: {unused_keys}"
    bot.reply_to(message, text)

# ----------------------------- Flask Server -----------------------------
app = Flask(__name__)

@app.route('/')
def index():
    # Simple status page
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE role='vip'")
    vip_users = c.fetchone()[0]
    conn.close()
    html = f"""
    <html>
    <head><title>WebsiteGrandMaster Bot</title></head>
    <body>
        <h1>WebsiteGrandMaster Bot Status</h1>
        <p>Bot is running.</p>
        <p>Total users: {total_users}</p>
        <p>VIP users: {vip_users}</p>
        <p>Last update: {datetime.now()}</p>
    </body>
    </html>
    """
    return html

def run_flask():
    app.run(host='0.0.0.0', port=5000)

# ----------------------------- Main -----------------------------
if __name__ == "__main__":
    init_db()
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    # Start bot polling
    bot.infinity_polling()
