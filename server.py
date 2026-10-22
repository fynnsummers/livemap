#!/usr/bin/env python3
"""Lagekarte: Angriffe aus Fail2ban und den Web-Logs."""

import array
import calendar
import csv
import gzip
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import subprocess
import threading
import time
import zlib
from bisect import bisect_right
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from dbutil import open_database

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
STATIC = ROOT / "static"
DB_PATH = DATA / "events.sqlite"
OFFSET_PATH = DATA / "f2b.offset"
GEO_PATH = DATA / "dbip-country-lite.csv.gz"
CITY_PATH = DATA / "dbip-city-lite.csv.gz"
NET_PATH = DATA / "networks.csv"
HIT_KEEP = 5000
F2B_LOG = Path(os.environ.get("LIVEMAP_F2B", "/var/log/fail2ban.log"))
NGINX_LOGS = [
    Path(item)
    for item in os.environ.get("LIVEMAP_NGINX", "/var/log/nginx/access.log").split(",")
    if item.strip()
]
HOST = os.environ.get("LIVEMAP_HOST", "127.0.0.1")
PORT = int(os.environ.get("LIVEMAP_PORT", "8791"))
DATABASE_URL = os.environ.get("LIVEMAP_DATABASE_URL", "").strip()
SESSION_COOKIE = "livemap_session"
SESSION_DAYS = int(os.environ.get("LIVEMAP_SESSION_DAYS", "14"))
STARTED = time.time()
ADMIN_USER = os.environ.get("LIVEMAP_ADMIN_USER", "admin").strip() or "admin"
ADMIN_PASSWORD = os.environ.get("LIVEMAP_ADMIN_PASSWORD", "").strip()
F2B_USE_SUDO = os.environ.get("LIVEMAP_F2B_SUDO", "1").strip() not in ("0", "false", "no")
F2B_BIN = os.environ.get("LIVEMAP_F2B_BIN", "/usr/bin/fail2ban-client").strip() or "/usr/bin/fail2ban-client"
PUBLIC_PATHS = {
    "/login",
    "/login.html",
    "/api/login",
    "/api/health",
    "/api/host",
    "/world.geojson",
    "/favicon.svg",
    "/favicon.png",
    "/logo.svg",
    "/logo.png",
    "/logo-dark.png",
    "/app.css",
    "/setup",
    "/setup.html",
    "/api/setup",
    "/api/setup/code",
}


def machine_hostname():
    for path in (Path("/proc/1/root/etc/hostname"), Path("/etc/hostname")):
        try:
            name = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if name:
            return name
    return socket.gethostname()


def _private_ipv4(ip: str) -> bool:
    try:
        parts = [int(part) for part in ip.split(".")]
    except ValueError:
        return True
    if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
        return True
    if parts[0] in (10, 127) or (parts[0] == 192 and parts[1] == 168):
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False


def machine_ipv4() -> str:
    for item in os.environ.get("LIVEMAP_OWN_IPS", "").split(","):
        ip = item.strip()
        if ip and ":" not in ip and not _private_ipv4(ip):
            return ip
    return ""


def app_version() -> str:
    try:
        text = (STATIC / "version.txt").read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    return text or "1.0.0"


SERVER = {
    "name": os.environ.get("LIVEMAP_NAME", socket.gethostname()),
    "hostname": machine_hostname(),
    "ipv4": machine_ipv4(),
    "version": app_version(),
    "hoster": os.environ.get("LIVEMAP_HOSTER", "ionos"),
    "hoster_name": os.environ.get("LIVEMAP_HOSTER_NAME", "IONOS"),
    "lat": float(os.environ.get("LIVEMAP_LAT", "52.52")),
    "lon": float(os.environ.get("LIVEMAP_LON", "13.405")),
}
OWN_IPS = {item.strip() for item in os.environ.get("LIVEMAP_OWN_IPS", "").split(",") if item.strip()}
ACTION_NETS = [
    item.strip()
    for item in os.environ.get(
        "LIVEMAP_ACTION_NETS",
        "127.0.0.1,::1,10.66.66.0/24," + ",".join(sorted(OWN_IPS)),
    ).split(",")
    if item.strip()
]
ACTION_JAILS = [
    item.strip()
    for item in os.environ.get(
        "LIVEMAP_ACTION_JAILS",
        "sshd,nginx-404-flood,nginx-env-scan,nginx-http-auth",
    ).split(",")
    if item.strip()
]
LOGIN_HITS = {}
LOGIN_LOCK = threading.Lock()
DB_ENGINE = "sqlite"
WHOIS_CACHE = {}
WHOIS_LOCK = threading.Lock()
LOOKUP_RATE = {"t": 0.0}
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
WHOIS_FIELD_RE = re.compile(
    r"(?im)^(netname|org[- ]?name|organization|org|country|origin(?:as)?|cidr|inetnum|route|"
    r"descr|abuse[- ]?mailbox|orgabuseemail|address|city|stateprov|postalcode|"
    r"phone|mnt-by|status)\s*:\s*(.+)$"
)

# Ungefähre Landesmitten, genug für eine Weltkarte.
CENTROIDS = {
    "AD": (42.5, 1.5, "Andorra"), "AE": (24.4, 54.4, "Vereinigte Arabische Emirate"),
    "AF": (33.9, 67.7, "Afghanistan"), "AL": (41.2, 20.2, "Albanien"),
    "AM": (40.1, 45.0, "Armenien"), "AO": (-11.2, 17.9, "Angola"),
    "AR": (-38.4, -63.6, "Argentinien"), "AT": (47.6, 14.1, "Österreich"),
    "AU": (-25.3, 133.8, "Australien"), "AZ": (40.1, 47.6, "Aserbaidschan"),
    "BA": (43.9, 17.7, "Bosnien und Herzegowina"), "BD": (23.7, 90.4, "Bangladesch"),
    "BE": (50.5, 4.5, "Belgien"), "BF": (12.2, -1.6, "Burkina Faso"),
    "BG": (42.7, 25.5, "Bulgarien"), "BH": (26.0, 50.6, "Bahrain"),
    "BI": (-3.4, 29.9, "Burundi"), "BJ": (9.3, 2.3, "Benin"),
    "BN": (4.5, 114.7, "Brunei"), "BO": (-16.3, -63.6, "Bolivien"),
    "BR": (-14.2, -51.9, "Brasilien"), "BS": (25.0, -77.4, "Bahamas"),
    "BT": (27.5, 90.4, "Bhutan"), "BW": (-22.3, 24.7, "Botsuana"),
    "BY": (53.7, 27.9, "Belarus"), "BZ": (17.2, -88.5, "Belize"),
    "CA": (56.1, -106.3, "Kanada"), "CD": (-4.0, 21.8, "Kongo (DR)"),
    "CF": (6.6, 20.9, "Zentralafrika"), "CG": (-0.2, 15.8, "Kongo"),
    "CH": (46.8, 8.2, "Schweiz"), "CI": (7.5, -5.5, "Côte d'Ivoire"),
    "CL": (-35.7, -71.5, "Chile"), "CM": (7.4, 12.4, "Kamerun"),
    "CN": (35.9, 104.2, "China"), "CO": (4.6, -74.1, "Kolumbien"),
    "CR": (9.7, -83.8, "Costa Rica"), "CU": (21.5, -78.0, "Kuba"),
    "CV": (16.0, -24.0, "Kap Verde"), "CY": (35.1, 33.4, "Zypern"),
    "CZ": (49.8, 15.5, "Tschechien"), "DE": (51.2, 10.4, "Deutschland"),
    "DJ": (11.8, 42.6, "Dschibuti"), "DK": (56.2, 9.5, "Dänemark"),
    "DO": (18.7, -70.2, "Dominikanische Republik"), "DZ": (28.0, 1.7, "Algerien"),
    "EC": (-1.8, -78.2, "Ecuador"), "EE": (58.6, 25.0, "Estland"),
    "EG": (26.8, 30.8, "Ägypten"), "ER": (15.2, 39.8, "Eritrea"),
    "ES": (40.2, -3.7, "Spanien"), "ET": (9.1, 40.5, "Äthiopien"),
    "FI": (64.0, 26.0, "Finnland"), "FJ": (-17.7, 178.1, "Fidschi"),
    "FR": (46.2, 2.2, "Frankreich"), "GA": (-0.8, 11.6, "Gabun"),
    "GB": (54.0, -2.5, "Vereinigtes Königreich"), "GE": (42.3, 43.4, "Georgien"),
    "GH": (7.9, -1.0, "Ghana"), "GI": (36.1, -5.3, "Gibraltar"),
    "GL": (71.7, -42.6, "Grönland"), "GR": (39.1, 21.8, "Griechenland"),
    "GT": (15.8, -90.2, "Guatemala"), "GY": (4.9, -58.9, "Guyana"),
    "HK": (22.3, 114.2, "Hongkong"), "HN": (15.2, -86.2, "Honduras"),
    "HR": (45.1, 15.2, "Kroatien"), "HT": (19.0, -72.3, "Haiti"),
    "HU": (47.2, 19.4, "Ungarn"), "ID": (-2.5, 118.0, "Indonesien"),
    "IE": (53.1, -8.0, "Irland"), "IL": (31.5, 34.8, "Israel"),
    "IN": (22.0, 79.0, "Indien"), "IQ": (33.2, 43.7, "Irak"),
    "IR": (32.4, 53.7, "Iran"), "IS": (64.9, -19.0, "Island"),
    "IT": (42.8, 12.6, "Italien"), "JM": (18.1, -77.3, "Jamaika"),
    "JO": (30.6, 36.2, "Jordanien"), "JP": (36.2, 138.2, "Japan"),
    "KE": (-0.0, 37.9, "Kenia"), "KG": (41.2, 74.8, "Kirgisistan"),
    "KH": (12.6, 105.0, "Kambodscha"), "KM": (-11.9, 43.9, "Komoren"),
    "KR": (36.5, 127.9, "Südkorea"), "KW": (29.3, 47.5, "Kuwait"),
    "KZ": (48.0, 68.0, "Kasachstan"), "LA": (18.2, 104.0, "Laos"),
    "LB": (33.9, 35.9, "Libanon"), "LK": (7.9, 80.8, "Sri Lanka"),
    "LR": (6.4, -9.4, "Liberia"), "LS": (-29.6, 28.2, "Lesotho"),
    "LT": (55.2, 23.9, "Litauen"), "LU": (49.8, 6.1, "Luxemburg"),
    "LV": (56.9, 24.6, "Lettland"), "LY": (26.3, 17.2, "Libyen"),
    "MA": (31.8, -7.1, "Marokko"), "MC": (43.7, 7.4, "Monaco"),
    "MD": (47.4, 28.4, "Moldau"), "ME": (42.7, 19.4, "Montenegro"),
    "MG": (-18.8, 46.9, "Madagaskar"), "MK": (41.6, 21.7, "Nordmazedonien"),
    "ML": (17.6, -4.0, "Mali"), "MM": (21.9, 95.9, "Myanmar"),
    "MN": (46.9, 103.8, "Mongolei"), "MR": (21.0, -10.9, "Mauretanien"),
    "MT": (35.9, 14.4, "Malta"), "MU": (-20.3, 57.6, "Mauritius"),
    "MV": (3.2, 73.2, "Malediven"), "MW": (-13.3, 34.3, "Malawi"),
    "MX": (23.6, -102.5, "Mexiko"), "MY": (4.2, 101.9, "Malaysia"),
    "MZ": (-18.7, 35.5, "Mosambik"), "NA": (-22.9, 18.5, "Namibia"),
    "NE": (17.6, 8.1, "Niger"), "NG": (9.1, 8.7, "Nigeria"),
    "NI": (12.9, -85.2, "Nicaragua"), "NL": (52.1, 5.3, "Niederlande"),
    "NO": (64.5, 16.0, "Norwegen"), "NP": (28.4, 84.1, "Nepal"),
    "NZ": (-41.0, 174.0, "Neuseeland"), "OM": (21.5, 55.9, "Oman"),
    "PA": (8.5, -80.8, "Panama"), "PE": (-9.2, -75.0, "Peru"),
    "PG": (-6.3, 143.9, "Papua-Neuguinea"), "PH": (12.9, 121.8, "Philippinen"),
    "PK": (30.4, 69.3, "Pakistan"), "PL": (52.0, 19.4, "Polen"),
    "PR": (18.2, -66.6, "Puerto Rico"), "PS": (31.9, 35.2, "Palästina"),
    "PT": (39.4, -8.2, "Portugal"), "PY": (-23.4, -58.4, "Paraguay"),
    "QA": (25.3, 51.2, "Katar"), "RO": (45.9, 24.9, "Rumänien"),
    "RS": (44.0, 21.0, "Serbien"), "RU": (61.5, 105.3, "Russland"),
    "RW": (-1.9, 29.9, "Ruanda"), "SA": (24.0, 45.0, "Saudi-Arabien"),
    "SD": (12.9, 30.2, "Sudan"), "SE": (62.2, 17.6, "Schweden"),
    "SG": (1.35, 103.8, "Singapur"), "SI": (46.1, 14.8, "Slowenien"),
    "SK": (48.7, 19.7, "Slowakei"), "SL": (8.5, -11.8, "Sierra Leone"),
    "SN": (14.5, -14.5, "Senegal"), "SO": (5.2, 46.2, "Somalia"),
    "SR": (3.9, -56.0, "Suriname"), "SV": (13.8, -88.9, "El Salvador"),
    "SY": (34.8, 38.9, "Syrien"), "TD": (15.5, 18.7, "Tschad"),
    "TG": (8.6, 0.8, "Togo"), "TH": (15.9, 100.9, "Thailand"),
    "TJ": (38.9, 71.3, "Tadschikistan"), "TM": (39.0, 59.6, "Turkmenistan"),
    "TN": (34.0, 9.5, "Tunesien"), "TR": (39.1, 35.2, "Türkei"),
    "TT": (10.7, -61.2, "Trinidad und Tobago"), "TW": (23.7, 121.0, "Taiwan"),
    "TZ": (-6.4, 34.9, "Tansania"), "UA": (48.4, 31.2, "Ukraine"),
    "UG": (1.4, 32.3, "Uganda"), "US": (39.8, -98.5, "USA"),
    "UY": (-32.5, -55.8, "Uruguay"), "UZ": (41.4, 64.6, "Usbekistan"),
    "VE": (6.4, -66.6, "Venezuela"), "VN": (14.1, 108.3, "Vietnam"),
    "YE": (15.6, 48.5, "Jemen"), "ZA": (-30.6, 22.9, "Südafrika"),
    "ZM": (-13.1, 27.8, "Sambia"), "ZW": (-19.0, 29.2, "Simbabwe"),
}

JAIL_KIND = {
    "sshd": "ssh",
    "nginx-env-scan": "scan",
    "nginx-404-flood": "flood",
    "nginx-http-auth": "login",
    "mailcow-postfix-auth": "mail",
}
F2B_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+.*\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*$"
)
NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d+) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
    r'(?: (?P<vhost>\S+))?$'
)
FILE_HOSTS = {
    "pelican.app-access.log": "panel.infynnite.de",
    "infynnite_access.log": "infynnite.de",
    "cloud.infynnite.de.access.log": "cloud.infynnite.de",
    "minecraft.infynnite.de_access.log": "minecraft.infynnite.de",
}
SITE_SUFFIXES = (
    "infynnite.de",
    "disdirectory.org",
    "fynnsummers.de",
    "femboy-paradise.de",
)
PROBE_RE = re.compile(
    r"(?i)(\.env(?:\.|$|\?)|wp-login|xmlrpc|phpmyadmin|/\.git|phpunit|boaform|/cgi-bin|actuator|/\.aws|/\.svn|wlwmanifest|\.php(?:\?|$))"
)
SCANNER_UA = re.compile(
    r"(?i)(zgrab|masscan|nmap|nikto|sqlmap|gobuster|nuclei|censys|shodan|leakix|l9scan|expanse|stretchoid|binaryedge|netsystemsresearch|palo\s*alto|internetmeasurement|libredtail)"
)
ASSET_RE = re.compile(r"(?i)\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|map|mp4|webm)(?:\?|$)")
ATTACK_KINDS = {"ssh", "scan", "flood", "login", "mail", "probe"}
BRANDS = {
    "cloudflare", "google", "amazon", "microsoft", "fastly", "digitalocean", "hetzner", "ovh",
    "akamai", "meta", "apple", "github", "oracle", "linode", "vultr", "contabo", "leaseweb",
    "alibaba", "tencent", "ionos", "godaddy", "rackspace", "strato", "net",
}
HOSTERS = {
    "akamai": "Akamai",
    "alibaba": "Alibaba",
    "amazon": "Amazon",
    "apple": "Apple",
    "cloudflare": "Cloudflare",
    "contabo": "Contabo",
    "digitalocean": "DigitalOcean",
    "fastly": "Fastly",
    "github": "GitHub",
    "godaddy": "GoDaddy",
    "google": "Google",
    "hetzner": "Hetzner",
    "ionos": "IONOS",
    "leaseweb": "Leaseweb",
    "linode": "Linode",
    "meta": "Meta",
    "microsoft": "Microsoft",
    "oracle": "Oracle",
    "ovh": "OVH",
    "rackspace": "Rackspace",
    "strato": "Strato",
    "tencent": "Tencent",
    "vultr": "Vultr",
}
NGINX_TS = "%d/%b/%Y:%H:%M:%S %z"

subscribers = []
sub_lock = threading.Lock()
db_lock = threading.RLock()
geo_starts = array.array("I")
geo_ends = array.array("I")
geo_ccs = array.array("H")
geo_codes = []
geo_lats = array.array("f")
geo_lons = array.array("f")
net_starts = array.array("I")
net_ends = array.array("I")
net_keys = []
net_labels = []


def ip4_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]


def is_public(ip):
    n = ip4_to_int(ip)
    if n is None or ip in OWN_IPS:
        return False
    a = (n >> 24) & 255
    b = (n >> 16) & 255
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if a == 169 and b == 254:
        return False
    return True


def client_ip(handler):
    forwarded = handler.headers.get("X-Real-IP") or handler.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or (handler.client_address[0] if handler.client_address else "")


def ip_allowed(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in nets:
        try:
            if "/" in item:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True
            elif addr == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def actions_allowed(handler):
    user = getattr(handler, "user", None)
    if user:
        return user.get("role") == "admin"
    return ip_allowed(client_ip(handler), ACTION_NETS)


def known_ip(ip):
    with db_lock:
        if DB.execute("SELECT 1 FROM hits WHERE ip = ? LIMIT 1", (ip,)).fetchone():
            return True
        if DB.execute("SELECT 1 FROM events WHERE ip = ? LIMIT 1", (ip,)).fetchone():
            return True
    return False


def reverse_dns(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return ""


def parse_whois_text(text):
    fields = {}
    for key, value in WHOIS_FIELD_RE.findall(text or ""):
        label = key.lower().replace(" ", "-")
        value = value.strip()
        if not value:
            continue
        if label in fields:
            if value not in fields[label] and len(fields[label]) < 240:
                fields[label] = f"{fields[label]} · {value}"
        else:
            fields[label] = value[:240]
    return fields


def run_whois(ip):
    now = time.time()
    with WHOIS_LOCK:
        cached = WHOIS_CACHE.get(ip)
        if cached and now - cached["t"] < 6 * 3600:
            return cached["data"]
        if now - LOOKUP_RATE["t"] < 1.2:
            time.sleep(1.2 - (now - LOOKUP_RATE["t"]))
        LOOKUP_RATE["t"] = time.time()
    try:
        proc = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        text = f"whois fehlgeschlagen: {exc}"
    data = {
        "raw": clip(text, 4500),
        "fields": parse_whois_text(text),
    }
    with WHOIS_LOCK:
        WHOIS_CACHE[ip] = {"t": time.time(), "data": data}
        if len(WHOIS_CACHE) > 400:
            for old in list(WHOIS_CACHE)[:80]:
                WHOIS_CACHE.pop(old, None)
    return data


_STATUS_CACHE = {"t": 0.0, "data": None}
_STATUS_LOCK = threading.Lock()


def _num(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def service_status():
    now = time.time()
    with _STATUS_LOCK:
        cached = _STATUS_CACHE["data"]
        if cached and now - _STATUS_CACHE["t"] < 12:
            cached["services"][0]["uptime"] = int(now - STARTED)
            return cached
    f2b_ok, f2b_out = f2b_run("ping")
    bans = banned_map()
    jails = []
    for jail in ACTION_JAILS:
        jails.append({"jail": jail, "banned": sum(1 for items in bans.values() if jail in items)})
    db_ok = False
    db_uptime = None
    hits = ips = countries = hour = 0
    kinds = []
    try:
        with db_lock:
            DB.execute("SELECT 1").fetchone()
            db_ok = True
            started = DB.execute("SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))").fetchone()
            db_uptime = _num(started[0] if started else 0)
            row = DB.execute(
                "SELECT COUNT(*), COUNT(DISTINCT ip), COUNT(DISTINCT NULLIF(cc, '')) FROM hits"
            ).fetchone()
            hits, ips, countries = (_num(row[0]), _num(row[1]), _num(row[2])) if row else (0, 0, 0)
            hour = _num(DB.execute("SELECT COUNT(*) FROM hits WHERE ts >= ?", (int(now) - 3600,)).fetchone()[0])
            kind_rows = DB.execute(
                "SELECT kind, COUNT(*) FROM hits GROUP BY kind ORDER BY COUNT(*) DESC"
            ).fetchall()
            kinds = [{"kind": r[0] or "", "count": _num(r[1])} for r in kind_rows]
    except Exception:
        db_ok = False
    nginx_age = None
    for path in NGINX_LOGS:
        try:
            age = max(0, now - path.stat().st_mtime)
        except OSError:
            continue
        nginx_age = age if nginx_age is None else min(nginx_age, age)
    nginx_ok = nginx_age is not None and nginx_age < 180
    if nginx_age is None:
        nginx_detail = "Log nicht lesbar"
    elif nginx_age < 90:
        nginx_detail = "Log gerade geschrieben"
    else:
        nginx_detail = f"Log vor {int(nginx_age)} Sek"
    data = {
        "ok": True,
        "services": [
            {
                "id": "livemap",
                "name": "Livemap",
                "up": True,
                "uptime": int(now - STARTED),
                "detail": f"{hits} Zugriffe gespeichert",
            },
            {
                "id": "postgres",
                "name": "Datenbank",
                "up": db_ok,
                "uptime": db_uptime,
                "detail": "Postgres",
            },
            {
                "id": "nginx",
                "name": "Nginx",
                "up": nginx_ok,
                "uptime": None,
                "detail": nginx_detail,
            },
            {
                "id": "fail2ban",
                "name": "Fail2ban",
                "up": f2b_ok,
                "uptime": None,
                "detail": f"{len(bans)} Adressen" if f2b_ok else (f2b_out or "keine Antwort")[:140],
            },
        ],
        "fail2ban": {"up": f2b_ok, "jails": jails, "banned": len(bans)},
        "traffic": {
            "hits": hits,
            "ips": ips,
            "countries": countries,
            "hour": hour,
            "kinds": kinds,
        },
        "general": {
            "name": SERVER.get("name") or "",
            "hostname": SERVER.get("hostname") or "",
            "hoster": SERVER.get("hoster_name") or SERVER.get("hoster") or "",
            "session_days": SESSION_DAYS,
        },
    }
    with _STATUS_LOCK:
        _STATUS_CACHE["t"] = now
        _STATUS_CACHE["data"] = data
    return data


def f2b_run(*args):
    cmd = [F2B_BIN, *args]
    if F2B_USE_SUDO:
        cmd = ["sudo", "-n", *cmd]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode == 0, out
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return False, str(exc)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, key_hex = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    check = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(check, stored)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def login_rate_ok(ip: str) -> bool:
    now = time.time()
    with LOGIN_LOCK:
        hits = [t for t in LOGIN_HITS.get(ip, []) if now - t < 900]
        if len(hits) >= 12:
            LOGIN_HITS[ip] = hits
            return False
        hits.append(now)
        LOGIN_HITS[ip] = hits
        return True


_SETUP_DONE = None
SETUP_CODE_PATH = DATA / "setup.code"
USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,31}$")
COMMON_PASSWORDS = {
    "password", "password1", "password123", "changeme", "livemap", "admin", "admin123",
    "qwerty", "qwerty123", "letmein", "welcome", "iloveyou", "12345678", "123456789",
    "1234567890", "passw0rd", "abc12345", "secret", "secret123",
}


def setting_get(key: str):
    row = DB.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def setting_put(key: str, value: str):
    DB.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def needs_setup() -> bool:
    global _SETUP_DONE
    if _SETUP_DONE is not None:
        return not _SETUP_DONE
    with db_lock:
        done = setting_get("setup_done") == "1"
    _SETUP_DONE = done
    return not done


def password_rank(password: str, username: str) -> tuple[int, str]:
    labels = ("Too short", "Weak", "Fair", "Good", "Strong")
    pw = password or ""
    if len(pw) < 12:
        return 0, labels[0]
    lowered = pw.lower()
    user = (username or "").strip().lower()
    if lowered in COMMON_PASSWORDS or (user and (lowered == user or user in lowered)):
        return 1, labels[1]
    classes = sum((
        any(ch.islower() for ch in pw),
        any(ch.isupper() for ch in pw),
        any(ch.isdigit() for ch in pw),
        any(not ch.isalnum() for ch in pw),
    ))
    if classes < 2:
        return 1, labels[1]
    if classes == 2:
        return 2, labels[2]
    if len(pw) < 16:
        return 3, labels[3]
    return 4, labels[4]


INVITE_DAYS = 7


def invite_secret() -> str:
    with db_lock:
        secret = setting_get("invite_secret")
        if secret:
            return secret
        secret = secrets.token_hex(32)
        setting_put("invite_secret", secret)
        DB.commit()
        return secret


def invite_binding(username: str, admin_name: str, admin_pw_hash: str, ip: str, token: str) -> str:
    material = "\n".join((username, admin_name, admin_pw_hash, ip, token))
    return hmac.new(invite_secret().encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


def find_invite(token: str):
    digest = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
    now = int(time.time())
    with db_lock:
        row = DB.execute(
            """SELECT username, role, binding, created_by, created_ip, admin_pw_hash, expires_at, used_at
               FROM invites WHERE token_hash = ? LIMIT 1""",
            (digest,),
        ).fetchone()
    if not row:
        return None
    username, role, binding, created_by, created_ip, admin_pw_hash, expires_at, used_at = row
    expected = invite_binding(username, created_by, admin_pw_hash, created_ip, token)
    if not hmac.compare_digest(binding, expected):
        return None
    if used_at or int(expires_at) < now:
        return None
    return {
        "username": username,
        "role": role or "viewer",
        "expires_at": int(expires_at),
    }


def setup_code_matches(code: str) -> bool:
    with db_lock:
        stored = setting_get("setup_code_hash") or ""
    digest = hashlib.sha256((code or "").strip().encode("utf-8")).hexdigest()
    if not stored:
        return False
    return hmac.compare_digest(stored, digest)


def ensure_setup_code():
    if not needs_setup():
        return
    with db_lock:
        stored = setting_get("setup_code_hash")
    if stored and SETUP_CODE_PATH.exists():
        print("einrichtung offen, code in data/setup.code", flush=True)
        return
    code = secrets.token_urlsafe(18)
    SETUP_CODE_PATH.write_text(code + "\n", encoding="utf-8")
    try:
        os.chmod(SETUP_CODE_PATH, 0o600)
    except OSError:
        pass
    with db_lock:
        setting_put("setup_code_hash", hashlib.sha256(code.encode("utf-8")).hexdigest())
        DB.commit()
    print("einrichtung offen, code in data/setup.code", flush=True)


def hoster_slug(value):
    text = re.sub(r"[^a-z0-9]", "", (value or "").strip().lower())
    if text in HOSTERS:
        return text
    for slug, label in HOSTERS.items():
        if re.sub(r"[^a-z0-9]", "", label.lower()) == text:
            return slug
    return ""


def apply_saved_server():
    with db_lock:
        name = setting_get("server_name")
        hoster_key = setting_get("server_hoster")
        hoster = setting_get("server_hoster_name")
        lat = setting_get("server_lat")
        lon = setting_get("server_lon")
    if name:
        SERVER["name"] = name
    picked = hoster_slug(hoster_key) or hoster_slug(hoster) or hoster_slug(SERVER.get("hoster"))
    if picked:
        SERVER["hoster"] = picked
        SERVER["hoster_name"] = HOSTERS[picked]
    elif hoster:
        SERVER["hoster"] = ""
        SERVER["hoster_name"] = hoster
    elif not hoster_slug(SERVER.get("hoster")):
        SERVER["hoster"] = ""
    try:
        if lat is not None:
            SERVER["lat"] = float(lat)
        if lon is not None:
            SERVER["lon"] = float(lon)
    except ValueError:
        pass


def ensure_admin_user():
    if needs_setup():
        return
    with db_lock:
        row = DB.execute("SELECT id FROM users LIMIT 1").fetchone()
        if row:
            return
        if not ADMIN_PASSWORD:
            return
        DB.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
            (ADMIN_USER, hash_password(ADMIN_PASSWORD), int(time.time())),
        )
        DB.commit()
    print(f"admin angelegt: {ADMIN_USER}", flush=True)


def create_session(user_id: int, ip: str, user_agent: str, remember: bool = True) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    span = SESSION_DAYS * 86400 if remember else 12 * 3600
    expires = now + span
    with db_lock:
        DB.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, ip, user_agent) "
            "VALUES (?,?,?,?,?,?)",
            (token_hash(token), user_id, now, expires, clip(ip, 64), clip(user_agent, 180)),
        )
        DB.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        DB.commit()
    return token


def destroy_session(token: str | None):
    if not token:
        return
    with db_lock:
        DB.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
        DB.commit()


def session_user(token: str | None):
    if not token:
        return None
    now = int(time.time())
    with db_lock:
        row = DB.execute(
            """SELECT u.id, u.username, COALESCE(u.role, 'admin'), s.expires_at
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token_hash = ? LIMIT 1""",
            (token_hash(token),),
        ).fetchone()
        if not row:
            return None
        if int(row[3]) < now:
            DB.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
            DB.commit()
            return None
    return {"id": row[0], "username": row[1], "role": row[2] or "admin"}


def parse_cookies(handler):
    raw = handler.headers.get("Cookie") or ""
    jar = http.cookies.SimpleCookie()
    try:
        jar.load(raw)
    except http.cookies.CookieError:
        return {}
    return {k: morsel.value for k, morsel in jar.items()}


def request_secure(handler) -> bool:
    proto = (handler.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    if proto == "https":
        return True
    return os.environ.get("LIVEMAP_SECURE_COOKIE", "1").strip() not in ("0", "false", "no")


def session_cookie_header(token: str, handler, clear=False, remember=True) -> str:
    parts = [
        f"{SESSION_COOKIE}={'' if clear else token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
    ]
    if clear:
        parts.append("Max-Age=0")
    elif remember:
        parts.append(f"Max-Age={SESSION_DAYS * 86400}")
    if request_secure(handler):
        parts.append("Secure")
    return "; ".join(parts)


_BAN_CACHE = {"t": 0.0, "data": {}}
_BAN_LOCK = threading.Lock()


def banned_map(force=False):
    now = time.time()
    with _BAN_LOCK:
        if not force and now - _BAN_CACHE["t"] < 20 and _BAN_CACHE["data"]:
            return _BAN_CACHE["data"]
    found = {}
    for jail in ACTION_JAILS:
        ok, out = f2b_run("get", jail, "banned")
        if not ok:
            continue
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out or ""):
            if ip4_to_int(ip) is None:
                continue
            jails = found.setdefault(ip, [])
            if jail not in jails:
                jails.append(jail)
    with _BAN_LOCK:
        _BAN_CACHE["t"] = now
        _BAN_CACHE["data"] = found
    return found


def f2b_banned(ip):
    banned = []
    for jail in ACTION_JAILS:
        ok, out = f2b_run("get", jail, "banned")
        if not ok:
            continue
        if re.search(rf"(?m)^\s*{re.escape(ip)}\s*$", out) or f"'{ip}'" in out or f'"{ip}"' in out:
            banned.append(jail)
    return banned


def local_ip_stats(ip):
    with db_lock:
        hit_rows = DB.execute(
            """SELECT kind, role, COUNT(*), MIN(ts), MAX(ts), SUM(bytes)
               FROM hits WHERE ip = ? GROUP BY kind, role""",
            (ip,),
        ).fetchall()
        ev_rows = DB.execute(
            "SELECT kind, COUNT(*), MIN(ts), MAX(ts) FROM events WHERE ip = ? GROUP BY kind",
            (ip,),
        ).fetchall()
        paths = DB.execute(
            """SELECT path, COUNT(*) AS c FROM hits
               WHERE ip = ? AND path != '' GROUP BY path ORDER BY c DESC LIMIT 8""",
            (ip,),
        ).fetchall()
    return {
        "hits": [
            {"kind": r[0], "role": r[1], "count": int(r[2]), "first": r[3], "last": r[4], "bytes": int(r[5] or 0)}
            for r in hit_rows
        ],
        "events": [
            {"kind": r[0], "count": r[1], "first": r[2], "last": r[3]}
            for r in ev_rows
        ],
        "paths": [{"path": r[0], "count": r[1]} for r in paths],
    }


def enrich_ip(ip):
    cc, name, lat, lon = place(ip)
    org_key, org_name = lookup_org(ip)
    whois = run_whois(ip)
    fields = whois.get("fields") or {}
    return {
        "ip": ip,
        "ptr": reverse_dns(ip),
        "geo": {"cc": cc or "", "name": name or "", "lat": lat, "lon": lon},
        "network": {"key": org_key, "name": org_name},
        "whois": fields,
        "whois_raw": whois.get("raw") or "",
        "stats": local_ip_stats(ip),
        "banned": f2b_banned(ip),
        "jails": ACTION_JAILS,
    }


def load_geo():
    codes = []
    index = {}
    starts = array.array("I")
    ends = array.array("I")
    ccs = array.array("H")
    lats = array.array("f")
    lons = array.array("f")
    path = CITY_PATH if CITY_PATH.exists() else GEO_PATH
    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) >= 8:
                start_s, end_s, _continent, code, _state, _city, lat_s, lon_s = row[:8]
            elif len(row) >= 3:
                start_s, end_s, code = row[:3]
                lat_s = lon_s = "0"
            else:
                continue
            code = code.strip().upper()
            if code in ("", "ZZ"):
                continue
            start = ip4_to_int(start_s.strip())
            end = ip4_to_int(end_s.strip())
            if start is None or end is None or end < start:
                continue
            try:
                lat = float(lat_s)
                lon = float(lon_s)
            except ValueError:
                lat = lon = 0.0
            if code not in index:
                index[code] = len(codes)
                codes.append(code)
            starts.append(start)
            ends.append(end)
            ccs.append(index[code])
            lats.append(lat)
            lons.append(lon)
    print(f"geo datei {path.name} bereiche {len(starts)}", flush=True)
    return starts, ends, ccs, codes, lats, lons


def lookup_place(ip):
    n = ip4_to_int(ip)
    if n is None or not geo_starts:
        return None, None, None
    i = bisect_right(geo_starts, n) - 1
    if i < 0 or n > geo_ends[i]:
        return None, None, None
    code = geo_codes[geo_ccs[i]]
    lat = float(geo_lats[i])
    lon = float(geo_lons[i])
    if lat == 0.0 and lon == 0.0:
        return code, None, None
    return code, lat, lon


def load_networks():
    starts = array.array("I")
    ends = array.array("I")
    keys = []
    labels = []
    if not NET_PATH.exists():
        return starts, ends, keys, labels
    for line in NET_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(",", 3)
        if len(parts) != 4:
            continue
        try:
            start = int(parts[0])
            end = int(parts[1])
        except ValueError:
            continue
        if end < start or start < 0 or end > 0xFFFFFFFF:
            continue
        starts.append(start)
        ends.append(end)
        keys.append(parts[2])
        labels.append(parts[3])
    return starts, ends, keys, labels


def lookup_org(ip):
    n = ip4_to_int(ip)
    if n is None or not net_starts:
        return "", ""
    i = bisect_right(net_starts, n) - 1
    if i < 0 or n > net_ends[i]:
        return "", ""
    return net_keys[i], net_labels[i]


def request_kind(path, ua):
    if PROBE_RE.search(path or "") or SCANNER_UA.search(ua or ""):
        return "probe"
    if ASSET_RE.search(path or ""):
        return "asset"
    return "page"


ip_activity = {}
activity_lock = threading.Lock()


def note_activity(ts, ip, path, status, kind):
    with activity_lock:
        bucket = ip_activity.setdefault(ip, [])
        bucket.append((int(ts), path or "", int(status or 0), kind or ""))
        cutoff = int(ts) - 45
        ip_activity[ip] = [item for item in bucket if item[0] >= cutoff][-120:]
        if len(ip_activity) > 8000:
            oldest = sorted(ip_activity.items(), key=lambda item: item[1][-1][0] if item[1] else 0)
            for dead, _ in oldest[:1000]:
                ip_activity.pop(dead, None)


def burst_verdict(ip, ts):
    with activity_lock:
        bucket = list(ip_activity.get(ip, []))
    recent = [item for item in bucket if item[0] >= int(ts) - 20]
    if len(recent) < 8:
        recent = [item for item in bucket if item[0] >= int(ts) - 35]
    # Normale Seitenaufrufe bleiben Besuche. Nur Fehlschläge und Sonden zählen als Burst.
    recent = [
        item for item in recent
        if not (item[3] in ("page", "asset") and 0 < item[2] < 400)
    ]
    if len(recent) < 6:
        return None
    paths = {item[1] for item in recent if item[1]}
    apis = {item[1] for item in recent if item[1].startswith("/api/")}
    fails = sum(1 for item in recent if item[2] >= 400)
    probes = sum(1 for item in recent if item[3] in ATTACK_KINDS or item[3] == "probe")
    n = len(recent)
    if probes >= 3 or fails >= 8 or n >= 28 or (len(apis) >= 5 and n >= 12):
        return "botnet", "", "Burst"
    if n >= 10 and (len(paths) >= 6 or len(apis) >= 3 or fails >= 4):
        return "burst", "burst", "Burst"
    if n >= 16:
        return "burst", "burst", "Burst"
    return None


def classify(ip, kind, path="", status=0, ts=None):
    key, label = lookup_org(ip)
    if key in BRANDS and key != "net":
        return "org", key, label
    if kind in ATTACK_KINDS:
        return "botnet", "", label
    stamp = int(ts or time.time())
    note_activity(stamp, ip, path, status, kind)
    burst = burst_verdict(ip, stamp)
    if burst:
        return burst
    if key == "net":
        return "org", "net", label
    return "traffic", "", ""


def clip(value, limit):
    value = (value or "").replace("\n", " ").strip()
    if len(value) > limit:
        return value[: limit - 1] + "…"
    return value


def log_host(path):
    name = path.name
    if name in FILE_HOSTS:
        return FILE_HOSTS[name]
    if name.endswith(".access.log"):
        stem = name[: -len(".access.log")]
        if "." in stem and not stem.startswith("."):
            return stem
    return ""


def referer_domain(referer: str) -> str:
    match = re.match(r"https?://([^/:]+)", referer or "", re.IGNORECASE)
    if not match:
        return ""
    host = match.group(1).lower().rstrip(".")
    if any(host == suffix or host.endswith("." + suffix) for suffix in SITE_SUFFIXES):
        return host
    return ""


def resolve_host(file_host: str, vhost: str, referer: str) -> str:
    name = (vhost or "").strip().lower().rstrip(".")
    if name and name not in ("-", "_") and "." in name and not name[0].isdigit():
        return clip(name, 120)
    if file_host:
        return file_host
    return referer_domain(referer)


def place(ip):
    code, lat, lon = lookup_place(ip)
    if code in CENTROIDS:
        country_lat, country_lon, name = CENTROIDS[code]
    else:
        country_lat = country_lon = None
        name = code or ""
    if lat is None:
        lat, lon = country_lat, country_lon
    if lat is None or lon is None:
        return code, name, None, None
    return code, name, round(lat, 3), round(lon, 3)


def connect():
    global DB_ENGINE
    db, engine, migrated = open_database(DATABASE_URL, DB_PATH)
    DB_ENGINE = engine
    if migrated != (0, 0):
        print(f"sqlite→postgres migriert: events={migrated[0]} hits={migrated[1]}", flush=True)
    print(f"datenbank {engine}", flush=True)
    return db


DB = None


def insert_event(ts, ip, kind, log=False):
    if not is_public(ip):
        return None
    ts = int(ts)
    cc, name, lat, lon = place(ip)
    row = None
    with db_lock:
        cur = DB.execute(
            "INSERT OR IGNORE INTO events (ts, ip, kind, cc, name, lat, lon) VALUES (?,?,?,?,?,?,?)",
            (ts, ip, kind, cc, name, lat, lon),
        )
        if cur.rowcount:
            DB.commit()
            row = {
                "id": cur.lastrowid,
                "ts": ts,
                "ip": ip,
                "kind": kind,
                "cc": cc or "",
                "name": name or cc or "",
                "lat": lat,
                "lon": lon,
            }
    if row:
        publish(row)
        if log:
            logged = make_hit(ts, ip, kind)
            if logged:
                flush_hits([logged], live=True)
    return row


def trim_hits():
    with db_lock:
        DB.execute(
            "DELETE FROM hits WHERE id NOT IN (SELECT id FROM hits ORDER BY ts DESC, id DESC LIMIT ?)",
            (HIT_KEEP,),
        )
        DB.commit()


def make_hit(ts, ip, kind, method="", path="", status=0, size=0, referer="", ua="", host=""):
    if not is_public(ip):
        return None
    cc, name, lat, lon = place(ip)
    role, org, org_name = classify(ip, kind, path=path, status=status, ts=ts)
    return {
        "ts": int(ts),
        "ip": ip,
        "kind": kind,
        "role": role,
        "org": org,
        "org_name": org_name,
        "cc": cc or "",
        "name": name or cc or "",
        "lat": lat,
        "lon": lon,
        "method": method,
        "path": clip(path, 180),
        "status": int(status or 0),
        "bytes": int(size or 0),
        "referer": clip(referer, 160),
        "ua": clip(ua, 180),
        "host": host,
    }


def hit_tuple(row):
    return (
        row["ts"], row["ip"], row["kind"], row["role"], row["org"], row["org_name"],
        row["cc"], row["name"], row["lat"], row["lon"], row["method"], row["path"],
        row["status"], row["bytes"], row["referer"], row["ua"], row["host"],
    )


HIT_SQL = """INSERT INTO hits
    (ts, ip, kind, role, org, org_name, cc, name, lat, lon, method, path, status, bytes, referer, ua, host)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""


def flush_hits(batch, live=False):
    if not batch:
        return
    with db_lock:
        DB.executemany(HIT_SQL, [hit_tuple(row) for row in batch])
        DB.commit()
    if live:
        for row in batch:
            publish(row)


def parse_nginx(line, host):
    match = NGINX_RE.match(line)
    if not match:
        return None
    ip = match.group("ip")
    if ip4_to_int(ip) is None:
        return None
    try:
        ts = int(datetime.strptime(match.group("ts"), NGINX_TS).timestamp())
    except ValueError:
        return None
    path = match.group("path") or "/"
    ua = match.group("ua") or ""
    referer = match.group("referer") or ""
    if referer == "-":
        referer = ""
    raw_bytes = match.group("bytes")
    try:
        size = 0 if raw_bytes in (None, "-") else int(raw_bytes)
    except ValueError:
        size = 0
    try:
        status = int(match.group("status"))
    except ValueError:
        status = 0
    kind = request_kind(path, ua)
    domain = resolve_host(host, match.groupdict().get("vhost") or "", referer)
    return make_hit(
        ts, ip, kind,
        method=match.group("method") or "",
        path=path,
        status=status,
        size=size,
        referer=referer,
        ua=ua,
        host=domain,
    )


def import_recent_hits():
    with db_lock:
        DB.execute("DELETE FROM hits")
        DB.commit()
    batch = []
    for path in NGINX_LOGS:
        if not path.exists():
            continue
        host = log_host(path)
        with path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 1_500_000))
            text = handle.read().decode("utf-8", "replace")
        for line in text.splitlines()[1:]:
            row = parse_nginx(line, host)
            if not row:
                continue
            batch.append(row)
            if len(batch) >= 400:
                flush_hits(batch, live=False)
                batch.clear()
    if batch:
        flush_hits(batch, live=False)
    trim_hits()
    with db_lock:
        count = DB.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
    print(f"zugriffe {count}", flush=True)


def publish(row):
    payload = json.dumps(row, ensure_ascii=False)
    with sub_lock:
        dead = []
        for sub in subscribers:
            try:
                sub.put_nowait(payload)
            except queue.Full:
                dead.append(sub)
        for sub in dead:
            if sub in subscribers:
                subscribers.remove(sub)


def parse_f2b_line(line):
    match = F2B_RE.match(line.strip())
    if not match:
        return None
    kind = JAIL_KIND.get(match.group("jail"))
    if not kind:
        return None
    ts = calendar.timegm(time.strptime(match.group(1), "%Y-%m-%d %H:%M:%S"))
    return ts, match.group("ip"), kind


def import_fail2ban():
    if not F2B_LOG.exists():
        return
    start = 0
    if OFFSET_PATH.exists():
        try:
            start = int(OFFSET_PATH.read_text().strip() or "0")
        except ValueError:
            start = 0
    size = F2B_LOG.stat().st_size
    if start > size:
        start = 0
    added = 0
    with F2B_LOG.open("r", errors="replace") as handle:
        handle.seek(start)
        batch = []
        for line in handle:
            parsed = parse_f2b_line(line)
            if not parsed:
                continue
            ts, ip, kind = parsed
            if not is_public(ip):
                continue
            cc, name, lat, lon = place(ip)
            batch.append((ts, ip, kind, cc, name, lat, lon))
            if len(batch) >= 500:
                added += flush_batch(batch)
                batch.clear()
        if batch:
            added += flush_batch(batch)
        end = handle.tell()
    OFFSET_PATH.write_text(str(end))
    print(f"fail2ban import +{added}", flush=True)


def flush_batch(batch):
    with db_lock:
        cur = DB.executemany(
            "INSERT OR IGNORE INTO events (ts, ip, kind, cc, name, lat, lon) VALUES (?,?,?,?,?,?,?)",
            batch,
        )
        DB.commit()
        return cur.rowcount if cur.rowcount is not None else 0


def follow_fail2ban():
    inode = None
    offset = 0
    if OFFSET_PATH.exists():
        try:
            offset = int(OFFSET_PATH.read_text().strip() or "0")
        except ValueError:
            offset = 0
    while True:
        try:
            if not F2B_LOG.exists():
                time.sleep(1)
                continue
            stat = F2B_LOG.stat()
            if inode is not None and inode != stat.st_ino:
                offset = 0
            if offset > stat.st_size:
                offset = 0
            inode = stat.st_ino
            with F2B_LOG.open("r", errors="replace") as handle:
                handle.seek(offset)
                while True:
                    line = handle.readline()
                    if not line:
                        offset = handle.tell()
                        OFFSET_PATH.write_text(str(offset))
                        time.sleep(0.5)
                        try:
                            now = F2B_LOG.stat()
                        except FileNotFoundError:
                            break
                        if now.st_ino != inode or now.st_size < offset:
                            break
                        continue
                    offset = handle.tell()
                    parsed = parse_f2b_line(line)
                    if parsed:
                        insert_event(*parsed, log=True)
        except Exception as exc:
            print(f"fail2ban tail: {exc}", flush=True)
            time.sleep(2)


def import_recent_probes():
    added = 0
    seen = {}
    for path in NGINX_LOGS:
        if not path.exists():
            continue
        with path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 8_000_000))
            text = handle.read().decode("utf-8", "replace")
        for line in text.splitlines()[1:]:
            match = NGINX_RE.match(line)
            if not match or not PROBE_RE.search(match.group("path")):
                continue
            ip = match.group("ip")
            try:
                ts = int(datetime.strptime(match.group("ts"), NGINX_TS).timestamp())
            except ValueError:
                continue
            slot = ts // 600
            key = (ip, slot)
            if key in seen:
                continue
            seen[key] = True
            if not is_public(ip):
                continue
            cc, name, lat, lon = place(ip)
            with db_lock:
                cur = DB.execute(
                    "INSERT OR IGNORE INTO events (ts, ip, kind, cc, name, lat, lon) VALUES (?,?,?,?,?,?,?)",
                    (ts, ip, "probe", cc, name, lat, lon),
                )
                added += 1 if cur.rowcount else 0
        with db_lock:
            DB.commit()
    print(f"nginx import +{added}", flush=True)


def follow_nginx():
    recent = {}
    states = {}
    pending = []
    stored = 0
    while True:
        try:
            for path in NGINX_LOGS:
                if not path.exists():
                    continue
                stat = path.stat()
                state = states.get(path)
                if state is None or state["ino"] != stat.st_ino or state["off"] > stat.st_size:
                    states[path] = {"ino": stat.st_ino, "off": stat.st_size}
                    continue
                if stat.st_size == state["off"]:
                    continue
                host = log_host(path)
                with path.open("r", errors="replace") as handle:
                    handle.seek(state["off"])
                    while True:
                        line = handle.readline()
                        if not line:
                            break
                        state["off"] = handle.tell()
                        row = parse_nginx(line, host)
                        if not row:
                            continue
                        pending.append(row)
                        if row["kind"] in ATTACK_KINDS:
                            now = time.time()
                            if now - recent.get(row["ip"], 0) >= 75:
                                recent[row["ip"]] = now
                                insert_event(row["ts"], row["ip"], row["kind"])
                                if len(recent) > 5000:
                                    cutoff = now - 600
                                    recent = {key: value for key, value in recent.items() if value >= cutoff}
                        if len(pending) >= 40:
                            flush_hits(pending, live=True)
                            stored += len(pending)
                            pending.clear()
            if pending:
                flush_hits(pending, live=True)
                stored += len(pending)
                pending.clear()
            if stored >= 200:
                trim_hits()
                stored = 0
            time.sleep(0.4)
        except Exception as exc:
            print(f"nginx tail: {exc}", flush=True)
            time.sleep(2)


def prune():
    cutoff = int(time.time()) - 21 * 86400
    with db_lock:
        DB.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        DB.commit()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def current_user(self):
        token = parse_cookies(self).get(SESSION_COOKIE)
        return session_user(token), token

    def require_auth(self, path: str):
        if path in PUBLIC_PATHS or path == "/api/logout":
            return True
        user, _ = self.current_user()
        if user:
            self.user = user
            return True
        if path.startswith("/api/"):
            self.json_error(401, "Login erforderlich")
        else:
            self.redirect("/login")
        return False

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self._head_only = True
        self.do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/setup/code":
            self.setup_code()
            return
        if path == "/api/setup":
            self.setup_finish()
            return
        if path == "/api/login":
            self.login()
            return
        if path == "/api/logout":
            self.logout()
            return
        if path == "/api/invite/open":
            self.invite_open()
            return
        if path == "/api/invite/finish":
            self.invite_finish()
            return
        if not self.require_auth(path):
            return
        if path == "/api/action":
            self.action()
        elif path == "/api/password":
            self.change_password()
        elif path == "/api/users":
            self.users_create()
        elif path == "/api/users/revoke":
            self.users_revoke()
        elif path == "/api/setup/reset":
            self.setup_reset()
        else:
            self.send_error(404)

    def do_GET(self):
        if not getattr(self, "_head_only", False):
            self._head_only = False
        path = urlparse(self.path).path
        if needs_setup() and path in ("/", "/index.html", "/login", "/login.html"):
            self.redirect("/setup")
            return
        if path in ("/setup", "/setup.html"):
            if not needs_setup():
                self.redirect("/login")
                return
            self.file(STATIC / "setup.html", "text/html; charset=utf-8")
            return
        if path == "/api/setup":
            self.setup_state()
            return
        if path in ("/login", "/login.html"):
            user, _ = self.current_user()
            if user:
                self.redirect("/")
                return
            self.file(STATIC / "login.html", "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self.bytes(b'{"ok":true}', "application/json")
            return
        if path == "/api/host":
            self.host_public()
            return
        if path == "/robots.txt":
            self.bytes(
                b"User-agent: *\nDisallow: /invite\n",
                "text/plain; charset=utf-8",
                {"Cache-Control": "public, max-age=86400"},
            )
            return
        if path == "/invite" or path.startswith("/invite/"):
            self.file(
                STATIC / "invite.html",
                "text/html; charset=utf-8",
                extra={"X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet", "Referrer-Policy": "no-referrer"},
            )
            return
        if path == "/world.geojson":
            self.file(DATA / "world.geojson", "application/geo+json", "public, max-age=86400")
            return
        if path in ("/favicon.svg", "/logo.svg", "/favicon.png", "/logo.png", "/logo-dark.png"):
            name = path.lstrip("/")
            kind = "image/png" if name.endswith(".png") else "image/svg+xml"
            self.file(STATIC / name, kind, "public, max-age=86400")
            return
        if path == "/app.css":
            self.file(STATIC / "app.css", "text/css; charset=utf-8")
            return
        if path == "/login-demo.js":
            self.file(STATIC / "login-demo.js", "text/javascript; charset=utf-8")
            return
        if re.fullmatch(r"/flags/[a-z]{2}\.svg", path):
            self.file(STATIC / "flags" / path.rsplit("/", 1)[1], "image/svg+xml", "public, max-age=86400")
            return
        if not self.require_auth(path):
            return
        if path == "/api/bootstrap":
            self.bootstrap()
        elif path == "/api/bans":
            self.bans()
        elif path == "/api/status":
            self.status()
        elif path == "/api/users":
            self.users_list()
        elif path == "/api/stream":
            self.stream()
        elif path == "/api/ip":
            self.ip_lookup()
        elif path in ("/", "/index.html"):
            self.file(STATIC / "index.html", "text/html; charset=utf-8")
        elif path == "/app.js":
            self.file(STATIC / "app.js", "text/javascript; charset=utf-8")
        elif re.fullmatch(r"/marks/[a-z0-9-]+\.svg", path):
            self.file(STATIC / "marks" / path.rsplit("/", 1)[1], "image/svg+xml", "public, max-age=86400")
        else:
            self.send_error(404)

    def read_json(self, limit=8000):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > limit:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeError):
            return None

    def setup_state(self):
        if not needs_setup():
            self.bytes(b'{"needed":false}', "application/json")
            return
        payload = json.dumps({
            "needed": True,
            "name": SERVER.get("name") or "",
            "hoster": hoster_slug(SERVER.get("hoster")) or hoster_slug(SERVER.get("hoster_name")) or "",
            "lat": SERVER.get("lat"),
            "lon": SERVER.get("lon"),
        }, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def setup_code(self):
        if not needs_setup():
            self.json_error(404, "Einrichtung ist schon fertig")
            return
        ip = client_ip(self)
        if not login_rate_ok(ip):
            self.json_error(429, "Zu viele Versuche, später erneut")
            return
        body = self.read_json()
        if not isinstance(body, dict):
            self.json_error(400, "JSON ungültig")
            return
        if not setup_code_matches(body.get("code") or ""):
            time.sleep(0.35)
            self.json_error(401, "Einrichtungscode stimmt nicht")
            return
        self.bytes(b'{"ok":true}', "application/json")

    def setup_finish(self):
        global _SETUP_DONE
        if not needs_setup():
            self.json_error(404, "Einrichtung ist schon fertig")
            return
        ip = client_ip(self)
        if not login_rate_ok(ip):
            self.json_error(429, "Zu viele Versuche, später erneut")
            return
        body = self.read_json()
        if not isinstance(body, dict):
            self.json_error(400, "JSON ungültig")
            return
        code = body.get("code") or ""
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        again = body.get("again") or ""
        name = (body.get("name") or "").strip()
        hoster = hoster_slug(body.get("hoster") or "")
        if not setup_code_matches(code):
            time.sleep(0.35)
            self.json_error(401, "Einrichtungscode stimmt nicht")
            return
        if not USER_RE.fullmatch(username):
            self.json_error(400, "Benutzer: Buchstabe, dann 2 bis 31 Zeichen aus Buchstaben, Ziffern, _ oder -")
            return
        if password != again:
            self.json_error(400, "Passwörter stimmen nicht überein")
            return
        rank, _label = password_rank(password, username)
        if rank < 3:
            self.json_error(400, "Passwort ist zu schwach")
            return
        if not name or len(name) > 60 or not hoster:
            self.json_error(400, "Name und Anbieter ausfüllen")
            return
        try:
            lat = float(body.get("lat"))
            lon = float(body.get("lon"))
        except (TypeError, ValueError):
            self.json_error(400, "Standort ungültig")
            return
        if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            self.json_error(400, "Standort ungültig")
            return
        now = int(time.time())
        hashed = hash_password(password)
        with db_lock:
            if setting_get("setup_done") == "1":
                self.json_error(404, "Einrichtung ist schon fertig")
                return
            row = DB.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
            if row:
                uid = row[0]
                DB.execute(
                    "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
                    (username, hashed, uid),
                )
            else:
                DB.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                    (username, hashed, now),
                )
                uid = DB.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
            DB.execute("DELETE FROM sessions")
            setting_put("setup_done", "1")
            setting_put("server_name", name)
            setting_put("server_hoster", hoster)
            setting_put("server_hoster_name", HOSTERS[hoster])
            setting_put("server_lat", str(lat))
            setting_put("server_lon", str(lon))
            DB.execute("DELETE FROM settings WHERE key = ?", ("setup_code_hash",))
            DB.commit()
        _SETUP_DONE = True
        SERVER["name"] = name
        SERVER["hoster"] = hoster
        SERVER["hoster_name"] = HOSTERS[hoster]
        SERVER["lat"] = lat
        SERVER["lon"] = lon
        try:
            SETUP_CODE_PATH.unlink()
        except OSError:
            pass
        token = create_session(uid, ip, self.headers.get("User-Agent") or "")
        payload = json.dumps({"ok": True, "user": {"id": uid, "username": username}}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", session_cookie_header(token, self))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def login(self):
        ip = client_ip(self)
        if not login_rate_ok(ip):
            self.json_error(429, "Zu viele Versuche – später erneut")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4000:
            self.json_error(400, "Leerer Request")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeError):
            self.json_error(400, "JSON ungültig")
            return
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not username or not password:
            self.json_error(400, "Benutzer und Passwort nötig")
            return
        with db_lock:
            row = DB.execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if not row or not verify_password(password, row[1]):
            time.sleep(0.35)
            self.json_error(401, "Login fehlgeschlagen")
            return
        remember = True if "remember" not in body else bool(body.get("remember"))
        token = create_session(row[0], ip, self.headers.get("User-Agent") or "", remember=remember)
        payload = json.dumps({"ok": True, "user": {"id": row[0], "username": username}}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", session_cookie_header(token, self, remember=remember))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def change_password(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4000:
            self.json_error(400, "Leerer Request")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeError):
            self.json_error(400, "JSON ungültig")
            return
        current = body.get("current") or ""
        new = body.get("password") or ""
        if len(new) < 8:
            self.json_error(400, "Mindestens 8 Zeichen")
            return
        if new == current:
            self.json_error(400, "Neues Passwort ist identisch")
            return
        with db_lock:
            row = DB.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (self.user["id"],),
            ).fetchone()
        if not row or not verify_password(current, row[0]):
            time.sleep(0.35)
            self.json_error(400, "Aktuelles Passwort stimmt nicht")
            return
        with db_lock:
            DB.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(new), self.user["id"]),
            )
            DB.commit()
        self.bytes(b'{"ok":true}', "application/json; charset=utf-8")

    def require_admin(self) -> bool:
        if (self.user or {}).get("role") == "admin":
            return True
        self.json_error(403, "Nur die Administration")
        return False

    def public_origin(self) -> str:
        proto = (self.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip() or "https"
        host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "livemap.infynnite.de").split(",")[0].strip()
        return f"{proto}://{host}"

    def invite_open(self):
        ip = client_ip(self)
        if not login_rate_ok(ip):
            self.json_error(429, "Zu viele Versuche, später erneut")
            return
        body = self.read_json()
        if not isinstance(body, dict):
            self.json_error(400, "JSON ungültig")
            return
        invite = find_invite((body.get("token") or "").strip())
        if not invite:
            time.sleep(0.2)
            self.json_error(404, "Einladung ungültig")
            return
        payload = json.dumps({"ok": True, "username": invite["username"]}, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def invite_finish(self):
        ip = client_ip(self)
        if not login_rate_ok(ip):
            self.json_error(429, "Zu viele Versuche, später erneut")
            return
        body = self.read_json()
        if not isinstance(body, dict):
            self.json_error(400, "JSON ungültig")
            return
        token = (body.get("token") or "").strip()
        password = body.get("password") or ""
        again = body.get("again") or ""
        invite = find_invite(token)
        if not invite:
            time.sleep(0.2)
            self.json_error(404, "Einladung ungültig")
            return
        if password != again:
            self.json_error(400, "Passwörter stimmen nicht überein")
            return
        rank, _label = password_rank(password, invite["username"])
        if rank < 3:
            self.json_error(400, "Passwort ist zu schwach")
            return
        now = int(time.time())
        hashed = hash_password(password)
        token_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with db_lock:
            fresh = find_invite(token)
            if not fresh:
                self.json_error(404, "Einladung ungültig")
                return
            exists = DB.execute("SELECT id FROM users WHERE username = ?", (fresh["username"],)).fetchone()
            if exists:
                self.json_error(409, "Dieses Konto gibt es schon")
                return
            DB.execute(
                "INSERT INTO users (username, password_hash, created_at, role) VALUES (?,?,?,?)",
                (fresh["username"], hashed, now, "viewer"),
            )
            DB.execute("UPDATE invites SET used_at = ? WHERE token_hash = ?", (now, token_digest))
            row = DB.execute("SELECT id FROM users WHERE username = ?", (fresh["username"],)).fetchone()
            DB.commit()
        session = create_session(row[0], ip, self.headers.get("User-Agent") or "", remember=True)
        payload = json.dumps({"ok": True, "username": fresh["username"]}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", session_cookie_header(session, self, remember=True))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def users_list(self):
        if not self.require_admin():
            return
        now = int(time.time())
        with db_lock:
            users = DB.execute(
                "SELECT username, COALESCE(role, 'admin'), created_at FROM users ORDER BY id"
            ).fetchall()
            invites = DB.execute(
                """SELECT username, created_at, expires_at FROM invites
                   WHERE used_at IS NULL AND expires_at >= ? ORDER BY created_at DESC""",
                (now,),
            ).fetchall()
        payload = json.dumps({
            "ok": True,
            "users": [
                {"username": row[0], "role": row[1] or "admin", "created_at": int(row[2] or 0)}
                for row in users
            ],
            "invites": [
                {"username": row[0], "created_at": int(row[1]), "expires_at": int(row[2])}
                for row in invites
            ],
        }, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def users_create(self):
        if not self.require_admin():
            return
        body = self.read_json()
        if not isinstance(body, dict):
            self.json_error(400, "JSON ungültig")
            return
        username = (body.get("username") or "").strip()
        if not USER_RE.fullmatch(username):
            self.json_error(400, "Benutzer: Buchstabe, dann 2 bis 31 Zeichen aus Buchstaben, Ziffern, _ oder -")
            return
        if username.lower() == (self.user.get("username") or "").lower():
            self.json_error(400, "Das eigene Konto ist schon da")
            return
        ip = client_ip(self)
        now = int(time.time())
        expires = now + INVITE_DAYS * 86400
        token = secrets.token_urlsafe(32)
        with db_lock:
            taken = DB.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if taken:
                self.json_error(409, "Dieses Konto gibt es schon")
                return
            admin = DB.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (self.user["id"],),
            ).fetchone()
            if not admin:
                self.json_error(403, "Nur die Administration")
                return
            binding = invite_binding(username, self.user["username"], admin[0], ip, token)
            DB.execute("DELETE FROM invites WHERE username = ? AND used_at IS NULL", (username,))
            DB.execute(
                """INSERT INTO invites
                   (username, role, token_hash, binding, created_by, created_ip, admin_pw_hash, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    username,
                    "viewer",
                    hashlib.sha256(token.encode("utf-8")).hexdigest(),
                    binding,
                    self.user["username"],
                    clip(ip, 64),
                    admin[0],
                    now,
                    expires,
                ),
            )
            DB.commit()
        url = f"{self.public_origin()}/invite/{token}"
        payload = json.dumps({
            "ok": True,
            "username": username,
            "url": url,
            "expires_at": expires,
        }, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def users_revoke(self):
        if not self.require_admin():
            return
        body = self.read_json()
        if not isinstance(body, dict):
            self.json_error(400, "JSON ungültig")
            return
        username = (body.get("username") or "").strip()
        with db_lock:
            DB.execute("DELETE FROM invites WHERE username = ? AND used_at IS NULL", (username,))
            DB.commit()
        self.bytes(b'{"ok":true}', "application/json; charset=utf-8")

    def setup_reset(self):
        global _SETUP_DONE
        if not self.require_admin():
            return
        code = secrets.token_urlsafe(18)
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        with db_lock:
            DB.execute("DELETE FROM sessions")
            DB.execute("DELETE FROM invites")
            DB.execute("DELETE FROM users")
            setting_put("setup_done", "0")
            setting_put("setup_code_hash", digest)
            DB.commit()
        SETUP_CODE_PATH.write_text(code + "\n", encoding="utf-8")
        try:
            os.chmod(SETUP_CODE_PATH, 0o600)
        except OSError:
            pass
        _SETUP_DONE = False
        payload = json.dumps({"ok": True, "code": code}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", session_cookie_header("", self, clear=True))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def logout(self):
        _, token = self.current_user()
        destroy_session(token)
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", session_cookie_header("", self, clear=True))
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def json_error(self, code, message):
        payload = json.dumps({"ok": False, "error": message}, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def ip_lookup(self):
        query = parse_qs(urlparse(self.path).query)
        ip = (query.get("ip") or [""])[0].strip()
        if not IPV4_RE.fullmatch(ip) or ip4_to_int(ip) is None:
            self.json_error(400, "Ungültige Adresse")
            return
        if not known_ip(ip) and not actions_allowed(self):
            self.json_error(404, "Adresse unbekannt")
            return
        payload = json.dumps({"ok": True, "lookup": enrich_ip(ip), "actions": actions_allowed(self)}, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def action(self):
        if not actions_allowed(self):
            if getattr(self, "user", None) and self.user.get("role") != "admin":
                self.json_error(403, "Dieses Konto kann nur zusehen")
            else:
                self.json_error(403, "Aktionen nur aus erlaubten Netzen")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4000:
            self.json_error(400, "Leerer Request")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeError):
            self.json_error(400, "JSON ungültig")
            return
        op = (body.get("op") or "").strip()
        ip = (body.get("ip") or "").strip()
        jail = (body.get("jail") or "sshd").strip()
        if not IPV4_RE.fullmatch(ip) or ip4_to_int(ip) is None:
            self.json_error(400, "Ungültige Adresse")
            return
        if ip in OWN_IPS:
            self.json_error(400, "Eigene Adresse")
            return
        if jail not in ACTION_JAILS:
            self.json_error(400, "Jail nicht erlaubt")
            return
        if op == "ban":
            ok, out = f2b_run("set", jail, "banip", ip)
        elif op == "unban":
            ok, out = f2b_run("set", jail, "unbanip", ip)
        else:
            self.json_error(400, "Unbekannte Aktion")
            return
        with _BAN_LOCK:
            _BAN_CACHE["t"] = 0.0
        payload = json.dumps(
            {"ok": ok, "op": op, "ip": ip, "jail": jail, "output": clip(out, 400), "banned": f2b_banned(ip)},
            ensure_ascii=False,
        ).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def bytes(self, data, content_type, extra=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if not (extra and "Cache-Control" in extra):
            self.send_header("Cache-Control", "no-cache")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(data)

    def file(self, path, content_type, cache="no-cache", extra=None):
        if not path.exists():
            self.send_error(404)
            return
        data = path.read_bytes()
        headers = dict(extra or {})
        if cache != "no-cache":
            headers["Cache-Control"] = cache
        self.bytes(data, content_type, headers or None)

    def host_public(self):
        payload = json.dumps({
            "name": SERVER.get("name") or "",
            "hostname": SERVER.get("hostname") or "",
            "ipv4": SERVER.get("ipv4") or "",
            "hoster": SERVER.get("hoster_name") or SERVER.get("hoster") or "",
            "lat": SERVER.get("lat"),
            "lon": SERVER.get("lon"),
        }, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def status(self):
        payload = json.dumps(service_status(), ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def bootstrap(self):
        with db_lock:
            rows = DB.execute(
                "SELECT ts, ip, kind, cc, name, lat, lon FROM events ORDER BY ts ASC"
            ).fetchall()
        events = [
            {"ts": r[0], "ip": r[1], "kind": r[2], "cc": r[3] or "", "name": r[4] or "", "lat": r[5], "lon": r[6]}
            for r in rows
        ]
        with db_lock:
            hit_rows = DB.execute(
                """SELECT ts, ip, kind, role, org, org_name, cc, name, lat, lon,
                          method, path, status, bytes, referer, ua, host
                   FROM hits ORDER BY ts ASC"""
            ).fetchall()
        hits = [
            {
                "ts": r[0], "ip": r[1], "kind": r[2], "role": r[3], "org": r[4] or "",
                "org_name": r[5] or "", "cc": r[6] or "", "name": r[7] or "",
                "lat": r[8], "lon": r[9], "method": r[10] or "", "path": r[11] or "",
                "status": r[12] or 0, "bytes": r[13] or 0, "referer": r[14] or "",
                "ua": r[15] or "", "host": r[16] or "",
            }
            for r in hit_rows
        ]
        SERVER["version"] = app_version()
        payload = json.dumps(
            {
                "server": SERVER,
                "events": events,
                "hits": hits,
                "user": {
                    "username": self.user["username"],
                    "ip": client_ip(self),
                    "role": self.user.get("role") or "admin",
                },
                "actions": actions_allowed(self),
                "jails": ACTION_JAILS,
                "bans": banned_map(),
            },
            ensure_ascii=False,
        ).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def bans(self):
        payload = json.dumps({"ok": True, "bans": banned_map()}, ensure_ascii=False).encode()
        self.bytes(payload, "application/json; charset=utf-8")

    def stream(self):
        q = queue.Queue(maxsize=400)
        with sub_lock:
            subscribers.append(q)
        self.protocol_version = "HTTP/1.0"
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.wfile.write(b": ok\n\n")
            self.wfile.flush()
            while True:
                try:
                    item = q.get(timeout=15)
                    self.wfile.write(f"data: {item}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        finally:
            with sub_lock:
                if q in subscribers:
                    subscribers.remove(q)


def relocate_events():
    with db_lock:
        ips = [row[0] for row in DB.execute("SELECT DISTINCT ip FROM events").fetchall()]
    updates = []
    for ip in ips:
        cc, name, lat, lon = place(ip)
        if lat is None:
            continue
        updates.append((lat, lon, cc or "", name or "", ip))
    if not updates:
        return
    with db_lock:
        DB.executemany("UPDATE events SET lat = ?, lon = ?, cc = ?, name = ? WHERE ip = ?", updates)
        DB.commit()
    print(f"orte aktualisiert {len(updates)}", flush=True)


def main():
    global DB, geo_starts, geo_ends, geo_ccs, geo_codes, geo_lats, geo_lons, net_starts, net_ends, net_keys, net_labels
    DATA.mkdir(parents=True, exist_ok=True)
    print("lade orte", flush=True)
    geo_starts, geo_ends, geo_ccs, geo_codes, geo_lats, geo_lons = load_geo()
    net_starts, net_ends, net_keys, net_labels = load_networks()
    print(f"geo-bereiche {len(geo_starts)} netze {len(net_starts)}", flush=True)
    DB = connect()
    ensure_setup_code()
    ensure_admin_user()
    apply_saved_server()
    prune()
    import_fail2ban()
    import_recent_probes()
    import_recent_hits()
    relocate_events()
    threading.Thread(target=follow_fail2ban, daemon=True).start()
    threading.Thread(target=follow_nginx, daemon=True).start()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"lagekarte http://{HOST}:{PORT} auth=on db={DB_ENGINE}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
