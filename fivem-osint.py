#!/usr/bin/env python3
"""
FiveM OSINT — FiveM Server Intelligence Suite (single unified tool).

Interactive menu mode:            python fivem-osint.py
CLI mode (all modules):           python fivem-osint.py profile 6r9ob4
                                  python fivem-osint.py players cfx.re/join/6r9ob4
                                  python fivem-osint.py batch codes.txt --out report.csv

Modules
  1 profile     full OSINT profile (API + endpoint probe + geo + owner + discord + mastodon)
  2 players     dump all online players (id / name / ping)
  3 resources   dump resources + framework detection
  4 scan        security / exposure scan (incl. TCP port check + RDAP)
  5 owner       owner account OSINT (forum profile, license-token cross-ref)
  6 discord     resolve the server Discord invite
  7 media       download icon + banners
  8 history     snapshot tracking (SQLite)
  9 batch       many codes -> CSV report
  10 raw         raw API JSON dump
  11 deep        deep OSINT: DNS records, TLS certs, CDN detection, reverse-IP,
                 certificate-transparency subdomains, player identifiers decoding,
                 GitHub linkage

All data comes from publicly exposed endpoints only:
  Cfx.re servers API, the game server's own /info.json, Discord, Cfx forum,
  Mastodon, ip-api.com, RDAP.
Unofficial. Not affiliated with Cfx.re / Rockstar / FiveM. Use responsibly.
"""

import argparse
import base64
import ctypes
import json
import os
import re
import socket
import ssl
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
API_ENDPOINTS = [
    "https://frontend.cfx-services.net/api/servers/single/{code}",
    "https://servers-frontend.fivem.net/api/servers/single/{code}",
]
GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
RDAP_API = "https://rdap.org/ip/{ip}"
DISCORD_API = "https://discord.com/api/v9/invites/{code}?with_counts=true&with_expiration=true"
FORUM_API = "https://forum.cfx.re/u/{user}.json"
MASTODON_LOOKUP = "https://{instance}/api/v1/accounts/lookup?acct={acct}"
HT_API = "https://api.hackertarget.com/{endpoint}?q={q}"
CRT_API = "https://crt.sh/?q={q}&output=json"
GITHUB_API = "https://api.github.com/search/repositories?q={q}&per_page=5"
WEB_PORTS = [80, 443, 8080, 8443, 8888, 40120]

CDN_PATTERNS = [
    ("Cloudflare", ["cloudflare", "cf-ray", "__cfduid"]),
    ("CloudFront (AWS)", ["cloudfront", "x-amz-cf"]),
    ("Akamai", ["akamai"]),
    ("Fastly", ["fastly", "x-served-by: cache"]),
    ("CDN77", ["cdn77"]),
    ("KeyCDN", ["keycdn"]),
    ("StackPath", ["stackpath", "stackcdn"]),
    ("Vercel", ["vercel"]),
    ("Netlify", ["netlify"]),
    ("GitHub Pages", ["github.io", "github.com"]),
    ("Discord CDN", ["cdn.discord", "discordapp.com"]),
    ("ImageKit", ["imagekit"]),
    ("FiveManage", ["fivemanage"]),
    ("Cfx.re CDN", ["imgproxy.cfx.re", "cfx.re"]),
    ("OVH", ["ovh"]),
    ("Hetzner", ["hetzner"]),
    ("Ionos", ["ionos"]),
    ("Contabo", ["contabo"]),
]

COLOR_RE = re.compile(r"\^[0-9a-zA-Z]")
SKIP_TOKENS = {"http", "https", "www", "cfx", "re", "join", "fivem", "com"}
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivem-osint.db")

# ---------------------------------------------------------------- colors
ENABLE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "black": "\033[30m", "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m", "white": "\033[37m",
    "bg_red": "\033[41m",
    "b_red": "\033[1;31m", "b_green": "\033[1;32m", "b_yellow": "\033[1;33m",
    "b_blue": "\033[1;34m", "b_magenta": "\033[1;35m", "b_cyan": "\033[1;36m",
    "b_white": "\033[1;37m",
}


def c(code, text):
    if not ENABLE_COLOR:
        return text
    return f"{ANSI.get(code, '')}{text}{ANSI['reset']}"


def enable_vt():
    if os.name != "nt":
        return
    try:
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


SEV_COLORS = {"CRIT": "b_red", "HIGH": "b_red", "MED": "b_yellow", "LOW": "b_blue", "INFO": "dim"}
SEV_MARK = {"CRIT": "[x]", "HIGH": "[!]", "MED": "[i]", "LOW": "[.]", "INFO": "[-]"}

# ---------------------------------------------------------------- helpers
def clean(s):
    return COLOR_RE.sub("", s or "").strip()


def http_get(url, timeout=15, binary=False, insecure=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            if binary:
                return body
            return body.decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLError) and not insecure:
            return http_get(url, timeout, binary, insecure=True)
        raise


def http_get_json(url, timeout=15):
    return json.loads(http_get(url, timeout))


def extract_code(text):
    if not text:
        return None
    text = urllib.parse.unquote(text.strip()).lower()
    for prefix in ("cfx.re/join/", "fivem://connect/"):
        if prefix in text:
            tail = text.split(prefix, 1)[1]
            m = re.search(r"[a-z0-9]{5,8}", tail)
            if m:
                return m.group(0)
    text = re.sub(r"^[a-z]+://", "", text)
    for tok in re.split(r"[^a-z0-9]+", text):
        if len(tok) >= 5 and tok not in SKIP_TOKENS:
            return tok
    return None


def split_endpoint(ep):
    host = ep
    scheme = ""
    if "://" in host:
        scheme, host = host.split("://", 1)
    port = None
    if ":" in host:
        host, port = host.rsplit(":", 1)
        try:
            port = int(port)
        except ValueError:
            port = None
    return host, port, scheme


def host_to_ip(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def tcp_check(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- API lookups
def api_lookup(code, timeout):
    last = None
    for tpl in API_ENDPOINTS:
        try:
            payload = http_get_json(tpl.format(code=code), timeout)
            if payload.get("Data") is not None:
                return {"ok": True, "data": payload["Data"], "raw": payload}
            last = payload.get("error") or "unknown API error"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
        except (urllib.error.URLError, ValueError) as e:
            last = str(e)
    return {"ok": False, "error": f"all Cfx API endpoints failed: {last}"}


def probe_info_json(endpoint, timeout=6):
    host, port, _ = split_endpoint(endpoint)
    if not host:
        return {"status": "invalid", "error": "no host"}
    port = port or 30120
    out = {"host": host, "port": port}
    url = f"http://{host}:{port}/info.json"
    t0 = time.time()
    try:
        body = http_get(url, timeout)
        out.update({"status": "open", "elapsed": round(time.time() - t0, 2)})
        try:
            out["data"] = json.loads(body)
        except ValueError:
            out.update({"status": "open-nonjson", "preview": body[:200]})
    except urllib.error.HTTPError as e:
        out.update({"status": f"http-{e.code}", "elapsed": round(time.time() - t0, 2)})
    except urllib.error.URLError as e:
        out.update({"status": "blocked", "error": str(e.reason), "elapsed": round(time.time() - t0, 2)})
    except socket.timeout:
        out.update({"status": "blocked", "error": "timeout", "elapsed": round(time.time() - t0, 2)})
    return out


def geo_lookup(ip, timeout=10):
    if not ip:
        return None
    if ip.startswith(("10.", "127.", "192.168.")) or ip in ("0.0.0.0", "255.255.255.255"):
        return None
    try:
        return http_get_json(GEO_API.format(ip=ip), timeout)
    except Exception:
        return None


def rdns(ip, timeout=3):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def rdap_lookup(ip, timeout=8):
    if not ip:
        return None
    try:
        d = http_get_json(RDAP_API.format(ip=ip), timeout)
        out = {
            "network": d.get("name"),
            "country": d.get("country"),
            "handle": d.get("handle"),
            "type": d.get("type"),
        }
        ent = []
        for e in (d.get("entities") or []):
            for vc in (e.get("vcardArray") or [None, []])[1]:
                if vc and len(vc) >= 3 and vc[0] == "fn":
                    ent.append(vc[3])
        out["registrants"] = ent
        return out
    except Exception:
        return None


def discord_info(invite_code, timeout=10):
    if not invite_code:
        return None
    code = re.sub(r"^.*discord\.(gg|com/invite)/", "", invite_code.strip()).split("/")[0].split("?")[0]
    try:
        d = http_get_json(DISCORD_API.format(code=code), timeout)
        guild = d.get("guild") or {}
        return {
            "code": code,
            "guild_id": guild.get("id"),
            "name": guild.get("name"),
            "icon": guild.get("icon"),
            "members": d.get("approximate_member_count"),
            "online": d.get("approximate_presence_count"),
            "channel": (d.get("channel") or {}).get("name"),
            "guild_features": guild.get("features"),
        }
    except Exception as e:
        return {"code": code, "error": str(e)}


def forum_user(username, timeout=10):
    if not username:
        return None
    try:
        u = http_get_json(FORUM_API.format(user=urllib.parse.quote(username)), timeout).get("user", {})
        return {
            "username": u.get("username"),
            "id": u.get("id"),
            "title": u.get("title"),
            "name": u.get("name"),
            "avatar_template": u.get("avatar_template"),
            "profile_url": f"https://forum.cfx.re/u/{u.get('username') or username}",
        }
    except Exception as e:
        return {"username": username, "error": str(e)}


def mastodon_info(handle, timeout=8):
    if not handle or "@" not in handle:
        return None
    acct, instance = handle.rsplit("@", 1)
    if not instance or "." not in instance:
        return None
    try:
        a = http_get_json(MASTODON_LOOKUP.format(instance=instance, acct=acct), timeout)
        return {
            "handle": handle,
            "display_name": a.get("display_name"),
            "followers": a.get("followers_count"),
            "following": a.get("following_count"),
            "posts": a.get("statuses_count"),
            "created_at": a.get("created_at"),
            "url": a.get("url"),
        }
    except Exception:
        return None


# ---------------------------------------------------------------- deep intel helpers
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
EXCLUDED_TLDS = {"local", "localhost", "onion"}


def extract_domains(*texts):
    out = set()
    for t in texts:
        if not t:
            continue
        for m in DOMAIN_RE.findall(t):
            d = m.strip(".").lower()
            tld = d.rsplit(".", 1)[-1]
            if tld in EXCLUDED_TLDS or d.count(".") < 1:
                continue
            out.add(d)
    return sorted(out)


def ht(endpoint, q, timeout=12):
    if not q:
        return None
    try:
        body = http_get(HT_API.format(endpoint=endpoint, q=urllib.parse.quote(q)), timeout)
        low = body.lower()
        if "api count exceeded" in low or low.startswith("error"):
            return None
        return body.strip()
    except Exception:
        return None


def dns_records(domain, timeout=12):
    body = ht("dnslookup", domain, timeout)
    if not body:
        return None
    recs = {}
    for line in body.splitlines():
        if ":" not in line:
            continue
        kind, _, val = line.partition(":")
        recs.setdefault(kind.strip(), []).append(val.strip())
    return recs or None


def hostsearch(domain, timeout=12):
    body = ht("hostsearch", domain, timeout)
    if not body:
        return None
    return [line.split(",")[0].strip() for line in body.splitlines() if "," in line]


def reverse_ip(ip, timeout=12):
    body = ht("reverseiplookup", ip, timeout)
    if not body:
        return None
    return [line.split(",")[0].strip() for line in body.splitlines() if "," in line]


def crt_domains(domain, timeout=25):
    try:
        body = http_get(CRT_API.format(q=urllib.parse.quote(f"%{domain}")), timeout)
        arr = json.loads(body)
        out = set()
        for e in arr:
            for n in (e.get("name_value") or "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n and n.endswith(domain):
                    out.add(n)
        return sorted(out)
    except Exception:
        return None


def web_probe(url, timeout=6, short=True):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(65536 if short else 2048).decode("utf-8", "replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            return {
                "status": resp.status,
                "server": hdrs.get("server"),
                "powered": hdrs.get("x-powered-by"),
                "title": (m.group(1).strip()[:120] if m else None),
                "cdns": detect_cdn(hdrs),
                "url": url,
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": str(e), "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}


def detect_cdn(headers):
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    return [name for name, needles in CDN_PATTERNS if any(n in blob for n in needles)]


def tls_cert(host, port=443, timeout=8):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
                flat = [v for pair in (c.get("subject") or []) for _, v in pair]
                issuer = [v for pair in (c.get("issuer") or []) for _, v in pair]
                sans = [v for kind, v in (c.get("subjectAltName") or [])]
                return {"subject": flat, "issuer": issuer, "sans": sans,
                        "valid_from": c.get("notBefore"), "valid_to": c.get("notAfter")}
    except Exception as e:
        return {"error": str(e)}


def decode_identifier(ident):
    if not ident or ":" not in ident:
        return None
    kind, val = ident.split(":", 1)
    kind, val = kind.lower(), val.strip()
    hexok = all(ch in "0123456789abcdef" for ch in val)
    try:
        if kind == "steam":
            if len(val) == 17 and val.isdigit():
                return f"SteamID64 {val}", f"https://steamcommunity.com/profiles/{val}"
            if len(val) in (15, 16) and hexok:
                sid = int(val, 16)
                return f"SteamID64 {sid}", f"https://steamcommunity.com/profiles/{sid}"
            if len(val) == 8 and hexok:
                num = int(val, 16)
                sid = 76561197960265728 + num
                y = num & 1
                x = num >> 1
                return f"SteamID64 {sid}  (STEAM_0:{y}:{x})", f"https://steamcommunity.com/profiles/{sid}"
            return f"Steam (hex {val[:24]}...)", None
        if kind == "discord":
            sid = int(val)
            dt = time.strftime("%Y-%m-%d", time.gmtime(((sid >> 22) + 1420070400000) / 1000))
            return f"Discord user {sid} (created {dt})", f"https://discord.com/users/{sid}"
        if kind in ("license", "license2"):
            return f"{kind} hash {val[:24]}... (unique player id)", "searchable on fivelook / toolsvault"
        if kind == "ip":
            return f"endpoint {val}", None
        if kind in ("xbl", "live"):
            return f"{kind} (console) hex {val[:24]}...", None
        if kind == "fivem":
            return f"session token {val[:16]}...", None
    except Exception:
        pass
    return ident, None


def github_search(q, timeout=10):
    if not q:
        return []
    try:
        d = http_get_json(GITHUB_API.format(q=urllib.parse.quote(q)), timeout)
        return [{"name": i.get("full_name"), "url": i.get("html_url"),
                 "desc": (i.get("description") or "")[:140],
                 "stars": i.get("stargazers_count") or 0, "lang": i.get("language") or ""}
                for i in d.get("items", [])[:5]]
    except Exception:
        return []
FRAMEWORK_PATTERNS = [
    ("QBCore", ["qb-core", "qbcore"]),
    ("QBox", ["qbox", "qbx_core"]),
    ("ESX Legacy", ["es_extended", "esx_legacy"]),
    ("vRP / vRPEX", ["vrp", "vrpex"]),
    ("ox_lib stack", ["ox_lib", "oxmysql", "ox_inventory"]),
    ("ND Framework", ["nd-core", "nd_core"]),
    ("DDCore", ["dd-core"]),
    ("TMC", ["tmc_framework", "tmcframework"]),
    ("RSG (RedM)", ["rsg-core", "rsg_core"]),
    ("VORP (RedM)", ["vorp_core", "vorpcore"]),
]

ADMIN_RESOURCES = ["admin", "easyadmin", "essentialmode", "amazingadmin", "vadmin", "myadmin",
                   "ep_admin", "fivem-panel", "staffchat", "vmenu", "ho-adminmannger", "ho-menu"]


def detect_frameworks(resources):
    if not resources:
        return []
    names = [r.lower() for r in resources]
    found = []
    for label, needles in FRAMEWORK_PATTERNS:
        if any(any(n in rn for rn in names) for n in needles):
            found.append(label)
    return found


def analyze_resources(resources):
    if not resources:
        return {"count": 0, "admin_tools": [], "frameworks": []}
    admin = [r for r in resources if r.lower() in ADMIN_RESOURCES or any(k in r.lower() for k in ("admin", "menu"))]
    return {"count": len(resources), "admin_tools": admin, "frameworks": detect_frameworks(resources)}


def license_token_owner_id(vars_map):
    tok = vars_map.get("sv_licenseKeyToken") or ""
    m = re.search(r"_(\d+):", tok)
    return m.group(1) if m else None


def security_findings(profile):
    v = profile.get("vars", {})
    findings = []
    probe = profile.get("probe") or {}
    if probe.get("status") == "open":
        findings.append(("HIGH", f"/info.json is publicly readable on the game port — full resource list, config & license token exposed ({probe.get('elapsed')}s)."))
        if probe.get("data", {}).get("enforceSteamAuth") is False:
            findings.append(("MED", "Steam auth NOT enforced on the game protocol (info.json reports enforceSteamAuth=false)."))
    elif probe.get("status") == "open-nonjson":
        findings.append(("MED", f"/info.json responds with non-JSON payload ({probe.get('status')})."))
    elif probe.get("status") == "blocked":
        findings.append(("INFO", f"/info.json blocked or firewalled ({probe.get('error')}). Direct endpoint data hidden."))
    if v.get("sv_scriptHookAllowed") == "true":
        findings.append(("CRIT", "sv_scriptHookAllowed=true — client scripts can call native functions. Major cheat surface."))
    if v.get("sv_lan") == "true":
        findings.append(("HIGH", "sv_lan=true — LAN mode enabled, server may be misconfigured for public play."))
    if v.get("sv_licenseKeyToken"):
        findings.append(("LOW", "sv_licenseKeyToken is broadcast in public API data (common, but reveals the owner account ID)."))
    if v.get("sv_enforceSteamAuth") == "false":
        findings.append(("LOW", "sv_enforceSteamAuth=false — players without Steam tickets can join."))
    if v.get("sv_pureLevel") == "1":
        findings.append(("MED", "sv_pureLevel=1 — pure server (whitelist) mode; join is restricted."))
    if v.get("sv_appearAllowlisted") == "true":
        findings.append(("INFO", "Server appears allowlisted (whitelist community): " + (v.get("sv_allowlistInstructions") or "no instructions given.")))
    if v.get("txAdmin-version"):
        findings.append(("INFO", f"txAdmin web panel detected, version {v['txAdmin-version']}."))
    if profile.get("private_relay"):
        findings.append(("INFO", "CFX Private Relay in use — the real origin IP is masked behind Cfx's proxy."))
    if profile.get("enhanced_host_support"):
        findings.append(("LOW", "enhancedHostSupport=true — host supports additional protocol features."))
    if not findings:
        findings.append(("INFO", "No obvious public exposure found."))
    return findings


# ---------------------------------------------------------------- db / history
def db_init():
    con = sqlite3.connect(DB_FILE)
    con.execute("""CREATE TABLE IF NOT EXISTS snapshots(
        code TEXT, ts TEXT, hostname TEXT, endpoint TEXT, players INTEGER, maxclients INTEGER,
        resources INTEGER, upvotes INTEGER, last_seen TEXT, status TEXT)""")
    con.commit()
    return con


def db_snapshot(profile):
    try:
        con = db_init()
        con.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (profile["code"], time.strftime("%Y-%m-%d %H:%M:%S"), profile.get("hostname"),
                     (profile.get("endpoints") or [""])[0], profile.get("players_count"),
                     profile.get("max_clients"), profile.get("resources_count"), profile.get("upvote_power"),
                     profile.get("last_seen"), profile.get("status") or ""))
        con.commit()
        con.close()
    except Exception as e:
        print(f"  {c('b_yellow', '[i]')} history not stored: {e}")


def db_history(code):
    try:
        con = db_init()
        rows = con.execute("SELECT * FROM snapshots WHERE code=? ORDER BY ts", (code,)).fetchall()
        con.close()
        return rows
    except Exception:
        return []


# ---------------------------------------------------------------- profile
def build_profile(code, timeout, with_geo=True, with_players=False, probe=True, with_extras=True):
    res = api_lookup(code, timeout)
    if not res["ok"]:
        return {"code": code, "error": res["error"]}
    d = res["data"]
    v = d.get("vars") or {}
    endpoints = [str(e) for e in (d.get("connectEndPoints") or [])]
    ep0 = endpoints[0] if endpoints else None
    private_relay = bool(ep0 and "private-placeholder" in ep0)
    resolved_ip = None
    if ep0 and not private_relay:
        h, _, _ = split_endpoint(ep0)
        resolved_ip = host_to_ip(h)

    profile = {
        "code": code,
        "hostname": clean(d.get("hostname")) or v.get("sv_projectName"),
        "gametype": d.get("gametype"),
        "mapname": d.get("mapname"),
        "game": v.get("gamename"),
        "locale": v.get("locale"),
        "players_count": len(d.get("players") or []),
        "max_clients": d.get("svMaxclients") or d.get("maxClients") or v.get("sv_maxClients"),
        "endpoints": endpoints,
        "resolved_ip": resolved_ip,
        "private_relay": private_relay,
        "enhanced_host_support": d.get("enhancedHostSupport"),
        "server_version": d.get("server"),
        "request_steam_ticket": d.get("requestSteamTicket"),
        "fallback": d.get("fallback"),
        "status": d.get("status"),
        "last_seen": d.get("lastSeen"),
        "suspended_till": d.get("suspendedTill"),
        "upvote_power": d.get("upvotePower"),
        "burst_power": d.get("burstPower"),
        "premium": v.get("premium"),
        "tags": v.get("tags"),
        "project_desc": v.get("sv_projectDesc"),
        "vars": v,
        "owner": {
            "name": d.get("ownerName"),
            "id": d.get("ownerID") or license_token_owner_id(v),
            "profile": d.get("ownerProfile"),
            "avatar": d.get("ownerAvatar"),
        },
        "resources_count": len(d.get("resources") or []),
        "resources": d.get("resources") or [],
        "icon_version": d.get("iconVersion"),
        "banners": [u for u in (v.get("banner_connecting"), v.get("banner_detail")) if u],
        "discord_url": v.get("Discord"),
        "mastodon_handle": v.get("activitypubFeed"),
    }
    if with_players:
        profile["players"] = [{"id": p.get("id"), "name": p.get("name"), "ping": p.get("ping"),
                               "identifiers": p.get("identifiers") or []} for p in (d.get("players") or [])]
    if with_extras:
        profile["analysis"] = analyze_resources(profile["resources"])
        if profile["owner"]["name"]:
            profile["owner"]["forum"] = forum_user(profile["owner"]["name"], timeout)
        if profile["discord_url"]:
            profile["discord"] = discord_info(profile["discord_url"], timeout)
        if profile["mastodon_handle"]:
            profile["mastodon"] = mastodon_info(profile["mastodon_handle"], timeout)
        if with_geo and resolved_ip and not private_relay:
            profile["geo"] = geo_lookup(resolved_ip, timeout)
            profile["rdns"] = rdns(resolved_ip, timeout)
    if probe and ep0 and not private_relay:
        profile["probe"] = probe_info_json(ep0, min(timeout, 6))
    if profile.get("probe", {}).get("status") == "open":
        pi = profile["probe"].get("data", {})
        if pi:
            profile["probe"]["resources"] = pi.get("resources") or []
            profile["probe"]["icon_b64"] = pi.get("icon")
            profile["probe"]["enforce_steam_auth"] = pi.get("enforceSteamAuth")
    return profile


def fmt_geo(g):
    if not g or g.get("status") != "success":
        return "n/a"
    parts = [p for p in (g.get("city"), g.get("regionName"), g.get("country")) if p]
    extra = []
    if g.get("hosting"):
        extra.append("hosting/DC")
    if g.get("proxy"):
        extra.append("proxy/VPN")
    if g.get("mobile"):
        extra.append("mobile")
    s = ", ".join(parts) + (f" [{g.get('isp') or g.get('org')}]" if g.get("isp") or g.get("org") else "")
    if extra:
        s += " (" + ", ".join(extra) + ")"
    return s


def print_profile(p, full=True):
    if "error" in p:
        print(f"  {c('b_red', '[x]')} {p['code']}: {p['error']}")
        return
    L = "=" * 60
    print(L)
    print(f"  {c('b_cyan', 'HOST')}     : {c('b_white', p.get('hostname') or 'n/a')}")
    print(f"  {c('b_cyan', 'Code')}     : {c('b_yellow', p['code'])}")
    print(f"  {c('b_cyan', 'Game')}     : {p.get('game')}   Type: {p.get('gametype')}   Map: {p.get('mapname') or 'n/a'}")
    print(f"  {c('b_cyan', 'Players')}  : {c('b_green', str(p.get('players_count')))} / {p.get('max_clients')}   Locale: {p.get('locale')}")
    print(f"  {c('b_cyan', 'Version')}  : {p.get('server_version') or 'n/a'}")
    eps = p.get("endpoints") or []
    if eps:
        for i, ep in enumerate(eps):
            tag = c('b_yellow', "  <-- resolved IP") if i == 0 and p.get("resolved_ip") and not p.get("private_relay") else ""
            print(f"  {c('b_cyan', 'Endpoint')}: {c('b_green', ep)}{tag}")
        if p.get("private_relay"):
            print(f"  {c('b_red', '!')} Private relay: origin IP is masked by Cfx.re")
    if p.get("resolved_ip"):
        print(f"  {c('b_cyan', 'Resolved')}: {c('b_yellow', p['resolved_ip'])}" + (f"  (rDNS: {p.get('rdns')})" if p.get("rdns") else ""))
        print(f"  {c('b_cyan', 'Geo')}      : {fmt_geo(p.get('geo'))}")
    print(f"  {c('b_cyan', 'Owner')}    : {p['owner'].get('name') or 'n/a'}  (id {c('b_blue', str(p['owner'].get('id')) or 'n/a')})")
    forum = p.get("owner", {}).get("forum")
    if forum and not forum.get("error"):
        print(f"  {c('b_cyan', 'Forum')}    : {forum.get('profile_url')}  title='{forum.get('title')}'")
    disc = p.get("discord")
    if disc:
        if disc.get("error"):
            print(f"  {c('b_cyan', 'Discord')}  : {c('b_red', 'resolution failed: ' + str(disc['error']))}")
        else:
            print(f"  {c('b_cyan', 'Discord')}  : {c('b_white', disc.get('name') or '')}  id={c('b_blue', str(disc.get('guild_id')))}  members={c('b_green', str(disc.get('members')))}  online={c('b_green', str(disc.get('online')))}  channel=#{disc.get('channel')}")
    mas = p.get("mastodon")
    if mas:
        print(f"  {c('b_cyan', 'Mastodon')}: {mas.get('handle')}  followers={mas.get('followers')}  posts={mas.get('posts')}  {mas.get('url')}")
    if p.get("premium"):
        print(f"  {c('b_cyan', 'Premium')}  : {p['premium']}")
    if p.get("upvote_power") is not None:
        print(f"  {c('b_cyan', 'Votes')}    : upvotes={p.get('upvote_power')}  burst={p.get('burst_power')}")
    if p.get("last_seen"):
        print(f"  {c('b_cyan', 'Last')}     : {p['last_seen']}")
    if p.get("suspended_till"):
        print(f"  {c('b_red', 'SUSPENDED till:')} {p['suspended_till']}")
    if p.get("project_desc"):
        print(f"  {c('b_cyan', 'About')}    : {clean(p['project_desc'])[:200]}")
    if p.get("tags"):
        print(f"  {c('b_cyan', 'Tags')}     : {p['tags']}")
    an = p.get("analysis")
    if an:
        fw = f"  frameworks: {c('b_magenta', ', '.join(an['frameworks']))}" if an["frameworks"] else "  frameworks: none detected"
        print(f"  {c('b_cyan', 'Resrcs')}   : {len(p.get('resources') or [])} total" + fw)
        if an["admin_tools"]:
            print(f"  {c('b_cyan', 'Admin')}    : {', '.join(an['admin_tools'][:10])}")
    probe = p.get("probe")
    if probe:
        st = probe.get("status")
        if st == "open":
            pi = probe.get("data", {})
            extra = f"  steam_auth={pi.get('enforceSteamAuth')}" if "enforceSteamAuth" in pi else ""
            print(f"  {c('b_cyan', '/info.json')}: {c('b_green', 'OPEN')} ({probe.get('elapsed')}s)  server={pi.get('server')}  resources={len(probe.get('resources') or [])}  icon=embedded{extra}")
        elif st == "open-nonjson":
            print(f"  {c('b_cyan', '/info.json')}: {c('b_yellow', 'non-JSON payload')} ({probe.get('preview', '')[:80]})")
        else:
            print(f"  {c('b_cyan', '/info.json')}: {c('b_red', st)}  ({probe.get('error')})")
    if full:
        print("-" * 60)
        print(f"  {c('b_white', 'FINDINGS')}")
        for sev, msg in security_findings(p):
            print(f"  {c(SEV_COLORS[sev], SEV_MARK[sev])} {c(SEV_COLORS[sev], '[' + sev + ']')} {msg}")
    print(L)


def print_players(p):
    if "error" in p:
        print(f"  {c('b_red', '[x]')} {p['code']}: {p['error']}")
        return
    print(f"  {c('b_white', p.get('hostname'))} — {c('b_green', str(p.get('players_count')))} players")
    for pl in p.get("players") or []:
        print(f"    {c('b_blue', '[' + str(pl['id']) + ']')} {pl['name']}  {c('b_yellow', 'ping=' + str(pl['ping']))}")


def print_resources(p):
    if "error" in p:
        print(f"  {c('b_red', '[x]')} {p['code']}: {p['error']}")
        return
    an = p.get("analysis") or {}
    print(f"  {c('b_white', p.get('hostname'))} — {c('b_green', str(len(p.get('resources') or [])))} resources")
    if an.get("frameworks"):
        print(f"  {c('b_cyan', 'Frameworks')}: {c('b_magenta', ', '.join(an['frameworks']))}")
    for r in p.get("resources") or []:
        print(f"    - {r}")


# ---------------------------------------------------------------- modules
def get_code_arg(args):
    code = extract_code(args.code)
    if not code:
        sys.exit(f"{c('b_red', '[x]')} cannot extract cfx code from '{args.code}'")
    return code


def mod_profile(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=not args.no_geo, with_players=args.players, probe=not args.no_probe)
    db_snapshot(p)
    if args.json:
        print(json.dumps(p, ensure_ascii=False, indent=2, default=str))
    elif args.out:
        import io
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        print_profile(p)
        sys.stdout = old
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
        print(f"saved profile to {args.out}")
    else:
        print_profile(p)


def mod_players(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=False, with_players=True, probe=False, with_extras=False)
    if args.json:
        print(json.dumps(p, ensure_ascii=False, indent=2, default=str))
    else:
        print_players(p)


def mod_resources(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=False, probe=True, with_extras=False)
    if "error" in p:
        sys.exit(f"{c('b_red', '[x]')} {p['error']}")
    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            fh.write("\n".join(p["resources"]))
        print(f"wrote {len(p['resources'])} resources to {args.save}")
    if args.json:
        print(json.dumps({"code": p["code"], "resources": p["resources"]}, ensure_ascii=False, indent=2))
    else:
        print_resources(p)


def mod_scan(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=False, probe=True, with_extras=False)
    if "error" in p:
        sys.exit(f"{c('b_red', '[x]')} {p['error']}")
    print_profile(p, full=False)
    print("=" * 60)
    print(f"  {c('b_white', 'SCAN REPORT')}")
    if p.get("resolved_ip") and not p.get("private_relay"):
        h, port, _ = split_endpoint((p.get("endpoints") or [""])[0])
        port = port or 30120
        open_ = tcp_check(h, port)
        print(f"  {c('b_green', '[+]')} game port {port}: {c('b_green', 'OPEN / connectable') if open_ else c('b_red', 'CLOSED / filtered')} ({h})")
        if p["vars"].get("txAdmin-version"):
            tx = tcp_check(h, 40120)
            print(f"  {c('b_green', '[+]')} txAdmin web port 40120: {c('b_green', 'OPEN') if tx else c('b_red', 'CLOSED / filtered')}")
        r = rdap_lookup(p["resolved_ip"], args.timeout)
        if r:
            print(f"  {c('b_cyan', '[i]')} RDAP: network='{r.get('network')}' country={r.get('country')} handle={r.get('handle')} registrants={', '.join(r.get('registrants') or []) or 'n/a'}")
    for sev, msg in security_findings(p):
        print(f"  {c(SEV_COLORS[sev], SEV_MARK[sev])} {c(SEV_COLORS[sev], '[' + sev + ']')} {msg}")
    print("=" * 60)
    if args.json:
        print(json.dumps(security_findings(p), ensure_ascii=False, indent=2))


def mod_owner(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=False, probe=False)
    if "error" in p:
        sys.exit(f"{c('b_red', '[x]')} {p['error']}")
    o = p["owner"]
    print("=" * 60)
    print(f"  {c('b_cyan', 'Owner')}     : {c('b_white', o.get('name') or 'n/a')}")
    print(f"  {c('b_cyan', 'Account ID')}: {c('b_blue', str(o.get('id') or 'n/a'))}")
    print(f"  {c('b_cyan', 'Profile')}   : {o.get('profile')}")
    print(f"  {c('b_cyan', 'Avatar')}    : {o.get('avatar')}")
    tok = p["vars"].get("sv_licenseKeyToken")
    if tok:
        print(f"  {c('b_cyan', 'Token')}     : visible in vars: ...{tok[-20:]}")
    forum = o.get("forum")
    if forum:
        if forum.get("error"):
            print(f"  {c('b_red', '[x]')} Forum lookup failed: {forum['error']}")
        else:
            print(f"  {c('b_cyan', 'Forum')}     : {forum.get('profile_url')}")
            print(f"  {c('b_cyan', 'Title')}     : {forum.get('title')}")
            avatar = forum.get("avatar_template") or ""
            if avatar:
                if avatar.startswith("http"):
                    print(f"  {c('b_cyan', 'Avatar')}    : {avatar.replace('{size}', '256')}")
                else:
                    print(f"  {c('b_cyan', 'Avatar')}    : https://forum.cfx.re{avatar.replace('{size}', '256')}")
    mas = p.get("mastodon")
    if mas:
        print(f"  {c('b_cyan', 'Mastodon')} : {mas.get('handle')} — {mas.get('display_name')}  followers={mas.get('followers')}")
    print("=" * 60)


def mod_discord(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=False, probe=False)
    if "error" in p:
        sys.exit(f"{c('b_red', '[x]')} {p['error']}")
    d = p.get("discord")
    if not d:
        print(f"  Server {p['code']} has no Discord invite in its vars.")
        return
    if d.get("error"):
        print(f"  {c('b_red', '[x]')} Discord resolution failed: {d['error']}")
        return
    print("=" * 60)
    print(f"  {c('b_cyan', 'Invite')}   : discord.gg/{d['code']}")
    print(f"  {c('b_cyan', 'Server')}   : {c('b_white', d.get('name'))}  (guild id {c('b_blue', str(d.get('guild_id')))})")
    print(f"  {c('b_cyan', 'Members')}  : {c('b_green', str(d.get('members')))}  (online {c('b_green', str(d.get('online')))})")
    print(f"  {c('b_cyan', 'Channel')}  : #{d.get('channel')}")
    if d.get("guild_features"):
        print(f"  {c('b_cyan', 'Features')}: {', '.join(d['guild_features'])}")
    print("=" * 60)


def mod_media(args):
    p = build_profile(get_code_arg(args), args.timeout, with_geo=False, probe=True, with_extras=False)
    if "error" in p:
        sys.exit(f"{c('b_red', '[x]')} {p['error']}")
    outdir = args.out or os.path.join("fivem-media", p["code"])
    os.makedirs(outdir, exist_ok=True)
    saved = []
    b64 = p.get("probe", {}).get("icon_b64")
    if b64:
        try:
            raw = base64.b64decode(b64)
            path = os.path.join(outdir, "icon.png")
            with open(path, "wb") as fh:
                fh.write(raw)
            saved.append(f"icon.png ({len(raw)} bytes)")
        except Exception as e:
            print(f"  {c('b_yellow', '[i]')} icon decode failed: {e}")
    for i, url in enumerate(p.get("banners") or []):
        try:
            raw = http_get(url, 15, binary=True)
            ext = os.path.splitext(urllib.parse.urlparse(url).path)[1] or ".img"
            if ext.lower() not in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
                ext = ".img"
            path = os.path.join(outdir, f"banner_{i+1}{ext}")
            with open(path, "wb") as fh:
                fh.write(raw)
            saved.append(f"banner_{i+1}{ext} ({len(raw)} bytes)")
        except Exception as e:
            print(f"  {c('b_yellow', '[i]')} banner {i+1} failed: {e}")
    if saved:
        print(f"  saved to {outdir}/")
        for s in saved:
            print(f"    - {c('b_green', s)}")
    else:
        print(f"  nothing to save (icon unavailable, no banners)")


def mod_history(args):
    code = extract_code(args.code) or args.code
    rows = db_history(code)
    if not rows:
        print(f"  no history for {code}")
        return
    print(f"  History for {c('b_yellow', code)} ({len(rows)} snapshots)")
    print(f"  {'timestamp':<20} {'players':>8} {'resrcs':>7} {'upvotes':>8}  endpoint")
    counts = [r[4] or 0 for r in rows]
    for r in rows:
        print(f"  {r[1]:<20} {c('b_green', str(r[4])):>8} {str(r[6]):>7} {str(r[7]):>8}  {r[3]}")
    if counts:
        print(f"  stats: min={min(counts)} max={max(counts)} avg={sum(counts)/len(counts):.1f}")


def mod_batch(args):
    try:
        with open(args.file, "r", encoding="utf-8") as fh:
            raw = [l.strip() for l in fh if l.strip()]
    except OSError as e:
        sys.exit(f"{c('b_red', '[x]')} {e}")
    if not raw:
        sys.exit("batch file empty")
    results = []
    for i, line in enumerate(raw, 1):
        code = extract_code(line) or line
        p = build_profile(code, args.timeout, with_geo=not args.no_geo, probe=not args.no_probe, with_extras=False)
        ep = (p.get("endpoints") or [""])[0]
        def sval(k):
            val = p.get(k)
            return "" if val is None else str(val)
        results.append([p.get("code", "") or "", p.get("hostname", "") or "", ep, p.get("resolved_ip", "") or "",
                        sval("players_count"), sval("max_clients"), p.get("game", "") or "",
                        ",".join((p.get("analysis") or {}).get("frameworks") or []),
                        p.get("owner", {}).get("name", "") or "", p.get("error", "") or ""])
        print(f"  {c('b_blue', '[' + str(i) + '/' + str(len(raw)) + ']')} {p.get('code')} -> {c('b_green', p.get('hostname') or '')}{c('b_red', ' ' + (p.get('error') or ''))}")
    out = args.out or "fivem-osint-report.csv"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("code,hostname,endpoint,resolved_ip,players,maxclients,game,frameworks,owner,error\n")
        for r in results:
            fh.write(",".join(f'"{cell.replace(chr(34), chr(34)+chr(34))}"' for cell in r) + "\n")
    print(f"  wrote {len(results)} rows to {c('b_green', out)}")


def mod_raw(args):
    code = get_code_arg(args)
    res = api_lookup(code, args.timeout)
    if not res["ok"]:
        sys.exit(f"{c('b_red', '[x]')} {res['error']}")
    print(json.dumps(res["raw"], ensure_ascii=False, indent=2))


# ---------------------------------------------------------------- deep OSINT module
def mod_deep(args):
    code = get_code_arg(args)
    p = build_profile(code, args.timeout, with_geo=True, with_players=True, probe=True, with_extras=True)
    if "error" in p:
        sys.exit(f"{c('b_red', '[x]')} {p['error']}")
    L = "=" * 62
    print(L)
    print(f"  {c('b_cyan', 'DEEP OSINT')}  {c('b_white', p.get('hostname') or p['code'])}  ({code})")
    print(L)
    print_profile(p, full=False)

    v = p.get("vars") or {}
    eps = p.get("endpoints") or []
    ip = p.get("resolved_ip")
    texts = [p.get("project_desc"), p.get("tags"), p.get("hostname"),
             " ".join(eps), " ".join(p.get("banners") or [])]
    domains = [d for d in extract_domains(*texts) if not d.endswith(("cfx.re", "fivem.net"))]

    print(f"\n  {c('b_magenta', '== LINKED DOMAINS & PROJECTS (extracted from public data) ==')}")
    if domains:
        for d in domains:
            print(f"    {c('b_blue', '-')} {c('b_white', d)}")
    else:
        print(f"    {c('dim', 'none found in public vars/desc/banners')}")

    if ip and not p.get("private_relay"):
        print(f"\n  {c('b_magenta', '== DEEP IP / HOST INTEL ==')}  {c('b_white', ip)}")
        rd = rdns(ip, 4)
        if rd:
            print(f"    rDNS: {c('b_green', rd)}")
        rev = reverse_ip(ip, 12)
        if rev:
            print(f"    domains on same IP ({len(rev)}): {', '.join(c('b_yellow', d) for d in rev[:12])}")
        rp = rdap_lookup(ip, 8)
        if rp:
            print(f"    RDAP : net='{rp.get('network')}' country={rp.get('country')} registrants={', '.join(rp.get('registrants') or []) or 'n/a'}")
        print(f"    {c('dim', 'web ports: probing 80/443/8080/8443/8888/40120 + game port ...')}")
        h0, port0, _ = split_endpoint(eps[0]) if eps else (ip, None, "")
        port0 = port0 or 30120
        ports = sorted(set(WEB_PORTS + [port0]))
        with ThreadPoolExecutor(max_workers=6) as ex:
            results = list(ex.map(lambda prt: (prt, web_probe(f"http://{ip}:{prt}/", 5)), ports))
        for prt, w in results:
            if w.get("error") and "404" not in str(w.get("error")):
                continue
            tag = []
            if w.get("server"):
                tag.append(f"Server: {w['server']}")
            if w.get("title"):
                tag.append(f"title: {w['title']}")
            if w.get("cdns"):
                tag.append(f"CDN: {', '.join(w['cdns'])}")
            extra = f"  ({c('b_yellow', '; '.join(tag))})" if tag else ""
            st = w.get("status", "?")
            stcol = "b_green" if isinstance(st, int) and st < 400 else "b_red"
            print(f"    port {prt:<6} HTTP {c(stcol, str(st))}{extra}")
        if port0 != 80 and port0 != 443:
            t = tls_cert(ip, port0, 6)
            if not t.get("error") and (t.get("issuer") or t.get("sans")):
                iss = ", ".join(t.get("issuer") or [])[:60] or "n/a"
                print(f"    TLS on {port0}: issuer={iss}")
                if t.get("sans"):
                    print(f"      SANs: {', '.join(t['sans'][:8])}")

    if domains:
        print(f"\n  {c('b_magenta', '== PER-DOMAIN PASSIVE RECON ==')}")
        def scan_domain(d):
            row = {"domain": d}
            row["dns"] = dns_records(d, 12)
            hs = hostsearch(d, 12)
            row["subs"] = hs
            row["crt"] = crt_domains(d, 20)
            row["web"] = web_probe(f"https://{d}/", 6)
            if row["web"].get("error"):
                row["web"] = web_probe(f"http://{d}/", 6)
            row["tls"] = tls_cert(d, 443, 6)
            return row
        with ThreadPoolExecutor(max_workers=3) as ex:
            rows = list(ex.map(scan_domain, domains[:6]))
        for row in rows:
            d = row["domain"]
            print(f"\n  {c('b_white', '· ' + d)}")
            dns = row.get("dns") or {}
            a = dns.get("A") or []
            if a:
                print(f"    A      : {', '.join(a)}")
            for k in ("AAAA", "MX", "NS"):
                if dns.get(k):
                    print(f"    {k:<7}: {', '.join(dns[k][:6])}")
            if dns.get("TXT"):
                print(f"    TXT    : {', '.join(dns['TXT'][:4])}")
            subs = sorted(set((row.get("subs") or []) + (row.get("crt") or [])))
            if subs:
                print(f"    subdomains ({len(subs)}): {', '.join(subs[:14])}")
                if len(subs) > 14:
                    print(f"      ... +{len(subs) - 14} more")
            w = row.get("web")
            if w and not w.get("error"):
                t = [f"title: {w['title']}"] if w.get("title") else []
                if w.get("server"):
                    t.append(f"Server: {w['server']}")
                if w.get("cdns"):
                    t.append(f"CDN: {', '.join(w['cdns'])}")
                print(f"    web    : HTTP {w.get('status')}" + (f"  ({'; '.join(t)})" if t else ""))
            tl = row.get("tls")
            if tl and not tl.get("error") and (tl.get("issuer") or tl.get("sans")):
                iss = ", ".join(tl.get("issuer") or [])[:70] or "n/a"
                print(f"    TLS    : issuer={iss}")
                sans = [s for s in tl.get("sans") or [] if s != d]
                if sans:
                    print(f"      SANs (extra names): {', '.join(sans[:8])}")

    print(f"\n  {c('b_magenta', '== PLAYER IDENTIFIERS (decoded, when broadcast) ==')}")
    ids_seen = set()
    count = 0
    for pl in p.get("players") or []:
        for ident in pl.get("identifiers") or []:
            dec = decode_identifier(ident)
            if not dec:
                continue
            desc, link = dec
            if ident in ids_seen:
                continue
            ids_seen.add(ident)
            count += 1
            linktxt = f"  {c('b_blue', link)}" if link else ""
            print(f"    [{pl['name'][:20]}] {c('b_cyan', ident[:40])} -> {c('b_green', desc)}{linktxt}")
    if count == 0:
        print(f"    {c('dim', 'this server does not broadcast player identifiers in the public API')}")

    print(f"\n  {c('b_magenta', '== GITHUB / PUBLIC PROJECT LINKAGE ==')}")
    for q in [p.get("hostname") or "", p.get("project_desc") or "", p["owner"].get("name") or ""]:
        q = re.sub(r"[^a-zA-Z0-9 ]", " ", q).strip()
        if len(q) < 3:
            continue
        hits = github_search(q)
        for h in hits:
            print(f"    {c('b_yellow', h['name'])}  ({h['lang']}, {h['stars']}*)  {h['url']}")
            if h.get("desc"):
                print(f"      {c('dim', h['desc'])}")
        break
    print(L)


# ---------------------------------------------------------------- stream module (global live server list)
STREAM_URL = "https://frontend.cfx-services.net/api/servers/stream/{ts}/"
STREAM_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivem-stream-cache.bin")
STREAM_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}")
STREAM_MASTO_RE = re.compile(r"([\w.-]+@[\w.-]+\.[a-z]{2,10})")
STREAM_DISCORD_RE = re.compile(r"discord\.gg/[\w-]+", re.I)
STREAM_CODE_RE = re.compile(r"[a-z0-9]{5,8}")
STREAM_STOP = {"false", "true", "premium", "locale", "tags", "gamename", "mapname", "activitypubfeed",
               "banner", "connect", "server", "players", "game", "name", "status", "owner"}


def _stream_code_ok(t):
    if not STREAM_CODE_RE.fullmatch(t) or t in STREAM_STOP:
        return False
    if t.endswith("b") and len(t) >= 5 and t[-2].isdigit():
        return False
    if t.endswith("bm") or t.endswith("bj"):
        return False
    if any(k in t for k in ("false", "true", "sv_", "roleplay", "freeroam")):
        return False
    return True


STREAM_STRICT_KEYS = ("sv_projectName", "sv_projectDesc", "sv_enforceGameBuild", "sv_scriptHookAllowed",
                      "sv_appearAllowlisted", "sv_allowlistInstructions", "gamename", "locale", "premium",
                      "tags", "mapname", "activitypubFeed", "onesync_enabled", "Discord", "banner_connecting",
                      "banner_detail", "gametype", "server", "requestSteamTicket", "enhancedHostSupport",
                      "sv_maxClients", "sv_pureLevel", "txAdmin-version", "sv_licenseKeyToken", "sv_lan",
                      "sv_enhancedHostSupport", "sv_replaceExeToSwitchBuilds", "sv_poolSizesIncrease",
                      "sv_projectUrl", "sv_enforceSteamAuth", "sv_disableClientReplays")
STREAM_KEYLIKE = re.compile(r"^(sv_|banner_|game|locale|premium|tags|mapname|activitypub|onesync|Discord|discord|request|enhanced|server|icon|false|true|selfReported|maxClients|clients|gametype|mapname|resources|players|upvote|burst|ownerID|ownerName|ownerProfile|ownerAvatar|suspended|lastSeen|fallback|private|connectEndPoints|iconVersion|support_status|requestSteam|sv_)")


def stream_positions(data):
    import bisect
    strings = [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    poss = [p for p, _ in strings]
    return strings, poss, bisect


def _stream_hostname_ok(t):
    """hostnames carry letters/spaces; keys and IPs do not."""
    if not t or len(t) > 120:
        return False
    if STREAM_KEYLIKE.match(t) or STREAM_IP_RE.match(t):
        return False
    if re.match(r"^[a-z]{2,3}-[A-Z]{2}", t):
        return False
    if any(c.isupper() for c in t):
        return True
    if len(t) >= 12 and (" " in t or "." in t):
        return True
    return False


def clean_stream_name(t):
    t = COLOR_RE.sub("", t or "")
    t = re.sub(r"[\"J)\\]", "", t)
    t = re.sub(r"\^|\|+$", "", t).strip()
    return re.sub(r"[^ -~]", "", t).strip()[:120]


def parse_stream(data):
    strings, poss, bisect = stream_positions(data)
    strict = []
    for p, t in strings:
        if 5 <= len(t) <= 8 and STREAM_CODE_RE.fullmatch(t) and p >= 2:
            if data[p - 2] == 0x0A and data[p - 1] == len(t):
                strict.append((p, t))
    uniq = {}
    for p, t in strict:
        uniq.setdefault(t, p)
    strict = sorted((p, t) for t, p in uniq.items())
    rows = []
    for i, (p, code) in enumerate(strict):
        end = strict[i + 1][0] if i + 1 < len(strict) else len(data)
        lo = bisect.bisect_right(poss, p)
        hi = bisect.bisect_left(poss, min(end, p + 1500))
        ws = strings[lo:hi]
        hmm = None
        for pp, t in ws[:8]:
            if STREAM_KEYLIKE.match(t):
                break
            if hmm is None:
                hmm = t
                break
        if not _stream_hostname_ok(hmm or ""):
            continue
        chunk = " ".join(t for _, t in ws)
        m = STREAM_IP_RE.search(chunk)
        ep = m.group(0) if m else ""
        m = STREAM_MASTO_RE.search(chunk)
        masto = re.sub(r"[^a-z0-9.@_-]+$", "", (m.group(1) if m else "")).rstrip("b")
        m = STREAM_DISCORD_RE.search(chunk)
        disc = re.sub(r"[^a-z0-9./_-]+$", "", (m.group(0) if m else "")).rstrip("b")
        rows.append([code, ep, masto, disc])
    return rows


def _proto_varint(buf, pos):
    r = 0
    s = 0
    for _ in range(10):
        if pos >= len(buf):
            return None, pos
        b = buf[pos]
        pos += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, pos
        s += 7
    return None, pos


def _proto_walk(buf, pos, end):
    out = []
    while pos < end:
        tag, pos = _proto_varint(buf, pos)
        if tag is None or pos > end:
            break
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            val, pos = _proto_varint(buf, pos)
            if val is None:
                break
            out.append((field, 0, val))
        elif wire == 2:
            ln, pos = _proto_varint(buf, pos)
            if ln is None or pos + ln > end:
                break
            out.append((field, 2, buf[pos:pos + ln]))
            pos += ln
        elif wire == 5:
            if pos + 4 > end:
                break
            out.append((field, 5, buf[pos:pos + 4]))
            pos += 4
        elif wire == 1:
            if pos + 8 > end:
                break
            out.append((field, 1, buf[pos:pos + 8]))
            pos += 8
        else:
            pos += 1
    return out


PROTO_DATA_FIELDS = {1: "svMaxclients", 2: "clients", 3: "protocol", 4: "hostname",
                     5: "gametype", 6: "mapname", 8: "resources", 9: "server",
                     10: "players", 11: "iconVersion", 12: "vars",
                     16: "enhanced", 17: "upvotePower",
                     18: "connectEndPoints", 19: "burstPower"}


def _proto_player(buf):
    """Player message: {1: name, 2: identifiers[], 3: endpoint} (official schema)."""
    p = {"name": "", "identifiers": [], "endpoint": ""}
    for f, w, v in _proto_walk(buf, 0, len(buf)):
        if w != 2:
            continue
        if f == 1:
            p["name"] = v.decode("utf-8", "ignore")
        elif f == 2:
            p["identifiers"].append(v.decode("utf-8", "ignore"))
        elif f == 3:
            p["endpoint"] = v.decode("utf-8", "ignore")
    return p


def parse_stream_proto(data):
    """Official Cfx.re stream format: 4-byte little-endian frame length + Server protobuf
    {1: EndPoint(code), 2: ServerData}. Full field decoding incl. clients/maxclients/vars."""
    LEN = len(data)
    out = []
    pos = 0
    while pos + 4 <= LEN:
        ln = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24)
        if ln > 65535 or pos + 4 + ln > LEN:
            pos += 1
            continue
        frame = data[pos + 4:pos + 4 + ln]
        pos += 4 + ln
        row = {"code": "", "clients": 0, "svMaxclients": 0, "hostname": "", "gametype": "",
               "mapname": "", "version": "", "protocol": 0, "upvote": 0, "burst": 0,
               "enhanced": False, "iconVersion": 0, "endpoints": [], "vars": {},
               "resources": [], "players": []}
        for field, wire, val in _proto_walk(frame, 0, len(frame)):
            if field == 1 and wire == 2:
                row["code"] = val.decode("utf-8", "ignore")
            elif field == 2 and wire == 2:
                for f2, w2, v2 in _proto_walk(val, 0, len(val)):
                    name = PROTO_DATA_FIELDS.get(f2)
                    if not name:
                        continue
                    if w2 == 2:
                        if name == "vars":
                            key = None
                            for f3, w3, v3 in _proto_walk(v2, 0, len(v2)):
                                if f3 == 1 and w3 == 2:
                                    key = v3.decode("utf-8", "ignore")
                                elif f3 == 2 and w3 == 2 and key:
                                    row["vars"][key] = v3.decode("utf-8", "ignore")
                        elif name == "resources":
                            row["resources"].append(v2.decode("utf-8", "ignore"))
                        elif name == "connectEndPoints":
                            row["endpoints"].append(v2.decode("utf-8", "ignore"))
                        elif name == "players":
                            row["players"].append(_proto_player(v2))
                        else:
                            row[name] = v2.decode("utf-8", "ignore")
                    elif w2 == 0:
                        row[name] = v2
        if row["code"] and len(row["code"]) >= 5:
            out.append(row)
    uniq = {}
    for r in out:
        uniq.setdefault(r["code"], r)
    return list(uniq.values())


def parse_stream_detailed(data):
    """Full per-server extraction from the official protobuf stream."""
    rows = parse_stream_proto(data)
    result = []
    for r in rows:
        v = r["vars"]
        sv = r.get("server", "")
        m = re.search(r"v(\d+(?:\.\d+)+)", sv)
        row = {
            "code": r["code"],
            "hostname": clean_stream_name(r["hostname"]) or clean_stream_name(v.get("sv_projectName")),
            "gametype": r["gametype"],
            "map": r["mapname"],
            "version": m.group(1) if m else "",
            "fxserver": sv,
            "clients": r["clients"],
            "maxclients": r["svMaxclients"],
            "upvote": r["upvote"],
            "burst": r["burst"],
            "protocol": r.get("protocol", 0),
            "enhanced": r.get("enhanced", False),
            "iconVersion": r["iconVersion"],
            "endpoint": next((e for e in r["endpoints"] if not e.startswith("https://")), r["endpoints"][0] if r["endpoints"] else ""),
            "endpoints": r["endpoints"],
            "locale": v.get("locale", ""),
            "gamename": v.get("gamename", ""),
            "premium": v.get("premium", ""),
            "tags": v.get("tags", ""),
            "desc": v.get("sv_projectDesc", "")[:220],
            "mastodon": re.sub(r"[^a-z0-9.@_-]+$", "", v.get("activitypubFeed", "")).rstrip("b"),
            "discord": re.sub(r"[^a-z0-9./_-]+$", "", (v.get("Discord") or v.get("discord") or "")).rstrip("b-")
                       or re.sub(r"[^a-z0-9./_-]+$", "", (STREAM_DISCORD_RE.search(v.get("sv_projectDesc", "")) or [""])[0]).rstrip("b-"),
            "banner": v.get("banner_connecting") or v.get("banner_detail") or "",
            "scriptHook": v.get("sv_scriptHookAllowed", ""),
            "allowlisted": v.get("sv_appearAllowlisted", ""),
            "onesync": v.get("onesync_enabled", ""),
            "txAdmin": v.get("txAdmin-version", ""),
            "gamebuild": v.get("sv_enforceGameBuild", ""),
            "lan": v.get("sv_lan", ""),
        }
        if row["endpoint"]:
            ip, _, port = row["endpoint"].rpartition(":")
            row["ip"], row["port"] = ip, port
        else:
            row["ip"], row["port"] = "", ""
        row["private"] = any("private-placeholder" in e for e in r["endpoints"])
        row["framework"] = detect_framework_stream(row["gametype"], row["tags"], row["desc"])
        row["player_count"] = len(r["players"])
        row["players"] = r["players"]
        result.append(row)
    return result


def detect_framework_stream(gametype, tags, desc):
    blob = f"{gametype} {tags} {desc}".lower()
    if "qbx" in blob or "qbox" in blob:
        return "QBox"
    if "qb-core" in blob or "qbcore" in blob:
        return "QBCore"
    if "esx" in blob:
        return "ESX"
    if "vrp" in blob or "vrop" in blob:
        return "vRP"
    if "nd_core" in blob or "nd-core" in blob:
        return "ND"
    return ""


def _stream_in_subnet(ip, subnet):
    ip_part, _, cidr = subnet.partition("/")
    try:
        bits = int(cidr) if cidr else 32
        base = sum(int(x) << (24 - 8 * i) for i, x in enumerate(ip_part.split(".")))
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        val = sum(int(x) << (24 - 8 * i) for i, x in enumerate(ip.split(".")))
    except (ValueError, TypeError):
        return False
    return (val & mask) == (base & mask)


def fetch_stream(fresh=False, timeout=90):
    if not fresh and os.path.exists(STREAM_CACHE) and time.time() - os.path.getmtime(STREAM_CACHE) < 3600 * 2:
        return open(STREAM_CACHE, "rb").read()
    body = http_get(STREAM_URL.format(ts=int(time.time())), timeout, binary=True)
    with open(STREAM_CACHE, "wb") as fh:
        fh.write(body)
    return body


def parse_stream(data):
    strings = [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    code_positions = []
    seen = set()
    for p, t in strings:
        if _stream_code_ok(t) and t not in seen:
            seen.add(t)
            code_positions.append((p, t))
    code_positions.sort()
    rows = []
    for i, (p, code) in enumerate(code_positions):
        end = code_positions[i + 1][0] if i + 1 < len(code_positions) else len(data)
        chunk = data[p:min(end, p + 800)].decode("ascii", "ignore")
        m = STREAM_IP_RE.search(chunk)
        ep = m.group(0) if m else ""
        m = STREAM_MASTO_RE.search(chunk)
        masto = re.sub(r"[^a-z0-9.@_-]+$", "", (m.group(1) if m else "")).rstrip("b")
        m = STREAM_DISCORD_RE.search(chunk)
        disc = re.sub(r"[^a-z0-9./_-]+$", "", (m.group(0) if m else "")).rstrip("b")
        rows.append([code, ep, masto, disc])
    return rows


def mod_stream(args):
    print(f"  {c('b_cyan', '[i]')} fetching global server stream (all live servers) ...")
    data = fetch_stream(args.fresh, 90)
    rows = parse_stream(data)
    total = len(rows)
    with_ep = [r for r in rows if r[1]]
    with_masto = [r for r in rows if r[2]]
    with_discord = [r for r in rows if r[3]]
    print(f"  {c('b_green', '[+]')} stream decoded: {c('b_white', str(total))} live servers "
          f"({len(with_ep)} with direct IP:port, {len(with_masto)} with Mastodon, {len(with_discord)} with Discord)")

    matches = rows
    if args.subnet:
        matches = [r for r in rows if r[1] and _stream_in_subnet(r[1].split(":")[0], args.subnet)]
        print(f"  {c('b_yellow', '[i]')} subnet {args.subnet}: {len(matches)} servers")
    if args.masto:
        matches = [r for r in matches if args.masto.lower() in r[2].lower()]
        print(f"  {c('b_yellow', '[i]')} mastodon filter '{args.masto}': {len(matches)} servers")
    if args.discord:
        matches = [r for r in matches if r[3]]
        print(f"  {c('b_yellow', '[i]')} discord filter: {len(matches)} servers")
    if args.port:
        matches = [r for r in matches if r[1] and r[1].rsplit(":", 1)[-1] == str(args.port)]
        print(f"  {c('b_yellow', '[i]')} port {args.port}: {len(matches)} servers")
    if args.search:
        matches = [r for r in matches if args.search.lower() in " ".join(r).lower()]
        print(f"  {c('b_yellow', '[i]')} keyword '{args.search}': {len(matches)} servers")

    show = matches if args.limit is None else matches[:args.limit]
    if args.export:
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write("code,endpoint,mastodon,discord\n")
            for r in rows:
                fh.write(",".join(f'"{x.replace(chr(34), chr(34) + chr(34))}"' for x in r) + "\n")
        print(f"  {c('b_green', '[+]')} exported {len(rows)} rows to {args.export}")
    for code, ep, masto, disc in show:
        line = (f"    {c('b_yellow', code):<10} {c('b_green', ep or '-'):<26} "
                f"{c('b_blue', masto or '-'):<38} {c('b_magenta', disc or '-')}")
        print(line)
    if args.limit is not None and len(matches) > args.limit:
        print(f"  {c('dim', f'... {len(matches) - args.limit} more (use --limit to show)')}")


# ---------------------------------------------------------------- interactive menu
MENU = [
    ("1", "Full Profile", "everything: endpoint, IP, geo, owner, discord, mastodon, probe", mod_profile),
    ("2", "Players Dump", "all online players (id / name / ping)", mod_players),
    ("3", "Resources Dump", "resources + framework detection", mod_resources),
    ("4", "Security Scan", "exposures, TCP ports, RDAP, findings", mod_scan),
    ("5", "Owner OSINT", "forum profile, account id, avatar", mod_owner),
    ("6", "Discord Lookup", "guild id, members, online", mod_discord),
    ("7", "Media Download", "icon + banners to folder", mod_media),
    ("8", "History", "SQLite snapshots & stats", mod_history),
    ("9", "Batch Mode", "file of codes -> CSV", mod_batch),
    ("10", "Raw API JSON", "dump the raw Cfx API response", mod_raw),
    ("11", "Deep OSINT", "DNS/TLS/CDN/reverse-IP/CT/identifiers/GitHub", mod_deep),
    ("12", "Stream", "global live-server list: search subnet/masto/discord, export", mod_stream),
]


def menu_choice_ok(choice, code, args):
    n = choice.lstrip("0")
    if choice == "1":
        mod_profile(args)
    elif choice == "2":
        mod_players(args)
    elif choice == "3":
        mod_resources(args)
    elif choice == "4":
        mod_scan(args)
    elif choice == "5":
        mod_owner(args)
    elif choice == "6":
        mod_discord(args)
    elif choice == "7":
        mod_media(args)
    elif choice == "8":
        args.code = code or "?"
        mod_history(args)
    elif choice == "9":
        f = input(c("b_green", "  batch file path: ")).strip()
        args.file = f
        mod_batch(args)
    elif choice == "10":
        args.code = code or input(c("b_green", "  code: ")).strip()
        mod_raw(args)
    elif choice == "11":
        args.code = code or input(c("b_green", "  code: ")).strip()
        mod_deep(args)
    elif choice == "12":
        args.fresh = False
        args.subnet = None
        args.masto = None
        args.discord = False
        args.port = None
        args.search = None
        args.limit = 30
        args.export = None
        q = input(c("b_green", "  filter (subnet=1.2.3.0/24, masto=name, discord, port=30120, keyword, none): ")).strip()
        if q.lower().startswith("subnet="):
            args.subnet = q.split("=", 1)[1]
        elif q.lower().startswith("masto="):
            args.masto = q.split("=", 1)[1]
        elif q.lower() == "discord":
            args.discord = True
        elif q.lower().startswith("port="):
            args.port = int(q.split("=", 1)[1])
        elif q and q.lower() != "none":
            args.search = q
        mod_stream(args)


def run_menu():
    args = argparse.Namespace()
    args.no_geo = False
    args.no_probe = False
    args.timeout = 15.0
    args.json = False
    args.players = False
    args.out = None
    args.save = None
    args.file = None
    last_code = None
    while True:
        print()
        print(c("b_cyan", "=" * 62))
        print(c("b_cyan", "  F I V E M   O S I N T") + c("b_white", "   —   FiveM Server Intelligence Suite"))
        print(c("b_cyan", "=" * 62))
        for num, title, desc, _ in MENU:
            print(f"  {c('b_yellow', num):>3}  {c('b_white', title):<20} {c('dim', desc)}")
        print(f"  {c('b_yellow', '0')}   Exit")
        print(c("b_cyan", "-" * 62))
        print(c("dim", "  tip: paste a code/URL directly at the menu prompt for a quick profile"))
        choice = input(c("b_green", "  choice> ")).strip().lower()
        if choice in ("0", "q", "quit", "exit", "x"):
            break
        if not choice:
            continue
        code = last_code
        if choice not in [m[0] for m in MENU]:
            code = extract_code(choice)
            if code:
                choice = "1"
            else:
                print(c("b_red", "  [x] invalid choice"))
                continue
        if choice in ("1", "2", "3", "4", "5", "6", "7", "8", "11"):
            if code is None:
                inp = input(c("b_green", "  server code / cfx URL: ")).strip()
                code = extract_code(inp)
                if not code:
                    print(c("b_red", "  [x] invalid code"))
                    continue
            last_code = code
            args.code = code
        try:
            menu_choice_ok(choice, code, args)
        except KeyboardInterrupt:
            print()
            continue
        except Exception as e:
            print(f"  {c('b_red', '[x]')} {e}")
    print(c("b_cyan", "  bye."))


# ---------------------------------------------------------------- main
def main():
    global ENABLE_COLOR
    enable_vt()
    ap = argparse.ArgumentParser(description="FiveM OSINT — FiveM Server Intelligence Suite (menu: run with no arguments).")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    sub = ap.add_subparsers(dest="cmd")

    def add_common(sp):
        sp.add_argument("--json", action="store_true")
        sp.add_argument("--no-geo", action="store_true")
        sp.add_argument("--no-color", action="store_true", help="disable ANSI colors")
        sp.add_argument("--timeout", type=float, default=15.0)

    specs = [
        ("profile", mod_profile, "full OSINT profile (everything in one pass)"),
        ("players", mod_players, "dump all online players"),
        ("resources", mod_resources, "dump resources & framework detection"),
        ("scan", mod_scan, "exposure / security scan"),
        ("owner", mod_owner, "owner account OSINT"),
        ("discord", mod_discord, "resolve the server Discord invite"),
        ("media", mod_media, "download icon + banners"),
        ("history", mod_history, "show snapshot history (SQLite)"),
        ("raw", mod_raw, "raw Cfx API JSON"),
        ("deep", mod_deep, "deep OSINT: DNS/TLS/CDN/reverse-IP/CT/identifiers/GitHub"),
    ]
    for name, fn, help_ in specs:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("code", nargs="?", help="cfx code / join URL / ip:port")
        add_common(sp)
        if name == "profile":
            sp.add_argument("--players", action="store_true")
            sp.add_argument("--no-probe", action="store_true")
            sp.add_argument("--out", metavar="FILE", help="save text report to file")
        if name == "resources":
            sp.add_argument("--save", metavar="FILE")
            sp.add_argument("--no-probe", action="store_true")
        if name == "media":
            sp.add_argument("--out", metavar="DIR", help="output directory (default fivem-media/<code>)")
            sp.add_argument("--no-probe", action="store_true")
        if name in ("players", "scan", "owner", "discord", "raw", "deep"):
            sp.add_argument("--no-probe", action="store_true")
        sp.set_defaults(fn=fn)

    sp = sub.add_parser("batch", help="resolve many codes from a file -> CSV")
    sp.add_argument("file")
    sp.add_argument("--out", metavar="FILE")
    sp.add_argument("--no-geo", action="store_true")
    sp.add_argument("--no-probe", action="store_true")
    sp.add_argument("--timeout", type=float, default=15.0)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=mod_batch)

    sp = sub.add_parser("stream", help="global live-server stream: decode, search, export")
    sp.add_argument("--subnet", metavar="CIDR", help="e.g. 162.222.16.0/24")
    sp.add_argument("--masto", metavar="HANDLE", help="filter by mastodon instance/handle")
    sp.add_argument("--discord", action="store_true", help="only servers with a Discord invite")
    sp.add_argument("--port", type=int, help="filter by endpoint port")
    sp.add_argument("--search", metavar="KW", help="free keyword across code/ip/masto/discord")
    sp.add_argument("--limit", type=int, default=None, help="max rows to print")
    sp.add_argument("--export", metavar="FILE", help="export full table to CSV")
    sp.add_argument("--fresh", action="store_true", help="force re-download the stream")
    sp.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    sp.set_defaults(fn=mod_stream)

    args = ap.parse_args()
    if getattr(args, "no_color", False):
        ENABLE_COLOR = False
    if not args.cmd:
        run_menu()
        return
    if args.cmd in ("profile", "players", "resources", "scan", "owner", "discord", "media", "history", "raw", "deep"):
        if not args.code:
            ap.print_help()
            sys.exit(2)
    args.fn(args)


if __name__ == "__main__":
    main()
