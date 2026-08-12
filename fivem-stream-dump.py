#!/usr/bin/env python3
"""
FiveM Stream Dump — pulls the ENTIRE live FiveM server list (~33k servers)
from Cfx.re's public stream endpoint (official protobuf frame format) and
writes a clean, organised CSV/JSON with live player counts and rich vars.

Run:  python fivem-stream-dump.py                                  (interactive menu)
      python fivem-stream-dump.py --out servers.csv --fresh        (force re-download)
      python fivem-stream-dump.py --json servers.json --sort-by players
      python fivem-stream-dump.py --sample 15                      (console preview)
      python fivem-stream-dump.py --top 50 --out top50.csv         (busiest servers)
      python fivem-stream-dump.py --min-players 10 --framework QBCore
      python fivem-stream-dump.py --subnet 162.222.16.0/24 --out subnet.csv
      python fivem-stream-dump.py --stats-only

Columns: code, hostname, gametype, map, version, clients, maxclients, fill,
         upvote, burst, framework, scriptHook, allowlisted, onesync, txAdmin,
         gamebuild, private, endpoint, ip, port, locale, gamename, premium,
         tags, desc, mastodon, discord, banner, resources
"""

import argparse
import csv
import importlib.util
import json
import os
import re
import sys
import time
from collections import Counter

CORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivem-osint.py")
_spec = importlib.util.spec_from_file_location("fivem_osint_core", CORE_PATH)
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)
core.ENABLE_COLOR = False

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

COLUMNS = ["code", "hostname", "gametype", "map", "version", "clients", "maxclients",
           "fill", "upvote", "burst", "protocol", "enhanced", "framework", "scriptHook",
           "allowlisted", "onesync", "txAdmin", "gamebuild", "private", "endpoint", "ip",
           "port", "locale", "gamename", "premium", "tags", "desc", "mastodon", "discord",
           "banner", "resources", "player_count", "country", "isp", "asn"]

SORTS = {"code": 0, "clients": 1, "maxclients": 2, "fill": 3, "upvote": 4}
FRAMEWORKS = ("ESX", "QBCore", "QBox", "vRP", "ND")


def clean(t):
    return re.sub(r"[^ -~]", " ", t or "").strip()


def enrich(rows):
    for r in rows:
        ep = r["endpoint"]
        m = re.match(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$", ep) if ep else None
        r["ip"], r["port"] = (m.group(1), m.group(2)) if m else ("", "")
        mc = r.get("maxclients") or 0
        cl = r.get("clients") or 0
        r["fill"] = round(cl / mc * 100) if mc > 0 else ""
        r["resources"] = len(r.get("resources") or [])
        r["country"] = r.get("country", "")
        r["isp"] = r.get("isp", "")
        r["asn"] = r.get("asn", "")
    return rows


_GEO_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivem-osint.db")


def _geo_cache():
    import sqlite3
    con = sqlite3.connect(_GEO_DB)
    con.execute("CREATE TABLE IF NOT EXISTS ip_geo(ip TEXT PRIMARY KEY, country TEXT, isp TEXT, asn TEXT)")
    con.commit()
    return con


def geo_enrich(rows, limit=300, pause=0.4):
    """Fill country/isp/asn for server IPs (cached in fivem-osint.db, resumable)."""
    con = _geo_cache()
    cached = {r[0]: r[1:] for r in con.execute("SELECT ip, country, isp, asn FROM ip_geo")}
    todo = []
    for r in rows:
        ip = r["ip"]
        if not ip:
            continue
        if ip in cached:
            r["country"], r["isp"], r["asn"] = cached[ip]
        else:
            todo.append((r, ip))
    done = 0
    for r, ip in todo:
        if done >= limit:
            break
        try:
            g = core.geo_lookup(ip, 10) or {}
            if g.get("status") == "success":
                ctry, isp = g.get("country", ""), (g.get("isp") or "")
                asn = (g.get("as") or "").lstrip("AS")
                if asn:
                    asn = "AS" + asn
                if not isp:
                    d = core.rdap_lookup(ip, 8) or {}
                    isp = d.get("network") or ""
                r["country"], r["isp"], r["asn"] = ctry, isp, asn
                con.execute("INSERT OR REPLACE INTO ip_geo VALUES(?,?,?,?)", (ip, ctry, isp, asn))
                con.commit()
                done += 1
        except Exception:
            pass
        time.sleep(pause)
    con.close()
    return len(todo), done


_HISTORY_TBL = """
CREATE TABLE IF NOT EXISTS dump_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, total INTEGER, players INTEGER,
  capacity INTEGER, direct_ip INTEGER, private INTEGER, discord INTEGER,
  mastodon INTEGER, premium INTEGER, esx INTEGER, qbcore INTEGER, qbox INTEGER,
  vrp INTEGER, nd INTEGER, avg_fill REAL)"""


def save_history(rows):
    import sqlite3
    n = len(rows)
    tpl = sum(r["clients"] or 0 for r in rows)
    cap = sum(r["maxclients"] or 0 for r in rows)
    fw = Counter((r["framework"] or "other") for r in rows)
    full = [r for r in rows if (r["maxclients"] or 0) > 0]
    fill = sum(r["clients"] or 0 for r in full) / sum(r["maxclients"] or 0 for r in full) * 100 if full else 0
    con = sqlite3.connect(_GEO_DB)
    con.execute(_HISTORY_TBL)
    con.execute("INSERT INTO dump_history(ts,total,players,capacity,direct_ip,private,discord,"
                "mastodon,premium,esx,qbcore,qbox,vrp,nd,avg_fill) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), n, tpl, cap,
                 sum(1 for r in rows if r["ip"]), sum(1 for r in rows if r["private"]),
                 sum(1 for r in rows if r["discord"]), sum(1 for r in rows if r["mastodon"]),
                 sum(1 for r in rows if r["premium"]), fw.get("ESX", 0), fw.get("QBCore", 0),
                 fw.get("QBox", 0), fw.get("vRP", 0), fw.get("ND", 0), round(fill, 1)))
    con.commit()
    con.close()


def show_history(limit=20):
    import sqlite3
    con = sqlite3.connect(_GEO_DB)
    con.execute(_HISTORY_TBL)
    rows = list(con.execute("SELECT ts,total,players,capacity,direct_ip,discord,mastodon,"
                            "esx,qbcore,avg_fill FROM dump_history ORDER BY id DESC LIMIT ?", (limit,)))
    con.close()
    print(f"\n  HISTORY (last {len(rows)} snapshots)")
    print(f"  {'TIMESTAMP':<20}{'TOTAL':<8}{'PLAYERS':<9}{'CAP':<9}{'IP':<7}{'DISC':<6}{'MASTO':<7}{'ESX':<7}{'QB':<7}FILL")
    print("  " + "-" * 95)
    prev = None
    for r in rows:
        delta = f"{r[2] - prev[2]:+d}" if prev and prev[0][:10] == r[0][:10] else ""
        print(f"  {r[0]:<20}{r[1]:<8}{r[2]:<9}{r[3]:<9}{r[4]:<7}{r[5]:<6}{r[6]:<7}{r[7]:<7}{r[8]:<7}{r[9]:<6}{delta}")
        prev = r


def deep_analysis(rows, topn=15):
    """Network farms (/24 & /16), duplicate IPs, deep distributions."""
    from collections import defaultdict
    ips = defaultdict(list)
    for r in rows:
        if r["ip"]:
            ips[r["ip"]].append(r["code"])
    dups = {ip: cs for ip, cs in ips.items() if len(cs) > 1}
    with_ip = sum(1 for r in rows if r["ip"])
    print(f"\n  DEEP ANALYSIS (servers with IP: {with_ip})")
    print(f"\n  [1] duplicate IPs (same host, multiple servers): {len(dups)} unique IPs")
    for ip, cs in sorted(dups.items(), key=lambda kv: -len(kv[1]))[:topn]:
        print(f"      {ip:<22}{len(cs):>3} servers  {', '.join(cs[:6])}{'...' if len(cs) > 6 else ''}")
    if len(dups) > topn:
        print(f"      ... {len(dups) - topn} more")

    def grp(bits):
        out = defaultdict(list)
        for r in rows:
            if r["ip"]:
                p = ".".join(r["ip"].split(".")[:bits])
                out[p].append((r["code"], r["clients"] or 0))
        return {k: v for k, v in out.items() if len(v) > 1}

    print(f"\n  [2] /24 blocks with many servers (hosting farms):")
    g24 = grp(3)
    cached = {}
    try:
        con = _geo_cache()
        cached = {r[0]: r[1:] for r in con.execute("SELECT ip, country, isp, asn FROM ip_geo")}
        con.close()
    except Exception:
        pass
    for blk, v in sorted(g24.items(), key=lambda kv: -len(kv[1]))[:topn]:
        pl = sum(c for _, c in v)
        seed = next((r for r in rows if r["ip"] and r["ip"].startswith(blk + ".")), None)
        info = ""
        if seed and seed["ip"] in cached:
            ctry, isp, asn = cached[seed["ip"]]
            info = f"  [{ctry} | {isp[:30]} | {asn}]"
        print(f"      {blk}.0/24  {len(v):>3} servers  {pl:>5} players{info}")
    print(f"\n  [3] /16 blocks (big networks):")
    g16 = grp(2)
    for blk, v in sorted(g16.items(), key=lambda kv: -len(kv[1]))[:topn]:
        pl = sum(c for _, c in v)
        seed = next((r for r in rows if r["ip"] and r["ip"].startswith(blk + ".")), None)
        info = ""
        if seed and seed["ip"] in cached:
            ctry, isp, asn = cached[seed["ip"]]
            info = f"  [{ctry} | {isp[:30]} | {asn}]"
        print(f"      {blk}.0.0/16  {len(v):>4} servers  {pl:>6} players{info}")
    if not g24:
        print("      (no IP data / all unique)")

    print(f"\n  [4] top endpoints by server count:")
    eps = defaultdict(int)
    for r in rows:
        if r["endpoint"]:
            eps[r["endpoint"].split(":")[0] if ":" in r["endpoint"] else r["endpoint"]] += 1
    for ep, n in sorted(eps.items(), key=lambda kv: -kv[1])[:topn]:
        print(f"      {ep:<40}{n:>4} servers")


def deep_stats(rows):
    from collections import Counter
    n = len(rows)
    gb = Counter((r.get("gamebuild") or "default") for r in rows)
    sh = sum(1 for r in rows if r.get("scriptHook") and r["scriptHook"] != "false")
    al = sum(1 for r in rows if r.get("allowlisted") and r["allowlisted"] != "false")
    os_ = sum(1 for r in rows if r.get("onesync") and r["onesync"] != "false")
    enh = sum(1 for r in rows if r.get("enhanced"))
    lan = sum(1 for r in rows if r.get("lan") and r["lan"] != "false")
    tags = Counter()
    for r in rows:
        for t in (r.get("tags") or "").split(","):
            t = t.strip().lower()
            if t and t not in ("", "roleplay", "rp"):
                tags[t] += 1
    print(f"\n  DEEP STATS (n={n})")
    print(f"    gamebuild     : {', '.join(f'{k}:{v}' for k, v in gb.most_common(8))}")
    print(f"    scriptHook on : {sh}   allowlisted: {al}   onesync: {os_}   enhancedHost: {enh}   lan: {lan}")
    print(f"    top tags      : {', '.join(f'{k}:{v}' for k, v in tags.most_common(12))}")


def write_dashboard(rows, out, stats, history):
    from collections import Counter
    html = []
    html.append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>FiveM Stream Dashboard</title>")
    html.append("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f1218;color:#dfe6f0}"
                "h1{color:#4fc3f7}h2{color:#ffd54f;border-bottom:1px solid #333;padding-bottom:6px;margin-top:30px}"
                "table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #2a3240;padding:4px 8px;text-align:left}"
                "th{background:#1a2230}tr:nth-child(even){background:#141a24}.card{display:inline-block;background:#141a24;"
                "border:1px solid #2a3240;border-radius:8px;padding:12px 18px;margin:6px;min-width:130px}"
                ".num{font-size:22px;font-weight:bold;color:#4fc3f7}.dim{color:#7f8ea3}</style></head><body>")
    html.append(f"<h1>FiveM Live Stream Dashboard</h1><p class='dim'>generated {time.strftime('%Y-%m-%d %H:%M:%S')}</p>")
    for label, val in [("Servers", stats[0]), ("Players live", stats[1]), ("Capacity", stats[2]),
                       ("Direct IP", stats[3]), ("Private", stats[4]), ("Discord", stats[5]),
                       ("Mastodon", stats[6]), ("Premium", stats[7])]:
        html.append(f"<span class='card'><div class='num'>{val}</div><div class='dim'>{label}</div></span>")
    html.append("<h2>Top 20 busiest servers</h2><table><tr><th>Code</th><th>Hostname</th><th>Players</th>"
                "<th>Max</th><th>Framework</th><th>Country</th><th>IP</th></tr>")
    for r in sorted(rows, key=lambda r: -(r["clients"] or 0))[:20]:
        html.append(f"<tr><td>{r['code']}</td><td>{clean(r['hostname'])[:60]}</td><td>{r['clients'] or 0}</td>"
                    f"<td>{r['maxclients'] or 0}</td><td>{r.get('framework') or '-'}</td><td>{r.get('country') or '-'}</td>"
                    f"<td>{r.get('ip') or '-'}</td></tr>")
    html.append("</table>")
    fw = Counter((r.get("framework") or "other") for r in rows)
    html.append("<h2>Frameworks</h2><table><tr><th>Framework</th><th>Count</th></tr>")
    for k, v in fw.most_common(12):
        html.append(f"<tr><td>{k}</td><td>{v}</td></tr>")
    html.append("</table>")
    loc = Counter((r.get("locale") or "unknown") for r in rows)
    html.append("<h2>Locales</h2><table><tr><th>Locale</th><th>Count</th></tr>")
    for k, v in loc.most_common(12):
        html.append(f"<tr><td>{k}</td><td>{v}</td></tr>")
    html.append("</table>")
    if history:
        html.append("<h2>Snapshot history</h2><table><tr><th>Time</th><th>Total</th><th>Players</th></tr>")
        for r in history:
            html.append(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>")
        html.append("</table>")
    html.append("</body></html>")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html))
    print(f"  [+] wrote dashboard -> {out}")


def apply_filters(rows, args):
    if args.subnet:
        rows = [r for r in rows if r["ip"] and core._stream_in_subnet(r["ip"], args.subnet)]
    if args.port:
        rows = [r for r in rows if r["port"] == str(args.port)]
    if args.masto:
        rows = [r for r in rows if args.masto.lower() in r["mastodon"].lower()]
    if args.discord:
        rows = [r for r in rows if r["discord"]]
    if args.keyword:
        rows = [r for r in rows if args.keyword.lower() in r["hostname"].lower()]
    if args.min_players is not None:
        rows = [r for r in rows if (r["clients"] or 0) >= args.min_players]
    if args.max_players is not None:
        rows = [r for r in rows if (r["clients"] or 0) <= args.max_players]
    if args.framework:
        want = args.framework.lower()
        rows = [r for r in rows if r["framework"].lower() == want]
    if args.premium_only:
        rows = [r for r in rows if r["premium"]]
    if args.sort_by:
        key = SORTS.get(args.sort_by)
        if key is not None:
            rows = sorted(rows, key=lambda r: r[args.sort_by] or 0, reverse=not args.reverse)
    if args.top:
        rows = sorted(rows, key=lambda r: r["clients"] or 0, reverse=True)[:args.top]
    if args.limit:
        rows = rows[:args.limit]
    return rows


def pretty_rows(rows, limit):
    print(f"\n  {'CODE':<9}{'PLAYERS':<9}{'CAP':<6}{'FW':<7}{'HOSTNAME':<32}{'GAMETYPE':<18}{'LOCALE':<8}ENDPOINT")
    print("  " + "-" * 118)
    for r in rows[:limit]:
        cl = r["clients"] or 0
        mc = r["maxclients"] or 0
        fw = (r["framework"] or "-")[:6]
        print(f"  {r['code']:<9}{f'{cl}/{mc}':<9}{r['fill'] if r['fill'] != '' else '-':<6}{fw:<7}"
              f"{(clean(r['hostname'])[:30] or '-'):<32}{(clean(r['gametype'])[:16] or '-'):<18}"
              f"{(r['locale'] or '-'):<8}{(r['endpoint'] or '-')}")
    if len(rows) > limit:
        print(f"  ... {len(rows) - limit} more")


def show_stats(rows):
    n = len(rows)
    total_players = sum(r["clients"] or 0 for r in rows)
    total_cap = sum(r["maxclients"] or 0 for r in rows)
    full = [r for r in rows if (r["maxclients"] or 0) > 0]
    avg_fill = sum(r["clients"] or 0 for r in full) / sum(r["maxclients"] or 0 for r in full) * 100 if full else 0
    print(f"\n  STATISTICS")
    print(f"    servers       : {n}")
    print(f"    players live  : {total_players}  (capacity {total_cap}, overall fill {avg_fill:.1f}%)")
    print(f"    with direct IP: {sum(1 for r in rows if r['ip'])}   private: {sum(1 for r in rows if r['private'])}")
    print(f"    with Discord  : {sum(1 for r in rows if r['discord'])}   Mastodon: {sum(1 for r in rows if r['mastodon'])}   premium: {sum(1 for r in rows if r['premium'])}")
    fw = Counter((r["framework"] or "other") for r in rows)
    if fw:
        print(f"    frameworks    : {', '.join(f'{k}={v}' for k, v in fw.most_common(8))}")
    loc = Counter(("default" if r["locale"] == "root-AQ" else (r["locale"] or "unknown")) for r in rows)
    if loc:
        print(f"    locales (top) : {', '.join(f'{k}:{v}' for k, v in loc.most_common(8))}")
    gt = Counter((r["gametype"] or "unknown") for r in rows)
    if gt:
        print(f"    gametypes     : {', '.join(f'{k}:{v}' for k, v in gt.most_common(6))}")
    tx = Counter("txAdmin" if r["txAdmin"] else "no-txAdmin" for r in rows)
    print(f"    txAdmin       : {tx.get('txAdmin', 0)} / {n}")
    onesync = Counter("Onesync" if r["onesync"] and r["onesync"] != "false" else "no-onesync" for r in rows)
    print(f"    onesync       : {onesync.get('Onesync', 0)} / {n}")
    print("    busiest:")
    for r in sorted(rows, key=lambda r: -(r["clients"] or 0))[:10]:
        print(f"      {r['code']:<9}{r['clients']:>5}/{r['maxclients']:<5} {clean(r['hostname'])[:60]}")


def ask(rows, msg="  choice> "):
    return input(msg).strip()


def run(args, auto_print=True):
    print("  [i] fetching global live-server stream ...")
    data = core.fetch_stream(args.fresh, 90)
    print("  [i] decoding protobuf stream (official Cfx frame format) ...")
    rows = enrich(core.parse_stream_detailed(data))
    print(f"  [+] decoded {len(rows)} live servers")

    if args.out:
        try:
            save_history(rows)
        except Exception:
            pass

    rows = apply_filters(rows, args)

    if getattr(args, "geo", False):
        print("  [i] geo/ASN enrichment (cached, resumable) ...")
        pending, done = geo_enrich(rows, getattr(args, "geo_limit", 300) or 300)
        print(f"  [+] geo: {done} enriched, {max(0, pending - done)} still pending (run again to continue)")

    if getattr(args, "deep", False):
        deep_analysis(rows)
        deep_stats(rows)

    if getattr(args, "dashboard", False) and args.dashboard:
        with_ip = sum(1 for r in rows if r["ip"])
        hist = []
        try:
            import sqlite3
            con = sqlite3.connect(_GEO_DB)
            con.execute(_HISTORY_TBL)
            hist = list(con.execute("SELECT ts,total,players,capacity FROM dump_history ORDER BY id DESC LIMIT 10"))
            con.close()
        except Exception:
            pass
        write_dashboard(rows, args.dashboard,
                        [len(rows), sum(r["clients"] or 0 for r in rows),
                         sum(r["maxclients"] or 0 for r in rows), with_ip,
                         sum(1 for r in rows if r["private"]),
                         sum(1 for r in rows if r["discord"]),
                         sum(1 for r in rows if r["mastodon"]),
                         sum(1 for r in rows if r["premium"])], hist)

    if args.stats_only:
        if auto_print:
            show_stats(rows)
        return rows

    if args.out:
        with open(args.out, "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            for r in rows:
                w.writerow([r.get(c, "") for c in COLUMNS])
        print(f"  [+] wrote {len(rows)} rows -> {args.out}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, ensure_ascii=False, indent=1)
        print(f"  [+] wrote JSON -> {args.json}")

    if args.sample and auto_print:
        pretty_rows(rows, args.sample)

    if auto_print:
        show_stats(rows)
    return rows


def menu():
    core.ENABLE_COLOR = True
    try:
        core.enable_vt()
    except AttributeError:
        pass
    c = core.c
    print(c("b_cyan", "=" * 62))
    print(c("b_cyan", "  F I V E M   S T R E A M   D U M P") + c("b_white", "   —   full live server list"))
    print(c("b_cyan", "=" * 62))
    items = [
        ("1", "Full dump", "write fivem-stream-full.csv (all servers)"),
        ("2", "Preview", "show N sample rows on console"),
        ("3", "Busiest", "top N servers by players -> CSV"),
        ("4", "Stats only", "no files, just statistics"),
        ("5", "Filters", "subnet / port / keyword / framework / players"),
        ("6", "JSON export", "write full JSON"),
        ("7", "Search", "interactive hostname / keyword search"),
        ("8", "Snapshot diff", "compare two dumps (CSV or JSON)"),
        ("9", "Live profile", "full live OSINT profile of one server"),
        ("10", "Players harvest", "extract player names + steam/ip identifiers from stream"),
        ("11", "Geo enrich", "country/ISP/ASN for server IPs (cached)"),
        ("12", "History", "past snapshots with player deltas"),
        ("13", "Deep analysis", "network farms / duplicate IPs / deep stats"),
        ("14", "Dashboard", "write an HTML report"),
    ]
    while True:
        print()
        print(c("b_cyan", "-" * 62))
        for num, title, desc in items:
            print(f"  {c('b_yellow', num):>3}  {c('b_white', title):<16} {c('dim', desc)}")
        print(f"  {c('b_yellow', '0')}   Exit")
        print(c("b_cyan", "-" * 62))
        choice = input(c("b_green", "  choice> ")).strip().lower()
        if choice in ("0", "q", "quit", "exit", "x"):
            break
        if choice == "1":
            run(argparse.Namespace(out="fivem-stream-full.csv", fresh=False, json=None,
                                   sample=0, stats_only=False, subnet=None, port=None,
                                   masto=None, discord=False, keyword=None, min_players=None,
                                   max_players=None, framework=None, premium_only=False,
                                   sort_by=None, reverse=False, top=None, limit=None))
        elif choice == "2":
            try:
                n = int(ask(None, c("b_green", "  how many rows? ")) or "10")
            except ValueError:
                n = 10
            run(argparse.Namespace(out=None, fresh=False, json=None, sample=n,
                                   stats_only=False, subnet=None, port=None, masto=None,
                                   discord=False, keyword=None, min_players=None,
                                   max_players=None, framework=None, premium_only=False,
                                   sort_by="clients", reverse=True, top=None, limit=None))
        elif choice == "3":
            try:
                n = int(ask(None, c("b_green", "  top N (default 50)? ")) or "50")
            except ValueError:
                n = 50
            out = ask(None, c("b_green", "  output csv (default top50.csv): ")).strip() or "top50.csv"
            run(argparse.Namespace(out=out, fresh=False, json=None, sample=0,
                                   stats_only=False, subnet=None, port=None, masto=None,
                                   discord=False, keyword=None, min_players=None,
                                   max_players=None, framework=None, premium_only=False,
                                   sort_by=None, reverse=False, top=n, limit=None))
        elif choice == "4":
            run(argparse.Namespace(out=None, fresh=False, json=None, sample=0,
                                   stats_only=True, subnet=None, port=None, masto=None,
                                   discord=False, keyword=None, min_players=None,
                                   max_players=None, framework=None, premium_only=False,
                                   sort_by=None, reverse=False, top=None, limit=None))
        elif choice == "5":
            subnet = ask(None, c("b_green", "  subnet (empty=all, e.g. 162.222.16.0/24): ")).strip() or None
            port = ask(None, c("b_green", "  port (empty=all): ")).strip()
            kw = ask(None, c("b_green", "  hostname keyword (empty=none): ")).strip() or None
            fw = ask(None, c("b_green", "  framework (ESX/QBCore/QBox/vRP/ND, empty=all): ")).strip() or None
            mn = ask(None, c("b_green", "  min players (empty=0): ")).strip()
            out = ask(None, c("b_green", "  output csv (empty=filtered.csv): ")).strip() or "filtered.csv"
            run(argparse.Namespace(out=out, fresh=False, json=None, sample=0,
                                   stats_only=False, subnet=subnet,
                                   port=int(port) if port.isdigit() else None,
                                   masto=None, discord=False, keyword=kw,
                                   min_players=int(mn) if mn.isdigit() else None,
                                   max_players=None, framework=fw, premium_only=False,
                                   sort_by=None, reverse=False, top=None, limit=None))
        elif choice == "6":
            out = ask(None, c("b_green", "  json file (default fivem-stream-full.json): ")).strip() or "fivem-stream-full.json"
            run(argparse.Namespace(out=None, fresh=False, json=out, sample=0,
                                   stats_only=False, subnet=None, port=None, masto=None,
                                   discord=False, keyword=None, min_players=None,
                                   max_players=None, framework=None, premium_only=False,
                                   sort_by=None, reverse=False, top=None, limit=None))
        elif choice == "7":
            kw = ask(None, c("b_green", "  search keyword: ")).strip()
            if not kw:
                continue
            try:
                n = int(ask(None, c("b_green", "  how many results (default 15)? ")) or "15")
            except ValueError:
                n = 15
            rows = run(argparse.Namespace(out=None, fresh=False, json=None, sample=0,
                                          stats_only=False, subnet=None, port=None, masto=None,
                                          discord=False, keyword=kw, min_players=None,
                                          max_players=None, framework=None, premium_only=False,
                                          sort_by="clients", reverse=True, top=None, limit=None))
            if rows:
                pretty_rows(rows, n)
        elif choice == "8":
            a = ask(None, c("b_green", "  older dump file (csv/json): ")).strip()
            b = ask(None, c("b_green", "  newer dump file (csv/json): ")).strip()
            if not a or not b or not os.path.exists(a) or not os.path.exists(b):
                print(c("b_red", "  [x] one of the files does not exist"))
                continue
            try:
                load_rows = lambda f: (json.load(open(f, encoding="utf-8")) if f.lower().endswith(".json")
                                       else list(csv.DictReader(open(f, encoding="utf-8-sig"))))
                ra, rb = load_rows(a), load_rows(b)
            except Exception as e:
                print(c("b_red", f"  [x] cannot read dumps: {e}"))
                continue
            ka = {r["code"] for r in ra}
            kb = {r["code"] for r in rb}
            players_a = sum(int(r.get("clients") or 0) for r in ra)
            players_b = sum(int(r.get("clients") or 0) for r in rb)
            print(c("b_cyan", "  --- snapshot diff ---"))
            print(f"  {c('b_white', a)}: {len(ra)} servers, {players_a} players")
            print(f"  {c('b_white', b)}: {len(rb)} servers, {players_b} players")
            print(f"  new servers    : {len(kb - ka)}")
            print(f"  gone servers   : {len(ka - kb)}")
            print(f"  player change  : {players_b - players_a:+d}")
            idx = {r["code"]: int(r.get("clients") or 0) for r in rb}
            if idx:
                top = sorted(idx.items(), key=lambda kv: -kv[1])[:10]
                print("  top players now:")
                for code, cl in top:
                    print(f"    {code:<10}{cl:>5}")
        elif choice == "9":
            code = ask(None, c("b_green", "  server code / cfx URL: ")).strip()
            if not code:
                continue
            code = core.extract_code(code) or code
            try:
                p = core.build_profile(code, 20, with_geo=True, with_players=True, probe=False, with_extras=True)
                core.print_profile(p, full=True)
            except Exception as e:
                print(c("b_red", f"  [x] {e}"))
        elif choice == "10":
            n = ask(None, c("b_green", "  fetch live players for top-N busiest servers (default 20): ")).strip()
            try:
                n = int(n) if n else 20
            except ValueError:
                n = 20
            rows = run(argparse.Namespace(out=None, fresh=False, json=None, sample=0,
                                          stats_only=False, subnet=None, port=None, masto=None,
                                          discord=False, keyword=None, min_players=None,
                                          max_players=None, framework=None, premium_only=False,
                                          sort_by=None, reverse=False, top=None, limit=None,
                                          geo=False, geo_limit=0), auto_print=False)
            top = sorted(rows, key=lambda r: -(r["clients"] or 0))[:n]
            print(c("b_cyan", f"  --- fetching players for top {len(top)} servers (public API) ---"))
            steam = ip_ids = xbl = discord_ids = 0
            fetched = []
            for r in top:
                try:
                    d = core.api_lookup(r["code"], 10)
                    pl = (d.get("data") or {}).get("players") or []
                except Exception:
                    pl = []
                st = sum(1 for p in pl for i in p.get("identifiers", []) if i.startswith("steam:"))
                ipp = sum(1 for p in pl for i in p.get("identifiers", []) if i.startswith("ip:"))
                xb = sum(1 for p in pl for i in p.get("identifiers", []) if i.startswith("xbl:"))
                dc = sum(1 for p in pl for i in p.get("identifiers", []) if i.startswith("discord:"))
                steam += st
                ip_ids += ipp
                xbl += xb
                discord_ids += dc
                fetched.append({"code": r["code"], "hostname": clean(r["hostname"])[:40],
                                "players": len(pl), "steam": st, "ip": ipp, "xbl": xb, "discord": dc})
                print(f"  {r['code']:<9}{len(pl):>4} players  {st:>3} steam  {ipp:>3} ip  {xb:>2} xbl  {dc:>3} discord  {clean(r['hostname'])[:40]}")
                time.sleep(0.3)
            print(c("b_cyan", "  --- totals ---"))
            print(f"  servers queried : {len(fetched)}")
            print(f"  steam ids       : {steam}")
            print(f"  ip ids          : {ip_ids}")
            print(f"  xbox ids        : {xbl}")
            print(f"  discord ids     : {discord_ids}")
            out = ask(None, c("b_green", "  save as CSV (empty = skip)? ")).strip()
            if out:
                with open(out, "w", encoding="utf-8-sig", newline="") as fh:
                    w = csv.DictWriter(fh, fieldnames=["code", "hostname", "players", "steam", "ip", "xbl", "discord"])
                    w.writeheader()
                    w.writerows(fetched)
                print(f"  [+] wrote -> {out}")
        elif choice == "11":
            n = ask(None, c("b_green", "  max new IPs to enrich (default 300): ")).strip()
            rows = run(argparse.Namespace(out=None, fresh=False, json=None, sample=0,
                                          stats_only=False, subnet=None, port=None, masto=None,
                                          discord=False, keyword=None, min_players=None,
                                          max_players=None, framework=None, premium_only=False,
                                          sort_by=None, reverse=False, top=None, limit=None,
                                          geo=True, geo_limit=int(n) if n.isdigit() else 300),
                       auto_print=False)
            cnt = Counter((r.get("country") or "?") for r in rows if r.get("country"))
            if cnt:
                print(c("b_cyan", "  --- top countries (enriched so far) ---"))
                for k, v in cnt.most_common(10):
                    print(f"    {k:<12}{v}")
            con = _geo_cache()
            total = con.execute("SELECT COUNT(*) FROM ip_geo").fetchone()[0]
            con.close()
            print(f"  cached geo records: {total}")
        elif choice == "12":
            show_history(20)
        elif choice == "13":
            rows = run(argparse.Namespace(out=None, fresh=False, json=None, sample=0,
                                          stats_only=False, subnet=None, port=None, masto=None,
                                          discord=False, keyword=None, min_players=None,
                                          max_players=None, framework=None, premium_only=False,
                                          sort_by=None, reverse=False, top=None, limit=None,
                                          geo=False, geo_limit=0, deep=True, dashboard=None),
                       auto_print=False)
        elif choice == "14":
            out = ask(None, c("b_green", "  dashboard file (default dashboard.html): ")).strip() or "dashboard.html"
            rows = run(argparse.Namespace(out=None, fresh=False, json=None, sample=0,
                                          stats_only=False, subnet=None, port=None, masto=None,
                                          discord=False, keyword=None, min_players=None,
                                          max_players=None, framework=None, premium_only=False,
                                          sort_by=None, reverse=False, top=None, limit=None,
                                          geo=False, geo_limit=0, deep=False, dashboard=out),
                       auto_print=False)
        else:
            print(c("b_red", "  [x] invalid choice"))
    print(c("b_cyan", "  bye."))


def main():
    if len(sys.argv) == 1:
        menu()
        return
    ap = argparse.ArgumentParser(description="FiveM Stream Dump — full live server list -> CSV/JSON")
    ap.add_argument("--out", metavar="FILE", default="fivem-stream-full.csv")
    ap.add_argument("--fresh", action="store_true", help="force re-download the stream")
    ap.add_argument("--json", metavar="FILE", help="also write full JSON")
    ap.add_argument("--sample", type=int, default=0, help="print a console preview of N rows")
    ap.add_argument("--stats-only", action="store_true")
    ap.add_argument("--subnet", metavar="CIDR", help="only servers in this subnet")
    ap.add_argument("--port", type=int, help="only servers on this endpoint port")
    ap.add_argument("--masto", metavar="HANDLE", help="only servers with this mastodon")
    ap.add_argument("--discord", action="store_true", help="only servers with a Discord invite")
    ap.add_argument("--keyword", metavar="KW", help="only servers whose hostname contains KW")
    ap.add_argument("--min-players", type=int, help="only servers with >= N players")
    ap.add_argument("--max-players", type=int, help="only servers with <= N players")
    ap.add_argument("--framework", choices=FRAMEWORKS, help="only servers running this framework")
    ap.add_argument("--premium-only", action="store_true", help="only premium servers")
    ap.add_argument("--sort-by", choices=sorted(SORTS), help="sort rows by column")
    ap.add_argument("--reverse", action="store_true", help="sort descending")
    ap.add_argument("--top", type=int, help="keep only the N busiest servers")
    ap.add_argument("--geo", action="store_true", help="enrich country/isp/asn (cached)")
    ap.add_argument("--geo-limit", type=int, default=300, help="max new IPs per geo run")
    ap.add_argument("--deep", action="store_true", help="network farms / duplicate IPs / deep stats")
    ap.add_argument("--dashboard", metavar="FILE", help="write an HTML dashboard")
    ap.add_argument("--history", action="store_true", help="show past snapshot history")
    ap.add_argument("--limit", type=int, help="cap rows (CSV/JSON too)")
    args = ap.parse_args()

    if args.history:
        show_history(20)
        return

    run(args)


if __name__ == "__main__":
    main()
