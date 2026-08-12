#!/usr/bin/env python3
"""
FiveM OSINT GUI — professional dark-mode desktop GUI for the FiveM OSINT suite.

Run:  python fivem-osint-gui.py
Self-test (auto-close):  python fivem-osint-gui.py --selftest
"""

import argparse
import csv
import importlib.util
import json
import os
import sys
import threading
import time
import tkinter as tk
import urllib.parse
from tkinter import ttk, filedialog, messagebox

CORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fivem-osint.py")
_spec = importlib.util.spec_from_file_location("fivem_osint_core", CORE_PATH)
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)
core.ENABLE_COLOR = False

# ---------------------------------------------------------------- palette
BG        = "#11111b"
BG_PANEL  = "#181825"
BG_FIELD  = "#1e1e2e"
BG_HOVER  = "#313244"
FG        = "#cdd6f4"
FG_MUTED  = "#6c7086"
ACCENT    = "#89b4fa"
GREEN     = "#a6e3a1"
YELLOW    = "#f9e2af"
RED       = "#f38ba8"
MAGENTA   = "#cba6f7"
CYAN      = "#94e2d5"
BORDER    = "#313244"

FONT      = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 10)
FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_BIG  = ("Segoe UI", 15, "bold")

SEV_TAGS = {"CRIT": RED, "HIGH": RED, "MED": YELLOW, "LOW": ACCENT, "INFO": FG_MUTED}


class Status:
    def __init__(self, root, label_var):
        self.root = root
        self.label_var = label_var
        self.busy = 0

    def set(self, text):
        self.root.after(0, lambda: self.label_var.set(text))

    def start(self, text="working..."):
        self.busy += 1
        self.set(text)

    def stop(self):
        self.busy = max(0, self.busy - 1)
        if self.busy == 0:
            self.set("ready")


class App:
    def __init__(self, root):
        self.root = root
        root.title("FiveM OSINT — Server Intelligence Suite")
        root.geometry("1080x740")
        root.minsize(900, 620)
        root.configure(bg=BG)
        self.last_code = None
        self._build_style()
        self._build_ui()
        self._threads = 0

    # ------------------------------------------------------------ styling
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_FIELD,
                        bordercolor=BORDER, lightcolor=BG, darkcolor=BG, font=FONT)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("TNotebook", background=BG_PANEL, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_MUTED,
                        padding=(14, 7), font=FONT)
        style.map("TNotebook.Tab", background=[("selected", BG_FIELD)],
                  foreground=[("selected", ACCENT)])
        style.configure("TButton", background=BG_FIELD, foreground=FG, padding=(12, 6), borderwidth=1)
        style.map("TButton", background=[("active", BG_HOVER), ("disabled", BG_PANEL)],
                  foreground=[("disabled", FG_MUTED)])
        style.configure("Accent.TButton", background=ACCENT, foreground=BG, font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#9fc6ff")])
        style.configure("TEntry", fieldbackground=BG_FIELD, foreground=FG, insertcolor=FG, padding=6)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG)
        style.configure("Muted.TLabel", background=BG, foreground=FG_MUTED)
        style.configure("Treeview", background=BG_FIELD, fieldbackground=BG_FIELD,
                        foreground=FG, rowheight=26, borderwidth=0, font=FONT)
        style.configure("Treeview.Heading", background=BG_PANEL, foreground=FG_MUTED,
                        font=("Segoe UI", 9, "bold"), padding=6)
        style.map("Treeview", background=[("selected", BG_HOVER)], foreground=[("selected", ACCENT)])
        style.configure("TProgressbar", background=ACCENT, troughcolor=BG_FIELD, borderwidth=0)
        style.configure("Horizontal.TScrollbar", background=BG_FIELD, troughcolor=BG_PANEL,
                        arrowcolor=FG, borderwidth=0)

    # ------------------------------------------------------------ ui build
    def _mk_text(self, parent, mono=False, wrap="word"):
        txt = tk.Text(parent, bg=BG_FIELD, fg=FG, insertbackground=FG, relief="flat",
                      padx=14, pady=10, wrap=wrap, font=FONT_MONO if mono else FONT,
                      selectbackground=BG_HOVER, selectforeground=ACCENT, cursor="arrow")
        txt.configure(state="disabled")
        txt.tag_configure("h1", foreground=ACCENT, font=FONT_TITLE, spacing1=6, spacing3=6)
        txt.tag_configure("h2", foreground=CYAN, font=("Segoe UI", 10, "bold"), spacing1=8, spacing3=2)
        txt.tag_configure("lbl", foreground=FG_MUTED)
        txt.tag_configure("val", foreground=FG)
        txt.tag_configure("key", foreground=MAGENTA)
        txt.tag_configure("good", foreground=GREEN)
        txt.tag_configure("warn", foreground=YELLOW)
        txt.tag_configure("bad", foreground=RED)
        txt.tag_configure("mono", foreground=YELLOW, font=FONT_MONO)
        txt.tag_configure("muted", foreground=FG_MUTED)
        return txt

    def _write(self, txt, text, tag=None):
        txt.configure(state="normal")
        txt.insert("end", text + "\n", tag) if tag else txt.insert("end", text + "\n")
        txt.configure(state="disabled")

    def _clear(self, txt):
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        txt.configure(state="disabled")

    def _build_ui(self):
        # ---------- top bar
        top = ttk.Frame(self.root, padding=(14, 12, 14, 6))
        top.pack(fill="x")
        ttk.Label(top, text="FIVEM", font=FONT_BIG, foreground=ACCENT).pack(side="left")
        ttk.Label(top, text="OSINT", font=FONT_BIG, foreground=MAGENTA).pack(side="left")
        ttk.Label(top, text="   FiveM Server Intelligence Suite", foreground=FG_MUTED).pack(side="left", padx=(8, 0))

        self.code_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.code_var, width=30, font=FONT_MONO)
        entry.pack(side="right", padx=(10, 8))
        entry.insert(0, "6r9ob4  or  cfx.re/join/abc123")
        entry.configure(foreground=FG_MUTED)
        entry.bind("<FocusIn>", lambda e: (self.code_var.set(""), entry.configure(foreground=FG)) if self.code_var.get() and "or" in self.code_var.get() else None)
        entry.bind("<Return>", lambda e: self.run_profile())
        ttk.Button(top, text="Resolve", style="Accent.TButton", command=self.run_profile).pack(side="right")

        # ---------- module buttons
        btns = ttk.Frame(self.root, padding=(14, 4, 14, 4))
        btns.pack(fill="x")
        actions = [
            ("Profile", self.run_profile), ("Players", self.run_players), ("Resources", self.run_resources),
            ("Scan", self.run_scan), ("Deep", self.run_deep), ("Stream", self.run_stream),
            ("Owner", self.run_owner), ("Discord", self.run_discord),
            ("Media", self.run_media), ("History", self.run_history), ("Raw", self.run_raw),
        ]
        for label, cmd in actions:
            ttk.Button(btns, text=label, command=cmd).pack(side="left", padx=(0, 6))

        # ---------- notebook
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(4, 4))

        # Profile
        self.tab_profile = ttk.Frame(self.nb, style="Panel.TFrame")
        self.profile_txt = self._mk_text(self.tab_profile)
        self.profile_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.nb.add(self.tab_profile, text=" Profile ")

        # Players
        self.tab_players = ttk.Frame(self.nb, style="Panel.TFrame")
        head = ttk.Frame(self.tab_players, style="Panel.TFrame")
        head.pack(fill="x", padx=8, pady=(8, 0))
        self.players_sum = ttk.Label(head, text="", style="Panel.TLabel")
        self.players_sum.pack(side="left")
        ttk.Button(head, text="Save CSV", command=self.save_players_csv).pack(side="right")
        self.players_tree = ttk.Treeview(self.tab_players, columns=("id", "name", "ping"),
                                         show="headings", selectmode="browse")
        for col, w in (("id", 80), ("name", 500), ("ping", 80)):
            self.players_tree.heading(col, text={"id": "ID", "name": "Name", "ping": "Ping"}[col])
            self.players_tree.column(col, width=w, anchor="w")
        self.players_tree.pack(fill="both", expand=True, padx=8, pady=8)
        self._add_scroll(self.players_tree)
        self.nb.add(self.tab_players, text=" Players ")

        # Resources
        self.tab_res = ttk.Frame(self.nb, style="Panel.TFrame")
        head = ttk.Frame(self.tab_res, style="Panel.TFrame")
        head.pack(fill="x", padx=8, pady=(8, 0))
        self.res_sum = ttk.Label(head, text="", style="Panel.TLabel")
        self.res_sum.pack(side="left")
        ttk.Button(head, text="Save TXT", command=self.save_resources_txt).pack(side="right")
        self.res_tree = ttk.Treeview(self.tab_res, columns=("name",), show="headings")
        self.res_tree.heading("name", text="Resource name")
        self.res_tree.column("name", width=800, anchor="w")
        self.res_tree.pack(fill="both", expand=True, padx=8, pady=8)
        self._add_scroll(self.res_tree)
        self.nb.add(self.tab_res, text=" Resources ")

        # Scan
        self.tab_scan = ttk.Frame(self.nb, style="Panel.TFrame")
        self.scan_txt = self._mk_text(self.tab_scan, mono=True)
        self.scan_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.nb.add(self.tab_scan, text=" Scan ")

        # Owner
        self.tab_owner = ttk.Frame(self.nb, style="Panel.TFrame")
        self.owner_txt = self._mk_text(self.tab_owner)
        self.owner_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.nb.add(self.tab_owner, text=" Owner ")

        # Discord
        self.tab_discord = ttk.Frame(self.nb, style="Panel.TFrame")
        self.discord_txt = self._mk_text(self.tab_discord)
        self.discord_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.nb.add(self.tab_discord, text=" Discord ")

        # Media
        self.tab_media = ttk.Frame(self.nb, style="Panel.TFrame")
        row = ttk.Frame(self.tab_media, style="Panel.TFrame")
        row.pack(fill="x", padx=8, pady=8)
        self.media_dir_var = tk.StringVar(value=os.path.join("fivem-media", "<code>"))
        ttk.Entry(row, textvariable=self.media_dir_var, width=50).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Folder...", command=self.pick_media_dir).pack(side="left")
        ttk.Button(row, text="Download", command=self.run_media).pack(side="left", padx=6)
        self.media_txt = self._mk_text(self.tab_media, mono=True)
        self.media_txt.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb.add(self.tab_media, text=" Media ")

        # History
        self.tab_hist = ttk.Frame(self.nb, style="Panel.TFrame")
        head = ttk.Frame(self.tab_hist, style="Panel.TFrame")
        head.pack(fill="x", padx=8, pady=(8, 0))
        self.hist_sum = ttk.Label(head, text="", style="Panel.TLabel")
        self.hist_sum.pack(side="left")
        self.hist_tree = ttk.Treeview(self.tab_hist, columns=("ts", "players", "resrcs", "upvotes", "endpoint"),
                                      show="headings")
        for col, text, w in (("ts", "Timestamp", 150), ("players", "Players", 80), ("resrcs", "Resrcs", 80),
                             ("upvotes", "Upvotes", 80), ("endpoint", "Endpoint", 300)):
            self.hist_tree.heading(col, text=text)
            self.hist_tree.column(col, width=w, anchor="w")
        self.hist_tree.pack(fill="both", expand=True, padx=8, pady=8)
        self._add_scroll(self.hist_tree)
        self.nb.add(self.tab_hist, text=" History ")

        # Raw
        self.tab_raw = ttk.Frame(self.nb, style="Panel.TFrame")
        self.raw_txt = self._mk_text(self.tab_raw, mono=True, wrap="none")
        self.raw_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self._add_scroll(self.raw_txt, vertical=True, horizontal=True)
        self.nb.add(self.tab_raw, text=" Raw ")

        # Stream (global live server list)
        self.tab_stream = ttk.Frame(self.nb, style="Panel.TFrame")
        row = ttk.Frame(self.tab_stream, style="Panel.TFrame")
        row.pack(fill="x", padx=8, pady=(8, 4))
        self.stream_filter_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.stream_filter_var, width=28).pack(side="left", padx=(0, 6))
        self.stream_mode_var = tk.StringVar(value="keyword")
        ttk.Combobox(row, textvariable=self.stream_mode_var, values=("keyword", "subnet", "mastodon", "port", "discord-only"),
                     width=12, state="readonly").pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Search", command=self.run_stream).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Reload Stream", command=lambda: self.run_stream(fresh=True)).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Export CSV", command=self.save_stream_csv).pack(side="left", padx=(0, 6))
        self.stream_sum = ttk.Label(row, text="", style="Panel.TLabel")
        self.stream_sum.pack(side="left", padx=(10, 0))
        self.stream_tree = ttk.Treeview(self.tab_stream, columns=("code", "endpoint", "masto", "discord"),
                                        show="headings")
        for col, text, w in (("code", "Code", 110), ("endpoint", "Endpoint", 180),
                             ("masto", "Mastodon", 220), ("discord", "Discord", 220)):
            self.stream_tree.heading(col, text=text)
            self.stream_tree.column(col, width=w, anchor="w")
        self.stream_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._add_scroll(self.stream_tree)
        self.stream_tree.bind("<Double-1>", self.stream_load_server)
        self.stream_rows = []
        self.nb.add(self.tab_stream, text=" Stream ")

        # Deep OSINT
        self.tab_deep = ttk.Frame(self.nb, style="Panel.TFrame")
        self.deep_txt = self._mk_text(self.tab_deep, mono=True)
        self.deep_txt.pack(fill="both", expand=True, padx=8, pady=8)
        self._add_scroll(self.deep_txt)
        self.nb.add(self.tab_deep, text=" Deep OSINT ")

        # Batch
        self.tab_batch = ttk.Frame(self.nb, style="Panel.TFrame")
        row = ttk.Frame(self.tab_batch, style="Panel.TFrame")
        row.pack(fill="x", padx=8, pady=(8, 4))
        self.batch_file_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.batch_file_var, width=55).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Browse...", command=self.pick_batch_file).pack(side="left")
        ttk.Button(row, text="Run Batch", command=self.run_batch).pack(side="left", padx=6)
        ttk.Button(row, text="Export CSV", command=self.export_batch_csv).pack(side="left")
        self.batch_prog = ttk.Progressbar(self.tab_batch, maximum=100)
        self.batch_prog.pack(fill="x", padx=8, pady=4)
        self.batch_tree = ttk.Treeview(self.tab_batch,
                                       columns=("code", "hostname", "endpoint", "ip", "players", "max", "game", "frameworks", "owner", "error"),
                                       show="headings")
        for col, text, w in (("code", "Code", 90), ("hostname", "Hostname", 220), ("endpoint", "Endpoint", 160),
                             ("ip", "IP", 130), ("players", "P", 60), ("max", "Max", 60), ("game", "Game", 90),
                             ("frameworks", "Frameworks", 130), ("owner", "Owner", 130), ("error", "Error", 200)):
            self.batch_tree.heading(col, text=text)
            self.batch_tree.column(col, width=w, anchor="w")
        self.batch_tree.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self._add_scroll(self.batch_tree)
        self.batch_tree.bind("<Double-1>", self.batch_load_server)
        self.batch_rows = []
        self.nb.add(self.tab_batch, text=" Batch ")

        # ---------- status bar
        bar = ttk.Frame(self.root, padding=(14, 4, 14, 8))
        bar.pack(fill="x")
        self.status_var = tk.StringVar(value="ready")
        ttk.Label(bar, textvariable=self.status_var, foreground=FG_MUTED).pack(side="left")
        self.status = Status(self.root, self.status_var)

    def _add_scroll(self, tree, vertical=True, horizontal=False):
        if vertical:
            vs = ttk.Scrollbar(tree.master, orient="vertical", command=tree.yview)
            vs.pack(side="right", fill="y", padx=(0, 8), pady=8)
            tree.configure(yscrollcommand=vs.set)

    # ------------------------------------------------------------ threading
    def async_run(self, fn, on_done, busy_msg="working..."):
        self._threads += 1
        self.status.start(busy_msg)

        def work():
            try:
                result = fn()
            except Exception as e:
                result = e
            self.root.after(0, lambda: self._finish(result, on_done))

        threading.Thread(target=work, daemon=True).start()

    def _finish(self, result, on_done):
        self._threads -= 1
        self.status.stop()
        if isinstance(result, Exception):
            messagebox.showerror("Error", str(result))
            return
        on_done(result)

    # ------------------------------------------------------------ input
    def current_code(self):
        raw = self.code_var.get().strip()
        if not raw or ("or" in raw and "cfx.re" in raw):
            if self.last_code:
                return self.last_code
            messagebox.showwarning("No code", "Enter a cfx code or join URL first.")
            return None
        code = core.extract_code(raw)
        if not code:
            messagebox.showwarning("Invalid input", f"Could not extract a code from:\n{raw}")
            return None
        self.last_code = code
        self.code_var.set(code)
        return code

    # ------------------------------------------------------------ profile
    def run_profile(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_profile)
        self._clear(self.profile_txt)
        self.async_run(lambda: core.build_profile(code, 20, with_geo=True, with_players=True, probe=True),
                       self.render_profile, f"resolving {code} ...")

    def render_profile(self, p):
        t = self.profile_txt
        self._clear(t)
        if "error" in p:
            self._write(t, f"[x] {p['error']}", "bad")
            return
        self._write(t, f"{p.get('hostname') or 'n/a'}   —   {p['code']}", "h1")
        self._write(t, "SERVER", "h2")
        self._kv(t, "Code", p.get("code"))
        self._kv(t, "Game / Type / Map", f"{p.get('game')}  /  {p.get('gametype')}  /  {p.get('mapname') or 'n/a'}")
        self._kv(t, "Players", f"{p.get('players_count')} / {p.get('max_clients')}", good=True)
        self._kv(t, "Locale", p.get("locale"))
        self._kv(t, "Version", p.get("server_version"))
        self._kv(t, "Premium", p.get("premium"))
        self._kv(t, "Votes", f"upvotes={p.get('upvote_power')}  burst={p.get('burst_power')}")
        self._write(t, "NETWORK", "h2")
        for i, ep in enumerate(p.get("endpoints") or ["(hidden / private relay)"]):
            self._kv(t, f"Endpoint", ep, key=True)
        if p.get("private_relay"):
            self._write(t, "!! Private relay: origin IP masked by Cfx.re", "bad")
        if p.get("resolved_ip"):
            self._kv(t, "Resolved IP", p["resolved_ip"], key=True)
            if p.get("rdns"):
                self._kv(t, "rDNS", p.get("rdns"))
            self._kv(t, "Geo", core.fmt_geo(p.get("geo")))
        self._write(t, "OWNER", "h2")
        self._kv(t, "Name", p.get("owner", {}).get("name"))
        self._kv(t, "Account ID", p.get("owner", {}).get("id"), key=True)
        self._kv(t, "Profile", p.get("owner", {}).get("profile"))
        forum = p.get("owner", {}).get("forum")
        if forum and not forum.get("error"):
            self._kv(t, "Forum title", forum.get("title"))
        self._write(t, "COMMUNITY", "h2")
        d = p.get("discord")
        if d:
            if d.get("error"):
                self._kv(t, "Discord", f"resolution failed: {d['error']}", warn=True)
            else:
                self._kv(t, "Discord", f"{d.get('name')}  (guild {d.get('guild_id')})")
                self._kv(t, "Members", f"{d.get('members')} total / {d.get('online')} online", good=True)
                self._kv(t, "Invite channel", f"#{d.get('channel')}")
        m = p.get("mastodon")
        if m:
            self._kv(t, "Mastodon", f"{m.get('handle')} — {m.get('url')}")
        self._write(t, "RESOURCES & CONFIG", "h2")
        an = p.get("analysis") or {}
        self._kv(t, "Resources", an.get("count"))
        if an.get("frameworks"):
            self._kv(t, "Frameworks", ", ".join(an["frameworks"]), key=True)
        if an.get("admin_tools"):
            self._kv(t, "Admin tools", ", ".join(an["admin_tools"][:8]), warn=True)
        for k in ("sv_enforceGameBuild", "sv_pureLevel", "sv_scriptHookAllowed", "txAdmin-version", "onesync_enabled", "sv_appearAllowlisted"):
            if p.get("vars", {}).get(k):
                self._kv(t, k, p["vars"][k])
        probe = p.get("probe")
        if probe:
            self._write(t, "DIRECT ENDPOINT PROBE (/info.json)", "h2")
            st = probe.get("status")
            if st == "open":
                self._kv(t, "Status", f"OPEN ({probe.get('elapsed')}s)  resources={len(probe.get('resources') or [])}", good=True)
                self._kv(t, "steam_auth", probe.get("data", {}).get("enforceSteamAuth"))
            elif st == "open-nonjson":
                self._kv(t, "Status", "responds non-JSON", warn=True)
            else:
                self._kv(t, "Status", f"blocked ({probe.get('error')})", warn=True)
        self._write(t, "FINDINGS", "h2")
        for sev, msg in core.security_findings(p):
            self._write(t, f"  [{sev}] {msg}", SEV_TAGS.get(sev, "muted"))

    def run_deep(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_deep)
        self._clear(self.deep_txt)
        self.async_run(lambda: self._deep_text(code), self.render_deep, f"deep OSINT on {code} ...")

    def _deep_text(self, code):
        import io
        import sys as _sys
        buf = io.StringIO()
        old_out, old_err = _sys.stdout, _sys.stderr
        old_color = core.ENABLE_COLOR
        core.ENABLE_COLOR = False
        _sys.stdout = buf
        try:
            args = argparse.Namespace(code=code, timeout=22, no_probe=False, no_geo=False,
                                      json=False, players=False, out=None, save=None, file=None)
            core.mod_deep(args)
        except SystemExit as e:
            buf.write(f"\n[aborted: {e}]")
        except Exception as e:
            buf.write(f"\n[error: {e}]")
        finally:
            _sys.stdout, _sys.stderr = old_out, old_err
            core.ENABLE_COLOR = old_color
        return buf.getvalue()

    def render_deep(self, text):
        t = self.deep_txt
        self._clear(t)
        self._write(t, "DEEP OSINT — DNS / TLS / CDN / reverse-IP / CT / identifiers / GitHub", "h1")
        for line in text.splitlines():
            if not line.strip():
                self._write(t, "", "muted")
            elif line.strip().startswith("==") and not line.strip().startswith("==="):
                self._write(t, line, "h2")
            elif line.strip().startswith("=="):
                self._write(t, line, "muted")
            elif "->" in line:
                self._write(t, line, "key")
            else:
                self._write(t, line, "val")

    def _kv(self, t, k, v, key=False, good=False, warn=False):
        v = "n/a" if v is None else str(v)
        tag = "key" if key else ("good" if good else ("warn" if warn else "val"))
        t.configure(state="normal")
        t.insert("end", f"  {k:<28} ", "lbl")
        t.insert("end", v + "\n", tag)
        t.configure(state="disabled")

    # ------------------------------------------------------------ players
    def run_players(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_players)
        for i in self.players_tree.get_children():
            self.players_tree.delete(i)
        self.players_sum.configure(text=f"loading {code} ...")
        self.async_run(lambda: core.build_profile(code, 20, with_geo=False, with_players=True, probe=False, with_extras=False),
                       self.render_players, f"dumping players of {code} ...")

    def render_players(self, p):
        if "error" in p:
            self.players_sum.configure(text=f"[x] {p['error']}")
            return
        for i in self.players_tree.get_children():
            self.players_tree.delete(i)
        for pl in p.get("players") or []:
            self.players_tree.insert("", "end", values=(pl.get("id"), pl.get("name"), pl.get("ping")))
        self.players_sum.configure(text=f"{p.get('hostname')} — {p.get('players_count')} players")
        self.p_players = p

    def save_players_csv(self):
        p = getattr(self, "p_players", None)
        if not p or not p.get("players"):
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"{p['code']}-players.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "name", "ping"])
            w.writerows((pl.get("id"), pl.get("name"), pl.get("ping")) for pl in p["players"])
        self.status.set(f"saved {len(p['players'])} players to {os.path.basename(path)}")

    # ------------------------------------------------------------ resources
    def run_resources(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_res)
        for i in self.res_tree.get_children():
            self.res_tree.delete(i)
        self.res_sum.configure(text=f"loading {code} ...")
        self.async_run(lambda: core.build_profile(code, 20, with_geo=False, probe=True, with_extras=False),
                       self.render_resources, f"dumping resources of {code} ...")

    def render_resources(self, p):
        if "error" in p:
            self.res_sum.configure(text=f"[x] {p['error']}")
            return
        for i in self.res_tree.get_children():
            self.res_tree.delete(i)
        for r in p.get("resources") or []:
            self.res_tree.insert("", "end", values=(r,))
        an = p.get("analysis") or {}
        fw = f"   frameworks: {', '.join(an.get('frameworks') or [])}" if an.get("frameworks") else ""
        probe = p.get("probe", {}).get("status")
        src = " (from /info.json)" if probe == "open" else ""
        self.res_sum.configure(text=f"{p.get('hostname')} — {len(p.get('resources') or [])} resources{fw}{src}")
        self.p_resources = p

    def save_resources_txt(self):
        p = getattr(self, "p_resources", None)
        if not p:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"{p['code']}-resources.txt",
                                            filetypes=[("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(p.get("resources") or []))
        self.status.set(f"saved {len(p.get('resources') or [])} resources to {os.path.basename(path)}")

    # ------------------------------------------------------------ scan
    def run_scan(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_scan)
        self._clear(self.scan_txt)
        self.async_run(lambda: self._scan_work(code), self.render_scan, f"scanning {code} ...")

    def _scan_work(self, code):
        p = core.build_profile(code, 20, with_geo=False, probe=True, with_extras=False)
        if "error" in p:
            return p
        extra = []
        if p.get("resolved_ip") and not p.get("private_relay"):
            h, port, _ = core.split_endpoint((p.get("endpoints") or [""])[0])
            port = port or 30120
            extra.append(("PORT", f"game port {port} on {h}: {'OPEN / connectable' if core.tcp_check(h, port) else 'CLOSED / filtered'}"))
            if p.get("vars", {}).get("txAdmin-version"):
                extra.append(("PORT", f"txAdmin web port 40120: {'OPEN' if core.tcp_check(h, 40120) else 'CLOSED / filtered'}"))
            r = core.rdap_lookup(p["resolved_ip"])
            if r:
                extra.append(("RDAP", f"network='{r.get('network')}' country={r.get('country')} handle={r.get('handle')} "
                                      f"registrants={', '.join(r.get('registrants') or []) or 'n/a'}"))
        p["_scan_extra"] = extra
        return p

    def render_scan(self, p):
        t = self.scan_txt
        self._clear(t)
        if "error" in p:
            self._write(t, f"[x] {p['error']}", "bad")
            return
        self._write(t, f"SCAN — {p.get('hostname')}  ({p['code']})", "h1")
        self._write(t, f"  endpoint : {p.get('endpoints') or 'n/a'}")
        self._write(t, f"  ip       : {p.get('resolved_ip') or 'n/a'}")
        for tag, msg in p.get("_scan_extra", []):
            color = "good" if tag == "PORT" and "OPEN" in msg else "val"
            self._write(t, f"  [{tag}] {msg}", color)
        self._write(t, "", None)
        for sev, msg in core.security_findings(p):
            self._write(t, f"  [{sev}] {msg}", SEV_TAGS.get(sev, "muted"))

    # ------------------------------------------------------------ owner
    def run_owner(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_owner)
        self._clear(self.owner_txt)
        self.async_run(lambda: core.build_profile(code, 20, with_geo=False, probe=False), self.render_owner,
                       f"owner OSINT for {code} ...")

    def render_owner(self, p):
        t = self.owner_txt
        self._clear(t)
        if "error" in p:
            self._write(t, f"[x] {p['error']}", "bad")
            return
        o = p.get("owner", {})
        self._write(t, f"OWNER OSINT — {p.get('hostname')}", "h1")
        self._kv(t, "Owner", o.get("name"))
        self._kv(t, "Account ID", o.get("id"), key=True)
        self._kv(t, "Profile", o.get("profile"))
        self._kv(t, "Avatar", o.get("avatar"))
        tok = p.get("vars", {}).get("sv_licenseKeyToken")
        if tok:
            self._write(t, f"  sv_licenseKeyToken visible in public vars: ...{tok[-20:]}", "warn")
        forum = o.get("forum")
        if forum:
            self._write(t, "CFX FORUM PROFILE", "h2")
            if forum.get("error"):
                self._write(t, f"  lookup failed: {forum['error']}", "warn")
            else:
                self._kv(t, "Username", forum.get("username"))
                self._kv(t, "Title", forum.get("title"))
                self._kv(t, "URL", forum.get("profile_url"))
                avatar = forum.get("avatar_template") or ""
                if avatar:
                    url = avatar.replace("{size}", "256")
                    self._kv(t, "Avatar", url if url.startswith("http") else f"https://forum.cfx.re{url}")
        m = p.get("mastodon")
        if m:
            self._write(t, "MASTODON", "h2")
            self._kv(t, "Handle", m.get("handle"))
            self._kv(t, "Followers", m.get("followers"))
            self._kv(t, "Posts", m.get("posts"))
            self._kv(t, "URL", m.get("url"))

    # ------------------------------------------------------------ discord
    def run_discord(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_discord)
        self._clear(self.discord_txt)
        self.async_run(lambda: core.build_profile(code, 20, with_geo=False, probe=False), self.render_discord,
                       f"resolving discord for {code} ...")

    def render_discord(self, p):
        t = self.discord_txt
        self._clear(t)
        if "error" in p:
            self._write(t, f"[x] {p['error']}", "bad")
            return
        d = p.get("discord")
        self._write(t, f"DISCORD LOOKUP — {p.get('hostname')}", "h1")
        if not d:
            self._write(t, "  this server has no Discord invite in its broadcast vars.", "muted")
            return
        if d.get("error"):
            self._write(t, f"  resolution failed: {d['error']}", "bad")
            return
        self._kv(t, "Invite", f"discord.gg/{d.get('code')}", key=True)
        self._kv(t, "Server", d.get("name"))
        self._kv(t, "Guild ID", d.get("guild_id"), key=True)
        self._kv(t, "Members", f"{d.get('members')} total / {d.get('online')} online", good=True)
        self._kv(t, "Channel", f"#{d.get('channel')}")
        if d.get("guild_features"):
            self._write(t, "GUILD FEATURES", "h2")
            self._write(t, "  " + ", ".join(d["guild_features"]), "muted")

    # ------------------------------------------------------------ media
    def pick_media_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.media_dir_var.set(d)

    def run_media(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_media)
        self._clear(self.media_txt)
        dstdir = self.media_dir_var.get().strip() or f"fivem-media/{code}"
        dstdir = dstdir.replace("<code>", code)
        self.async_run(lambda: self._media_work(code, dstdir), lambda r: self.render_media(r, dstdir),
                       f"downloading media for {code} ...")

    def _media_work(self, code, dstdir):
        p = core.build_profile(code, 20, with_geo=False, probe=True, with_extras=False)
        if "error" in p:
            return p
        os.makedirs(dstdir, exist_ok=True)
        saved = []
        b64 = p.get("probe", {}).get("icon_b64")
        if b64:
            try:
                raw = core.base64.b64decode(b64)
                with open(os.path.join(dstdir, "icon.png"), "wb") as fh:
                    fh.write(raw)
                saved.append(f"icon.png ({len(raw)} bytes)")
            except Exception as e:
                saved.append(f"icon decode failed: {e}")
        for i, url in enumerate(p.get("banners") or []):
            try:
                raw = core.http_get(url, 15, binary=True, insecure=True)
                ext = os.path.splitext(urllib.parse.urlparse(url).path)[1] or ".img"
                if ext.lower() not in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
                    ext = ".img"
                with open(os.path.join(dstdir, f"banner_{i+1}{ext}"), "wb") as fh:
                    fh.write(raw)
                saved.append(f"banner_{i+1}{ext} ({len(raw)} bytes)")
            except Exception as e:
                saved.append(f"banner {i+1} failed: {e}")
        p["_media"] = saved
        return p

    def render_media(self, p, dstdir):
        t = self.media_txt
        self._clear(t)
        if "error" in p:
            self._write(t, f"[x] {p['error']}", "bad")
            return
        self._write(t, f"MEDIA — {p.get('hostname')}  ->  {dstdir}", "h1")
        for s in p.get("_media", []):
            self._write(t, f"  {s}", "good" if s.endswith("bytes)") else "warn")

    # ------------------------------------------------------------ history
    def run_history(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_hist)
        for i in self.hist_tree.get_children():
            self.hist_tree.delete(i)
        rows = core.db_history(code)
        if not rows:
            self.hist_sum.configure(text=f"no history for {code} yet — resolve it once to create snapshots")
            return
        for r in rows:
            self.hist_tree.insert("", "end", values=(r[1], r[4], r[6], r[7], r[3]))
        counts = [r[4] or 0 for r in rows]
        self.hist_sum.configure(text=f"{code} — {len(rows)} snapshots | min={min(counts)} max={max(counts)} avg={sum(counts)/len(counts):.1f}")

    # ------------------------------------------------------------ stream
    def run_stream(self, fresh=False):
        self.nb.select(self.tab_stream)
        mode = self.stream_mode_var.get()
        q = self.stream_filter_var.get().strip()

        def work():
            data = core.fetch_stream(fresh, 90)
            rows = core.parse_stream(data)
            if mode == "subnet" and q:
                rows = [r for r in rows if r[1] and core._stream_in_subnet(r[1].split(":")[0], q)]
            elif mode == "mastodon" and q:
                rows = [r for r in rows if q.lower() in r[2].lower()]
            elif mode == "port" and q.isdigit():
                rows = [r for r in rows if r[1] and r[1].rsplit(":", 1)[-1] == q]
            elif mode == "discord-only":
                rows = [r for r in rows if r[3]]
            elif q:
                rows = [r for r in rows if q.lower() in " ".join(r).lower()]
            return rows

        self.async_run(work, self.render_stream, "fetching global server stream ...")

    def render_stream(self, result):
        self.stream_rows = result
        for i in self.stream_tree.get_children():
            self.stream_tree.delete(i)
        for r in result:
            self.stream_tree.insert("", "end", values=r)
        eps = sum(1 for r in result if r[1])
        mastos = sum(1 for r in result if r[2])
        self.stream_sum.configure(text=f"{len(result)} servers | {eps} IP:port | {mastos} mastodon")

    def save_stream_csv(self):
        if not self.stream_rows:
            messagebox.showwarning("No data", "Run a stream search first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="fivem-stream.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("code,endpoint,mastodon,discord\n")
            for r in self.stream_rows:
                fh.write(",".join(f'"{x.replace(chr(34), chr(34) + chr(34))}"' for x in r) + "\n")
        messagebox.showinfo("Exported", f"{len(self.stream_rows)} rows -> {path}")

    def stream_load_server(self, event):
        sel = self.stream_tree.selection()
        if not sel:
            return
        code = self.stream_tree.item(sel[0], "values")[0]
        if not core._stream_code_ok(code):
            messagebox.showwarning("Not a server code", f"'{code}' is not a valid server code (filter artifact).")
            return
        self.code_var.set(code)
        self.last_code = code
        self.run_profile()

    # ------------------------------------------------------------ raw
    def run_raw(self):
        code = self.current_code()
        if not code:
            return
        self.nb.select(self.tab_raw)
        self._clear(self.raw_txt)
        self.async_run(lambda: core.api_lookup(code, 20), self.render_raw, f"fetching raw API data for {code} ...")

    def render_raw(self, res):
        t = self.raw_txt
        self._clear(t)
        if not res.get("ok"):
            self._write(t, res.get("error", "unknown error"), "bad")
            return
        self._write(t, json.dumps(res["raw"], ensure_ascii=False, indent=2), "mono")

    # ------------------------------------------------------------ batch
    def pick_batch_file(self):
        f = filedialog.askopenfilename(filetypes=[("Text", "*.txt *.csv"), ("All", "*.*")])
        if f:
            self.batch_file_var.set(f)

    def run_batch(self):
        path = self.batch_file_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("Batch", "Choose a text file with one code per line.")
            return
        self.nb.select(self.tab_batch)
        for i in self.batch_tree.get_children():
            self.batch_tree.delete(i)
        self.batch_rows = []
        with open(path, "r", encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        if not lines:
            messagebox.showwarning("Batch", "File is empty.")
            return
        self.batch_prog.configure(maximum=len(lines), value=0)
        self._batch_lines = lines
        self.async_run(self._batch_work, self.render_batch_done, f"batch: 0/{len(lines)} ...")

    def _batch_work(self):
        lines = self._batch_lines
        results = []
        for i, line in enumerate(lines, 1):
            code = core.extract_code(line) or line
            p = core.build_profile(code, 20, with_geo=False, probe=False, with_extras=False)
            ep = (p.get("endpoints") or [""])[0]
            def sval(k):
                v = p.get(k)
                return "" if v is None else str(v)
            results.append([p.get("code", "") or "", p.get("hostname", "") or "", ep,
                            p.get("resolved_ip", "") or "", sval("players_count"), sval("max_clients"),
                            p.get("game", "") or "", ",".join((p.get("analysis") or {}).get("frameworks") or []),
                            p.get("owner", {}).get("name", "") or "", p.get("error", "") or ""])
            self.root.after(0, lambda i=i: self.batch_prog.configure(value=i))
            self.status.set(f"batch: {i}/{len(lines)} ...")
        return results

    def render_batch_done(self, rows):
        self.batch_rows = rows
        for i in self.batch_tree.get_children():
            self.batch_tree.delete(i)
        for r in rows:
            tag = "red" if r[9] else ""
            self.batch_tree.insert("", "end", values=r)
        self.status.set(f"batch done: {len(rows)} servers")

    def export_batch_csv(self):
        if not self.batch_rows:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="fivem-osint-report.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["code", "hostname", "endpoint", "resolved_ip", "players", "maxclients", "game", "frameworks", "owner", "error"])
            w.writerows(self.batch_rows)
        self.status.set(f"exported {len(self.batch_rows)} rows to {os.path.basename(path)}")

    def batch_load_server(self, event):
        sel = self.batch_tree.selection()
        if not sel:
            return
        vals = self.batch_tree.item(sel[0], "values")
        code = vals[0] if vals else None
        if code:
            self.code_var.set(code)
            self.last_code = code
            self.run_profile()


def main():
    selftest = "--selftest" in sys.argv
    root = tk.Tk()
    app = App(root)
    if selftest:
        root.after(2500, root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
