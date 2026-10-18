#!/usr/bin/env python3
"""
VEXALITHRA v10 — Sistem Manajemen Tim Keamanan (Final Stable)
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from http import cookies
import sqlite3, hashlib, secrets, html, time, os, re, ssl
import urllib.request, urllib.error

PORT = int(os.environ.get("PORT", 8000))
DB = "vexalithra.db"
SECRET = "VexalithraSecretKey2026_Am4n_Dan_Terjaga"

LOGO_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="80" height="80">
  <path d="M50 5 L90 20 L90 50 C90 75 50 95 50 95 C50 95 10 75 10 50 L10 20 Z" fill="#0a0e14" stroke="#58a6ff" stroke-width="4"/>
  <text x="50" y="60" font-family="monospace" font-size="30" font-weight="bold" fill="#58a6ff" text-anchor="middle">VX</text>
</svg>
"""

def now(): return time.strftime("%Y-%m-%d %H:%M:%S")
def hash_pw(pw): return hashlib.sha256((pw + SECRET).encode()).hexdigest()
def db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
        display_name TEXT, created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
        owner TEXT NOT NULL, permission_status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL,
        title TEXT NOT NULL, severity TEXT NOT NULL, category TEXT,
        description TEXT, reproduction TEXT, remediation TEXT, raw_code TEXT,
        status TEXT NOT NULL DEFAULT 'open', assigned_to INTEGER,
        found_by INTEGER, created_at TEXT NOT NULL)""")
    
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username,password_hash,role,display_name,created_at) VALUES (?,?,?,?,?)",
                  ("admin", hash_pw("vexalithra2026"), "admin", "Administrator", now()))
    conn.commit(); conn.close()

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    conn = db()
    conn.execute("INSERT INTO sessions (token,user_id,created_at,expires_at) VALUES (?,?,?,datetime('now','+7 days'))", (token, user_id, now()))
    conn.commit(); conn.close(); return token

def get_user(handler):
    raw = handler.headers.get("Cookie", "")
    if not raw: return None
    c = cookies.SimpleCookie(); c.load(raw)
    if "vx_session" not in c: return None
    conn = db()
    row = conn.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>datetime('now')", (c["vx_session"].value,)).fetchone()
    conn.close(); return row

def can_write(user): return user and user["role"] in ("admin", "lead", "pentester")
def can_admin(user): return user and user["role"] in ("admin", "lead")

class Scanner:
    TIMEOUT = 8
    def __init__(self, base_url):
        self.base = base_url.rstrip("/")
        self.findings = []
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _req(self, url, method="GET"):
        req = urllib.request.Request(url, headers={"User-Agent": "VEXALITHRA/10.0"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.TIMEOUT, context=self.ctx) as r:
                return r.status, r.read(500000).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read(500000).decode("utf-8", errors="ignore")
        except Exception: return None, ""

    def add(self, title, severity, category, desc, repro, remediation="", raw_code=None):
        self.findings.append({"title": title, "severity": severity, "category": category, "description": desc, "reproduction": repro, "remediation": remediation, "raw_code": raw_code})

    def run(self):
        status, body = self._req(self.base)
        if status is None: return self.findings
        
        sensitive_files = ["/.env", "/.git/config", "/config.php.bak", "/phpinfo.php", "/backup.sql", "/.DS_Store"]
        for path in sensitive_files:
            st, bd = self._req(self.base + path)
            if st == 200 and len(bd) > 5:
                bd_lower = bd.lower()
                is_html_page = "<html" in bd_lower or "<!doctype" in bd_lower or "<body" in bd_lower
                indikator_bocor = any(x in bd for x in ["DB_", "PASSWORD", "SECRET", "<?php", "root:x:0:0", "[core]", "extension="])
                
                if not is_html_page and indikator_bocor:
                    self.add(f"File Bocor: {path}", "high", "Exposed File", 
                             f"File {path} dapat diakses publik. Source code berhasil diambil.", 
                             f"curl -s {self.base}{path}", 
                             "Hapus file dari server atau batasi akses.", raw_code=bd)

        sqli_url = f"{self.base}/?id={quote(chr(39))}"
        st, bd = self._req(sqli_url)
        if bd and re.search(r"(SQL syntax|mysql_fetch|SQLite3::|ORA-\d{5})", bd, re.I):
            match = re.search(r"(.{0,100}(SQL syntax|mysql_fetch|SQLite3::|ORA-\d{5}).{0,200})", bd, re.I|re.S)
            raw = match.group(1) if match else bd[:500]
            self.add("Indikasi SQL Injection", "critical", "SQLi", "Error SQL muncul saat kutip tunggal dikirim.", f"curl -s '{sqli_url}'", "Gunakan prepared statement.", raw_code=raw)

        return self.findings

def run_scan(target_id, user_id):
    conn = db()
    t = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not t or t["permission_status"] != "granted": conn.close(); return {"ok": False}
    scanner = Scanner(t["url"])
    try: results = scanner.run()
    except: results = []
    for f in results:
        conn.execute("INSERT INTO findings (target_id,title,severity,category,description,reproduction,remediation,raw_code,status,found_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", 
                     (target_id, f["title"], f["severity"], f["category"], f["description"], f["reproduction"], f.get("remediation", ""), f.get("raw_code"), "open", user_id, now()))
    conn.commit(); conn.close()
    return {"ok": True}

BASE_CSS = """
<style>
:root{--bg:#0a0e14;--panel:#11161f;--border:#1e2633;--text:#c9d1d9;--muted:#7d8590;--accent:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:sans-serif;background:var(--bg);color:var(--text);line-height:1.6;}
a{color:var(--accent);text-decoration:none;} a:hover{text-decoration:underline;}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px;}
header{border-bottom:1px solid var(--border);padding:14px 0;background:var(--panel);}
header .wrap{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;}
nav{display:flex;gap:14px;font-size:13px;flex-wrap:wrap;} nav a{color:var(--muted);}
main{padding:28px 0;min-height:70vh;}
h2{font-size:20px;margin-bottom:16px;} h3{font-size:14px;color:var(--accent);margin:24px 0 12px;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:14px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;}
.stat .n{font-size:26px;font-weight:700;color:var(--accent);}
table{width:100%;border-collapse:collapse;font-size:13px;} th,td{text-align:left;padding:10px;border-bottom:1px solid var(--border);} th{color:var(--muted);font-size:11px;}
input,textarea,select{width:100%;padding:9px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;margin:6px 0;}
button{padding:9px 18px;background:var(--accent);color:#000;border:none;border-radius:6px;font-weight:600;cursor:pointer;margin-top:10px;}
.badge{font-size:10px;padding:2px 8px;border-radius:10px;text-transform:uppercase;}
.badge.critical,.badge.open{background:#f8514922;color:var(--bad);}
.badge.high,.badge.pending,.badge.in-progress{background:#d2992222;color:var(--warn);}
.badge.medium{background:#58a6ff22;color:var(--accent);}
.badge.low,.badge.fixed,.badge.granted{background:#3fb95022;color:var(--ok);}
.msg{padding:10px;border-radius:6px;margin-bottom:14px;font-size:13px;}
.login-box{max-width:380px;margin:60px auto;}
pre.code{background:#000;color:#4af626;padding:15px;border-radius:6px;overflow-x:auto;font-family:monospace;font-size:12px;border:1px solid var(--border); white-space: pre-wrap; word-wrap: break-word;}
</style>
"""

def page(handler, title, content, user=None):
    nav = ""
    if user:
        if user["role"] in ("admin", "lead"):
            nav = '<nav><a href="/admin/dashboard">Dashboard Admin</a><a href="/targets">Target</a><a href="/findings">Semua Temuan</a><a href="/scan">Scan</a><a href="/members">Anggota</a></nav>'
        else:
            nav = '<nav><a href="/member/dashboard">Dashboard Saya</a><a href="/findings">Temuan</a></nav>'
        who = f'<div class="user" style="font-size:12px">Masuk: <b>{html.escape(user["display_name"] or user["username"])}</b> · {user["role"]} <a href="/logout" style="margin-left:10px">Keluar</a></div>'
    else: who = ""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{title} — VEXALITHRA</title>{BASE_CSS}</head><body>
<header><div class="wrap"><div class="brand" style="font-size:16px;font-weight:bold;color:var(--accent)">VX VEXALITHRA</div><div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">{nav}{who}</div></div></header>
<main><div class="wrap">{content}</div></main></body></html>""".encode("utf-8")

class Handler(BaseHTTPRequestHandler):
    def send_page(self, title, content, user=None, code=200, cookie=None):
        body = page(self, title, content, user)
        self.send_response(code); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers(); self.wfile.write(body)

    def send_raw(self, data, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def redirect(self, loc, cookie=None):
        self.send_response(302); self.send_header("Location", loc)
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def parse_form(self, raw): return parse_qs(raw.decode("utf-8", errors="ignore"))
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); path = u.path
        user = get_user(self)

        if path == "/":
            if user: return self.redirect("/admin/dashboard" if user["role"] in ("admin", "lead") else "/member/dashboard")
            content = """<div style="text-align:center; padding: 40px 10px; max-width: 600px; margin: 0 auto;"><h1 style="font-size: 32px; letter-spacing: .1em; color: var(--accent); margin-bottom: 10px;">VEXALITHRA</h1><p style="font-size: 14px; color: var(--muted); margin-bottom: 30px;">Cybersecurity Research Team</p><div style="display: flex; flex-direction: column; gap: 15px; max-width: 300px; margin: 0 auto;"><a href="/admin" style="display: block; padding: 14px; background: var(--accent); color: #000; font-weight: bold; border-radius: 8px;">🛡️ Portal Admin</a><a href="/member" style="display: block; padding: 14px; background: var(--panel); border: 1px solid var(--border); color: var(--text); font-weight: bold; border-radius: 8px;">👤 Portal Anggota</a></div></div>"""
            return self.send_page("Beranda", content)

        if path in ("/login", "/admin", "/member"):
            if user: return self.redirect("/admin/dashboard" if user["role"] in ("admin", "lead") else "/member/dashboard")
            if path == "/admin": return self.send_page("Login Admin", self.login_form("admin"))
            if path == "/member": return self.send_page("Login Anggota", self.login_form("member"))
            return self.send_page("Portal", """<div class="login-box"><div class="card" style="text-align:center;"><h2 style="color:var(--accent);margin-bottom:20px;">VEXALITHRA</h2><a href="/admin" style="display:block;padding:12px;background:var(--panel);border:1px solid var(--border);border-radius:6px;margin-bottom:10px;font-weight:bold;">🛡️ Portal Admin</a><a href="/member" style="display:block;padding:12px;background:var(--panel);border:1px solid var(--border);border-radius:6px;font-weight:bold;">👤 Portal Anggota</a></div></div>""")

        if path == "/logout":
            raw = self.headers.get("Cookie", "")
            if raw:
                c = cookies.SimpleCookie(); c.load(raw)
                if "vx_session" in c:
                    conn = db(); conn.execute("DELETE FROM sessions WHERE token=?", (c["vx_session"].value,))
                    conn.commit(); conn.close()
            return self.redirect("/login", cookie="vx_session=; Max-Age=0; Path=/")

        if not user: return self.redirect("/login")

        if path == "/print-report":
            if not can_admin(user): return self.send_page("403", '<div class="msg err">Akses ditolak.</div>', user, 403)
            tid = q.get("target_id", [""])[0]
            conn = db()
            t = conn.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
            fs = conn.execute("SELECT * FROM findings WHERE target_id=? ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END", (tid,)).fetchall()
            conn.close()
            if not t: return self.send_page("404", "Target tidak ada", user, 404)

            rows = ""
            for i, f in enumerate(fs, 1):
                rows += f"""<tr><td>{i}</td><td><b>{html.escape(f['title'])}</b><br><small>{html.escape(f['category'] or '')}</small></td><td><span style="text-transform:uppercase; font-weight:bold; color:{'#d32f2f' if f['severity']=='critical' else '#f57c00' if f['severity']=='high' else '#1976d2'}">{f['severity']}</span></td><td>{html.escape(f['description'] or '-')}</td><td>{html.escape(f['reproduction'] or '-')}</td></tr>"""

            html_report = f"""<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><title>Laporan Keamanan - {html.escape(t['name'])}</title>
            <style>
                body {{ font-family: sans-serif; color: #333; margin: 0; padding: 20px; background: #fff; }}
                .header {{ display: flex; align-items: center; border-bottom: 3px solid #0a0e14; padding-bottom: 20px; margin-bottom: 30px; }}
                .header-text {{ margin-left: 20px; }} .header-text h1 {{ margin: 0; font-size: 24px; letter-spacing: 2px; }} .header-text p {{ color: #666; font-size: 14px; margin: 5px 0 0 0; }}
                .meta table {{ width: 100%; border-collapse: collapse; font-size: 14px; }} .meta td {{ padding: 5px 0; }} .meta td:first-child {{ font-weight: bold; width: 150px; }}
                h2 {{ font-size: 18px; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }}
                table.data {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }}
                table.data th {{ background: #f4f4f4; text-align: left; padding: 10px; border: 1px solid #ddd; }} table.data td {{ padding: 10px; border: 1px solid #ddd; vertical-align: top; }}
                .footer {{ margin-top: 50px; text-align: center; font-size: 11px; color: #888; border-top: 1px solid #ddd; padding-top: 20px; }}
                @media print {{ body {{ padding: 0; }} .no-print {{ display: none; }} }}
                .btn-print {{ background: #0a0e14; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; margin-bottom: 20px; }}
            </style></head><body>
            <button class="btn-print no-print" onclick="window.print()">🖨️ Cetak / Simpan PDF</button>
            <div class="header">{LOGO_SVG}<div class="header-text"><h1>VEXALITHRA</h1><p>Cybersecurity Research Team</p></div></div>
            <div class="meta"><h2>Laporan Hasil Pengujian Keamanan</h2><table>
                <tr><td>Target Aplikasi</td><td>: {html.escape(t['name'])}</td></tr><tr><td>URL / Endpoint</td><td>: {html.escape(t['url'])}</td></tr>
                <tr><td>Pemilik Sistem</td><td>: {html.escape(t['owner'])}</td></tr><tr><td>Status Izin</td><td>: {t['permission_status'].upper()}</td></tr>
                <tr><td>Tanggal Laporan</td><td>: {now()}</td></tr>
            </table></div>
            <h2>Ringkasan Temuan ({len(fs)} Isu)</h2>
            <table class="data"><thead><tr><th width="5%">No</th><th width="25%">Kerentanan</th><th width="10%">Severity</th><th width="30%">Deskripsi</th><th width="30%">Reproduksi</th></tr></thead><tbody>
                {rows if rows else "<tr><td colspan='5' style='text-align:center'>Tidak ada temuan.</td></tr>"}
            </tbody></table>
            <div class="footer"><p>Laporan ini dihasilkan secara otomatis oleh Sistem VEXALITHRA.</p><p>Seluruh pengujian dilakukan dengan izin tertulis.</p></div>
            </body></html>"""
            return self.send_raw(html_report.encode("utf-8"))

        if path == "/admin/dashboard":
            if not can_admin(user): return self.send_page("403", '<div class="msg err">Akses ditolak.</div>', user, 403)
            conn = db()
            n_t = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            n_f = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            conn.close()
            content = f"<h2>Panel Admin</h2><div class='grid'><div class='stat'><div class='n'>{n_t}</div><div class='l'>Target</div></div><div class='stat'><div class='n'>{n_f}</div><div class='l'>Temuan</div></div></div>"
            return self.send_page("Panel Admin", content, user)

        if path == "/member/dashboard":
            content = f"<h2>Dashboard Anggota</h2><p>Halo, {html.escape(user['display_name'] or user['username'])}.</p>"
            return self.send_page("Dashboard Anggota", content, user)

        if path == "/targets":
            if not can_admin(user): return self.send_page("403", '<div class="msg err">Akses ditolak.</div>', user, 403)
            conn = db()
            targets = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
            conn.close()
            rows = "".join(f"<tr><td>{r['id']}</td><td>{html.escape(r['name'])}</td><td><span class='badge {r['permission_status']}'>{r['permission_status']}</span></td><td><a href='/print-report?target_id={r['id']}' target='_blank' style='background:#3fb950;color:#000;padding:4px 8px;border-radius:4px;font-size:11px;font-weight:bold;text-decoration:none'>📄 Laporan</a></td></tr>" for r in targets)
            content = f"<h2>Target</h2><div class='card'><h3>Tambah Target</h3><form method='POST' action='/targets/add'><label>Nama</label><input name='name' required><label>URL</label><input name='url' required><label>Pemilik</label><input name='owner' required><label>Izin</label><select name='permission_status'><option value='pending'>Pending</option><option value='granted'>Granted</option></select><button>Simpan</button></form></div><div class='card'><table><tr><th>ID</th><th>Nama</th><th>Izin</th><th>Laporan</th></tr>{r
