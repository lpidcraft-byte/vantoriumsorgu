# app.py
import os, sys, json, sqlite3, subprocess, signal, threading, time, secrets, re, urllib.request, traceback, logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque
from flask import Flask, request, jsonify, session, redirect, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash

# ============ LOGGING ============
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vantorium")

# ============ APP ============
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vantorium-super-secret-change-me-please")
app.permanent_session_lifetime = timedelta(days=365)

DATA_DIR = Path("/data") if Path("/data").exists() and os.access("/data", os.W_OK) else Path("/tmp")
BASE_DIR = DATA_DIR / "hosting"
BASE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = BASE_DIR / "db.sqlite3"
SELF_URL = os.environ.get("SELF_URL", "")

# ============ DB ============
def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'user',
        banned INTEGER DEFAULT 0,
        created TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created TEXT,
        expires TEXT,
        ip TEXT,
        ua TEXT
    );
    CREATE TABLE IF NOT EXISTS projects(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        main_file TEXT DEFAULT 'main.py',
        status TEXT DEFAULT 'stopped',
        pid INTEGER,
        autostart INTEGER DEFAULT 1,
        created TEXT,
        UNIQUE(user_id, name)
    );
    CREATE TABLE IF NOT EXISTS project_env(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        UNIQUE(project_id, key)
    );
    CREATE TABLE IF NOT EXISTS ip_bans(
        ip TEXT PRIMARY KEY, reason TEXT, until TEXT, created TEXT
    );
    CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, action TEXT, meta TEXT, ip TEXT, ts TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
    """)
    c.commit(); c.close()

init_db()
PROCS = {}
LOCK = threading.Lock()

# ============ SECURITY / GUARD ============
RATE = defaultdict(deque)
RATE_LOCK = threading.Lock()
RATE_LIMIT = 70                # <-- 70 istek / pencere
RATE_WINDOW = 60.0
BURST_LIMIT = 25
BURST_WINDOW = 1.0
BANNED_UAS = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|wget|scrapy|spider|crawler|ahrefs|semrush|mj12|petal|bytespider)", re.I)
LOGIN_FAILS = defaultdict(int)
LOGIN_FAILS_LOCK = threading.Lock()
LOGIN_FAILS_MAX = 15

def client_ip():
    xff = request.headers.get("X-Forwarded-For","")
    if xff: return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def ip_banned(ip):
    try:
        c = db(); r = c.execute("SELECT * FROM ip_bans WHERE ip=?", (ip,)).fetchone(); c.close()
        if not r: return False
        if r["until"]:
            try:
                if datetime.fromisoformat(r["until"]) < datetime.utcnow():
                    c = db(); c.execute("DELETE FROM ip_bans WHERE ip=?", (ip,)); c.commit(); c.close()
                    return False
            except Exception: pass
        return True
    except Exception:
        return False

def ban_ip(ip, reason="auto", minutes=60):
    try:
        until = (datetime.utcnow()+timedelta(minutes=minutes)).isoformat()
        c = db()
        c.execute("INSERT OR REPLACE INTO ip_bans(ip,reason,until,created) VALUES(?,?,?,?)",
                  (ip, reason, until, datetime.utcnow().isoformat()))
        c.commit(); c.close()
        log.warning(f"Banned {ip} ({reason}) for {minutes}m")
    except Exception as e: log.error(f"ban_ip: {e}")

def audit(uid, action, meta="", ip=None):
    try:
        c = db()
        c.execute("INSERT INTO audit(user_id,action,meta,ip,ts) VALUES(?,?,?,?,?)",
                  (uid, action, meta, ip or "", datetime.utcnow().isoformat()))
        c.commit(); c.close()
    except Exception: pass

@app.before_request
def guard():
    if request.path in ("/healthz", "/favicon.ico"): return None
    ip = client_ip(); ua = request.headers.get("User-Agent","")
    if ip_banned(ip): return ("Banned", 403)
    if not ua or BANNED_UAS.search(ua):
        ban_ip(ip, "bad_ua", 1440); return ("Forbidden", 403)
    now = time.time()
    with RATE_LOCK:
        dq = RATE[ip]
        while dq and dq[0] < now - RATE_WINDOW: dq.popleft()
        recent = sum(1 for t in dq if t > now - BURST_WINDOW)
        if recent >= BURST_LIMIT:
            ban_ip(ip, "burst", 10); return ("Too Many Requests", 429)
        if len(dq) >= RATE_LIMIT:
            ban_ip(ip, "rate", 30); return ("Too Many Requests", 429)
        dq.append(now)
    if request.content_length and request.content_length > 8*1024*1024:
        ban_ip(ip, "big_body", 60); return ("Payload Too Large", 413)
    return None

@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; img-src 'self' data: https:; font-src 'self' data: https:;"
    return resp

# ============ SESSIONS ============
def create_session(uid, ip, ua):
    token = secrets.token_urlsafe(48)
    c = db()
    exp = (datetime.utcnow()+timedelta(days=365)).isoformat()
    c.execute("INSERT INTO sessions(token,user_id,created,expires,ip,ua) VALUES(?,?,?,?,?,?)",
              (token, uid, datetime.utcnow().isoformat(), exp, ip, ua))
    c.commit(); c.close()
    return token

def get_session_user():
    token = request.cookies.get("sid")
    if not token: return None
    try:
        c = db(); r = c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone(); c.close()
        if not r: return None
        if datetime.fromisoformat(r["expires"]) < datetime.utcnow():
            c = db(); c.execute("DELETE FROM sessions WHERE token=?", (token,)); c.commit(); c.close()
            return None
        c = db(); u = c.execute("SELECT banned FROM users WHERE id=?", (r["user_id"],)).fetchone(); c.close()
        if u and u["banned"]: return None
        return r["user_id"]
    except Exception: return None

def set_session_cookie(resp, token):
    resp.set_cookie("sid", token, max_age=365*24*3600, httponly=True, samesite="Lax", secure=True)
    return resp

def clear_session_cookie(resp):
    resp.set_cookie("sid", "", max_age=0); return resp

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        uid = get_session_user()
        if not uid: return redirect("/login")
        session["uid"] = uid
        request.uid = uid
        return f(*a, **k)
    return w

def proj_dir(uid, name):
    d = BASE_DIR / f"u{uid}" / name
    d.mkdir(parents=True, exist_ok=True)
    return d

# ============ PROCESS ============
def load_env(project_id):
    try:
        c = db()
        rows = c.execute("SELECT key,value FROM project_env WHERE project_id=?", (project_id,)).fetchall()
        c.close()
        return {r["key"]: r["value"] for r in rows}
    except Exception: return {}

def start_project(uid, name, main_file="main.py"):
    key = f"{uid}:{name}"
    with LOCK:
        p = PROCS.get(key)
        if p and p.poll() is None: return False, "already running"
        d = proj_dir(uid, name)
        mf = d / main_file
        if not mf.exists(): return False, f"{main_file} not found"
        try:
            c = db()
            r = c.execute("SELECT id FROM projects WHERE user_id=? AND name=?", (uid, name)).fetchone()
            c.close()
        except Exception: r = None
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["WATERMARK"] = "BY VANTORIUM TEAM"
        if r: env.update(load_env(r["id"]))
        try:
            log_fp = open(d / "output.log", "ab")
            p = subprocess.Popen([sys.executable, "-u", str(mf)], cwd=str(d),
                                 stdout=log_fp, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        except Exception as e:
            log.error(f"start_project {key}: {e}")
            return False, str(e)
        PROCS[key] = p
        try:
            c = db()
            c.execute("UPDATE projects SET status='running', pid=? WHERE user_id=? AND name=?", (p.pid, uid, name))
            c.commit(); c.close()
        except Exception: pass
        log.info(f"Started {key} PID={p.pid}")
        return True, f"PID {p.pid}"

def stop_project(uid, name):
    key = f"{uid}:{name}"
    with LOCK:
        p = PROCS.get(key)
        if p and p.poll() is None:
            try: os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try: p.terminate()
                except: pass
            try: p.wait(timeout=5)
            except Exception:
                try: p.kill()
                except: pass
        PROCS.pop(key, None)
        try:
            c = db()
            c.execute("UPDATE projects SET status='stopped', pid=NULL WHERE user_id=? AND name=?", (uid, name))
            c.commit(); c.close()
        except Exception: pass
        return True

def is_alive(uid, name):
    p = PROCS.get(f"{uid}:{name}")
    try: return bool(p and p.poll() is None)
    except Exception: return False

# ============ SUPERVISOR + SELF-PING (60sn'de 2 istek) ============
PING_INTERVAL = 60
PING_COUNT = 2
PING_GAP = 25
PROJ_CHECK_INTERVAL = 40

def _ping_once():
    if not SELF_URL: return
    try:
        urllib.request.urlopen(SELF_URL + "/healthz", timeout=20).read()
        log.debug("ping ok")
    except Exception as e:
        log.debug(f"ping: {e}")

def supervisor():
    log.info(f"Supervisor started (ping {PING_COUNT}x / {PING_INTERVAL}s)")
    last_ping_cycle = 0
    last_proj_check = 0
    while True:
        try:
            now = time.time()
            if now - last_proj_check >= PROJ_CHECK_INTERVAL:
                last_proj_check = now
                try:
                    c = db()
                    rows = c.execute("SELECT * FROM projects WHERE autostart=1").fetchall()
                    c.close()
                    for r in rows:
                        if not is_alive(r["user_id"], r["name"]):
                            start_project(r["user_id"], r["name"], r["main_file"])
                except Exception as e:
                    log.error(f"supervisor proj: {e}")
            if now - last_ping_cycle >= PING_INTERVAL:
                last_ping_cycle = now
                for i in range(PING_COUNT):
                    if i > 0: time.sleep(PING_GAP)
                    _ping_once()
        except Exception as e:
            log.error(f"supervisor: {e}")
        time.sleep(2)

threading.Thread(target=supervisor, daemon=True).start()

# ============ UI ============
BASE_HTML = r"""
<!doctype html><html lang="tr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}} — BY VANTORIUM TEAM</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#070b14; --bg2:#0c1222; --card:#0f1729; --card2:#131c33;
  --border:rgba(96,165,250,0.12); --border2:rgba(96,165,250,0.25);
  --text:#e6edf7; --muted:#7d8ba6;
  --primary:#3b82f6; --primary2:#60a5fa; --accent:#8b5cf6; --pink:#ec4899;
  --green:#10b981; --red:#ef4444; --yellow:#f59e0b;
  --grad:linear-gradient(135deg,#3b82f6 0%,#8b5cf6 50%,#ec4899 100%);
  --grad2:linear-gradient(135deg,#1e40af 0%,#4c1d95 100%);
}
html,body{height:100%}
body{
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  background:var(--bg); color:var(--text);
  min-height:100vh; padding-bottom:70px;
  -webkit-font-smoothing:antialiased; font-size:14px; line-height:1.5;
  background-image:
    radial-gradient(1200px 600px at 10% -10%, rgba(59,130,246,0.15), transparent 60%),
    radial-gradient(900px 500px at 110% 10%, rgba(139,92,246,0.12), transparent 60%),
    radial-gradient(800px 500px at 50% 120%, rgba(236,72,153,0.10), transparent 60%);
  background-attachment:fixed;
}
a{color:var(--primary2);text-decoration:none;transition:.15s}
a:hover{color:#93c5fd}
.nav{
  position:sticky;top:0;z-index:100;
  background:rgba(7,11,20,0.85);backdrop-filter:blur(16px);
  border-bottom:1px solid var(--border);padding:14px 24px;
  display:flex;justify-content:space-between;align-items:center;
}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:16px;letter-spacing:-.3px}
.brand-ico{
  width:32px;height:32px;border-radius:9px;background:var(--grad);
  display:grid;place-items:center;font-size:16px;box-shadow:0 4px 20px rgba(59,130,246,0.4)
}
.brand span{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.nav-links{display:flex;gap:8px;align-items:center}
.nav-links a{
  color:var(--muted);font-size:13px;font-weight:500;
  padding:7px 12px;border-radius:8px;transition:.15s
}
.nav-links a:hover{color:var(--text);background:rgba(96,165,250,0.1)}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px}
.card{
  background:linear-gradient(180deg,var(--card) 0%,var(--card2) 100%);
  border:1px solid var(--border);border-radius:16px;
  padding:22px;margin-bottom:16px;position:relative;overflow:hidden;
  box-shadow:0 4px 24px rgba(0,0,0,0.2);
  transition:.2s;
}
.card:hover{border-color:var(--border2);box-shadow:0 8px 32px rgba(59,130,246,0.08)}
.card::before{
  content:"BY VANTORIUM TEAM";position:absolute;
  right:-20px;bottom:-12px;font-size:56px;font-weight:900;
  color:rgba(96,165,250,0.035);transform:rotate(-8deg);
  pointer-events:none;letter-spacing:2px;white-space:nowrap;
  font-family:'Inter';user-select:none
}
.card h1,.card h2{font-weight:700;letter-spacing:-.4px;margin-bottom:8px}
.card h1{font-size:28px}
.card h2{font-size:20px}
.card h3{font-size:15px;font-weight:600;margin-bottom:12px;color:var(--text)}
.card p{margin:8px 0;color:var(--muted);font-size:14px}
.card > *{position:relative;z-index:1}
input,textarea,select{
  background:rgba(7,11,20,0.6);color:var(--text);
  border:1px solid var(--border);border-radius:9px;
  padding:10px 12px;font-family:inherit;font-size:14px;
  transition:.15s;outline:none;width:100%
}
input:focus,textarea:focus,select:focus{
  border-color:var(--primary);box-shadow:0 0 0 3px rgba(59,130,246,0.15)
}
textarea{resize:vertical;min-height:400px;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;line-height:1.6}
button,.btn{
  background:var(--primary);color:#fff;border:none;cursor:pointer;
  padding:10px 18px;border-radius:9px;font-family:inherit;font-size:13.5px;
  font-weight:600;letter-spacing:.1px;transition:.15s;
  display:inline-flex;align-items:center;gap:7px;text-decoration:none
}
button:hover,.btn:hover{background:#2563eb;transform:translateY(-1px);box-shadow:0 6px 18px rgba(59,130,246,0.35)}
button:active{transform:translateY(0)}
button.danger,.btn.danger{background:var(--red)}
button.danger:hover{background:#dc2626;box-shadow:0 6px 18px rgba(239,68,68,0.35)}
button.ghost,.btn.ghost{background:rgba(96,165,250,0.08);color:var(--primary2);border:1px solid var(--border)}
button.ghost:hover{background:rgba(96,165,250,0.16);box-shadow:none;transform:none}
button.success{background:var(--green)}
button.success:hover{background:#059669}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.grow{flex:1}
pre,code{
  background:rgba(0,0,0,0.4);border:1px solid var(--border);
  padding:14px;border-radius:10px;overflow:auto;max-height:450px;
  font-size:12px;line-height:1.6;font-family:'JetBrains Mono',ui-monospace,monospace;
  color:#a5d6ff
}
.small{font-size:12px;color:var(--muted)}
.badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.3px;text-transform:uppercase}
.badge.run{background:rgba(16,185,129,0.15);color:#34d399;border:1px solid rgba(16,185,129,0.3)}
.badge.stop{background:rgba(148,163,184,0.12);color:#94a3b8;border:1px solid rgba(148,163,184,0.25)}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left}
th{color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:none}
ul{list-style:none}
ul li{
  padding:9px 12px;background:rgba(0,0,0,0.2);border-radius:8px;
  margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;gap:8px;
  font-size:13.5px;border:1px solid transparent;transition:.15s
}
ul li:hover{border-color:var(--border);background:rgba(96,165,250,0.05)}
ul li form{display:inline}
footer.watermark{
  position:fixed;bottom:0;left:0;right:0;z-index:9999;
  background:rgba(7,11,20,0.92);backdrop-filter:blur(16px);
  border-top:1px solid var(--border);padding:12px;text-align:center;
  font-size:12px;font-weight:700;letter-spacing:3px;color:var(--muted);
  user-select:none
}
footer.watermark b{
  background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent;font-weight:900
}
.hero{padding:60px 20px;text-align:center}
.hero h1{font-size:52px;line-height:1.1;letter-spacing:-1.5px;margin-bottom:16px;font-weight:900}
.hero h1 span{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{font-size:17px;color:var(--muted);max-width:600px;margin:0 auto 28px}
.hero-actions{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.hero-actions .btn{padding:13px 28px;font-size:15px}
.feature-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:32px}
.feature{background:rgba(15,23,41,0.6);border:1px solid var(--border);border-radius:14px;padding:20px;transition:.2s}
.feature:hover{transform:translateY(-2px);border-color:var(--border2);background:rgba(15,23,41,0.9)}
.feature .ico{font-size:24px;margin-bottom:10px}
.feature h4{font-size:15px;font-weight:700;margin-bottom:6px}
.feature p{font-size:13px;color:var(--muted);margin:0}
.proj-item{
  display:flex;justify-content:space-between;align-items:center;
  padding:14px 16px;background:rgba(0,0,0,0.25);
  border:1px solid var(--border);border-radius:12px;margin-bottom:8px;transition:.2s
}
.proj-item:hover{border-color:var(--border2);background:rgba(96,165,250,0.05)}
.proj-name{font-weight:600;font-size:14.5px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.proj-meta{font-size:12px;color:var(--muted);margin-top:4px}
.warn{background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);color:#fbbf24;padding:12px;border-radius:10px;font-size:13px;margin-bottom:12px}
.ok{background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);color:#34d399;padding:12px;border-radius:10px;font-size:13px;margin-bottom:12px}
.err{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#f87171;padding:12px;border-radius:10px;font-size:13px;margin-bottom:12px}
.zoom-controls{position:fixed;right:16px;bottom:70px;display:flex;flex-direction:column;gap:6px;z-index:9998}
.zoom-controls button{
  width:38px;height:38px;padding:0;border-radius:10px;justify-content:center;
  background:rgba(15,23,41,0.9);border:1px solid var(--border);color:var(--text);
  font-size:16px;backdrop-filter:blur(10px)
}
.zoom-controls button:hover{background:var(--primary);border-color:var(--primary)}
@media(max-width:640px){
  .hero h1{font-size:34px}
  .nav{padding:12px 16px}
  .wrap{padding:20px 14px}
  .card{padding:16px;border-radius:12px}
  .card::before{font-size:36px}
  .zoom-controls{right:10px;bottom:60px}
  .zoom-controls button{width:34px;height:34px;font-size:14px}
}
</style></head><body>

<nav class="nav">
  <a href="/" class="brand"><div class="brand-ico">⚡</div><span>VANTORIUM</span></a>
  <div class="nav-links">
    {% if session.get('uid') %}
      <a href="/dashboard">Panel</a>
      <a href="/logout">Çıkış</a>
    {% else %}
      <a href="/login">Giriş</a>
      <a href="/register">Kayıt</a>
    {% endif %}
  </div>
</nav>

<div class="wrap">{{body|safe}}</div>

<div class="zoom-controls">
  <button onclick="zoomIn()" title="Yakınlaştır">+</button>
  <button onclick="zoomOut()" title="Uzaklaştır">−</button>
  <button onclick="zoomReset()" title="Sıfırla">⟲</button>
</div>

<footer class="watermark">BY <b>VANTORIUM TEAM</b></footer>

<script>
(function(){
  var KEY='vz', z=parseFloat(localStorage.getItem(KEY))||1;
  function apply(){
    z=Math.max(0.75,Math.min(1.5,z));
    document.documentElement.style.fontSize=(14*z)+'px';
    localStorage.setItem(KEY,z);
  }
  window.zoomIn=function(){z+=0.1;apply()};
  window.zoomOut=function(){z-=0.1;apply()};
  window.zoomReset=function(){z=1;apply()};
  apply();
  document.addEventListener('keydown',function(e){
    if(e.ctrlKey||e.metaKey){
      if(e.key==='+'||e.key==='='){e.preventDefault();zoomIn()}
      if(e.key==='-'){e.preventDefault();zoomOut()}
      if(e.key==='0'){e.preventDefault();zoomReset()}
    }
  });
  var sk='vscroll';
  window.addEventListener('scroll',function(){localStorage.setItem(sk,window.scrollY)});
  var s=localStorage.getItem(sk); if(s)window.scrollTo(0,parseInt(s)||0);
})();
</script>
</body></html>
"""

# ============ ROUTES ============
@app.route("/")
def home():
    body = """
    <div class="hero">
      <h1>Python kodunu <span>7/24</span> çalıştır</h1>
      <p>Telegram bot, Discord bot, API ve daha fazlasını saniyeler içinde barındır. Otomatik yeniden başlatma, kalıcı dosyalar, gerçek zamanlı loglar.</p>
      <div class="hero-actions">
        <a href="/register" class="btn">🚀 Hemen Başla</a>
        <a href="/login" class="btn ghost">Giriş Yap</a>
      </div>
    </div>
    <div class="feature-grid">
      <div class="feature"><div class="ico">♾️</div><h4>7/24 Kesintisiz</h4><p>Render uyku sorununu çözen otomatik self-ping ve supervisor.</p></div>
      <div class="feature"><div class="ico">🔄</div><h4>Otomatik Yenileme</h4><p>Proje çökerse saniyeler içinde kendini yeniden başlatır.</p></div>
      <div class="feature"><div class="ico">💾</div><h4>Kalıcı Veri</h4><p>Kullanıcı, proje ve dosyalar SQLite + kalıcı disk ile saklanır.</p></div>
      <div class="feature"><div class="ico">🛡️</div><h4>DDoS Koruması</h4><p>IP rate-limit (70/dk), bot guard, UA filtresi ve otomatik ban.</p></div>
      <div class="feature"><div class="ico">📁</div><h4>Dosya Yöneticisi</h4><p>main.py, index.html ve diğer tüm dosyaları editörden yönet.</p></div>
      <div class="feature"><div class="ico">🔐</div><h4>Kalıcı Oturum</h4><p>365 gün boyunca giriş yapmadan kalabilirsin.</p></div>
    </div>
    """
    return render_template_string(BASE_HTML, title="Vantorium Hosting", body=body)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        ip = client_ip()
        with LOGIN_FAILS_LOCK:
            if LOGIN_FAILS[ip] > LOGIN_FAILS_MAX:
                ban_ip(ip, "register_spam", 60)
                return render_template_string(BASE_HTML, title="Kayıt",
                    body='<div class="card"><div class="err">Çok fazla deneme. Lütfen bekleyin.</div><a href="/register">Geri</a></div>')
        u = request.form.get("username","").strip().lower()
        p = request.form.get("password","")
        e = request.form.get("email","").strip()
        if not re.match(r"^[a-z0-9_]{3,32}$", u):
            return render_template_string(BASE_HTML, title="Kayıt",
                body='<div class="card"><div class="err">Geçersiz kullanıcı adı (3-32 harf/rakam/altçizgi).</div><a href="/register">Geri</a></div>')
        if len(p) < 6:
            return render_template_string(BASE_HTML, title="Kayıt",
                body='<div class="card"><div class="err">Şifre en az 6 karakter olmalı.</div><a href="/register">Geri</a></div>')
        c = db()
        try:
            c.execute("INSERT INTO users(username,password,email,created) VALUES(?,?,?,?)",
                      (u, generate_password_hash(p), e, datetime.utcnow().isoformat()))
            c.commit()
            uid = c.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone()["id"]
        except sqlite3.IntegrityError:
            c.close()
            return render_template_string(BASE_HTML, title="Kayıt",
                body='<div class="card"><div class="err">Bu kullanıcı adı alınmış.</div><a href="/register">Geri</a></div>')
        c.close()
        audit(uid, "register", ip=ip)
        token = create_session(uid, ip, request.headers.get("User-Agent",""))
        return set_session_cookie(redirect("/dashboard"), token)
    return render_template_string(BASE_HTML, title="Kayıt", body="""
    <div class="card" style="max-width:420px;margin:60px auto">
      <h2>Kayıt Ol</h2>
      <p class="small">Hesabını oluştur ve saniyeler içinde bot çalıştır.</p>
      <form method="post" style="margin-top:18px">
        <p><input name="username" placeholder="kullanıcı adı" required autocomplete="username"></p>
        <p><input name="email" type="email" placeholder="e-posta (opsiyonel)" autocomplete="email"></p>
        <p><input name="password" type="password" placeholder="şifre (min 6)" required autocomplete="new-password"></p>
        <button type="submit" style="width:100%;margin-top:6px">Hesap Oluştur</button>
      </form>
    </div>
    """)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        with LOGIN_FAILS_LOCK:
            if LOGIN_FAILS[ip] > LOGIN_FAILS_MAX:
                ban_ip(ip, "login_brute", 60)
                return render_template_string(BASE_HTML, title="Giriş",
                    body='<div class="card"><div class="err">Çok fazla deneme. Lütfen bekleyin.</div></div>')
        u = request.form.get("username","").strip().lower()
        p = request.form.get("password","")
        c = db(); row = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone(); c.close()
        if row and not row["banned"] and check_password_hash(row["password"], p):
            with LOGIN_FAILS_LOCK: LOGIN_FAILS[ip] = 0
            token = create_session(row["id"], ip, request.headers.get("User-Agent",""))
            session["uid"] = row["id"]; session["uname"] = row["username"]
            audit(row["id"], "login", ip=ip)
            return set_session_cookie(redirect("/dashboard"), token)
        with LOGIN_FAILS_LOCK: LOGIN_FAILS[ip] += 1
        audit(None, "login_fail", meta=u, ip=ip)
        return render_template_string(BASE_HTML, title="Giriş",
            body='<div class="card" style="max-width:420px;margin:60px auto"><div class="err">Kullanıcı adı veya şifre hatalı.</div><a href="/login">Geri</a></div>')
    return render_template_string(BASE_HTML, title="Giriş", body="""
    <div class="card" style="max-width:420px;margin:60px auto">
      <h2>Giriş Yap</h2>
      <p class="small">Hesabına giriş yap.</p>
      <form method="post" style="margin-top:18px">
        <p><input name="username" placeholder="kullanıcı adı" required autocomplete="username"></p>
        <p><input name="password" type="password" placeholder="şifre" required autocomplete="current-password"></p>
        <button type="submit" style="width:100%;margin-top:6px">Giriş</button>
      </form>
    </div>
    """)

@app.route("/logout")
def logout():
    token = request.cookies.get("sid")
    if token:
        c = db(); c.execute("DELETE FROM sessions WHERE token=?", (token,)); c.commit(); c.close()
    session.clear()
    return clear_session_cookie(redirect("/"))

@app.route("/dashboard")
@login_required
def dashboard():
    uid = request.uid
    c = db(); rows = c.execute("SELECT * FROM projects WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall(); c.close()
    items = ""
    for r in rows:
        alive = is_alive(uid, r["name"])
        items += f"""<div class="proj-item">
          <div>
            <div class="proj-name">{r['name']} <span class="badge {'run' if alive else 'stop'}">{'running' if alive else 'stopped'}</span></div>
            <div class="proj-meta">/kullanici/{r['name']} · main: {r['main_file']} · auto: {'✅' if r['autostart'] else '❌'}</div>
          </div>
          <a href="/p/{r['name']}" class="btn">Yönet</a>
        </div>"""
    if not items: items = '<div class="small" style="padding:20px;text-align:center">Henüz projeniz yok. İlk projenizi oluşturun.</div>'
    body = f"""<div class="card">
      <h2>Projelerim</h2>
      <p class="small">Yeni proje oluştur veya mevcut projeni yönet.</p>
      <form method="post" action="/create" class="row" style="margin-top:14px">
        <input name="name" placeholder="proje-adı" required pattern="[a-z0-9_-]{{2,32}}" class="grow" style="min-width:180px">
        <input name="main_file" placeholder="main.py" value="main.py" style="max-width:180px">
        <button type="submit">+ Oluştur</button>
      </form>
    </div>
    <div class="card"><h3>Tüm Projeler</h3>{items}</div>"""
    return render_template_string(BASE_HTML, title="Panel", body=body)

@app.route("/create", methods=["POST"])
@login_required
def create():
    uid = request.uid
    name = request.form.get("name","").strip().lower()
    mf = request.form.get("main_file","main.py").strip() or "main.py"
    if not re.match(r"^[a-z0-9_-]{2,32}$", name): return redirect("/dashboard")
    d = proj_dir(uid, name)
    fp = d / mf
    if not fp.exists():
        if mf.endswith(".html"):
            fp.write_text("<!-- BY VANTORIUM TEAM -->\n<!doctype html><html><head><meta charset='utf-8'><title>Vantorium</title></head><body><h1>Hello Vantorium</h1></body></html>\n")
        else:
            fp.write_text('# BY VANTORIUM TEAM\nimport time\nprint("Hello from Vantorium Hosting")\nwhile True:\n    print("alive", flush=True)\n    time.sleep(30)\n')
    c = db()
    try:
        c.execute("INSERT INTO projects(user_id,name,main_file,autostart,created) VALUES(?,?,?,?,?)",
                  (uid, name, mf, 1, datetime.utcnow().isoformat()))
        c.commit()
    except sqlite3.IntegrityError: pass
    c.close()
    audit(uid, "create_project", meta=name, ip=client_ip())
    return redirect(f"/p/{name}")

def get_proj(name):
    c = db(); r = c.execute("SELECT * FROM projects WHERE user_id=? AND name=?", (request.uid, name)).fetchone(); c.close()
    return r

@app.route("/p/<name>")
@login_required
def project(name):
    r = get_proj(name)
    if not r: abort(404)
    uid = request.uid
    alive = is_alive(uid, name)
    d = proj_dir(uid, name)
    files = [str(f.relative_to(d)) for f in sorted(d.rglob("*"))
             if f.is_file() and "output.log" not in f.name and not f.name.startswith(".")]
    files_html = "".join(f'<li><a href="/p/{name}/edit?f={f}">{f}</a></li>' for f in files)
    c = db(); envs = c.execute("SELECT * FROM project_env WHERE project_id=?", (r["id"],)).fetchall(); c.close()
    env_html = "".join(
        f'<tr><td style="font-family:monospace">{e["key"]}</td><td>••••</td><td style="text-align:right">'
        f'<form method="post" action="/p/{name}/env/del"><input type="hidden" name="k" value="{e["key"]}"><button class="danger" style="padding:5px 10px;font-size:12px">x</button></form></td></tr>'
        for e in envs)
    body = f"""<div class="card">
      <div class="row" style="justify-content:space-between">
        <div><h2 style="display:inline">{name}</h2> <span class="badge {'run' if alive else 'stop'}">{'running' if alive else 'stopped'}</span></div>
        <a href="/dashboard" class="btn ghost">← Panel</a>
      </div>
      <div class="row" style="margin-top:14px">
        <form method="post" action="/p/{name}/start"><button class="success">▶ Başlat</button></form>
        <form method="post" action="/p/{name}/stop"><button class="danger">■ Durdur</button></form>
        <form method="post" action="/p/{name}/autostart"><button class="ghost">Otomatik: {'Açık' if r['autostart'] else 'Kapalı'}</button></form>
        <a href="/p/{name}/logs" class="btn ghost">📄 Loglar</a>
        <a href="/p/{name}/files" class="btn ghost">📁 Dosyalar</a>
      </div>
    </div>
    <div class="card"><h3>Dosyalar</h3><ul>{files_html or '<li class=small>Dosya yok</li>'}</ul></div>
    <div class="card"><h3>Environment Variables</h3>
      <form method="post" action="/p/{name}/env/add" class="row">
        <input name="k" placeholder="KEY" required class="grow">
        <input name="v" placeholder="value" required class="grow">
        <button type="submit">Ekle</button>
      </form>
      <table style="margin-top:12px"><tr><th>Key</th><th>Value</th><th></th></tr>{env_html or '<tr><td colspan=3 class=small>Boş</td></tr>'}</table>
    </div>"""
    return render_template_string(BASE_HTML, title=name, body=body)

@app.route("/p/<name>/start", methods=["POST"])
@login_required
def pstart(name):
    r = get_proj(name)
    if not r: abort(404)
    ok, msg = start_project(request.uid, name, r["main_file"])
    audit(request.uid, "start_project", meta=f"{name}:{msg}", ip=client_ip())
    return redirect(f"/p/{name}")

@app.route("/p/<name>/stop", methods=["POST"])
@login_required
def pstop(name):
    if not get_proj(name): abort(404)
    stop_project(request.uid, name)
    c = db(); c.execute("UPDATE projects SET autostart=0 WHERE user_id=? AND name=?", (request.uid, name)); c.commit(); c.close()
    audit(request.uid, "stop_project", meta=name, ip=client_ip())
    return redirect(f"/p/{name}")

@app.route("/p/<name>/autostart", methods=["POST"])
@login_required
def pauto(name):
    r = get_proj(name)
    if not r: abort(404)
    c = db()
    c.execute("UPDATE projects SET autostart=? WHERE user_id=? AND name=?",
              (0 if r["autostart"] else 1, request.uid, name))
    c.commit(); c.close()
    return redirect(f"/p/{name}")

@app.route("/p/<name>/env/add", methods=["POST"])
@login_required
def penv_add(name):
    r = get_proj(name)
    if not r: abort(404)
    k = request.form.get("k","").strip().upper()
    v = request.form.get("v","")
    if re.match(r"^[A-Z_][A-Z0-9_]{0,63}$", k):
        c = db()
        c.execute("INSERT OR REPLACE INTO project_env(project_id,key,value) VALUES(?,?,?)", (r["id"], k, v))
        c.commit(); c.close()
    return redirect(f"/p/{name}")

@app.route("/p/<name>/env/del", methods=["POST"])
@login_required
def penv_del(name):
    r = get_proj(name)
    if not r: abort(404)
    k = request.form.get("k","").strip()
    c = db(); c.execute("DELETE FROM project_env WHERE project_id=? AND key=?", (r["id"], k)); c.commit(); c.close()
    return redirect(f"/p/{name}")

@app.route("/p/<name>/logs")
@login_required
def plogs(name):
    if not get_proj(name): abort(404)
    d = proj_dir(request.uid, name)
    log_file = d / "output.log"
    content = log_file.read_text(errors="replace")[-30000:] if log_file.exists() else "(log yok)"
    content_html = content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    body = f'<div class="card"><div class="row" style="justify-content:space-between"><h2>{name} — Loglar</h2><a href="/p/{name}" class="btn ghost">← Geri</a></div><pre>{content_html}</pre></div>'
    return render_template_string(BASE_HTML, title=f"{name} Logs", body=body)

@app.route("/p/<name>/files")
@login_required
def pfiles(name):
    if not get_proj(name): abort(404)
    d = proj_dir(request.uid, name)
    items = []
    for f in sorted(d.rglob("*")):
        if f.is_file() and f.name != "output.log":
            rel = f.relative_to(d)
            items.append(f'<li><a href="/p/{name}/edit?f={rel}">📄 {rel}</a> '
                         f'<form method="post" action="/p/{name}/delete" style="display:inline">'
                         f'<input type="hidden" name="f" value="{rel}">'
                         f'<button class="danger" style="padding:5px 10px;font-size:12px">Sil</button></form></li>')
    body = f"""<div class="card">
      <div class="row" style="justify-content:space-between">
        <h2>{name} — Dosyalar</h2><a href="/p/{name}" class="btn ghost">← Geri</a>
      </div>
      <form method="post" action="/p/{name}/new" class="row" style="margin-top:14px">
        <input name="f" placeholder="yeni_dosya.py" required class="grow">
        <button type="submit">+ Oluştur</button>
      </form>
      <ul style="margin-top:12px">{''.join(items) or '<li class=small>Dosya yok</li>'}</ul>
    </div>"""
    return render_template_string(BASE_HTML, title=f"{name} Files", body=body)

@app.route("/p/<name>/new", methods=["POST"])
@login_required
def pnew(name):
    if not get_proj(name): abort(404)
    f = request.form.get("f","").strip()
    if f and ".." not in f and not f.startswith("/"):
        d = proj_dir(request.uid, name)
        fp = d / f
        fp.parent.mkdir(parents=True, exist_ok=True)
        if not fp.exists():
            if f.endswith(".html"):
                fp.write_text("<!-- BY VANTORIUM TEAM -->\n<!doctype html><html><head><meta charset='utf-8'><title>Page</title></head><body><h1>Hello</h1></body></html>\n")
            elif f.endswith(".py"):
                fp.write_text("# BY VANTORIUM TEAM\n")
            else:
                fp.touch()
    return redirect(f"/p/{name}/files")

@app.route("/p/<name>/edit", methods=["GET","POST"])
@login_required
def pedit(name):
    if not get_proj(name): abort(404)
    f = request.args.get("f") or request.form.get("f") or "main.py"
    if ".." in f or f.startswith("/"): abort(400)
    d = proj_dir(request.uid, name)
    fp = d / f
    if request.method == "POST":
        content = request.form.get("content","")
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
        return redirect(f"/p/{name}/edit?f={f}")
    content = fp.read_text(errors="replace") if fp.exists() else ""
    content_esc = content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    body = f"""<div class="card">
      <div class="row" style="justify-content:space-between">
        <h2>Düzenle: <code style="background:rgba(96,165,250,0.15);padding:3px 8px;border-radius:6px;color:#93c5fd">{f}</code></h2>
        <a href="/p/{name}/files" class="btn ghost">← Dosyalar</a>
      </div>
      <form method="post" style="margin-top:14px">
        <input type="hidden" name="f" value="{f}">
        <textarea name="content" spellcheck="false">{content_esc}</textarea>
        <div class="row" style="margin-top:10px">
          <button type="submit">💾 Kaydet</button>
          <span class="small">Ctrl+S ile de kaydedebilirsin</span>
        </div>
      </form>
    </div>
    <script>
    document.addEventListener('keydown',function(e){{
      if((e.ctrlKey||e.metaKey)&&e.key==='s'){{e.preventDefault();document.querySelector('form').submit();}}
      if(e.key==='Tab'){{
        var t=e.target;
        if(t.tagName==='TEXTAREA'){{
          e.preventDefault();
          var s=t.selectionStart,en=t.selectionEnd;
          t.value=t.value.substring(0,s)+'    '+t.value.substring(en);
          t.selectionStart=t.selectionEnd=s+4;
        }}
      }}
    }});
    </script>"""
    return render_template_string(BASE_HTML, title=f"Edit {f}", body=body)

@app.route("/p/<name>/delete", methods=["POST"])
@login_required
def pdelete(name):
    if not get_proj(name): abort(404)
    f = request.form.get("f","")
    if f and ".." not in f:
        d = proj_dir(request.uid, name)
        try: (d / f).unlink()
        except: pass
    return redirect(f"/p/{name}/files")

@app.route("/kullanici/<uname>/<pname>")
def public_proj(uname, pname):
    try:
        c = db(); u = c.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
        if not u: c.close(); abort(404)
        r = c.execute("SELECT * FROM projects WHERE user_id=? AND name=?", (u["id"], pname)).fetchone(); c.close()
        if not r: abort(404)
        alive = is_alive(u["id"], pname)
    except Exception: abort(404)
    body = f"""<div class="card" style="max-width:500px;margin:60px auto;text-align:center">
      <h2>{uname}/{pname}</h2>
      <p style="margin-top:10px"><span class="badge {'run' if alive else 'stop'}">{'running' if alive else 'stopped'}</span></p>
      <p class="small" style="margin-top:16px">7/24 VANTORIUM TEAM tarafından ayakta tutulur.</p>
    </div>"""
    return render_template_string(BASE_HTML, title=f"{uname}/{pname}", body=body)

@app.route("/healthz")
def healthz():
    try:
        c = db()
        bans = c.execute("SELECT COUNT(*) c FROM ip_bans").fetchone()["c"]
        projs = c.execute("SELECT COUNT(*) c FROM projects").fetchone()["c"]
        c.close()
    except Exception: bans = projs = 0
    return jsonify(status="ok", time=datetime.utcnow().isoformat(), procs=len(PROCS),
                   ips_banned=bans, total_projects=projs,
                   rate_limit=RATE_LIMIT, ping_interval=PING_INTERVAL, ping_count=PING_COUNT)

@app.errorhandler(404)
def e404(e):
    return render_template_string(BASE_HTML, title="404", body='<div class="card" style="max-width:400px;margin:60px auto;text-align:center"><h2>404</h2><p>Sayfa bulunamadı.</p><a href="/" class="btn" style="margin-top:14px">Ana Sayfa</a></div>'), 404

@app.errorhandler(500)
def e500(e):
    log.error(f"500: {e}\n{traceback.format_exc()}")
    return render_template_string(BASE_HTML, title="500", body='<div class="card" style="max-width:400px;margin:60px auto;text-align:center"><h2>500</h2><p>Sunucu hatası.</p><a href="/" class="btn" style="margin-top:14px">Ana Sayfa</a></div>'), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    log.info(f"Starting Vantorium on :{port} — RATE_LIMIT={RATE_LIMIT}/min")
    app.run(host="0.0.0.0", port=port, threaded=True)
