#!/usr/bin/env python3
"""
Borum VPN - Panneau Web 3XUI Moderne
Serveur web avec API REST complète et interface admin/revendeur.
Gère les comptes SSH Orange Fast 3, les revendeurs et les quotas.
Synchronisé avec stivaros.sh.
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

def format_bytes(b):
    """Formate les bytes en format lisible (B, KB, MB, GB, TB)"""
    if b is None:
        return "0 B"
    b = int(b)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_FILE = os.path.join(BASE_DIR, "web_panel.db")
ADMIN_DIR = os.path.join(BASE_DIR, "admin")
RESELLER_DIR = os.path.join(BASE_DIR, "reseller")
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
STIVAROS_DB = "/opt/stivaros/stivaros.db"

# Tunnels fixes pour correspondance stivaros.sh
TUNNELS = {
    "xray": {"name": "Xray", "port": 443, "protocol": "vless", "transport": "ws", "tls": 1},
    "zivpn": {"name": "ZIVPN", "port": 5667, "protocol": "zivpn", "transport": "udp", "tls": 0},
    "slowdns": {"name": "SlowDNS", "port": 53, "protocol": "dnstt", "transport": "udp", "tls": 0},
    "sshslowdns": {"name": "SSH+SlowDNS", "port": 22, "protocol": "ssh", "transport": "tcp", "tls": 0},
    "v2raydns": {"name": "V2Ray+DNS", "port": 443, "protocol": "vmess", "transport": "ws", "tls": 1},
}

ORANGE_MODES = {
    "orange": {"addr": "192.179.18.100", "sni": "192.179.18.100", "path": "/xray", "uuid": "aaaa0000-1111-4222-8333-444455556666", "tier": "0"},
    "orange_fast": {"addr": "192.179.18.100", "sni": "crashlyticsreports-pa.googleapis.com", "path": "/@kighmu", "uuid": "aaaa0000-1111-4222-8333-444455556666", "tier": "0"},
    "orange_fast2": {"addr": "192.179.18.100", "sni": "crashlyticsreports-pa.googleapis.com", "path": "/@kighmu2", "uuid": "aaaa0000-1111-4222-8333-444455556666", "tier": "0"},
    "mtn_unlimited": {"addr": "104.18.123.45", "sni": "mtnplay.com", "path": "/vless", "uuid": "aaaa0000-1111-4222-8333-444455556666", "tier": "0"},
    "orange_fast3": {"addr": "99.86.91.72", "port": 80, "sni": "99.86.91.72", "path": "/tieme", "uuid": "aaaa0000-1111-4222-8333-444455556667", "tier": "0"},
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"mode": "plain", "port": 8985, "admin_user": "admin"}

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

USERS = {
    "admin": {"password_hash": hashlib.sha256(b"admin").hexdigest(), "role": "admin"},
    "reseller": {"password_hash": hashlib.sha256(b"reseller").hexdigest(), "role": "reseller"},
}

SESSIONS = {}

def init_web_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS resellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            quota_data_gb INTEGER DEFAULT 0,
            quota_data_used_gb REAL DEFAULT 0,
            max_configs INTEGER DEFAULT 0,
            configs_created INTEGER DEFAULT 0,
            expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS reseller_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reseller_id INTEGER NOT NULL,
            client_name TEXT,
            config_id INTEGER,
            server_address TEXT,
            server_port INTEGER,
            ssh_user TEXT,
            ssh_pass TEXT,
            ssh_payload TEXT,
            path TEXT,
            mode TEXT DEFAULT 'orange_fast3',
            status TEXT DEFAULT 'active',
            data_used_gb REAL DEFAULT 0,
            expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reseller_id) REFERENCES resellers(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            target TEXT,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def get_stivaros_conn():
    if not os.path.exists(STIVAROS_DB):
        return None
    conn = sqlite3.connect(STIVAROS_DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_stivaros_configs(mode_filter=None):
    conn = get_stivaros_conn()
    if not conn:
        return []
    cur = conn.cursor()
    sql = "SELECT id, user_id, mode, server_address, server_port, protocol, transport, tls, sni, host, isp, tier, xray_uuid, path, ssh_user, ssh_pass, ssh_payload, zivpn_password, nameserver, slowdns_pubkey FROM vpn_configs"
    params = []
    if mode_filter:
        sql += " WHERE mode=?"
        params.append(mode_filter)
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_stivaros_users():
    conn = get_stivaros_conn()
    if not conn:
        return []
    cur = conn.cursor()
    cur.execute("""
        SELECT u.*, 
            (SELECT COUNT(*) FROM vpn_configs WHERE user_id=u.id) as config_count,
            (SELECT GROUP_CONCAT(DISTINCT mode) FROM vpn_configs WHERE user_id=u.id) as modes
        FROM users u
        ORDER BY u.id DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def log_admin(action, target, details):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO admin_logs (action, target, details) VALUES (?, ?, ?)", (action, target, details))
    conn.commit()
    conn.close()

def get_session(handler):
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            sid = part.split("=", 1)[1]
            if sid in SESSIONS and SESSIONS[sid]["expires"] > datetime.now():
                return SESSIONS[sid]
            elif sid in SESSIONS:
                del SESSIONS[sid]
    return None

def require_session(handler, role=None):
    session = get_session(handler)
    if not session:
        handler.send_response(302)
        handler.send_header("Location", "/login")
        handler.end_headers()
        return False
    if role and session.get("role") != role:
        handler.send_response(302)
        handler.send_header("Location", "/admin" if session["role"] == "admin" else "/reseller")
        handler.end_headers()
        return False
    return session

def send_json(handler, data, status=200):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(json.dumps(data).encode("utf-8"))

def send_html(handler, html, status=200):
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(html.encode("utf-8"))

def send_file(handler, path, status=200):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        handler.send_response(status)
        if path.endswith(".css"):
            handler.send_header("Content-Type", "text/css; charset=utf-8")
        elif path.endswith(".js"):
            handler.send_header("Content-Type", "application/javascript; charset=utf-8")
        else:
            handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.end_headers()
        handler.wfile.write(content.encode("utf-8"))
    else:
        handler.send_response(404)
        handler.end_headers()

class PanelHandler(BaseHTTPRequestHandler):
    timeout = 15
    protocol_version = "HTTP/1.0"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Routes publiques
        if path == "/":
            session = get_session(self)
            if session:
                self.send_response(302)
                self.send_header("Location", "/admin" if session["role"] == "admin" else "/reseller")
                self.end_headers()
                return
            send_file(self, os.path.join(PUBLIC_DIR, "login.html"))
            return

        if path == "/login":
            send_file(self, os.path.join(PUBLIC_DIR, "login.html"))
            return

        if path == "/logout":
            self.send_response(302)
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
            self.send_header("Location", "/login")
            self.end_headers()
            return

        # Routes admin
        if path == "/admin":
            session = require_session(self, "admin")
            if not session:
                return
            send_file(self, os.path.join(ADMIN_DIR, "index.html"))
            return

        if path == "/admin/api/stats":
            session = require_session(self, "admin")
            if not session:
                return
            configs = get_stivaros_configs()
            users = get_stivaros_users()
            def parse_expires(exp):
                if not exp:
                    return None
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        return datetime.strptime(exp, fmt)
                    except ValueError:
                        continue
                return None
            active_users = len([u for u in users if parse_expires(u.get("expires_at")) and parse_expires(u.get("expires_at")) > datetime.now()])
            expired_users = len(users) - active_users
            send_json(self, {
                "total_configs": len(configs),
                "active_configs": len([c for c in configs if c.get("ssh_user")]),
                "total_users": len(users),
                "active_users": active_users,
                "expired_users": expired_users,
                "servers": len(set(c.get("server_address") for c in configs if c.get("server_address"))),
                "tunnels": list(TUNNELS.keys()),
            })
            return

        if path == "/admin/api/tunnels":
            session = require_session(self, "admin")
            if not session:
                return
            # Vérifier état tunnels via systemd
            tunnel_status = {}
            for key, t in TUNNELS.items():
                service_file = f"/etc/systemd/system/stivaros-{key}.service"
                if not os.path.exists(service_file):
                    tunnel_status[key] = "not_installed"
                else:
                    try:
                        result = subprocess.run(["systemctl", "is-active", f"stivaros-{key}"], capture_output=True, text=True, timeout=2)
                        tunnel_status[key] = result.stdout.strip() if result.returncode == 0 else "inactive"
                    except Exception:
                        tunnel_status[key] = "unknown"
            send_json(self, {"tunnels": tunnel_status})
            return

        if path == "/admin/api/users":
            session = require_session(self, "admin")
            if not session:
                return
            users = get_stivaros_users()
            send_json(self, {"users": users})
            return

        if path == "/admin/api/users/configs":
            session = require_session(self, "admin")
            if not session:
                return
            user_id = parse_qs(parsed.query).get("user_id", [None])[0]
            if not user_id:
                send_json(self, {"error": "user_id requis"}, 400)
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"configs": []})
                return
            cur = conn.cursor()
            cur.execute("SELECT * FROM vpn_configs WHERE user_id=?", (user_id,))
            configs = [dict(r) for r in cur.fetchall()]
            conn.close()
            send_json(self, {"configs": configs})
            return

        if path == "/admin/api/hosts":
            session = require_session(self, "admin")
            if not session:
                return
            hosts = {}
            for key in ["orange", "orange_fast", "orange_fast2", "mtn_unlimited"]:
                host_file = f"/opt/stivaros/{key}_host.txt"
                if os.path.exists(host_file):
                    with open(host_file) as f:
                        hosts[key] = f.read().strip()
                else:
                    hosts[key] = ""
            send_json(self, {"hosts": hosts})
            return

        if path == "/admin/api/quota/stats":
            session = require_session(self, "admin")
            if not session:
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"users": []})
                return
            cur = conn.cursor()
            cur.execute("SELECT id, phone, name, quota_mb, bytes_used, expires_at, multi_device FROM users WHERE active=1 ORDER BY bytes_used DESC")
            users = [dict(r) for r in cur.fetchall()]
            conn.close()
            # Ajouter formatage lisible
            for u in users:
                used = u.get("bytes_used") or 0
                quota = u.get("quota_mb") or 0
                limit = quota * 1048576 if quota > 0 else 0
                u["used_bytes"] = used
                u["used_human"] = format_bytes(used)
                if limit > 0:
                    u["limit_bytes"] = limit
                    u["limit_human"] = format_bytes(limit)
                    u["remaining_bytes"] = max(0, limit - used)
                    u["remaining_human"] = format_bytes(max(0, limit - used))
                    u["pct_used"] = round(used / limit * 100, 1) if limit > 0 else 0
                else:
                    u["limit_bytes"] = 0
                    u["limit_human"] = "Illimité"
                    u["remaining_bytes"] = 0
                    u["remaining_human"] = "Illimité"
                    u["pct_used"] = 0
                u["unlimited"] = (quota or 0) <= 0
            send_json(self, {"users": users})
            return

        if path == "/admin/api/resellers":
            session = require_session(self, "admin")
            if not session:
                return
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, username, quota_data_gb, quota_data_used_gb, max_configs, configs_created, expires_at, is_active FROM resellers")
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            send_json(self, {"resellers": rows})
            return

        if path == "/admin/api/logs":
            session = require_session(self, "admin")
            if not session:
                return
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 100")
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            send_json(self, {"logs": rows})
            return

        # API vpn_configs (pour admin et reseller)
        if path == "/api/vpn_configs":
            session = get_session(self)
            if not session:
                send_json(self, {"error": "non authentifié"}, 401)
                return
            configs = get_stivaros_configs("orange_fast3")
            send_json(self, {"configs": configs})
            return

        if path == "/api/admin/resellers":
            session = require_session(self, "admin")
            if not session:
                return
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, username, quota_data_gb, quota_data_used_gb, max_configs, configs_created, expires_at, is_active FROM resellers")
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            send_json(self, {"resellers": rows})
            return

        if path == "/api/admin/configs":
            session = require_session(self, "admin")
            if not session:
                return
            configs = get_stivaros_configs("orange_fast3")
            send_json(self, {"configs": configs})
            return

        # Routes reseller
        if path == "/reseller":
            session = require_session(self, "reseller")
            if not session:
                return
            send_file(self, os.path.join(RESELLER_DIR, "index.html"))
            return

        if path == "/reseller/api/my-configs":
            session = require_session(self, "reseller")
            if not session:
                return
            configs = get_stivaros_configs("orange_fast3")
            send_json(self, {"configs": configs})
            return

        if path == "/reseller/api/clients":
            session = require_session(self, "reseller")
            if not session:
                return
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Trouver le reseller connecté
            cur.execute("SELECT id FROM resellers WHERE is_active=1 LIMIT 1")
            row = cur.fetchone()
            if not row:
                send_json(self, {"clients": []})
                conn.close()
                return
            reseller_id = row[0]
            cur.execute("SELECT * FROM reseller_clients WHERE reseller_id=? ORDER BY id DESC", (reseller_id,))
            clients = [dict(r) for r in cur.fetchall()]
            conn.close()
            send_json(self, {"clients": clients})
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""

        # Login public
        if path == "/login":
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            username = data.get("username", "")
            password = data.get("password", "")
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            user = USERS.get(username)
            if user and user["password_hash"] == pwd_hash:
                sid = uuid.uuid4().hex
                SESSIONS[sid] = {"user": username, "role": user["role"], "expires": datetime.now() + timedelta(days=7)}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly; Max-Age=604800")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "role": user["role"]}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Identifiants invalides"}).encode())
            return

        # Admin: créer utilisateur
        if path == "/api/admin/create-user":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            phone = data.get("phone", "")
            name = data.get("name", "")
            days = int(data.get("days", 30))
            quota_mb = int(data.get("quota_mb", 0))
            multi_device = 1 if data.get("multi_device") else 0
            allowed_uuids = data.get("allowed_uuids", "")
            if not phone or not valid_phone(phone):
                send_json(self, {"ok": False, "error": "Numéro invalide"}, 400)
                return
            expires = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
            code = generate_activation_code()
            user_uuid = str(uuid.uuid4())
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            try:
                c.execute("""
                    INSERT INTO users (uuid, phone, name, activation_code, expires_at, quota_mb, multi_device, allowed_uuids, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (user_uuid, phone, name, code, expires, quota_mb, multi_device, allowed_uuids))
                conn.commit()
                user_id = c.lastrowid
                conn.close()
                log_admin("create_user", phone, f"days={days}, quota={quota_mb}, multi={multi_device}, uuids={allowed_uuids}")
                send_json(self, {"ok": True, "user_id": user_id, "code": code})
            except sqlite3.IntegrityError:
                conn.close()
                send_json(self, {"ok": False, "error": "Utilisateur existe"}, 400)
            return

        # Admin: créer utilisateur test (heures)
        if path == "/api/admin/create-test-user":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            phone = data.get("phone", "")
            hours = int(data.get("hours", 1))
            multi_device = 1 if data.get("multi_device") else 0
            allowed_uuids = data.get("allowed_uuids", "")
            if not phone or not valid_phone(phone):
                send_json(self, {"ok": False, "error": "Numéro invalide"}, 400)
                return
            expires = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            code = generate_activation_code()
            user_uuid = str(uuid.uuid4())
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            try:
                c.execute("""
                    INSERT INTO users (uuid, phone, name, activation_code, expires_at, quota_mb, multi_device, allowed_uuids, created_at)
                    VALUES (?, ?, ?, ?, ?, 0, ?, ?, datetime('now'))
                """, (user_uuid, phone, "TEST", code, expires, multi_device, allowed_uuids))
                conn.commit()
                user_id = c.lastrowid
                conn.close()
                log_admin("create_test_user", phone, f"hours={hours}, multi={multi_device}, uuids={allowed_uuids}")
                send_json(self, {"ok": True, "user_id": user_id, "code": code, "expires": expires})
            except sqlite3.IntegrityError:
                conn.close()
                send_json(self, {"ok": False, "error": "Utilisateur existe"}, 400)
            return

        # Admin: lister utilisateurs
        if path == "/api/admin/users":
            session = require_session(self, "admin")
            if not session:
                return
            users = get_stivaros_users()
            send_json(self, {"users": users})
            return

        # Admin: supprimer utilisateur
        if path == "/api/admin/delete-user":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            user_id = data.get("user_id")
            if not user_id:
                send_json(self, {"ok": False, "error": "user_id requis"}, 400)
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
            c.execute("DELETE FROM vpn_configs WHERE user_id=?", (user_id,))
            conn.commit()
            conn.close()
            log_admin("delete_user", str(user_id), "")
            send_json(self, {"ok": True})
            return

        # Admin: configs d'un utilisateur
        if path == "/api/admin/user-configs":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            user_id = data.get("user_id")
            if not user_id:
                send_json(self, {"ok": False, "error": "user_id requis"}, 400)
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            c.execute("SELECT * FROM vpn_configs WHERE user_id=?", (user_id,))
            configs = [dict(r) for r in cur.fetchall()]
            conn.close()
            send_json(self, {"configs": configs})
            return

        # Admin: ajouter config à utilisateur
        if path == "/api/admin/add-config":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            user_id = data.get("user_id")
            mode = data.get("mode", "xray")
            if not user_id:
                send_json(self, {"ok": False, "error": "user_id requis"}, 400)
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            # Générer UUID
            xray_uuid = str(uuid.uuid4())
            c = conn.cursor()
            if mode in ORANGE_MODES:
                m = ORANGE_MODES[mode]
                host = get_orange_host(mode)
                c.execute(f"""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path)
                    VALUES (?, ?, ?, 'vless', 'ws', 1, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, m["addr"], 443, m["sni"], host or m["sni"], mode, mode, m["tier"], xray_uuid, m["path"]))
            elif mode == "orange_fast3":
                m = ORANGE_MODES["orange_fast3"]
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path, ssh_user, ssh_pass, ssh_payload)
                    VALUES (?, ?, ?, 'ssh', 'tcp', 0, ?, ?, 'orange_fast3', 'orange_fast3', '0', ?, ?, ?, ?, ?)
                """, (user_id, m["addr"], m["port"], m["sni"], m["sni"], m["tier"], m["uuid"], m["path"], "danaelssh-damope", "damop", "GET / HTTP/1.1\r\nHost: m.batch.com\r\n\r\nX / HTTP/1.1\r\nHost: [host]\r\n\r\nGET /tieme HTTP/1.1\r\nHost: d76eob7wpy03j.cloudfront.net\r\nBackend: crashlyticsreports-pa.googleapis.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nUser-agent:\r\n\r\n"))
            elif mode == "zivpn":
                server_addr = get_domain()
                server_addr = server_addr or (socket.gethostbyname(socket.gethostname()) if socket.gethostbyname(socket.gethostname()) != "127.0.0.1" else "127.0.0.1")
                zivpn_pass = generate_secret()[:12]
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range)
                    VALUES (?, ?, ?, 'zivpn', 'udp', 0, ?, ?, 'camtel', 'zivpn', '150', ?, ?, ?)
                """, (user_id, server_addr, 5667, server_addr, server_addr, xray_uuid, zivpn_pass, "10000-20000"))
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range)
                    VALUES (?, ?, ?, 'zivpn', 'udp', 0, ?, ?, '', 'zivpn', '100', ?, ?, ?)
                """, (user_id, server_addr, 5667, server_addr, server_addr, xray_uuid, zivpn_pass, "10000-20000"))
            elif mode == "sshslowdns":
                server_addr = get_domain()
                server_addr = server_addr or (socket.gethostbyname(socket.gethostname()) if socket.gethostbyname(socket.gethostname()) != "127.0.0.1" else "127.0.0.1")
                ns4 = "1.1.1.1"  # default NS
                dnstt_pub = "default_pubkey"
                ssh_user = "u" + str(user_id)
                ssh_pass = generate_secret()[:12]
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass)
                    VALUES (?, ?, 22, 'ssh', 'dnstt', 0, ?, ?, '', 'sshslowdns', '150', ?, ?, ?, ?, ?)
                """, (user_id, server_addr, server_addr, server_addr, xray_uuid, ns4, dnstt_pub, ssh_user, ssh_pass))
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass)
                    VALUES (?, ?, 22, 'ssh', 'dnstt', 0, ?, ?, '', 'sshslowdns', '150', ?, ?, ?, ?, ?)
                """, (user_id, server_addr, server_addr, server_addr, xray_uuid, ns4, dnstt_pub, ssh_user, ssh_pass))
            elif mode == "v2raydns":
                server_addr = get_domain()
                server_addr = server_addr or (socket.gethostbyname(socket.gethostname()) if socket.gethostbyname(socket.gethostname()) != "127.0.0.1" else "127.0.0.1")
                nv4 = "1.1.1.1"  # default NS
                dnstt_pub = "default_pubkey"
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey)
                    VALUES (?, ?, 443, 'vless', 'dnstt', 0, ?, ?, '', 'v2raydns', '150', ?, ?, ?)
                """, (user_id, server_addr, server_addr, server_addr, xray_uuid, nv4, dnstt_pub))
                c.execute("""
                    INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey)
                    VALUES (?, ?, 443, 'vless', 'dnstt', 0, ?, ?, '', 'v2raydns', '150', ?, ?, ?)
                """, (user_id, server_addr, server_addr, server_addr, xray_uuid, nv4, dnstt_pub))
            else:
                send_json(self, {"ok": False, "error": "Mode inconnu"}, 400)
                conn.close()
                return
            conn.commit()
            conn.close()
            log_admin("add_config", str(user_id), f"mode={mode}")
            send_json(self, {"ok": True, "xray_uuid": xray_uuid})
            return

        # Admin: supprimer config
        if path == "/api/admin/delete-config":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            config_id = data.get("config_id")
            if not config_id:
                send_json(self, {"ok": False, "error": "config_id requis"}, 400)
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            c.execute("DELETE FROM vpn_configs WHERE id=?", (config_id,))
            conn.commit()
            conn.close()
            log_admin("delete_config", str(config_id), "")
            send_json(self, {"ok": True})
            return

        # Admin: gérer devices/UUID
        if path == "/api/admin/devices":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            action = data.get("action")
            phone = data.get("phone", "")
            device_id = data.get("device_id", "")
            allowed_uuids = data.get("allowed_uuids", "")
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            if action == "set":
                c.execute("UPDATE users SET device_install_id=?, allowed_uuids=? WHERE phone=?", (device_id, allowed_uuids, phone))
            elif action == "clear":
                c.execute("UPDATE users SET device_install_id='', allowed_uuids='' WHERE phone=?", (phone,))
            conn.commit()
            conn.close()
            log_admin("devices", phone, f"action={action}")
            send_json(self, {"ok": True})
            return

        # Admin: host Orange
        if path == "/api/admin/host":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            mode = data.get("mode")
            host = data.get("host", "")
            action = data.get("action", "set")
            if mode not in ["orange", "orange_fast", "orange_fast2", "mtn_unlimited"]:
                send_json(self, {"ok": False, "error": "Mode invalide"}, 400)
                return
            host_file = f"/opt/stivaros/{mode}_host.txt"
            if action == "set":
                with open(host_file, "w") as f:
                    f.write(host)
                os.chmod(host_file, 0o600)
                conn = get_stivaros_conn()
                if conn:
                    c = conn.cursor()
                    c.execute(f"UPDATE vpn_configs SET host=? WHERE isp=? AND mode=?", (host, mode, mode))
                    conn.commit()
                    conn.close()
                log_admin("host_set", mode, host)
            elif action == "delete":
                if os.path.exists(host_file):
                    os.remove(host_file)
                conn = get_stivaros_conn()
                if conn:
                    c = conn.cursor()
                    c.execute(f"UPDATE vpn_configs SET host='' WHERE isp=? AND mode=?", (mode, mode))
                    conn.commit()
                    conn.close()
                log_admin("host_delete", mode, "")
            send_json(self, {"ok": True})
            return

        # Admin: tunnels
        if path == "/api/admin/tunnel-action":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            tunnel = data.get("tunnel")
            action = data.get("action")
            if tunnel not in TUNNELS or action not in ["install", "repair", "restart", "status"]:
                send_json(self, {"ok": False, "error": "Paramètres invalides"}, 400)
                return
            try:
                if action == "install":
                    subprocess.run(["/opt/stivaros/stivaros.sh", "install-tunnel", tunnel], check=True, capture_output=True, text=True, timeout=120)
                elif action == "repair":
                    subprocess.run(["/opt/stivaros/stivaros.sh", "repair-tunnel", tunnel], check=True, capture_output=True, text=True, timeout=120)
                elif action == "restart":
                    subprocess.run(["systemctl", "restart", f"stivaros-{tunnel}"], check=True, capture_output=True, text=True, timeout=30)
                elif action == "status":
                    result = subprocess.run(["systemctl", "is-active", f"stivaros-{tunnel}"], capture_output=True, text=True, timeout=5)
                    status = result.stdout.strip() if result.returncode == 0 else "inactive"
                    send_json(self, {"ok": True, "status": status})
                    return
                log_admin("tunnel", tunnel, action)
                send_json(self, {"ok": True})
            except subprocess.CalledProcessError as e:
                send_json(self, {"ok": False, "error": e.stderr or str(e)}, 500)
            except Exception as e:
                send_json(self, {"ok": False, "error": str(e)}, 500)
            return

        # Admin: quota
        if path == "/api/admin/quota":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            user_id = data.get("user_id")
            quota_mb = int(data.get("quota_mb", 0))
            if not user_id:
                send_json(self, {"ok": False, "error": "user_id requis"}, 400)
                return
            conn = get_stivaros_conn()
            if not conn:
                send_json(self, {"ok": False, "error": "DB indisponible"}, 500)
                return
            c = conn.cursor()
            c.execute("UPDATE users SET quota_mb=? WHERE id=?", (quota_mb, user_id))
            conn.commit()
            conn.close()
            log_admin("quota", str(user_id), f"quota_mb={quota_mb}")
            send_json(self, {"ok": True})
            return

        # Admin: créer revendeur
        if path == "/api/admin/create-reseller":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            username = data.get("username", "")
            password = data.get("password", "admin123")
            quota_gb = int(data.get("quota_gb", 0))
            max_cfgs = int(data.get("max_configs", 0))
            days = int(data.get("days", 30))
            if not username:
                send_json(self, {"ok": False, "error": "Nom requis"}, 400)
                return
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            try:
                c.execute("""
                    INSERT INTO resellers (username, password_hash, quota_data_gb, max_configs, expires_at)
                    VALUES (?, ?, ?, ?, datetime('now', '+{} days'))
                """.format(days), (username, hashlib.sha256(password.encode()).hexdigest(), quota_gb, max_cfgs))
                conn.commit()
                reseller_id = c.lastrowid
                conn.close()
                log_admin("create_reseller", username, f"quota={quota_gb}")
                send_json(self, {"ok": True, "reseller_id": reseller_id})
            except sqlite3.IntegrityError:
                conn.close()
                send_json(self, {"ok": False, "error": "Revendeur déjà existant"}, 400)
            return

        # Admin: supprimer revendeur
        if path == "/api/admin/delete-reseller":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            reseller_id = data.get("reseller_id")
            if not reseller_id:
                send_json(self, {"ok": False, "error": "reseller_id requis"}, 400)
                return
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM resellers WHERE id=?", (reseller_id,))
            c.execute("DELETE FROM reseller_clients WHERE reseller_id=?", (reseller_id,))
            conn.commit()
            conn.close()
            log_admin("delete_reseller", str(reseller_id), "")
            send_json(self, {"ok": True})
            return

        # Admin: créer config Orange Fast 3
        if path == "/api/admin/create-vpn-config":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            server_address = data.get("server_address", "99.86.91.72")
            server_port = int(data.get("server_port", 80))
            ssh_user = data.get("ssh_user", "")
            ssh_pass = data.get("ssh_pass", "")
            ssh_payload = data.get("ssh_payload", "")
            path = data.get("path", "/tieme")
            label = data.get("label", ssh_user or "config")
            if not server_address or not ssh_user or not ssh_pass:
                send_json(self, {"ok": False, "error": "server_address, ssh_user et ssh_pass requis"}, 400)
                return
            ok = add_stivaros_config(server_address, server_port, ssh_user, ssh_pass, ssh_payload, path)
            if ok:
                send_json(self, {"ok": True, "message": "Config créée avec succès"})
            else:
                send_json(self, {"ok": False, "error": "Erreur lors de la création"}, 500)
            return

        # Reseller: créer config client
        if path == "/api/reseller/create-vpn-config":
            session = require_session(self, "reseller")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            username = data.get("client_name", "")
            ssh_user = data.get("ssh_user", "")
            ssh_pass = data.get("ssh_pass", "")
            ssh_payload = data.get("ssh_payload", "")
            path = data.get("path", "/tieme")
            server_address = data.get("server_address", "99.86.91.72")
            server_port = int(data.get("server_port", 80))
            if not ssh_user or not ssh_pass:
                send_json(self, {"ok": False, "error": "ssh_user et ssh_pass requis"}, 400)
                return
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT id FROM resellers WHERE is_active=1 LIMIT 1")
            row = c.fetchone()
            if not row:
                conn.close()
                send_json(self, {"ok": False, "error": "Aucun revendeur trouvé"}, 400)
                return
            reseller_id = row[0]
            ok = add_stivaros_config(server_address, server_port, ssh_user, ssh_pass, ssh_payload, path)
            if ok:
                c.execute("SELECT id FROM vpn_configs WHERE ssh_user=? AND server_address=? ORDER BY id DESC LIMIT 1", (ssh_user, server_address))
                cfg_row = c.fetchone()
                config_id = cfg_row[0] if cfg_row else None
                c.execute("""
                    INSERT INTO reseller_clients (reseller_id, client_name, config_id, server_address, server_port, ssh_user, ssh_pass, ssh_payload, path, mode, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'orange_fast3', 'active')
                """, (reseller_id, username or ssh_user, config_id, server_address, server_port, ssh_user, ssh_pass, ssh_payload, path))
                conn.commit()
                conn.close()
                send_json(self, {"ok": True, "message": "Compte client créé avec succès"})
            else:
                conn.close()
                send_json(self, {"ok": False, "error": "Erreur lors de la création"}, 500)
            return

        self.send_response(404)
        self.end_headers()

def generate_secret():
    import secrets
    return secrets.token_hex(16)

def generate_activation_code():
    """Génère un code d'activation à 6 chiffres (ex: 684462)"""
    import random
    return str(random.randint(100000, 999999))

def get_domain():
    """Get server domain or fallback to public IP"""
    try:
        import socket
        # Try to get hostname
        hostname = socket.gethostname()
        ips = socket.gethostbyname_ex(hostname)[2]
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
                return ip
        # If no public IP found, return first non-localhost
        for ip in ips:
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "99.86.91.72"  # fallback

def valid_phone(phone):
    import re
    return bool(re.match(r'^[+]?[0-9]{8,15}$', phone))

def generate_secret():
    import secrets
    return secrets.token_hex(16)

def get_orange_host(mode):
    host_file = f"/opt/stivaros/{mode}_host.txt"
    if os.path.exists(host_file):
        with open(host_file) as f:
            return f.read().strip()
    return None

def add_stivaros_config(server_address, server_port, ssh_user, ssh_pass, ssh_payload, path, user_id=None, label=None, mode='orange_fast3'):
    if not os.path.exists(STIVAROS_DB):
        return False
    conn = sqlite3.connect(STIVAROS_DB)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path, ssh_user, ssh_pass, ssh_payload)
            VALUES (?, ?, ?, 'ssh', 'tcp', 0, ?, ?, 'orange_fast3', 'orange_fast3', '', '0', 'aaaa0000-1111-4222-8333-444455556667', ?, ?, ?, ?)
        """, (user_id or 1, server_address, server_port, server_address, server_address, path, ssh_user, ssh_pass, ssh_payload))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Erreur insertion config: {e}")
        conn.close()
        return False

def main():
    init_web_db()
    parser = argparse.ArgumentParser(description="Borum VPN Panel Web 3XUI Moderne")
    parser.add_argument("--port", type=int, default=8985, help="Port d'écoute")
    parser.add_argument("--ssl", action="store_true", help="Activer le SSL")
    parser.add_argument("--cert", type=str, default=None, help="Chemin certificat SSL")
    parser.add_argument("--key", type=str, default=None, help="Chemin clé privée SSL")
    args = parser.parse_args()

    cfg = load_config()
    port = args.port or cfg.get("port", 8985)

    server = ThreadingHTTPServer(("0.0.0.0", port), PanelHandler)

    if args.ssl and args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    print(f"[Panel Web 3XUI] Serveur démarré sur {proto}://0.0.0.0:{port}")
    print(f"[Panel Web 3XUI] Identifiants par défaut: admin / admin")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Panel Web 3XUI] Arrêt")
        server.server_close()

if __name__ == "__main__":
    main()