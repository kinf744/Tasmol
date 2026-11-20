#!/usr/bin/env python3
"""
Borum VPN - Panneau Web 3XUI Moderne
Serveur web avec API REST complète et interface admin/revendeur.
Gère les comptes SSH Orange Fast 3, les revendeurs et les quotas.
"""

import argparse
import hashlib
import json
import os
import ssl
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_FILE = os.path.join(BASE_DIR, "web_panel.db")
ADMIN_DIR = os.path.join(BASE_DIR, "admin")
RESELLER_DIR = os.path.join(BASE_DIR, "reseller")
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
STIVAROS_DB = "/opt/stivaros/stivaros.db"

# Utilisateurs par défaut du panel (admin et revendeur de démo)
USERS = {
    "admin": {
        "password_hash": hashlib.sha256(b"admin").hexdigest(),
        "role": "admin",
    },
    "reseller": {
        "password_hash": hashlib.sha256(b"reseller").hexdigest(),
        "role": "reseller",
    }
}

SESSIONS = {}  # session_id -> {"user": ..., "role": ..., "expires": ...}

def init_web_db():
    """Initialise la base de données du panel web (revendeurs, quotas, clients, logs)"""
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

def get_stivaros_configs():
    """Lit les configs Orange Fast 3 depuis la base stivaros"""
    if not os.path.exists(STIVAROS_DB):
        return []
    conn = sqlite3.connect(STIVAROS_DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT id, user_id, mode, server_address, server_port, ssh_user, ssh_pass, ssh_payload, path, label
        FROM vpn_configs WHERE mode='orange_fast3'
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def add_stivaros_config(server_address, server_port, ssh_user, ssh_pass, ssh_payload, path, user_id=None, label=None, mode='orange_fast3'):
    """Ajoute une config Orange Fast 3 dans la base stivaros"""
    if not os.path.exists(STIVAROS_DB):
        return False
    conn = sqlite3.connect(STIVAROS_DB)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path, ssh_user, ssh_pass, ssh_payload, label)
            VALUES (?, ?, ?, 'ssh', 'tcp', 0, '', '', 'orange_fast3', ?, '0', '', ?, ?, ?, ?, ?)
        """, (user_id or 1, server_address, server_port, mode, path, ssh_user, ssh_pass, ssh_payload, label or ssh_user))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Erreur insertion config: {e}")
        conn.close()
        return False

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
        handler.send_header("Location", "/admin")
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
    def log_message(self, format, *args):
        pass  # réduire le bruit

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
            self.send_json({
                "total_configs": len(configs),
                "active_configs": len([c for c in configs if c.get("ssh_user")]),
                "servers": len(set(c.get("server_address") for c in configs)),
                "total_payload_bytes": sum(len(c.get("ssh_payload", "")) for c in configs),
            })
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

        if path == "/api/vpn_configs":
            session = get_session(self)
            if not session:
                send_json(self, {"error": "non authentifié"}, 401)
                return
            configs = get_stivaros_configs()
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
            configs = get_stivaros_configs()
            send_json(self, {"configs": configs})
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")

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

        if path == "/api/admin/resellers":
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
                    VALUES (?, ?, ?, ?, ?)
                """, (username, hashlib.sha256(password.encode()).hexdigest(), quota_gb, max_cfgs,
                      (datetime.now() + timedelta(days=days)).isoformat()))
                conn.commit()
                reseller_id = c.lastrowid
                conn.close()
                send_json(self, {"ok": True, "reseller_id": reseller_id})
            except sqlite3.IntegrityError:
                conn.close()
                send_json(self, {"ok": False, "error": "Revendeur déjà existant"}, 400)
            return

        if path == "/api/admin/create-vpn-config":
            session = require_session(self, "admin")
            if not session:
                return
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            server_address = data.get("server_address", "")
            server_port = int(data.get("server_port", 80))
            ssh_user = data.get("ssh_user", "")
            ssh_pass = data.get("ssh_pass", "")
            ssh_payload = data.get("ssh_payload", "")
            path = data.get("path", "/tieme")
            label = data.get("label", ssh_user or "config")
            if not server_address or not ssh_user or not ssh_pass:
                send_json(self, {"ok": False, "error": "server_address, ssh_user et ssh_pass requis"}, 400)
                return
            ok = add_stivaros_config(server_address, server_port, ssh_user, ssh_pass, ssh_payload, path, label=label)
            if ok:
                send_json(self, {"ok": True, "message": "Config créée avec succès"})
            else:
                send_json(self, {"ok": False, "error": "Erreur lors de la création"}, 500)
            return

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
            if not ssh_user or not ssh_pass:
                send_json(self, {"ok": False, "error": "ssh_user et ssh_pass requis"}, 400)
                return
            # Trouver le reseller connecté (simplifié: premier reseller actif)
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT id FROM resellers WHERE is_active=1 LIMIT 1")
            row = c.fetchone()
            if not row:
                conn.close()
                send_json(self, {"ok": False, "error": "Aucun revendeur trouvé"}, 400)
                return
            reseller_id = row[0]
            # Créer la config dans stivaros
            ok = add_stivaros_config("99.86.91.72", 80, ssh_user, ssh_pass, ssh_payload, path, label=username or ssh_user)
            if ok:
                # Récupérer l'id de la config créée
                c.execute("SELECT id FROM vpn_configs WHERE ssh_user=? AND server_address='99.86.91.72' ORDER BY id DESC LIMIT 1", (ssh_user,))
                cfg_row = c.fetchone()
                config_id = cfg_row[0] if cfg_row else None
                c.execute("""
                    INSERT INTO reseller_clients (reseller_id, client_name, config_id, server_address, server_port, ssh_user, ssh_pass, ssh_payload, path, mode, path, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'orange_fast3', ?, 'active')
                """, (reseller_id, username or ssh_user, config_id, "99.86.91.72", 80, ssh_user, ssh_pass, ssh_payload, path, path))
                conn.commit()
                conn.close()
                send_json(self, {"ok": True, "message": "Compte client créé avec succès"})
            else:
                conn.close()
                send_json(self, {"ok": False, "error": "Erreur lors de la création"}, 500)
            return

        self.send_response(404)
        self.end_headers()

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

    server = HTTPServer(("0.0.0.0", port), PanelHandler)

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