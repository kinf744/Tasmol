#!/usr/bin/env python3
"""
Borum VPN - Panneau Web 3XUI
Serveur web simple pour l'administration des tunnels et revendeurs.
"""

import argparse
import hashlib
import json
import os
import ssl
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_FILE = os.path.join(BASE_DIR, "web_panel.db")
ADMIN_DIR = os.path.join(BASE_DIR, "admin")
RESELLER_DIR = os.path.join(BASE_DIR, "reseller")
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

# Utilisateurs en dur (a remplacer par une base reelle)
USERS = {
    "admin": {
        "password_hash": hashlib.sha256(b"admin").hexdigest(),
        "role": "admin",
    }
}

SESSIONS = {}  # session_id -> {"user": ..., "role": ...}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"mode": "plain", "port": 8985, "admin_user": "admin"}

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def read_file(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def get_session(handler):
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            sid = part.split("=", 1)[1]
            return SESSIONS.get(sid)
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

class PanelHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def send_file(self, path, status=200):
        content = read_file(path)
        if content is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(status)
        if path.endswith(".css"):
            self.send_header("Content-Type", "text/css; charset=utf-8")
        elif path.endswith(".js"):
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
        else:
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # Routes publiques
        if path == "/":
            session = get_session(self)
            if session:
                self.send_response(302)
                self.send_header("Location", "/admin" if session["role"] == "admin" else "/reseller")
                self.end_headers()
                return
            self.send_file(os.path.join(PUBLIC_DIR, "login.html"))
            return

        if path == "/login":
            self.send_file(os.path.join(PUBLIC_DIR, "login.html"))
            return

        if path == "/logout":
            # Invalider la session (simplifie)
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
            self.send_file(os.path.join(ADMIN_DIR, "index.html"))
            return

        if path == "/admin/api/resellers":
            session = require_session(self, "admin")
            if not session:
                return
            self.send_json({"resellers": []})
            return

        # Routes reseller
        if path == "/reseller":
            session = require_session(self, "reseller")
            if not session:
                return
            self.send_file(os.path.join(RESELLER_DIR, "index.html"))
            return

        # API vpn configs (lire depuis stivaros.db)
        if path == "/api/vpn_configs":
            session = get_session(self)
            if not session:
                self.send_json({"error": "non authentifie"}, 401)
                return
            import sqlite3
            db_path = "/opt/stivaros/stivaros.db"
            if not os.path.exists(db_path):
                self.send_json({"configs": []})
                return
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, mode, server_address, server_port, ssh_user, ssh_pass, ssh_payload, label FROM vpn_configs WHERE mode='orange_fast3'")
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            self.send_json({"configs": rows})
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
                import uuid
                sid = uuid.uuid4().hex
                SESSIONS[sid] = {"user": username, "role": user["role"]}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={sid}; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "role": user["role"]}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Identifiants invalides"}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # reduire le bruit


def main():
    parser = argparse.ArgumentParser(description="Borum VPN Panel Web 3XUI")
    parser.add_argument("--port", type=int, default=8985, help="Port d'ecoute")
    parser.add_argument("--ssl", action="store_true", help="Activer le SSL")
    parser.add_argument("--cert", type=str, default=None, help="Chemin certificat SSL")
    parser.add_argument("--key", type=str, default=None, help="Chemin cle privee SSL")
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

    print(f"[Panel Web 3XUI] Serveur demarre sur {proto}://0.0.0.0:{port}")
    print(f"[Panel Web 3XUI] Identifiants par defaut: admin / admin")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Panel Web 3XUI] Arret")
        server.server_close()


if __name__ == "__main__":
    main()