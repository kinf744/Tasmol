#!/usr/bin/env python3
"""Stivaros activation API (compat EPHANG VPN)."""
import json, os, sqlite3, sys
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB_PATH = os.environ.get("STIVAROS_DB", "/opt/stivaros/stivaros.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            name TEXT DEFAULT '',
            activation_code TEXT NOT NULL,
            device_install_id TEXT DEFAULT '',
            app_version TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT,
            active INTEGER DEFAULT 1,
            quota_mb INTEGER DEFAULT 0,
            bytes_used INTEGER DEFAULT 0,
            multi_device INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS vpn_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_address TEXT,
            server_port INTEGER DEFAULT 443,
            protocol TEXT DEFAULT 'vless',
            transport TEXT DEFAULT 'xhttp',
            tls INTEGER DEFAULT 1,
            sni TEXT, host TEXT DEFAULT '',
            isp TEXT DEFAULT '', mode TEXT DEFAULT '', flow TEXT DEFAULT '',
            tier TEXT DEFAULT '150',
            xray_uuid TEXT DEFAULT '',
            zivpn_password TEXT DEFAULT '', zivpn_port INTEGER DEFAULT 5667,
            port_range TEXT DEFAULT '',
            nameserver TEXT DEFAULT '', slowdns_pubkey TEXT DEFAULT '',
            ssh_user TEXT DEFAULT '', ssh_pass TEXT DEFAULT '',
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    for col, ddl in [("nameserver", "TEXT DEFAULT ''"), ("slowdns_pubkey", "TEXT DEFAULT ''"),
                     ("ssh_user", "TEXT DEFAULT ''"), ("ssh_pass", "TEXT DEFAULT ''"),
                     ("host", "TEXT DEFAULT ''"), ("port_range", "TEXT DEFAULT ''"),
                     ("path", "TEXT DEFAULT ''"),
                     ("utunnel_secret", "TEXT DEFAULT ''"), ("utunnel_hop", "INTEGER DEFAULT 0"),
                     ("quota_mb", "INTEGER DEFAULT 0"), ("bytes_used", "INTEGER DEFAULT 0")]:
        # quota_mb/bytes_used ciblent la table users
        table = "users" if col in ("quota_mb", "bytes_used") else "vpn_configs"
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
        except Exception:
            pass
    # Migration: les rows zivpn héritées pointaient vers l'ancienne
    # instance partagée (:5667, DNAT 6000-19999). L'instance dédiée
    # stivaros écoute :5668 avec DNAT 34000-49999.
    conn.execute(
        "UPDATE vpn_configs SET server_port = 5668, port_range = ?"
        " WHERE mode = 'zivpn'"
        "   AND port_range != ?",
        ("34000-37999,38000-41999,42000-45999,46000-49999",
         "34000-37999,38000-41999,42000-45999,46000-49999"))

    # Verrou d'appareil : multi_device (0 = mono, activable/joignable
    # uniquement depuis l'UUID qui a activé le compte ; 1 = tout appareil).
    # Les comptes créés AVANT l'introduction du verrou passent en mode
    # multi-appareils : personne ne se retrouve verrouillé hors de son
    # appareil du jour au lendemain ; bascule possible depuis le menu
    # Appareils (menu principal, rubrique "Appareils & verrou UUID").
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    if "multi_device" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN multi_device INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE users SET multi_device = 1")

    conn.commit()
    conn.close()

def find_users(identifier):
    """TOUTes les lignes correspondant à un identifiant (uuid du compte,
    uuid d'appareil lié, ou téléphone). Un appareil lié à plusieurs comptes
    (réactivations successives) faisait gagner une ligne arbitraire : le
    serveur concatène les trois recherches et laisse le contrôle de code
    choisir la bonne (cf. _authorized_user).

    Pour un compte multi-appareils, device_install_id est une LISTE
    d'UUID séparés par des virgules : le LIKE avec délimiteurs de part
    et d'autre retrouve toute ligne dont l'appareil présenté en fait
    partie, qu'il soit le dernier activé ou non."""
    ident = (identifier or "").strip()
    conn = get_db()
    rows = list(conn.execute(
        "SELECT * FROM users WHERE uuid = ? OR device_install_id = ? OR phone = ?",
        (ident, ident, ident)).fetchall())
    if ident and len(ident) <= 64 and "%" not in ident and "_" not in ident:
        rows += conn.execute(
            "SELECT * FROM users WHERE (',' || device_install_id || ',') LIKE ?",
            ("%,%" + ident + ",%",)).fetchall()
    rows = [dict(r) for r in rows]
    seen, out = set(), []
    for r in rows:
        if r["id"] not in seen:
            seen.add(r["id"])
            out.append(r)
    conn.close()
    return out

def find_user(identifier):
    users = find_users(identifier)
    return users[0] if users else None

class APIHandler(BaseHTTPRequestHandler):
    def _send(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return {}
        if length <= 0 or length > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def _authorized_user(self, uuid, code):
        if not uuid or not code:
            return None, ({"success": False, "message": "Missing uuid/code"}, 400)
        # Un identifiant peut correspondre à plusieurs comptes (un appareil
        # réactivé sur un autre compte, numéro partagé…) : on retient la
        # ligne dont le code correspond, pas "la première trouvée", tout en
        # préservant les statuts d'erreur distincts (404 / 403 / code).
        rows = find_users(uuid)
        if not rows:
            return None, ({"success": False, "message": "User not found or inactive"}, 404)
        user = None
        has_active = False
        for cand in rows:
            if not cand["active"]:
                continue
            has_active = True
            if cand["activation_code"] == code:
                user = cand
                break
        if user is None:
            if not has_active:
                return None, ({"success": False, "message": "User not found or inactive"}, 404)
            return None, ({"success": False, "message": "Invalid activation code"}, 403)
        # Verrou d'appareil (mono) : l'identifiant présenté DOIT être un
        # UUID de la liste des appareils autorisés. Un accès par téléphone —
        # même avec le bon code d'activation — est refusé, exactement comme à
        # l'activation.
        if not user["multi_device"]:
            bound_list = [d.strip().lower()
                          for d in (user["device_install_id"] or "").split(",") if d.strip()]
            if not bound_list:
                return None, ({"success": False,
                               "message": "Compte mono-appareil sans appareil lié : "
                                          "activez-le d'abord depuis votre téléphone"}, 403)
            if uuid.strip().lower() not in bound_list:
                return None, ({"success": False,
                               "message": "Compte verrouillé sur un autre appareil"}, 403)
        exp = user["expires_at"]
        if exp and datetime.fromisoformat(exp) < datetime.now():
            return None, ({"success": False, "message": "Subscription expired"}, 403)
        return user, None

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Activation-Code")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/api/v1/devices/check":
            device_id = params.get("device_id", [None])[0]
            if not device_id:
                return self._send({"activated": False, "message": "Missing device_id"}, 400)
            user = find_user(device_id)
            if user and user["active"]:
                exp = user["expires_at"]
                if exp and datetime.fromisoformat(exp) < datetime.now():
                    return self._send({"activated": False, "message": "Subscription expired"}, 403)
                # Objet account complet (quota) pour l'onglet PROFILS de
                # Borum VPN : quota_mb<=0 => illimite (semantique quota.py).
                qmb = user["quota_mb"] if "quota_mb" in user.keys() else 0
                used = user["bytes_used"] if "bytes_used" in user.keys() else 0
                limit = max(0, qmb or 0) * 1048576
                account = {
                    "active": 1, "name": user["name"], "phone": user["phone"],
                    "expires_at": user["expires_at"],
                    "unlimited": (qmb or 0) <= 0,
                    "data_limit_bytes": limit,
                    "data_remaining_bytes": max(0, limit - (used or 0)),
                    "data_used_bytes": used or 0,
                }
                return self._send({"activated": True, "phone": user["phone"],
                                   "name": user["name"], "expires_at": user["expires_at"],
                                   "account": account,
                                   "message": "Device is active"})
            return self._send({"activated": False, "message": "Device not found or inactive"}, 404)

        if path == "/api/v1/user/configs":
            user, err = self._authorized_user(params.get("uuid", [""])[0],
                                              params.get("code", [""])[0])
            if err:
                return self._send(*err)
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM vpn_configs WHERE user_id = ? ORDER BY tier DESC, mode ASC, id ASC",
                (user["id"],)).fetchall()
            conn.close()
            configs, seen = [], set()
            # Round-robin par famille : plusieurs configs sshslowdns (resp.
            # v2raydns) DOIVENT être servies avec des labels distincts,
            # l'app les combine ensuite en round-robin à 2 profils.
            mode_total = {}
            for c in rows:
                m = c["mode"] or "xray"
                mode_total[m] = mode_total.get(m, 0) + 1
            mode_rank = {}
            for cfg in rows:
                mode = cfg["mode"] or "xray"
                isp = cfg["isp"] or ""
                tier = cfg["tier"] or "150"
                if mode == "zivpn":
                    label = "Camtel UDP"
                elif mode == "utunnel":
                    label = "Utunnel UDP"
                elif mode == "v2raydns":
                    label = "V2Ray + SlowDNS"
                elif mode == "sshslowdns":
                    label = "SSH + SlowDNS"
                elif mode == "wgslowdns":
                    label = "WireGuard + SlowDNS"
                elif mode == "xray" and isp == "orange":
                    label = "Orange Illimité"
                elif mode == "xray" and isp == "mtn" and tier == "150":
                    label = "MTN 150Mo"
                elif mode == "xray" and isp == "mtn" and tier == "100":
                    label = "MTN 100Mo"
                elif mode == "xray" and isp == "":
                    label = f"XRAY {tier}Mo"
                else:
                    continue
                if mode in ("sshslowdns", "v2raydns") and mode_total.get(mode, 0) > 1:
                    mode_rank[mode] = mode_rank.get(mode, 0) + 1
                    label = f"{label} {mode_rank[mode]}"
                if label in seen:
                    continue
                seen.add(label)
                entry = {
                    "label": label, "address": cfg["server_address"],
                    "port": cfg["server_port"], "protocol": cfg["protocol"],
                    "transport": cfg["transport"], "tls": bool(cfg["tls"]),
                    "sni": cfg["sni"], "host": cfg["host"] or cfg["server_address"],
                    "flow": cfg["flow"] or "", "tier": tier, "mode": mode, "isp": isp,
                    "xray_uuid": cfg["xray_uuid"] or "",
                    "path": cfg["path"] or "",
                    "config_id": cfg["id"],
                }
                if mode == "zivpn":
                    entry["zivpn_password"] = cfg["zivpn_password"] or ""
                    entry["port_range"] = cfg["port_range"] or \
                        "34000-37999,38000-41999,42000-45999,46000-49999"
                if mode == "wgslowdns":
                    # Les clés WireGuard : servies dans le champ wg_keys
                    # (JSON string) — l'app les parse dans advanced.wg_*.
                    try:
                        wgk = cfg["wg_keys"] or ""
                        if wgk:
                            wg_obj = json.loads(wgk)
                            entry["wg_secret_key"] = wg_obj.get("wg_secret_key", "")
                            entry["wg_peer_public_key"] = wg_obj.get("wg_peer_public_key", "")
                            entry["wg_pre_shared_key"] = wg_obj.get("wg_pre_shared_key", "")
                            entry["wg_address"] = wg_obj.get("wg_address", "10.66.66.2/32")
                            entry["wg_peer_endpoint"] = wg_obj.get("wg_peer_endpoint", "")
                            entry["wg_allowed_ips"] = wg_obj.get("wg_allowed_ips", "0.0.0.0/0,::/0")
                            entry["wg_mtu"] = wg_obj.get("wg_mtu", 1420)
                            entry["wg_keep_alive"] = wg_obj.get("wg_keep_alive", 25)
                            entry["wg_no_kernel_tun"] = wg_obj.get("wg_no_kernel_tun", True)
                            entry["wg_remote_dns"] = wg_obj.get("wg_remote_dns", "1.1.1.1,8.8.8.8")
                    except Exception:
                        pass
                if mode == "utunnel":
                    # Clé client PRÉ-CALCULÉE (64 hex) : le serveur utunnel
                    # dérive SHA256(uuid:secret) — la même formule est servie
                    # ici, l'app n'a rien à calculer. server_port = port RÉEL
                    # d'écoute (:5669), la plage est DNAT-ée côté serveur.
                    entry["utunnel_secret"] = cfg["utunnel_secret"] or ""
                    entry["utunnel_hop"] = cfg["utunnel_hop"] or 0
                    # Plage DNAT servie aussi : le journal de l'app
                    # (kighmu.txt) l'affiche — "plage absente" dans le log
                    # = cause n°1 du "dial: aucune réponse du serveur".
                    entry["port_range"] = cfg["port_range"] or "50000-59999"
                if mode in ("v2raydns", "sshslowdns"):
                    entry["nameserver"] = cfg["nameserver"] or ""
                    entry["slowdns_pubkey"] = cfg["slowdns_pubkey"] or ""
                    entry["ssh_user"] = cfg["ssh_user"] or ""
                    entry["ssh_pass"] = cfg["ssh_pass"] or ""
                configs.append(entry)
            return self._send({"success": True, "configs": configs})

        if path == "/api/v1/status":
            conn = get_db()
            count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE active=1").fetchone()["c"]
            conn.close()
            return self._send({"status": "ok", "active_users": count})

        return self._send({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/v1/devices/register":
            body = self._read_body()
            uuid = str(body.get("device_install_id") or body.get("uuid", "")).strip()[:64]
            phone = str(body.get("phone_number", ""))[:20].strip()
            code = str(body.get("activation_code", ""))[:10]
            if not uuid or not phone or not code:
                return self._send({"success": False, "message": "Missing required fields"}, 400)
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)).fetchone()
            if not user:
                user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
            if not user:
                conn.close()
                return self._send({"success": False,
                                   "message": "Device not registered. Contact admin."}, 404)
            if user["activation_code"] != code:
                conn.close()
                return self._send({"success": False, "message": "Invalid activation code"}, 403)
            if not user["active"]:
                conn.close()
                return self._send({"success": False, "message": "Device is disabled"}, 403)
            exp = user["expires_at"]
            if exp and datetime.fromisoformat(exp) < datetime.now():
                conn.close()
                return self._send({"success": False, "message": "Subscription expired"}, 403)
            # Verrou d'appareil — strict, même si numéro + code sont corrects.
            # multi_device = 1 : tout appareil accepté, et AJOUTÉ à la liste
            #   des appareils connus du compte (en écraser l'existant rendrait
            #   invisible à find_user tout appareil activé précédemment :
            #   "Invalid activation code" au fetch pour les autres appareils
            #   du même compte).
            # multi_device = 0 : seul l'UUID lié au compte peut activer ;
            #   - aucun appareil lié : PREMIÈRE activation = verrouillage sur
            #     cet appareil (elle "gomme" le défaut "aucune restriction");
            #   - appareil lié différent de celui présenté : refus ferme.
            new_iid = uuid
            if not user["multi_device"]:
                bound_list = [d.strip().lower()
                              for d in (user["device_install_id"] or "").split(",") if d.strip()]
                if bound_list and uuid.lower() not in bound_list:
                    conn.close()
                    return self._send({"success": False,
                                       "message": "Ce compte est verrouillé sur un autre appareil "
                                                  "(UUID différent). Demandez à l'administrateur de "
                                                  "réinitialiser l'appareil lié ou de passer ce "
                                                  "compte en multi-appareils."},
                                      403)
            else:
                known = [d.strip() for d in (user["device_install_id"] or "").split(",") if d.strip()]
                if uuid.lower() not in [d.lower() for d in known]:
                    known.append(uuid)
                new_iid = ",".join(known)
                if len(new_iid) > 2000:
                    conn.close()
                    return self._send({"success": False,
                                       "message": "Trop d'appareils liés à ce compte"}, 403)
            conn.execute("UPDATE users SET device_install_id=?, app_version=? WHERE id=?",
                         (new_iid, str(body.get("app_version", ""))[:20], user["id"]))
            conn.commit()
            conn.close()
            return self._send({"success": True, "message": "Device activated successfully",
                               "phone": phone, "expires_at": exp,
                               "device_mode": "multi" if user["multi_device"] else "mono"})

        return self._send({"error": "Not found"}, 404)

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s %s\n" %
                         (self.log_date_time_string(), self.client_address[0], fmt % args))

if __name__ == "__main__":
    import ssl, threading

    init_db()
    port = int(os.environ.get("STIVAROS_PORT", 8080))
    tls_port = int(os.environ.get("STIVAROS_TLS_PORT", 9443))
    cert = os.environ.get("STIVAROS_TLS_CERT", "/opt/stivaros/api/api.crt")
    key = os.environ.get("STIVAROS_TLS_KEY", "/opt/stivaros/api/api.key")

    httpd = ThreadingHTTPServer(("0.0.0.0", port), APIHandler)
    print(f"[stivaros-api] HTTP on 0.0.0.0:{port}")

    if os.path.exists(cert) and os.path.exists(key):
        tlsd = ThreadingHTTPServer(("127.0.0.1", tls_port), APIHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        tlsd.socket = ctx.wrap_socket(tlsd.socket, server_side=True)
        threading.Thread(target=tlsd.serve_forever, daemon=True).start()
        print(f"[stivaros-api] HTTPS on 127.0.0.1:{tls_port} (HAProxy SNI backend)")

    httpd.serve_forever()
