#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# STIVAROS VPN — Bot Telegram (gestion complète style stivaros.sh)
# ════════════════════════════════════════════════════════════════════════════
import json, os, sqlite3, sys, subprocess, html, uuid, random, re
from datetime import datetime, timedelta
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

BASE      = Path("/opt/stivaros")
DB_PATH   = BASE / "stivaros.db"
CONFIG    = BASE / "tg_bot_config.json"
LOG_FILE  = Path("/var/log/stivaros-tg-bot.log")
SLOWDNS_DIR = Path("/etc/slowdns")
ZIVPN_HOME = Path("/etc/stivaros-zivpn")
ZIVPN_USER_FILE = ZIVPN_HOME / "users.list"
ZIVPN_RANGES = "34000-37999,38000-41999,42000-45999,46000-49999"
ZIVPN_PORT = 5668
V2RAY_PORT = 5402
ORANGE_FAST_ADDR = "192.179.18.100"
ORANGE_FAST_SNI = "crashlyticsreports-pa.googleapis.com"
ORANGE_FAST_HOST_FILE = BASE / "orange_fast_host.txt"
ORANGE_FAST_PATH = "/@kighmu"
ORANGE_FAST_UUID = "aaaa0000-1111-4222-8333-444455556666"
XRAY_PATH = "/vless-xhttp"
ORANGE_ADDR = "reprise.orange-business.com"
ORANGE_HOST_FILE = BASE / "orange_host.txt"
TZ_OFFSET_FILE = BASE / "tz_offset"

# ── MTN Illimité (VLESS WS TLS) ─────────────────────────────────────────────
MTN_UNLIMITED_ADDR = "findschoolnews.blogspot.com"
MTN_UNLIMITED_SNI = "findschoolnews.blogspot.com"
MTN_UNLIMITED_HOST_FILE = BASE / "mtn_unlimited_host.txt"
MTN_UNLIMITED_PATH = "/@kighmu"
MTN_UNLIMITED_UUID = "aaaa0000-1111-4222-8333-444455556666"

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def get_config():
    try:
        return json.loads(CONFIG.read_text())
    except Exception:
        return {}

def is_authorized(user_id: int) -> bool:
    cfg = get_config()
    return str(user_id) == str(cfg.get("admin_id", ""))

def db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def fmt_bytes(b):
    b = float(b or 0)
    for u in ("o", "Ko", "Mo", "Go", "To"):
        if b < 1024 or u == "To":
            return f"{int(b)} {u}" if u == "o" else f"{b:.1f} {u}"
        b /= 1024

def get_tz_offset():
    try:
        if TZ_OFFSET_FILE.exists():
            s = TZ_OFFSET_FILE.read_text().strip()
            if re.match(r'^-?[0-9]+$', s):
                return int(s)
    except:
        pass
    try:
        out = subprocess.check_output(["date", "+%z"], text=True).strip()
        sign = 1 if out[0] == '+' else -1
        hh = int(out[1:3]); mm = int(out[3:5])
        return sign * (hh + mm/60)
    except:
        return 0

def apply_tz_offset_date(days=None, hours=None):
    try:
        off = get_tz_offset()
        if days is not None:
            dt = datetime.utcnow() + timedelta(days=int(days))
            if off != 0:
                dt = dt + timedelta(hours=off)
            return dt.strftime("%Y-%m-%d")
        if hours is not None:
            dt = datetime.utcnow() + timedelta(hours=int(hours))
            if off != 0:
                dt = dt + timedelta(hours=off)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass
    if days is not None:
        return (datetime.utcnow() + timedelta(days=int(days))).strftime("%Y-%m-%d")
    if hours is not None:
        return (datetime.utcnow() + timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")
    return datetime.utcnow().strftime("%Y-%m-%d")

def orange_host_get():
    try:
        if ORANGE_HOST_FILE.exists():
            return ORANGE_HOST_FILE.read_text().strip()
    except:
        pass
    return ""

def orange_fast_host_get():
    try:
        if ORANGE_FAST_HOST_FILE.exists():
            return ORANGE_FAST_HOST_FILE.read_text().strip()
    except:
        pass
    return ""

def mtn_unlimited_host_get():
    try:
        if MTN_UNLIMITED_HOST_FILE.exists():
            return MTN_UNLIMITED_HOST_FILE.read_text().strip()
    except:
        pass
    return ""

def get_domain():
    try:
        p = Path("/etc/xray/domain")
        if p.exists():
            return p.read_text().strip()
    except:
        pass
    return ""

def gen_code():
    return f"{random.randint(100000,999999):06d}"

def gen_pass(n=12):
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(n))

def sqlq(s):
    if s is None: return ''
    return str(s).replace("'", "''")

MAIN_KB = InlineKeyboardMarkup([
    [InlineKeyboardButton("📋 Comptes", callback_data="menu_comptes"),
     InlineKeyboardButton("🔧 Services", callback_data="menu_services")],
    [InlineKeyboardButton("📊 État VPS", callback_data="menu_etat"),
     InlineKeyboardButton("⚙️ Gestion", callback_data="menu_gestion")],
])
BACK_KB = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Retour", callback_data="menu_principal")]])
GESTION_KB = InlineKeyboardMarkup([
    [InlineKeyboardButton("❓ Aide", callback_data="menu_aide")],
    [InlineKeyboardButton("/create — Créer un compte", callback_data="cmd_create")],
    [InlineKeyboardButton("/list — Lister les comptes", callback_data="cmd_list")],
    [InlineKeyboardButton("/delete — Supprimer un compte", callback_data="cmd_delete")],
    [InlineKeyboardButton("/quota — Modifier le quota data", callback_data="cmd_quota")],
    [InlineKeyboardButton("/status — État du panel", callback_data="cmd_status")],
    [InlineKeyboardButton("/services — État des services", callback_data="cmd_services")],
    [InlineKeyboardButton("⬅️ Retour", callback_data="menu_principal")],
])

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return
    context.user_data.clear()
    await update.message.reply_text(
        "🤖 <b>Stivaros VPN Bot</b>\nGérez votre panel VPN depuis Telegram.\n\nSélectionnez une option :",
        reply_markup=MAIN_KB, parse_mode="HTML")

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_authorized(q.from_user.id):
        await q.edit_message_text("⛔ Non autorisé.")
        return
    d = q.data

    if d == "menu_principal":
        await q.edit_message_text(
            "🤖 <b>Stivaros VPN Bot</b>\nSélectionnez une option :",
            reply_markup=MAIN_KB, parse_mode="HTML")
    elif d == "menu_gestion":
        await q.edit_message_text(
            "⚙️ <b>Gestion</b>\n\nSélectionnez une commande :",
            reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "menu_aide":
        await q.edit_message_text(
            "❓ <b>Aide</b>\n\n/start — Menu principal\n/create — Créer un compte\n/list — Lister les comptes\n/delete &lt;id&gt; — Supprimer un compte\n/quota &lt;id&gt; &lt;Go&gt; — Modifier le quota\n/status — État du panel\n/services — État des services\n/help — Cette aide",
            reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_create":
        context.user_data.clear()
        context.user_data["create_step"] = "type"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("1. Compte normal (jours)", callback_data="create_type_jours")],
            [InlineKeyboardButton("2. Compte TEST (heures)", callback_data="create_type_heures")],
            [InlineKeyboardButton("⬅️ Retour", callback_data="menu_gestion")],
        ])
        await q.edit_message_text(
            "📝 <b>Créer un compte — Choisissez le type :</b>\n\n1️⃣ Compte normal : durée en JOURS\n2️⃣ Compte TEST : durée en HEURES",
            reply_markup=kb, parse_mode="HTML")
    elif d == "create_type_jours":
        context.user_data["create_type"] = "jours"
        context.user_data["create_step"] = "nom"
        await q.edit_message_text("📝 <b>Compte normal (jours)</b>\n\nÉtape 1/8 — Saisissez le <b>nom</b> du compte :", reply_markup=BACK_KB, parse_mode="HTML")
    elif d == "create_type_heures":
        context.user_data["create_type"] = "heures"
        context.user_data["create_step"] = "nom"
        await q.edit_message_text("📝 <b>Compte TEST (heures)</b>\n\nÉtape 1/8 — Saisissez le <b>nom</b> du compte :", reply_markup=BACK_KB, parse_mode="HTML")
    elif d == "cmd_list":
        await liste_comptes(q, context)
    elif d == "cmd_delete":
        await q.edit_message_text("🗑 <b>Supprimer un compte</b>\n\nUtilisation : <code>/delete &lt;id_compte&gt;</code>", reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_quota":
        await q.edit_message_text("💾 <b>Modifier le quota</b>\n\nUtilisation : <code>/quota &lt;id&gt; &lt;Go&gt;</code> (0 = illimité)", reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_status":
        await q.edit_message_text("📊 <b>État du panel</b>\n\nUtilisation : <code>/status</code>", reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_services":
        await q.edit_message_text("🔧 <b>État des services</b>\n\nUtilisation : <code>/services</code>", reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "menu_comptes":
        await liste_comptes(q, context)
    elif d == "menu_services":
        await liste_services(q, context)
    elif d == "menu_etat":
        await etat_vps(q, context)

async def dev_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_authorized(q.from_user.id):
        await q.edit_message_text("⛔ Non autorisé.")
        return
    d = q.data
    if d == "dev_1":
        context.user_data["multi_device"] = 0
        context.user_data["allowed_uuids"] = ""
        context.user_data["dev_uuid"] = ""
        context.user_data["create_step"] = "devuuid"
        await q.edit_message_text("📝 Mono-appareil\n\nÉtape 4/8 — Saisissez l'<b>UUID appareil</b> ou envoyez simplement <b>0</b> / <b>vide</b> pour verrouillage à la première activation :", parse_mode="HTML")
    elif d == "dev_2":
        context.user_data["multi_device"] = 1
        context.user_data["allowed_uuids"] = ""
        context.user_data["dev_uuid"] = ""
        context.user_data["create_step"] = "quota"
        await q.edit_message_text("📝 Multi-appareils\n\nÉtape 4/8 — Saisissez le <b>quota data en Go</b> (0 = illimité) :", parse_mode="HTML")
    elif d == "dev_3":
        context.user_data["multi_device"] = 0
        context.user_data["create_step"] = "alloweduuids"
        await q.edit_message_text("📝 UUIDs définis\n\nÉtape 4/8 — Saisissez les <b>UUIDs séparés par des virgules</b> :", parse_mode="HTML")

async def cfg_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_authorized(q.from_user.id):
        await q.edit_message_text("⛔ Non autorisé.")
        return
    d = q.data
    context.user_data["cfg_sel"] = d.replace("cfg_", "")
    context.user_data["create_step"] = "duree"
    ctype = context.user_data.get("create_type", "jours")
    unite = "JOURS" if ctype == "jours" else "HEURES"
    ex = "5, 10, 30" if ctype == "jours" else "24, 48, 72"
    await q.edit_message_text(f"✅ Sélection enregistrée.\n\nÉtape 7/8 — Saisissez la durée en <b>{unite}</b> (ex: {ex}) :", parse_mode="HTML")

async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return
    text = update.message.text.strip()
    step = context.user_data.get("create_step", "")
    if not step:
        await update.message.reply_text("Utilisez /start pour accéder au menu.")
        return

    if step == "nom":
        if not text or not all(c.isalnum() or c in "._-" for c in text):
            await update.message.reply_text("❌ Nom invalide. Lettres, chiffres, . _ - uniquement.\nRéessayez :")
            return
        context.user_data["create_nom"] = text
        context.user_data["create_step"] = "tel"
        await update.message.reply_text(f"✅ Nom : {html.escape(text)}\n\nÉtape 2/8 — Saisissez le <b>téléphone</b> :", parse_mode="HTML")
        return
    if step == "tel":
        if not re.match(r'^[0-9]{8,15}$', text):
            await update.message.reply_text("❌ Téléphone invalide (8-15 chiffres).\nRéessayez :")
            return
        context.user_data["create_tel"] = text
        context.user_data["create_step"] = "devmode"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("1. Mono-appareil", callback_data="dev_1")],
            [InlineKeyboardButton("2. Multi-appareils", callback_data="dev_2")],
            [InlineKeyboardButton("3. UUIDs définis", callback_data="dev_3")],
        ])
        await update.message.reply_text("✅ Téléphone enregistré.\n\nÉtape 3/8 — <b>Appareils autorisés</b> :", reply_markup=kb, parse_mode="HTML")
        return
    if step == "devuuid":
        t = text.strip()
        if t.lower() in ("", "0", "-", "none", "null"):
            context.user_data["dev_uuid"] = ""
            context.user_data["create_step"] = "quota"
            await update.message.reply_text("✅ OK (verrouillage à la première activation)\n\nÉtape 5/8 — Saisissez le <b>quota data en Go</b> (0 = illimité) :", parse_mode="HTML")
            return
        if not re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', t):
            await update.message.reply_text("❌ UUID invalide. Format 8-4-4-4-12 hex ou envoyez <b>0</b> pour laisser vide.", parse_mode="HTML")
            return
        context.user_data["dev_uuid"] = t.lower()
        context.user_data["create_step"] = "quota"
        await update.message.reply_text("✅ UUID enregistré\n\nÉtape 5/8 — Saisissez le <b>quota data en Go</b> (0 = illimité) :", parse_mode="HTML")
        return
    if step == "alloweduuids":
        context.user_data["allowed_uuids"] = text.replace(" ", "").lower()
        context.user_data["create_step"] = "quota"
        await update.message.reply_text("✅ OK\n\nÉtape 5/8 — Saisissez le <b>quota data en Go</b> (0 = illimité) :", parse_mode="HTML")
        return
    if step == "quota":
        try:
            qv = float(str(text).replace(',', '.'))
            if qv < 0: raise ValueError
            quota_mb = int(round(qv * 1024))
        except Exception:
            await update.message.reply_text("❌ Quota invalide. Ex: 0, 0.15, 10\nRéessayez :")
            return
        context.user_data["quota_mb"] = quota_mb
        context.user_data["create_step"] = "configs"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("1. XRAY (MTN 150/100 + Orange illimité)", callback_data="cfg_1")],
            [InlineKeyboardButton("2. ZIVPN (Camtel UDP)", callback_data="cfg_2")],
            [InlineKeyboardButton("3. SSH + SlowDNS", callback_data="cfg_3")],
            [InlineKeyboardButton("4. V2Ray + SlowDNS", callback_data="cfg_4")],
            [InlineKeyboardButton("5. Orange Fast (VLESS WS TLS)", callback_data="cfg_5")],
            [InlineKeyboardButton("6. MTN Illimité (VLESS WS TLS)", callback_data="cfg_6")],
            [InlineKeyboardButton("0. Toutes", callback_data="cfg_0")],
        ])
        await update.message.reply_text("✅ Quota enregistré.\n\nÉtape 6/8 — <b>Configs à inclure</b> (ex: 1,3,4 ou 0 pour tout) :", reply_markup=kb, parse_mode="HTML")
        return
    if step == "duree":
        if not text.isdigit() or int(text) < 1:
            ctype = context.user_data.get("create_type", "jours")
            unite = "jours" if ctype == "jours" else "heures"
            await update.message.reply_text(f"❌ Durée invalide. Entier >=1 en {unite}.\nRéessayez :")
            return
        context.user_data["create_duree"] = int(text)
        context.user_data["create_step"] = "confirmer"
        ctype = context.user_data.get("create_type", "jours")
        unite = "JOURS" if ctype == "jours" else "HEURES"
        nom = context.user_data.get("create_nom", "")
        tel = context.user_data.get("create_tel", "")
        multi = context.user_data.get("multi_device", 0)
        quota_mb = context.user_data.get("quota_mb", 0)
        cfg_sel = context.user_data.get("cfg_sel", "0")
        qstr = "Illimité" if quota_mb == 0 else f"{quota_mb/1024.0:.2f} Go".rstrip('0').rstrip('.') + " Go"
        await update.message.reply_text(
            f"✅ Durée enregistrée : {text} {unite}\n\nÉtape 8/8 — Récapitulatif :\n• Type : {'Compte normal' if ctype == 'jours' else 'Compte TEST'}\n• Nom : {html.escape(nom)}\n• Téléphone : {tel}\n• Appareils : {'Multi' if multi else 'Mono'}\n• Quota : {qstr}\n• Configs : {cfg_sel}\n• Durée : {text} {unite}\n\nEnvoyez <b>OUI</b> pour confirmer, <b>NON</b> pour annuler.",
            parse_mode="HTML")
        return
    if step == "confirmer":
        if text.upper() == "OUI":
            await finaliser_creation_full(update, context)
        elif text.upper() == "NON":
            context.user_data.clear()
            await update.message.reply_text("❌ Création annulée.", reply_markup=MAIN_KB)
        else:
            await update.message.reply_text("❌ Envoyez <b>OUI</b> ou <b>NON</b>.", parse_mode="HTML")
        return

async def finaliser_creation_full(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        nom = context.user_data.get("create_nom", "")
        tel = context.user_data.get("create_tel", "")
        duree = int(context.user_data.get("create_duree", 1))
        ctype = context.user_data.get("create_type", "jours")
        multi_device = int(context.user_data.get("multi_device", 0))
        dev_uuid = context.user_data.get("dev_uuid", "") or ""
        allowed_uuids = context.user_data.get("allowed_uuids", "") or ""
        quota_mb = int(context.user_data.get("quota_mb", 0))
        cfg_sel = context.user_data.get("cfg_sel", "0")
        conn = db()
        cur = conn.cursor()
        try:
            cur.execute("ALTER TABLE users ADD COLUMN allowed_uuids TEXT DEFAULT ''"); conn.commit()
        except: pass
        try:
            cur.execute("ALTER TABLE users ADD COLUMN multi_device INTEGER NOT NULL DEFAULT 0"); conn.commit()
        except: pass
        uid = str(uuid.uuid4())
        code = gen_code()
        if ctype == "jours":
            expires = apply_tz_offset_date(days=duree)
        else:
            expires = apply_tz_offset_date(hours=duree)
        cur.execute(
            "INSERT INTO users (uuid, phone, name, activation_code, expires_at, active, quota_mb, multi_device, device_install_id, allowed_uuids) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (uid, tel, nom, code, expires, quota_mb, multi_device, dev_uuid, allowed_uuids))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        def want(n):
            if cfg_sel == '0': return True
            parts = [p.strip() for p in cfg_sel.split(',')]
            return str(n) in parts
        want_xray = 1 if want(1) else 0
        want_zivpn = 1 if want(2) else 0
        want_sshdns = 1 if want(3) else 0
        want_v2dns = 1 if want(4) else 0
        want_orange_fast = 1 if want(5) else 0
        want_mtn_unlimited = 1 if want(6) else 0
        if not any([want_xray,want_zivpn,want_sshdns,want_v2dns,want_orange_fast,want_mtn_unlimited]):
            want_xray=want_zivpn=want_sshdns=want_v2dns=want_orange_fast=want_mtn_unlimited=1
        domain = get_domain()
        try:
            out = subprocess.check_output(["hostname", "-I"], text=True)
            server_addr = domain or out.split()[0]
        except:
            server_addr = domain or "127.0.0.1"
        xray_uuid = str(uuid.uuid4())
        zivpn_pass = gen_pass(12)
        ssh_pass = gen_pass(12)
        try:
            ns4 = (SLOWDNS_DIR / "ns4.conf").read_text().strip().splitlines()[0]
        except:
            try: ns4 = (SLOWDNS_DIR / "ns.conf").read_text().strip().splitlines()[0]
            except: ns4 = ""
        try:
            nv4 = (SLOWDNS_DIR / "nv4.conf").read_text().strip().splitlines()[0]
        except:
            try: nv4 = (SLOWDNS_DIR / "nv4/ns.conf").read_text().strip().splitlines()[0]
            except: nv4 = ""
        try:
            dnstt_pub = (SLOWDNS_DIR / "server.pub").read_text().strip().replace('\n','').replace('\r','')
        except:
            dnstt_pub = ""
        ssh_user = "u" + ''.join(re.findall(r'\d', tel)) or ("u" + str(random.randint(100000,999999)))
        sql_list = []
        # cfg_0 = Toutes : toutes les variantes. Sinon : une seule config par
        # option choisie (évite l'affichage de configs non demandées dans l'app).
        all_configs = (cfg_sel == '0')

        # 1) XRAY (MTN 150/100 + Orange illimité)
        if want_xray:
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path) SELECT id, '{sqlq(server_addr)}', 443, 'vless', 'ws', 1, 'mtnplay.com', '{sqlq(server_addr)}', 'mtn', '', '', '150', '{sqlq(xray_uuid)}', '/vless' FROM users WHERE uuid='{sqlq(uid)}';")
            if all_configs:
                sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path) SELECT id, '{sqlq(server_addr)}', 443, 'vless', 'ws', 1, 'yamo.mtn.cm', '{sqlq(server_addr)}', 'mtn', '', '', '100', '{sqlq(xray_uuid)}', '/vless' FROM users WHERE uuid='{sqlq(uid)}';")
                sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path) SELECT id, '{sqlq(ORANGE_ADDR)}', 443, 'vless', 'xhttp', 1, '{sqlq(ORANGE_ADDR)}', '{sqlq(orange_host_get())}', 'orange', 'xray', '0', '{sqlq(xray_uuid)}', '{sqlq(XRAY_PATH)}' FROM users WHERE uuid='{sqlq(uid)}';")

        # 5) Orange Fast (VLESS WS TLS)
        if want_orange_fast:
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path) SELECT id, '{sqlq(ORANGE_FAST_ADDR)}', 443, 'vless', 'ws', 1, '{sqlq(ORANGE_FAST_SNI)}', '{sqlq(orange_fast_host_get())}', 'orange_fast', 'orange_fast', '0', '{sqlq(ORANGE_FAST_UUID)}', '{sqlq(ORANGE_FAST_PATH)}' FROM users WHERE uuid='{sqlq(uid)}';")

        # 6) MTN Illimité (VLESS WS TLS)
        if want_mtn_unlimited:
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path) SELECT id, '{sqlq(MTN_UNLIMITED_ADDR)}', 443, 'vless', 'ws', 1, '{sqlq(MTN_UNLIMITED_SNI)}', '{sqlq(mtn_unlimited_host_get())}', 'mtn', 'mtn_unlimited', '0', '{sqlq(MTN_UNLIMITED_UUID)}', '{sqlq(MTN_UNLIMITED_PATH)}' FROM users WHERE uuid='{sqlq(uid)}';")

        # 2) ZIVPN (Camtel UDP)
        if want_zivpn:
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range) SELECT id, '{sqlq(server_addr)}', {ZIVPN_PORT}, 'zivpn', 'udp', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', 'camtel', 'zivpn', '150', '{sqlq(xray_uuid)}', '{sqlq(zivpn_pass)}', '{sqlq(ZIVPN_RANGES)}' FROM users WHERE uuid='{sqlq(uid)}';")
            if all_configs:
                sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range) SELECT id, '{sqlq(server_addr)}', {ZIVPN_PORT}, 'zivpn', 'udp', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', '', 'zivpn', '100', '{sqlq(xray_uuid)}', '{sqlq(zivpn_pass)}', '{sqlq(ZIVPN_RANGES)}' FROM users WHERE uuid='{sqlq(uid)}';")

        # 3) SSH + SlowDNS
        if want_sshdns:
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass) SELECT id, '{sqlq(server_addr)}', 22, 'ssh', 'dnstt', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', '', 'sshslowdns', '150', '{sqlq(xray_uuid)}', '{sqlq(ns4)}', '{sqlq(dnstt_pub)}', '{sqlq(ssh_user)}', '{sqlq(ssh_pass)}' FROM users WHERE uuid='{sqlq(uid)}';")
            if all_configs:
                sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass) SELECT id, '{sqlq(server_addr)}', 22, 'ssh', 'dnstt', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', '', 'sshslowdns', '150', '{sqlq(xray_uuid)}', '{sqlq(ns4)}', '{sqlq(dnstt_pub)}', '{sqlq(ssh_user)}', '{sqlq(ssh_pass)}' FROM users WHERE uuid='{sqlq(uid)}';")

        # 4) V2Ray + SlowDNS
        if want_v2dns:
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey) SELECT id, '{sqlq(server_addr)}', {V2RAY_PORT}, 'vless', 'dnstt', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', '', 'v2raydns', '150', '{sqlq(xray_uuid)}', '{sqlq(nv4)}', '{sqlq(dnstt_pub)}' FROM users WHERE uuid='{sqlq(uid)}';")
            if all_configs:
                sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey) SELECT id, '{sqlq(server_addr)}', {V2RAY_PORT}, 'vless', 'dnstt', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', '', 'v2raydns', '150', '{sqlq(xray_uuid)}', '{sqlq(nv4)}', '{sqlq(dnstt_pub)}' FROM users WHERE uuid='{sqlq(uid)}';")
            sql_list.append(f"INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey) SELECT id, '{sqlq(server_addr)}', {V2RAY_PORT}, 'vless', 'dnstt', 0, '{sqlq(server_addr)}', '{sqlq(server_addr)}', '', 'v2raydns', '150', '{sqlq(xray_uuid)}', '{sqlq(nv4)}', '{sqlq(dnstt_pub)}' FROM users WHERE uuid='{sqlq(uid)}';")
        conn = db(); cur = conn.cursor()
        try:
            for s in sql_list: cur.execute(s)
            conn.commit()
        finally: conn.close()
        try:
            if want_sshdns:
                subprocess.run(["useradd","-M","-N","-s","/usr/sbin/nologin",ssh_user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p=subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE); p.communicate(input=f"{ssh_user}:{ssh_pass}\n".encode())
                subprocess.run(["chage","-E",expires.split()[0],ssh_user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass
        try:
            if want_zivpn and ZIVPN_USER_FILE.parent.exists():
                ZIVPN_USER_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(ZIVPN_USER_FILE,"a") as f: f.write(f"{uid}|{zivpn_pass}|{expires}\n")
                subprocess.run(["systemctl","restart","stivaros-zivpn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass
        try:
            if want_xray: subprocess.run(["systemctl","reload-or-restart","xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass
        context.user_data.clear()
        msg = f"✅ <b>Compte créé</b>\n\n• Nom : {html.escape(nom)}\n• Téléphone : {tel}\n• Code : <b>{code}</b>\n• Type : {'Compte normal (jours)' if ctype=='jours' else 'Compte TEST (heures)'}\n• Durée : {duree}\n• Expire : {expires}\n• ID : {user_id}\n• Appareils : {'Multi' if multi_device else 'Mono'}"
        if want_xray: msg += f"\n• XRAY: {server_addr}:443 uuid={xray_uuid}"
        if want_orange_fast: msg += f"\n• Orange Fast: {ORANGE_FAST_ADDR}:443 uuid={ORANGE_FAST_UUID}"
        if want_mtn_unlimited: msg += f"\n• MTN Illimité: {MTN_UNLIMITED_ADDR}:443 uuid={MTN_UNLIMITED_UUID} host={mtn_unlimited_host_get() or '(par défaut)'}"
        if want_zivpn: msg += f"\n• ZIVPN: {server_addr}:{ZIVPN_PORT} pass={zivpn_pass}"
        if want_sshdns: msg += f"\n• SSH+SlowDNS: NS={ns4} user={ssh_user} pass={ssh_pass}"
        if want_v2dns: msg += f"\n• V2Ray+SlowDNS: NS={nv4} uuid={xray_uuid} port={V2RAY_PORT}"
        await update.message.reply_text(msg, parse_mode="HTML", reply_markup=MAIN_KB)
    except Exception as e:
        context.user_data.clear()
        await update.message.reply_text(f"❌ Erreur : {e}", parse_mode="HTML", reply_markup=MAIN_KB)

async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id): return await update.message.reply_text("⛔ Non autorisé.")
    try:
        conn = db(); rows = conn.execute("SELECT id,name,phone,expires_at,active,quota_mb,bytes_used FROM users ORDER BY id DESC LIMIT 15").fetchall(); conn.close()
        if not rows: return await update.message.reply_text("Aucun compte.")
        text = "📋 <b>Comptes récents</b>\n\n"
        for r in rows:
            st = "🟢 Actif" if r["active"] else "🔴 Bloqué"
            q = fmt_bytes(r["quota_mb"]*1024*1024) if r["quota_mb"] and r["quota_mb"]>0 else "Illimité"
            u = fmt_bytes(r["bytes_used"])
            text += f"• #{r['id']} {html.escape(r['name'] or '-')}\n  📞 {r['phone']} | ⏰ {r['expires_at']}\n  📊 {u} / {q} | {st}\n\n"
        await update.message.reply_text(text, parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id): return await update.message.reply_text("⛔ Non autorisé.")
    if not context.args:
        # Afficher la liste des comptes avec noms et IDs pour choisir quoi supprimer
        try:
            conn = db()
            rows = conn.execute("SELECT id, name, phone, expires_at, active FROM users ORDER BY id DESC LIMIT 25").fetchall()
            conn.close()
            if not rows:
                return await update.message.reply_text("Aucun compte à supprimer.")
            text = "🗑 <b>Supprimer un compte</b>\n\nSélectionnez l'ID du compte à supprimer :\n\n"
            for r in rows:
                st = "🟢 Actif" if r["active"] else "🔴 Bloqué"
                text += f"• #{r['id']} {html.escape(r['name'] or '-')} | {r['phone']} | {st}\n"
            text += "\nUtilisation : <code>/delete &lt;id&gt;</code>"
            await update.message.reply_text(text, parse_mode="HTML")
        except Exception as e:
            await update.message.reply_text(f"❌ Erreur : {e}")
        return
    try:
        uid=int(context.args[0]); conn=db(); cur=conn.cursor()
        row = conn.execute("SELECT name FROM users WHERE id=?", (uid,)).fetchone()
        cur.execute("DELETE FROM vpn_configs WHERE user_id=?", (uid,))
        cur.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit(); conn.close()
        nom = row["name"] if row else "?"
        await update.message.reply_text(f"✅ Compte #{uid} ({html.escape(nom)}) supprimé avec ses configs.")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def quota_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id): return await update.message.reply_text("⛔ Non autorisé.")
    if len(context.args)<2: return await update.message.reply_text("Usage: /quota &lt;id&gt; &lt;Go&gt; (0 = illimité)")
    try:
        uid,gb=int(context.args[0]),float(str(context.args[1]).replace(',','.')); quota_mb=int(gb*1024); conn=db(); conn.execute("UPDATE users SET quota_mb=? WHERE id=?", (quota_mb,uid)); conn.commit(); conn.close()
        await update.message.reply_text(f"✅ Quota compte #{uid} mis à jour : {gb} Go")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id): return await update.message.reply_text("⛔ Non autorisé.")
    try:
        conn=db(); active=conn.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]; total=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]; blocked=conn.execute("SELECT COUNT(*) FROM users WHERE active=0").fetchone()[0]; conn.close()
        await update.message.reply_text(f"📊 <b>État du panel Stivaros</b>\n\nComptes totaux : {total}\nActifs : {active}\nBloqués/Expirés : {blocked}\nHeure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def services_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id): return await update.message.reply_text("⛔ Non autorisé.")
    services = ["stivaros-api","xray","zivpn","ssh","v2ray","slowdns-ns4","slowdns-nv4","dnsdist","haproxy"]
    lines=["🔧 <b>État des services</b>\n"]; ok=0
    for s in services:
        try:
            r=subprocess.run(["systemctl","is-active",s], capture_output=True, text=True, timeout=5); active=r.stdout.strip()=="active"
        except: active=False
        lines.append(f"{'🟢' if active else '🔴'} {s}")
        if active: ok+=1
    lines.append(f"\n✅ {ok}/{len(services)} actifs")
    await update.message.reply_text("\n".join(lines), parse_mode="HTML")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id): return await update.message.reply_text("⛔ Non autorisé.")
    await update.message.reply_text("❓ <b>Aide Stivaros VPN Bot</b>\n\n/start — Menu principal\n/create — Créer un compte\n/list — Lister les comptes\n/delete &lt;id&gt; — Supprimer\n/quota &lt;id&gt; &lt;Go&gt; — Quota\n/status — État\n/services — Services", parse_mode="HTML")

async def liste_comptes(q,context):
    try:
        conn=db(); rows=conn.execute("SELECT id,name,phone,expires_at,active,quota_mb,bytes_used FROM users ORDER BY id DESC LIMIT 10").fetchall(); conn.close()
        if not rows: return await q.edit_message_text("📋 Aucun compte.", reply_markup=BACK_KB)
        text="📋 <b>Comptes</b>\n\n"
        for r in rows:
            st="🟢 Actif" if r["active"] else "🔴 Bloqué"; qv=fmt_bytes(r["quota_mb"]*1024*1024) if r["quota_mb"] and r["quota_mb"]>0 else "Illimité"; u=fmt_bytes(r["bytes_used"])
            text+=f"• #{r['id']} {html.escape(r['name'] or '-')}\n  📞 {r['phone']} | ⏰ {r['expires_at']}\n  📊 {u} / {qv} | {st}\n\n"
        await q.edit_message_text(text, reply_markup=BACK_KB, parse_mode="HTML")
    except Exception as e:
        await q.edit_message_text(f"❌ Erreur : {e}", reply_markup=BACK_KB)

async def liste_services(q,context):
    services = ["stivaros-api","xray","zivpn","ssh","v2ray","slowdns-ns4","slowdns-nv4","dnsdist","haproxy"]
    lines=["🔧 <b>État des services</b>\n"]; ok=0
    for s in services:
        try:
            r=subprocess.run(["systemctl","is-active",s], capture_output=True, text=True, timeout=5); active=r.stdout.strip()=="active"
        except: active=False
        lines.append(f"{'🟢' if active else '🔴'} {s}")
        if active: ok+=1
    lines.append(f"\n✅ {ok}/{len(services)} actifs")
    await q.edit_message_text("\n".join(lines), reply_markup=BACK_KB, parse_mode="HTML")

async def etat_vps(q,context):
    try:
        try: upt=subprocess.check_output(["uptime","-p"],text=True).strip()
        except: upt="N/A"
        conn=db(); total=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]; active=conn.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]; conn.close()
        await q.edit_message_text(f"🖥 <b>État VPS</b>\n\n• Uptime : {upt}\n• Comptes totaux : {total}\n• Comptes actifs : {active}\n• Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", reply_markup=BACK_KB, parse_mode="HTML")
    except Exception as e:
        await q.edit_message_text(f"❌ Erreur : {e}", reply_markup=BACK_KB)

def main():
    cfg=get_config(); token=cfg.get("token","")
    if not token:
        print("Aucun token configuré"); sys.exit(1)
    app=Application.builder().token(token).build()
    app.add_handler(CommandHandler("start",start))
    app.add_handler(CommandHandler("list",list_cmd))
    app.add_handler(CommandHandler("delete",delete_cmd))
    app.add_handler(CommandHandler("quota",quota_cmd))
    app.add_handler(CommandHandler("status",status_cmd))
    app.add_handler(CommandHandler("services",services_cmd))
    app.add_handler(CommandHandler("help",help_cmd))
    app.add_handler(CallbackQueryHandler(dev_callback, pattern="^dev_"))
    app.add_handler(CallbackQueryHandler(cfg_callback, pattern="^cfg_"))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    log("Bot Telegram démarré")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__=="__main__": main()
