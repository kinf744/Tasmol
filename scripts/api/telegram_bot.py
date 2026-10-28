#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# STIVAROS VPN — Bot Telegram professionnel
# Gestion à distance : comptes, configs, quotas, tunnels, état du panel
# ════════════════════════════════════════════════════════════════════════════
import json, os, sqlite3, sys, subprocess, html
from datetime import datetime, timedelta
from pathlib import Path

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
except ImportError:
    print("python-telegram-bot non installe. Installez-le : pip install python-telegram-bot")
    sys.exit(1)

BASE      = Path("/opt/stivaros")
DB_PATH   = BASE / "stivaros.db"
CONFIG    = BASE / "config.json"
STATE     = BASE / "tg_bot_state.json"
LOG_FILE  = Path("/var/log/stivaros-tg-bot.log")

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass

def get_state():
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {}

def save_state(s):
    STATE.write_text(json.dumps(s, indent=2))

def is_authorized(update: Update) -> bool:
    s = get_state()
    chat_id = str(update.effective_chat.id)
    return chat_id in s.get("authorized_chat_ids", [])

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

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text(
            "🔒 Accès restreint. Configurez le bot avec :\n"
            "/setup <TOKEN_BOT> <VOTRE_CHAT_ID>\n\n"
            "Obtenez votre chat_id avec @userinfobot"
        )
        return
    await update.message.reply_text(
        "🤖 <b>Stivaros VPN Bot</b>\n"
        "Gérez votre panel VPN depuis Telegram.\n\n"
        "Commandes disponibles :\n"
        "• /setup &lt;token&gt; &lt;chat_id&gt; — Configurer l'accès\n"
        "• /create &lt;nom&gt; &lt;tel&gt; &lt;jours&gt; — Créer un compte (jours)\n"
        "• /create_test &lt;nom&gt; &lt;tel&gt; &lt;heures&gt; — Compte test (heures)\n"
        "• /list — Lister les comptes\n"
        "• /delete &lt;id&gt; — Supprimer un compte\n"
        "• /quota &lt;id&gt; &lt;Go&gt; — Modifier le quota data\n"
        "• /configs &lt;id&gt; — Voir les configs d'un compte\n"
        "• /status — État du panel et des tunnels\n"
        "• /help — Cette aide",
        parse_mode="HTML")

async def setup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /setup &lt;TOKEN&gt; &lt;CHAT_ID&gt;")
        return
    token, chat_id = context.args[0], context.args[1]
    s = get_state()
    s["bot_token"] = token
    s.setdefault("authorized_chat_ids", []).append(chat_id)
    s["configured_at"] = datetime.now().isoformat()
    save_state(s)
    await update.message.reply_text(
        f"✅ Bot configuré.\nToken: {token[:8]}...\nChat ID autorisé: {chat_id}")

async def cmd_create(update: Update, context: ContextTypes.DEFAULT_TYPE, test=False):
    if not is_authorized(update):
        await update.message.reply_text("🔒 Non autorisé. Faites d'abord /setup.")
        return
    if len(context.args) < 3:
        label = "/create_test" if test else "/create"
        await update.message.reply_text(f"Usage: {label} &lt;nom&gt; &lt;tel&gt; &lt;jours|heures&gt;\nEx: {label} client1 674000000 30")
        return
    name, phone, val = context.args[0], context.args[1], context.args[2]
    try:
        conn = db()
        cur = conn.cursor()
        import uuid as uuid_mod
        uid = str(uuid_mod.uuid4())
        code = f"{__import__('random').randint(100000, 999999):06d}"
        now = datetime.utcnow()
        if test:
            expires = (now + timedelta(hours=int(val))).strftime("%Y-%m-%d %H:%M:%S")
        else:
            expires = (now + timedelta(days=int(val))).strftime("%Y-%m-%d")
        cur.execute(
            "INSERT INTO users (uuid, phone, name, activation_code, expires_at, active, quota_mb, multi_device, device_install_id, allowed_uuids) "
            "VALUES (?, ?, ?, ?, ?, 1, 0, 1, '', '')",
            (uid, phone, name, code, expires))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        await update.message.reply_text(
            f"✅ Compte {'TEST ' if test else ''}créé\n"
            f"Nom : {name}\n"
            f"Téléphone : {phone}\n"
            f"Code : {code}\n"
            f"Expire : {expires}\n"
            f"ID : {user_id}")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def create_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await cmd_create(update, context, test=False)

async def create_test_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await cmd_create(update, context, test=True)

async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("🔒 Non autorisé. /setup d'abord.")
        return
    try:
        conn = db()
        rows = conn.execute("SELECT id, name, phone, expires_at, active, quota_mb, bytes_used FROM users ORDER BY id DESC LIMIT 15").fetchall()
        conn.close()
        if not rows:
            await update.message.reply_text("Aucun compte.")
            return
        text = "📋 <b>Comptes récents</b>\n\n"
        for r in rows:
            st = "🟢 Actif" if r["active"] else "🔴 Bloqué"
            q = fmt_bytes(r["quota_mb"] * 1024 * 1024) if r["quota_mb"] > 0 else "Illimité"
            u = fmt_bytes(r["bytes_used"])
            text += (f"• #{r['id']} {html.escape(r['name'] or '-')}\n"
                     f"  📞 {r['phone']} | ⏰ {r['expires_at']}\n"
                     f"  📊 {u} / {q} | {st}\n\n")
        await update.message.reply_text(text, parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("🔒 Non autorisé.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /delete &lt;id_compte&gt;")
        return
    try:
        uid = int(context.args[0])
        conn = db()
        cur = conn.cursor()
        cur.execute("DELETE FROM vpn_configs WHERE user_id=?", (uid,))
        cur.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        await update.message.reply_text(f"✅ Compte #{uid} supprimé avec ses configs.")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def quota_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("🔒 Non autorisé.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /quota &lt;id&gt; &lt;Go&gt; (0 = illimité)")
        return
    try:
        uid, gb = int(context.args[0]), float(context.args[1])
        quota_mb = int(gb * 1024)
        conn = db()
        conn.execute("UPDATE users SET quota_mb=? WHERE id=?", (quota_mb, uid))
        conn.commit()
        conn.close()
        await update.message.reply_text(f"✅ Quota compte #{uid} mis à jour : {gb} Go")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def configs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("🔒 Non autorisé.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /configs &lt;id_compte&gt;")
        return
    try:
        uid = int(context.args[0])
        conn = db()
        rows = conn.execute("SELECT mode, isp, label, server_address, server_port, xray_uuid, path FROM vpn_configs WHERE user_id=? ORDER BY id", (uid,)).fetchall()
        conn.close()
        if not rows:
            await update.message.reply_text("Aucune config pour ce compte.")
            return
        text = f"🔧 Configs du compte #{uid}\n\n"
        for r in rows:
            text += (f"• {html.escape(r['label'] or r['mode'])}\n"
                     f"  Mode: {r['mode']} | ISP: {r['isp'] or '-'}\n"
                     f"  Serveur: {r['server_address']}:{r['server_port']}\n"
                     f"  UUID: {r['xray_uuid'] or '-'}\n\n")
        await update.message.reply_text(text, parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("🔒 Non autorisé.")
        return
    try:
        conn = db()
        active = conn.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM users WHERE active=0").fetchone()[0]
        conn.close()
        await update.message.reply_text(
            f"📊 <b>État du panel Stivaros</b>\n\n"
            f"Comptes totaux : {total}\n"
            f"Actifs : {active}\n"
            f"Bloqués/Expirés : {blocked}\n"
            f"API : port 9090\n"
            f"Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)

def build_app():
    token = get_state().get("bot_token", "")
    if not token:
        return None
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("setup", setup))
    app.add_handler(CommandHandler("create", create_cmd))
    app.add_handler(CommandHandler("create_test", create_test_cmd))
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("delete", delete_cmd))
    app.add_handler(CommandHandler("quota", quota_cmd))
    app.add_handler(CommandHandler("configs", configs_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    return app

def main():
    app = build_app()
    if not app:
        print("Aucun token configuré. Faites /setup TOKEN CHAT_ID")
        return
    log("Bot Telegram démarré")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
