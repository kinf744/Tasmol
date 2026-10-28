#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# STIVAROS VPN — Bot Telegram (gestion comptes, services, infos VPS)
# Version simplifiée — uniquement ce qui concerne stivaros.sh
# ════════════════════════════════════════════════════════════════════════════
import json, os, sqlite3, sys, subprocess, html
from datetime import datetime, timedelta
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

BASE      = Path("/opt/stivaros")
DB_PATH   = BASE / "stivaros.db"
CONFIG    = BASE / "tg_bot_config.json"
STATE     = BASE / "tg_bot_state.json"
LOG_FILE  = Path("/var/log/stivaros-tg-bot.log")

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

# ════════════════════════════════════════════════════════════════════════════
# MENUS INLINE
# ════════════════════════════════════════════════════════════════════════════

MAIN_KB = InlineKeyboardMarkup([
    [InlineKeyboardButton("📋 Comptes", callback_data="menu_comptes"),
     InlineKeyboardButton("🔧 Services", callback_data="menu_services")],
    [InlineKeyboardButton("📊 État VPS", callback_data="menu_etat"),
     InlineKeyboardButton("❓ Aide", callback_data="menu_aide")],
])

BACK_KB = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Retour", callback_data="menu_principal")]])

# ════════════════════════════════════════════════════════════════════════════
# HANDLERS
# ════════════════════════════════════════════════════════════════════════════

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return
    text = ("🤖 <b>Stivaros VPN Bot</b>\n"
            "Gérez votre panel VPN depuis Telegram.\n\n"
            "Sélectionnez une option :")
    await update.message.reply_text(text, reply_markup=MAIN_KB, parse_mode="HTML")

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
    elif d == "menu_aide":
        await q.edit_message_text(
            "❓ <b>Aide</b>\n\n"
            "/start — Menu principal\n"
            "/create &lt;nom&gt; &lt;tel&gt; &lt;jours&gt; — Créer un compte\n"
            "/list — Lister les comptes\n"
            "/delete &lt;id&gt; — Supprimer un compte\n"
            "/quota &lt;id&gt; &lt;Go&gt; — Modifier le quota data\n"
            "/status — État du panel et des tunnels\n"
            "/services — État des services\n"
            "/help — Cette aide",
            reply_markup=BACK_KB, parse_mode="HTML")
    elif d == "menu_comptes":
        await liste_comptes(q, context)
    elif d == "menu_services":
        await liste_services(q, context)
    elif d == "menu_etat":
        await etat_vps(q, context)

# ════════════════════════════════════════════════════════════════════════════
# COMMANDES TEXTE
# ════════════════════════════════════════════════════════════════════════════

async def create_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return
    if len(context.args) < 3:
        await update.message.reply_text("Usage: /create &lt;nom&gt; &lt;tel&gt; &lt;jours&gt;\nEx: /create client1 674000000 30", parse_mode="HTML")
        return
    name, phone, jours = context.args[0], context.args[1], context.args[2]
    if not jours.isdigit() or int(jours) < 1:
        await update.message.reply_text("❌ Nombre de jours invalide.")
        return
    try:
        conn = db()
        cur = conn.cursor()
        import uuid as uuid_mod, random
        uid = str(uuid_mod.uuid4())
        code = f"{random.randint(100000, 999999):06d}"
        now = datetime.utcnow()
        expires = (now + timedelta(days=int(jours))).strftime("%Y-%m-%d")
        cur.execute(
            "INSERT INTO users (uuid, phone, name, activation_code, expires_at, active, quota_mb, multi_device, device_install_id, allowed_uuids) "
            "VALUES (?, ?, ?, ?, ?, 1, 0, 1, '', '')",
            (uid, phone, name, code, expires))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        await update.message.reply_text(
            f"✅ <b>Compte créé</b>\n"
            f"Nom : {html.escape(name)}\n"
            f"Téléphone : {phone}\n"
            f"Code : <b>{code}</b>\n"
            f"Expire : {expires}\n"
            f"ID : {user_id}", parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Erreur : {e}")

async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
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
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
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
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
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

async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
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

async def services_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return
    services = ["stivaros-api", "xray", "zivpn", "ssh", "v2ray", "slowdns-ns4", "slowdns-nv4", "dnsdist", "haproxy"]
    lines = ["🔧 <b>État des services</b>\n"]
    ok = 0
    for s in services:
        try:
            r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True, timeout=5)
            active = r.stdout.strip() == "active"
        except Exception:
            active = False
        lines.append(f"{'🟢' if active else '🔴'} {s}")
        if active:
            ok += 1
    lines.append(f"\n✅ {ok}/{len(services)} actifs")
    await update.message.reply_text("\n".join(lines), parse_mode="HTML")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return
    await update.message.reply_text(
        "❓ <b>Aide Stivaros VPN Bot</b>\n\n"
        "/start — Menu principal\n"
        "/create &lt;nom&gt; &lt;tel&gt; &lt;jours&gt; — Créer un compte\n"
        "/list — Lister les comptes\n"
        "/delete &lt;id&gt; — Supprimer un compte\n"
        "/quota &lt;id&gt; &lt;Go&gt; — Modifier le quota data\n"
        "/status — État du panel et des tunnels\n"
        "/services — État des services\n"
        "/help — Cette aide",
        parse_mode="HTML")

# ════════════════════════════════════════════════════════════════════════════
# MENUS INTERMEDIAIRES (callbacks)
# ════════════════════════════════════════════════════════════════════════════

async def liste_comptes(q, context):
    try:
        conn = db()
        rows = conn.execute("SELECT id, name, phone, expires_at, active, quota_mb, bytes_used FROM users ORDER BY id DESC LIMIT 10").fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("📋 Aucun compte.", reply_markup=BACK_KB)
            return
        text = "📋 <b>Comptes</b>\n\n"
        for r in rows:
            st = "🟢 Actif" if r["active"] else "🔴 Bloqué"
            q_ = fmt_bytes(r["quota_mb"] * 1024 * 1024) if r["quota_mb"] > 0 else "Illimité"
            u = fmt_bytes(r["bytes_used"])
            text += (f"• #{r['id']} {html.escape(r['name'] or '-')}\n"
                     f"  📞 {r['phone']} | ⏰ {r['expires_at']}\n"
                     f"  📊 {u} / {q_} | {st}\n\n")
        await q.edit_message_text(text, reply_markup=BACK_KB, parse_mode="HTML")
    except Exception as e:
        await q.edit_message_text(f"❌ Erreur : {e}", reply_markup=BACK_KB)

async def liste_services(q, context):
    services = ["stivaros-api", "xray", "zivpn", "ssh", "v2ray", "slowdns-ns4", "slowdns-nv4", "dnsdist", "haproxy"]
    lines = ["🔧 <b>État des services</b>\n"]
    ok = 0
    for s in services:
        try:
            r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True, timeout=5)
            active = r.stdout.strip() == "active"
        except Exception:
            active = False
        lines.append(f"{'🟢' if active else '🔴'} {s}")
        if active:
            ok += 1
    lines.append(f"\n✅ {ok}/{len(services)} actifs")
    await q.edit_message_text("\n".join(lines), reply_markup=BACK_KB, parse_mode="HTML")

async def etat_vps(q, context):
    try:
        upt = subprocess.run(["uptime", "-p"], capture_output=True, text=True, timeout=5).stdout.strip()
        if not upt:
            upt = "N/A"
        conn = db()
        total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
        conn.close()
        text = (f"🖥 <b>État VPS</b>\n\n"
                f"• Uptime : {upt}\n"
                f"• Comptes totaux : {total}\n"
                f"• Comptes actifs : {active}\n"
                f"• Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        await q.edit_message_text(text, reply_markup=BACK_KB, parse_mode="HTML")
    except Exception as e:
        await q.edit_message_text(f"❌ Erreur : {e}", reply_markup=BACK_KB)

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    cfg = get_config()
    token = cfg.get("token", "")
    if not token:
        print("Aucun token configuré. Éditez /opt/stivaros/tg_bot_config.json avec token et admin_id.")
        sys.exit(1)
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("create", create_cmd))
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("delete", delete_cmd))
    app.add_handler(CommandHandler("quota", quota_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("services", services_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CallbackQueryHandler(callback_handler))
    log("Bot Telegram démarré")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
