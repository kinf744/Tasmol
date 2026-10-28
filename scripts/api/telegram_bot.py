#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# STIVAROS VPN — Bot Telegram (gestion comptes, services, infos VPS)
# Sélection par numéro pour la création de compte (jours / heures)
# ════════════════════════════════════════════════════════════════════════════
import json, os, sqlite3, sys, subprocess, html, uuid, random
from datetime import datetime, timedelta
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

BASE      = Path("/opt/stivaros")
DB_PATH   = BASE / "stivaros.db"
CONFIG    = BASE / "tg_bot_config.json"
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

# ════════════════════════════════════════════════════════════════════════════
# HANDLERS CALLBACK
# ════════════════════════════════════════════════════════════════════════════

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
            "❓ <b>Aide</b>\n\n"
            "/start — Menu principal\n"
            "/create — Créer un compte (sélection par numéro)\n"
            "/list — Lister les comptes\n"
            "/delete &lt;id&gt; — Supprimer un compte\n"
            "/quota &lt;id&gt; &lt;Go&gt; — Modifier le quota data\n"
            "/status — État du panel et des tunnels\n"
            "/services — État des services\n"
            "/help — Cette aide",
            reply_markup=GESTION_KB, parse_mode="HTML")

    # ── Création de compte par numéro ──
    elif d == "cmd_create":
        context.user_data.clear()
        context.user_data["create_step"] = "type"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("1. Compte normal (jours)", callback_data="create_type_jours")],
            [InlineKeyboardButton("2. Compte TEST (heures)", callback_data="create_type_heures")],
            [InlineKeyboardButton("⬅️ Retour", callback_data="menu_gestion")],
        ])
        await q.edit_message_text(
            "📝 <b>Créer un compte — Choisissez le type :</b>\n\n"
            "1️⃣ Compte normal : durée en JOURS (ex: 5, 10, 30)\n"
            "2️⃣ Compte TEST : durée en HEURES (ex: 24, 48, 72)\n\n"
            "Sélectionnez une option :",
            reply_markup=kb, parse_mode="HTML")

    elif d == "create_type_jours":
        context.user_data["create_type"] = "jours"
        context.user_data["create_step"] = "nom"
        await q.edit_message_text(
            "📝 <b>Compte normal (jours)</b>\n\n"
            "Étape 1/4 — Saisissez le <b>nom</b> du compte :\n"
            "(lettres, chiffres, . _ - uniquement)",
            reply_markup=BACK_KB, parse_mode="HTML")

    elif d == "create_type_heures":
        context.user_data["create_type"] = "heures"
        context.user_data["create_step"] = "nom"
        await q.edit_message_text(
            "📝 <b>Compte TEST (heures)</b>\n\n"
            "Étape 1/4 — Saisissez le <b>nom</b> du compte :\n"
            "(lettres, chiffres, . _ - uniquement)",
            reply_markup=BACK_KB, parse_mode="HTML")

    elif d == "cmd_list":
        await liste_comptes(q, context)
    elif d == "cmd_delete":
        await q.edit_message_text(
            "🗑 <b>Supprimer un compte</b>\n\n"
            "Utilisation : <code>/delete &lt;id_compte&gt;</code>\n"
            "Exemple : <code>/delete 42</code>\n\n"
            "Supprime le compte et toutes ses configurations associées.",
            reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_quota":
        await q.edit_message_text(
            "💾 <b>Modifier le quota data</b>\n\n"
            "Utilisation : <code>/quota &lt;id&gt; &lt;Go&gt;</code>\n"
            "Exemple : <code>/quota 42 10</code>\n"
            "Mettez 0 pour illimité.",
            reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_status":
        await q.edit_message_text(
            "📊 <b>État du panel</b>\n\n"
            "Utilisation : <code>/status</code>\n\n"
            "Affiche le nombre de comptes totaux, actifs et bloqués/expirés.",
            reply_markup=GESTION_KB, parse_mode="HTML")
    elif d == "cmd_services":
        await q.edit_message_text(
            "🔧 <b>État des services</b>\n\n"
            "Utilisation : <code>/services</code>\n\n"
            "Affiche l'état (actif/arrêté) de tous les services du panel Stivaros.",
            reply_markup=GESTION_KB, parse_mode="HTML")

    elif d == "menu_comptes":
        await liste_comptes(q, context)
    elif d == "menu_services":
        await liste_services(q, context)
    elif d == "menu_etat":
        await etat_vps(q, context)

# ════════════════════════════════════════════════════════════════════════════
# HANDLERS TEXTE (saisie étape par étape)
# ════════════════════════════════════════════════════════════════════════════

async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorisé.")
        return

    text = update.message.text.strip()
    step = context.user_data.get("create_step", "")

    if not step:
        # Pas de création en cours, ignorer ou traiter comme commande inconnue
        await update.message.reply_text("Utilisez /start pour accéder au menu.")
        return

    # ── Étape : nom ──
    if step == "nom":
        if not text or not all(c.isalnum() or c in "._-" for c in text):
            await update.message.reply_text(
                "❌ Nom invalide. Utilisez uniquement lettres, chiffres, . _ -\n"
                "Réessayez :")
            return
        context.user_data["create_nom"] = text
        context.user_data["create_step"] = "tel"
        await update.message.reply_text(
            f"✅ Nom enregistré : {text}\n\n"
            f"Étape 2/4 — Saisissez le <b>téléphone</b> :\n"
            f"(ex: 674000000)",
            parse_mode="HTML")
        return

    # ── Étape : téléphone ──
    if step == "tel":
        if not text.isdigit() or len(text) < 8:
            await update.message.reply_text(
                "❌ Téléphone invalide. Saisissez uniquement des chiffres (min 8).\n"
                "Réessayez :")
            return
        context.user_data["create_tel"] = text
        context.user_data["create_step"] = "duree"
        ctype = context.user_data.get("create_type", "jours")
        unite = "JOURS" if ctype == "jours" else "HEURES"
        await update.message.reply_text(
            f"✅ Téléphone enregistré : {text}\n\n"
            f"Étape 3/4 — Saisissez la durée en {unite} :\n"
            f"(ex: {'5, 10, 30' if ctype == 'jours' else '24, 48, 72'})",
            parse_mode="HTML")
        return

    # ── Étape : durée ──
    if step == "duree":
        if not text.isdigit() or int(text) < 1:
            ctype = context.user_data.get("create_type", "jours")
            unite = "jours" if ctype == "jours" else "heures"
            await update.message.reply_text(
                f"❌ Durée invalide. Saisissez un nombre entier de {unite} (>=1).\n"
                f"Réessayez :")
            return
        context.user_data["create_duree"] = int(text)
        context.user_data["create_step"] = "confirmer"
        ctype = context.user_data.get("create_type", "jours")
        unite = "JOURS" if ctype == "jours" else "HEURES"
        nom = context.user_data.get("create_nom", "")
        tel = context.user_data.get("create_tel", "")
        await update.message.reply_text(
            f"✅ Durée enregistrée : {text} {unite}\n\n"
            f"Étape 4/4 — Récapitulatif :\n"
            f"• Type : {'Compte normal' if ctype == 'jours' else 'Compte TEST'}\n"
            f"• Nom : {nom}\n"
            f"• Téléphone : {tel}\n"
            f"• Durée : {text} {unite}\n\n"
            f"Envoyez <b>OUI</b> pour confirmer la création, ou <b>NON</b> pour annuler.",
            parse_mode="HTML", reply_markup=BACK_KB)
        return

    # ── Étape : confirmation ──
    if step == "confirmer":
        if text.upper() == "OUI":
            await finaliser_creation(update, context)
        elif text.upper() == "NON":
            context.user_data.clear()
            await update.message.reply_text(
                "❌ Création annulée.", reply_markup=MAIN_KB, parse_mode="HTML")
        else:
            await update.message.reply_text(
                "❌ Réponse invalide. Envoyez <b>OUI</b> ou <b>NON</b>.",
                parse_mode="HTML")
        return

async def finaliser_creation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Crée le compte en base selon le type (jours ou heures)."""
    nom = context.user_data.get("create_nom", "")
    tel = context.user_data.get("create_tel", "")
    duree = context.user_data.get("create_duree", 1)
    ctype = context.user_data.get("create_type", "jours")

    try:
        conn = db()
        cur = conn.cursor()
        uid = str(uuid.uuid4())
        code = f"{random.randint(100000, 999999):06d}"
        now = datetime.utcnow()

        if ctype == "jours":
            expires = (now + timedelta(days=duree)).strftime("%Y-%m-%d")
        else:
            expires = (now + timedelta(hours=duree)).strftime("%Y-%m-%d %H:%M:%S")

        cur.execute(
            "INSERT INTO users (uuid, phone, name, activation_code, expires_at, active, quota_mb, multi_device, device_install_id, allowed_uuids) "
            "VALUES (?, ?, ?, ?, ?, 1, 0, 1, '', '')",
            (uid, tel, nom, code, expires))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()

        context.user_data.clear()
        await update.message.reply_text(
            f"✅ <b>Compte créé avec succès</b>\n\n"
            f"• Nom : {html.escape(nom)}\n"
            f"• Téléphone : {tel}\n"
            f"• Code : <b>{code}</b>\n"
            f"• Type : {'Compte normal (jours)' if ctype == 'jours' else 'Compte TEST (heures)'}\n"
            f"• Durée : {duree}\n"
            f"• Expire : {expires}\n"
            f"• ID : {user_id}",
            parse_mode="HTML", reply_markup=MAIN_KB)

    except Exception as e:
        context.user_data.clear()
        await update.message.reply_text(
            f"❌ Erreur lors de la création : {e}",
            parse_mode="HTML", reply_markup=MAIN_KB)

# ════════════════════════════════════════════════════════════════════════════
# COMMANDES TEXTE (liste, delete, quota, status, services, help)
# ════════════════════════════════════════════════════════════════════════════

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
        "/create — Créer un compte (sélection par numéro : jours ou heures)\n"
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
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("delete", delete_cmd))
    app.add_handler(CommandHandler("quota", quota_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("services", services_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    log("Bot Telegram démarré")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
