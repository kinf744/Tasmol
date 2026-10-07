#!/usr/bin/env bash
# ── install_utunnel_stivaros.sh — intégration utunnel au style stivaros ─
#
# À coller (fonction install_utunnel + détection) dans stivaros.sh, ou à
# exécuter tel quel en root sur un serveur déjà stivaros. Idempotent :
#   tunnel_installed utunnel → (re)démarrage si besoin ; absent → install.
#
#   - PSK  : /etc/utunnel/server.psk (générée si absente) ;
#   - plage clients : 40000-45999 (DISTINCTE de stivaros-zivpn 34000-49999) ;
#   - DNAT nftables de la plage vers :5669 (port-hopping client natif) ;
#   - users.list stivaros accepté tel quel (uuid|secret|YYYY-MM-DD).
# ───────────────────────────────────────────────────────────────────────
set -euo pipefail
umask 077

readonly UT_DIR="/etc/utunnel"
readonly UT_BIN="/usr/local/bin/utunnel-server"
readonly UT_SERVICE="utunnel.service"
readonly UT_PORT=5669
readonly UT_RANGE="40000-45999"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> /var/log/stivaros.log 2>/dev/null || true; }
msg()  { echo "[✓] $1"; log "OK   $1"; }
err()  { echo "[✗] $1" >&2; log "ERR  $1"; }
die()  { err "$1"; exit 1; }

tunnel_installed() {
    case "$1" in
        utunnel) [[ -x "$UT_BIN" && -f "/etc/systemd/system/$UT_SERVICE" ]] ;;
        *) return 1 ;;
    esac
}

tunnel_active() {
    systemctl is-active --quiet "$UT_SERVICE"
}

ensure_utunnel() {
    if tunnel_installed utunnel; then
        if tunnel_active; then
            msg "utunnel déjà actif (:5669)"; return 0
        fi
        systemctl restart "$UT_SERVICE" && { msg "utunnel redémarré"; return 0; }
        err "utunnel ne démarre pas"; return 1
    fi
    install_utunnel
}

install_utunnel() {
    command -v nft &>/dev/null || apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables 2>/dev/null || true

    if [[ ! -x "$UT_BIN" ]]; then
        # Binaire depuis le repo (dist/ du build) — adapter si besoin :
        # scripts/build_utunnel.sh produit dist/utunnel-server-{amd64,arm64,armv7}
        local arch; arch="$(uname -m)"
        case "$arch" in
            x86_64)  arch=amd64 ;;
            aarch64) arch=arm64 ;;
            armv7*)  arch=armv7 ;;
            *) die "arch non supportée: $arch" ;;
        esac
        local src="dist/utunnel-server-$arch"
        [[ -f "$src" ]] || die "binaire introuvable: $src (exécutez scripts/build_utunnel.sh)"
        install -m 755 "$src" "$UT_BIN"
    fi

    mkdir -p "$UT_DIR"
    if [[ ! -s "$UT_DIR/server.psk" ]]; then
        tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -1 > "$UT_DIR/server.psk"
        msg "PSK générée : $(head -1 "$UT_DIR/server.psk")"
    fi
    chmod 600 "$UT_DIR/server.psk"

    [[ -f "$UT_DIR/users.list" ]] || : > "$UT_DIR/users.list"
    chmod 600 "$UT_DIR/users.list"

    install -m 644 deploy/utunnel.service /etc/systemd/system/ 2>/dev/null \
        || die "copiez deploy/utunnel.service dans /etc/systemd/system/"

    # nftables : plage DISTINCTE de stivaros-zivpn (34000-49999)
    local iface; iface="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
    iface="${iface:-eth0}"
    local tmp; tmp="$(mktemp)"
    cat > "$tmp" << EOF
destroy table inet utunnel
table inet utunnel {
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport $UT_PORT accept
        udp dport $UT_RANGE accept
    }
    chain prerouting {
        type nat hook prerouting priority -100;
        iifname "$iface" udp dport $UT_RANGE dnat to :$UT_PORT
    }
}
EOF
    if nft -c -f "$tmp" 2>/dev/null; then
        mkdir -p /etc/nftables
        cp "$tmp" /etc/nftables/utunnel.nft
        nft -f /etc/nftables/utunnel.nft 2>/dev/null || true
        msg "DNAT nftables : $UT_RANGE -> :$UT_PORT sur $iface"
    else
        err "règles nftables invalides — ignorées"
    fi
    rm -f "$tmp"

    systemctl daemon-reload
    systemctl enable --now "$UT_SERVICE"
    systemctl restart "$UT_SERVICE"
    if tunnel_active; then
        msg "utunnel actif (:5669, plage $UT_RANGE)"
        msg "clé client = hex(sha256(PSK)) : sha256sum < $UT_DIR/server.psk"
    else
        err "utunnel ne démarre pas"; journalctl -u "$UT_SERVICE" -n 10 --no-pager; return 1
    fi
}

uninstall_utunnel() {
    systemctl disable --now "$UT_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$UT_SERVICE" "$UT_BIN" /etc/nftables/utunnel.nft
    nft delete table inet utunnel 2>/dev/null || true
    systemctl daemon-reload
    msg "utunnel désinstallé"
}

case "${1:-install}" in
    install)  ensure_utunnel ;;
    remove)   uninstall_utunnel ;;
    *) echo "usage: $0 [install|remove]"; exit 1 ;;
esac
