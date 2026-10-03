#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  STIVAROS VPN PANEL — Gestion des comptes d'activation + tunnels
#  Version: 2.0.0 (réécriture professionnelle)
#
#  Rôle:
#    - API d'activation (comptes, codes 6 chiffres, configs distantes)
#      compatible avec l'application EPHANG VPN (endpoint api-v1).
#    - Détection automatique des tunnels installés (Xray, ZIVPN,
#      SlowDNS/dnstt, V2Ray-DNS, SSH) et installation à la demande.
#    - Tunnels: Xray (VLESS+XHTTP+TLS:443), ZIVPN (UDP:5667),
#      SSH+SlowDNS (dnstt NS -> SSH:22), V2Ray+SlowDNS (dnstt NV -> V2Ray:5402).
#
#  Sécurité: set -euo pipefail, validation stricte des entrées, échappement
#  SQL, permissions restrictives sur les secrets, aucun secret dans les
#  arguments de processus.
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail
umask 077

# ── Constantes ─────────────────────────────────────────────────────────
readonly INSTALL_DIR="/opt/stivaros"
readonly API_DIR="$INSTALL_DIR/api"
readonly DB_PATH="$INSTALL_DIR/stivaros.db"
readonly CONFIG_PATH="$INSTALL_DIR/config.json"
readonly LOG_FILE="/var/log/stivaros.log"
readonly SERVICE_FILE="/etc/systemd/system/stivaros-api.service"
readonly API_PORT=9090

readonly RELEASES="https://github.com/kinf744/fasto/releases/download/v1.0.0-zivpn"

# Xray
readonly XRAY_BIN="/usr/local/bin/xray"
readonly XRAY_DIR="/etc/xray"
readonly XRAY_DOMAIN_FILE="$XRAY_DIR/domain"
readonly XRAY_PATH="/vless-xhttp"
readonly XRAY_UUID_DEFAULT="cfe75234-b0d9-477d-b30f-9d24654b2487"

# ZIVPN
readonly ZIVPN_BIN="/usr/local/bin/zivpn"
# Instance dédiée: cohabitation avec un éventuel panel tiers (install2)
# qui réécrit /etc/zivpn/config.json périodiquement. On n'y touche pas.
readonly ZIVPN_SERVICE="stivaros-zivpn.service"
readonly ZIVPN_HOME="/etc/stivaros-zivpn"
readonly ZIVPN_CONFIG="$ZIVPN_HOME/config.json"
readonly ZIVPN_USER_FILE="$ZIVPN_HOME/users.list"
readonly ZIVPN_DOMAIN_FILE="$ZIVPN_HOME/domain.txt"
readonly ZIVPN_PORT=5668
# DNAT serveur (nft) — plage dédiée, distincte de l'autre instance.
readonly ZIVPN_RANGE="34000-49999"
# Plages clients round-robin (8 sous-plages, un processus par plage).
readonly ZIVPN_RANGES="34000-37999,38000-41999,42000-45999,46000-49999"

# SlowDNS (dnstt + dnsdist)
readonly SLOWDNS_DIR="/etc/slowdns"
readonly DNSTT_BIN="/usr/local/bin/dnstt-server"
readonly DNSDIST_PORT=5300
readonly DNSTT_NS4_PORT=5353   # NS4 -> SSH (127.0.0.1:22)
readonly DNSTT_NV4_PORT=5354   # NV4 -> V2Ray stivaros (127.0.0.1:5402)
readonly SLOWDNS_MTU_DEFAULT=1232

# V2Ray-DNS
readonly V2RAY_BIN="/usr/local/bin/v2ray"
readonly V2RAY_DIR="/etc/stivaros-v2ray"
readonly V2RAY_PORT=5402
readonly V2RAY_SERVICE="stivaros-v2ray.service"

# Orange illimité: SNI/adresse FIXES, seul le host XHTTP est administrable
# (exactement UN host à la fois, partagé par toutes les configs orange).
readonly ORANGE_ADDR="reprise.orange-business.com"
readonly ORANGE_HOST_FILE="$INSTALL_DIR/orange_host.txt"

# Stats/quota (xray/v2ray exposent leurs compteurs via l'API gRPC locale)
readonly XRAY_STATS_ADDR="127.0.0.1:10085"
readonly V2RAY_STATS_ADDR="127.0.0.1:10087"
readonly QUOTA_STATE="$INSTALL_DIR/quota_state.json"
readonly QUOTA_SCRIPT="$API_DIR/quota.py"
readonly QUOTA_TIMER="stivaros-quota.timer"

# ── Couleurs / sortie ──────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; WHITE=$'\033[1;37m'; NC=$'\033[0m'; BOLD=$'\033[1m'
    # Palette étendue (refonte UI v2.1) — 256 couleurs.
    PURPLE=$'\033[38;5;135m'; BLUE=$'\033[38;5;39m'; PINK=$'\033[38;5;198m'
    ORANGE=$'\033[38;5;208m'; DIM=$'\033[2m'; BG=$'\033[48;5;236m'
    LIME=$'\033[38;5;118m'; GOLD=$'\033[38;5;220m'; GRAY=$'\033[38;5;245m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; WHITE=""; NC=""; BOLD=""
    PURPLE=""; BLUE=""; PINK=""; ORANGE=""; DIM=""; BG=""
    LIME=""; GOLD=""; GRAY=""
fi

log()  { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE" 2>/dev/null || true; }
msg()   { echo -e "${GREEN}[✓]${NC} $1"; log "OK   $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; log "WARN $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; log "ERR  $1"; }
info()  { echo -e "${CYAN}[i]${NC} $1"; log "INFO $1"; }
die()   { error "$1"; exit 1; }

# ── Cadres d'interface (refonte UI v2.1) ───────────────────────────────
# Toutes les fonctions d'affichage uniquement: aucune logique n'est touchée.
box_top()    { echo -e "${BLUE}  ╔$(printf '═%.0s' $(seq 54))╗${NC}"; }
box_mid()    { echo -e "${BLUE}  ╠$(printf '═%.0s' $(seq 54))╣${NC}"; }
box_bot()    { echo -e "${BLUE}  ╚$(printf '═%.0s' $(seq 54))╝${NC}"; }
box_sep()    { echo -e "${GRAY}  ├$(printf '─%.0s' $(seq 54))┤${NC}"; }
# box_line "texte" — contenu à LARGEUR FIXEDE 52 (escape codes ignorés via %b trick)
box_line() {
    local txt="$1" vis len pad
    # retire les séquences ANSI pour mesurer la longueur visible
    vis=$(printf '%b' "$txt" | sed $'s/\033\\[[0-9;]*m//g')
    len=${#vis}
    pad=$((52 - len)); ((pad < 0)) && pad=0
    echo -e "${BLUE}  ║${NC}${txt}$(printf ' %.0s' $(seq 1 $((pad + 1))))${BLUE} ║${NC}"
}
box_title() {
    local txt="$1" vis len pad
    vis=$(printf '%b' "$txt" | sed $'s/\033\\[[0-9;]*m//g')
    len=${#vis}
    pad=$(((52 - len) / 2)); ((pad < 1)) && pad=1
    echo -e "${BLUE}  ║${NC}$(printf ' %.0s' $(seq 1 $pad))${BOLD}${GOLD}${txt}${NC}$(printf ' %.0s' $(seq 1 $((52 - len - pad + 2))))${BLUE} ║${NC}"
}

banner() { clear; }

# ── Dashboard (v2.1): infos système + comptes + tunnels ────────────────
# Uniquement de la lecture/affichage; aucune mutation.
sys_ip_pub()  { curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null \
                || curl -fsSL --max-time 4 ifconfig.me 2>/dev/null \
                || hostname -I 2>/dev/null | awk '{print $1}' || echo "?"; }
sys_cpu()     { local u; u=$(top -bn1 2>/dev/null | awk -F'[,% ]' '/^%Cpu/ {printf "%.0f", $2+$4}');
                echo "${u:-0}"; }
sys_ram() {
    awk '/^MemTotal/{t=$2}/^MemAvailable/{a=$2}END{
        u=t-a; if(t>0) printf "%d/%d Mo (%d%%)", u/1024, t/1024, u*100/t}' /proc/meminfo
}
sys_disk() {
    df -m / 2>/dev/null | awk 'NR==2{printf "%d/%d Go (%d%%)", $3/1024, $2/1024, $5+0}'
}
acc_counts() {
    # écrit "actifs|expirés" — 0|0 si la DB n'existe pas encore.
    if [[ ! -f "$DB_PATH" ]]; then echo "0|0"; return; fi
    sqlite3 -batch "$DB_PATH" "
      SELECT
        COALESCE(SUM(CASE WHEN active=1
             AND (expires_at IS NULL OR expires_at >= DATE('now')) THEN 1 ELSE 0 END),0)
        || '|' ||
        COALESCE(SUM(CASE WHEN active=0
             OR (expires_at IS NOT NULL AND expires_at < DATE('now')) THEN 1 ELSE 0 END),0)
      FROM users;" 2>/dev/null || echo "0|0"
}
tun_dot() { # $1 nom court — pastille colorée ●◌
    local s; s=$(tunnel_state "$1" 2>/dev/null || echo 2)
    case "$s" in
        0) echo -e "${GREEN}●${NC}";;
        1) echo -e "${YELLOW}◐${NC}";;
        *) echo -e "${RED}○${NC}";;
    esac
}

# Fusé dans menu() — un seul cadre: supervision + options + invite.
dashboard() {
    local ip cuv cpun ram disk counts valid expired uptime_v osname
    ip=$(sys_ip_pub)
    cuv=$(sys_cpu); cpun=$(nproc 2>/dev/null || echo 1)
    ram=$(sys_ram); disk=$(sys_disk)
    counts=$(acc_counts); valid=${counts%|*}; expired=${counts#*|}
    ((cuv > 100)) && cuv=100
    local fill=$((cuv / 10)) bar
    bar="$(printf '█%.0s' $(seq 1 $fill 2>/dev/null))$(printf '░%.0s' $(seq 1 $((10-fill)) 2>/dev/null))"
    local load; load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo "?")
    uptime_v=$(uptime -p 2>/dev/null | sed 's/up //' || echo "?")
    local apic="${RED}●${NC}"
    systemctl is-active --quiet stivaros-api && apic="${GREEN}●${NC}"
    # OS court : NAME VERSION_ID (par ex. "Ubuntu 22.04")
    osname=$(. /etc/os-release 2>/dev/null && echo "${NAME:-Linux} ${VERSION_ID:-}" | sed 's/ *$//' || uname -s)
    # largeur interne du cadre = 54; centre "STIVAROS V2.5" (13) : 20 + 21
    echo -e "${BLUE}  ╔$(printf '═%.0s' $(seq 54))╗${NC}"
    echo -e "${BLUE}  ║$(printf ' %.0s' $(seq 1 20))${BOLD}${GOLD}STIVAROS V2.5${NC}$(printf ' %.0s' $(seq 1 21))${BLUE}║${NC}"
    box_mid
    box_line "  ${GOLD}IP publique${NC} : ${BOLD}${CYAN}${ip}${NC}"
    box_line "  ${GOLD}OS${NC}          : ${WHITE}${osname} ${GRAY}($(uname -m))${NC}"
    box_line "  ${GOLD}Uptime${NC}      : ${WHITE}${uptime_v}${NC}"
    box_sep
    box_line "  ${GOLD}CPU${NC}    : ${cpun} ${PURPLE}${bar}${NC} ${BOLD}${WHITE}${cuv}%${NC} ${GRAY}load ${load}${NC}"
    box_line "  ${GOLD}RAM${NC}    : ${PINK}${ram}${NC}"
    box_line "  ${GOLD}Disque${NC} : ${ORANGE}${disk}${NC}"
    box_sep
    box_line "  ${GOLD}Comptes${NC} : ${LIME}${BOLD}${valid} valide(s)${NC} ${GRAY}│${NC} ${RED}${BOLD}${expired} expiré(s)${NC}"
    box_sep
    box_line "  ${GOLD}Tunnels${NC} : $(tun_dot xray) ${WHITE}Xray${NC} $(tun_dot zivpn) ${WHITE}ZIVPN${NC} $(tun_dot ssh) ${WHITE}SSH${NC}"
    box_line "            $(tun_dot v2ray) ${WHITE}V2Ray-DNS${NC} $(tun_dot slowdns) ${WHITE}SlowDNS${NC}"
    box_line "  ${GOLD}API${NC}     : ${apic} ${WHITE}stivaros-api :${API_PORT}${NC}"
    box_sep
}

# ── Garde-fous ─────────────────────────────────────────────────────────
check_root() {
    [[ $EUID -eq 0 ]] || die "Ce script doit être exécuté en root."
}

need_cmd() {
    command -v "$1" &>/dev/null || die "Commande requise manquante: $1 (apt-get install -y $2)"
}

ensure_deps() {
    local missing=()
    for c in curl jq openssl sqlite3 python3 systemctl; do
        command -v "$c" &>/dev/null || missing+=("$c")
    done
    if ((${#missing[@]})); then
        info "Installation des dépendances: ${missing[*]}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            curl jq openssl sqlite3 python3 2>/dev/null \
            || die "Impossible d'installer les dépendances"
    fi
}

pause()   { [[ -n "${STIVAROS_NOPAUSE:-}" ]] && return 0; echo; read -r -p "Entrée pour continuer..." _ || true; }
confirm() { local r; read -r -p "$1 [y/N]: " r; [[ "$r" =~ ^[yY]$ ]]; }

# ── Validation & génération (sécurité) ─────────────────────────────────
generate_secret() { tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -1; }
gen_pass()        { tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "${1:-12}" | head -1; }
gen_code()        { tr -dc '0-9' < /dev/urandom | fold -w 6 | head -1; }
gen_uuid()        { cat /proc/sys/kernel/random/uuid; }

valid_uuid()  { [[ "$1" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; }
valid_phone() { [[ "$1" =~ ^[+]?[0-9]{8,15}$ ]]; }
valid_date()  { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && date -d "$1" &>/dev/null; }
valid_name()  { [[ "$1" =~ ^[a-zA-Z0-9._-]{1,32}$ ]]; }
valid_domain(){ [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && [[ ! "$1" =~ \.\. ]]; }
valid_code()  { [[ "$1" =~ ^[0-9]{6}$ ]]; }

# Échappe une valeur pour insertion SQL (quote doubling).
sqlq() { printf '%s' "$1" | sed "s/'/''/g"; }

# Exécute du SQL en refusant tout texte venant d'une entrée non validée
# ailleurs que dans les paramètres échappés.
sql() { sqlite3 -batch "$DB_PATH" "$1"; }

main_iface() { ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'; }

# ── Détection des tunnels (installé ? actif ?) ─────────────────────────
tunnel_installed() {
    case "$1" in
        xray)    [[ -x "$XRAY_BIN" && -f /etc/systemd/system/xray.service ]] ;;
        zivpn)   [[ -x "$ZIVPN_BIN" && -f "/etc/systemd/system/$ZIVPN_SERVICE" ]] ;;
        slowdns) [[ -x "$DNSTT_BIN" && -f /etc/systemd/system/slowdns-ns4.service ]] ;;
        v2ray)   [[ -x "$V2RAY_BIN" && -f "/etc/systemd/system/$V2RAY_SERVICE" ]] ;;
        ssh)     dpkg -s openssh-server &>/dev/null || command -v sshd &>/dev/null ;;
        *)       return 1 ;;
    esac
}

tunnel_active() {
    case "$1" in
        xray)    systemctl is-active --quiet xray ;;
        zivpn)   systemctl is-active --quiet "$ZIVPN_SERVICE" ;;
        slowdns) systemctl is-active --quiet slowdns-ns4 \
              && systemctl is-active --quiet slowdns-nv4 \
              && systemctl is-active --quiet dnsdist ;;
        v2ray)   systemctl is-active --quiet "$V2RAY_SERVICE" ;;
        ssh)     systemctl is-active --quiet ssh || systemctl is-active --quiet sshd ;;
        *)       return 1 ;;
    esac
}

# installed+active → "0" ; installed mais down → "1" ; absent → "2".
# (echo, retour toujours 0: compatible set -e quel que soit l'état)
tunnel_state() {
    if ! tunnel_installed "$1"; then echo 2; return 0; fi
    if tunnel_active "$1"; then echo 0; return 0; fi
    echo 1
}

tunnel_badge() {
    local s
    s=$(tunnel_state "$1")
    case "$s" in
        0) echo -e " ${GREEN}●${NC} $2 (actif)";;
        1) echo -e " ${YELLOW}◐${NC} $2 (installé, inactif)";;
        2) echo -e " ${RED}○${NC} $2 (non installé)";;
    esac
}

# Garantit qu'un tunnel est utilisable: déjà installé → (re)démarrage si
# besoin ; absent → installation complète. Retourne non-zéro si échec.
ensure_tunnel() {
    local t="$1" st
    st=$(tunnel_state "$t")
    case "$st" in
        0) return 0 ;;
        1)
            warn "$t installé mais inactif — redémarrage"
            case "$t" in
                slowdns) systemctl restart slowdns-ns4 slowdns-nv4 dnsdist || true ;;
                ssh)     systemctl restart ssh 2>/dev/null || systemctl restart sshd || true ;;
                *)       systemctl restart "$t" || true ;;
            esac
            sleep 1
            tunnel_active "$t" && { msg "$t redémarré"; return 0; }
            error "$t ne démarre pas"; return 1
            ;;
        2)
            info "$t non installé — installation…"
            # Pas de "Entrée pour continuer" dans les installs enchaînées.
            STIVAROS_NOPAUSE=1 "install_$t" || true
            tunnel_active "$t" || { error "$t: installation incomplète"; return 1; }
            return 0
            ;;
    esac
}

# ── Prérequis commun: domaine ──────────────────────────────────────────
get_domain() {
    for f in /etc/kighmu/domain.txt "$XRAY_DOMAIN_FILE" /etc/v2ray/domain.txt; do
        [[ -s "$f" ]] && { head -1 "$f" | tr -d '[:space:]'; return; }
    done
    echo ""
}

ask_domain() {
    local cur def
    cur=$(get_domain)
    if [[ -n "$cur" ]]; then
        echo "$cur"; return
    fi
    read -r -p "Domaine du serveur (ex: vpn.example.com): " def
    valid_domain "$def" || die "Domaine invalide: $def"
    mkdir -p /etc/kighmu
    echo "$def" > /etc/kighmu/domain.txt
    chmod 600 /etc/kighmu/domain.txt
    echo "$def"
}

# ══════════════════════════════════════════════════════════════════════
#  INSTALLATEURS DE TUNNELS
#  Chaque install_* est idempotent et vérifiable via tunnel_state.
# ══════════════════════════════════════════════════════════════════════

download_binary() { # $1 url $2 dest
    local tmp
    tmp=$(mktemp)
    if curl -fsSL --connect-timeout 15 --max-time 300 "$1" -o "$tmp"; then
        chmod 755 "$tmp"
        mv "$tmp" "$2"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

self_signed() { # $1 key $2 cert $3 cn
    openssl req -x509 -newkey rsa:2048 -keyout "$1" -out "$2" -nodes \
        -days 3650 -subj "/CN=$3" 2>/dev/null
    chmod 600 "$1"; chmod 644 "$2"
}

# ── Xray (VLESS + XHTTP + TLS :443) ────────────────────────────────────
install_xray() {
    banner; echo -e "${BOLD}Tunnel Xray (VLESS+XHTTP/WS+TLS)${NC}\n"

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip ca-certificates haproxy 2>/dev/null \
        || die "Échec installation haproxy"

    if ! tunnel_installed xray; then
        info "Téléchargement de Xray…"
        download_binary "$RELEASES/xray" "$XRAY_BIN" \
            || die "Échec du téléchargement de Xray"
    fi
    setcap cap_net_bind_service=+ep "$XRAY_BIN" 2>/dev/null || true

    mkdir -p "$XRAY_DIR" /var/log/xray
    local domain
    domain=$(ask_domain)

    # Certificat: existant > auto-signé (prod: brancher ici un ACME/LE).
    if [[ ! -s "$XRAY_DIR/xray.crt" || ! -s "$XRAY_DIR/xray.key" ]]; then
        self_signed "$XRAY_DIR/xray.key" "$XRAY_DIR/xray.crt" "$domain"
        warn "Certificat auto-signé généré pour $domain"
    fi
    echo "$domain" > "$XRAY_DOMAIN_FILE"; chmod 600 "$XRAY_DOMAIN_FILE"

    cat > "$XRAY_DIR/config.json" << EOF
{
  "log": { "loglevel": "warning",
           "access": "/var/log/xray/access.log",
           "error": "/var/log/xray/error.log" },
  "stats": {},
  "api": { "tag": "api", "services": ["StatsService"] },
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1", "port": 4443,
      "protocol": "vless",
      "settings": { "clients": [{"id": "$XRAY_UUID_DEFAULT", "email": "default"}], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": { "certificates": [{
            "certificateFile": "$XRAY_DIR/xray.crt",
            "keyFile": "$XRAY_DIR/xray.key" }] },
        "xhttpSettings": { "path": "$XRAY_PATH" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    },
    {
      "listen": "127.0.0.1", "port": 8443,
      "protocol": "vless",
      "settings": { "clients": [{"id": "$XRAY_UUID_DEFAULT", "email": "default"}], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": { "certificates": [{
            "certificateFile": "$XRAY_DIR/xray.crt",
            "keyFile": "$XRAY_DIR/xray.key" }] },
        "wsSettings": { "path": "/vless" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    },
    {
      "tag": "api", "listen": "127.0.0.1", "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": { "rules": [
    { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
    { "type": "field", "ip": ["geoip:private"], "outboundTag": "blocked" },
    { "type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked" }
  ] }
}
EOF
    chmod 600 "$XRAY_DIR/config.json"

    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Stivaros Xray (VLESS+XHTTP+TLS)
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray -config /etc/xray/config.json
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # HAProxy :443 en passthrough TCP, répartition par SNI (faux-SNI MTN → WS,
    # le reste → XHTTP). La terminaison TLS reste chez Xray (cert unique).
    cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    maxconn 100000
    log /dev/log local0

defaults
    mode tcp
    option tcplog
    timeout connect 10s
    timeout client 300s
    timeout server 300s

frontend tls_in
    bind *:443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend xray_ws if { req.ssl_sni -i mtnplay.com } || { req.ssl_sni -i yamo.mtn.cm }
    default_backend xray_xhttp

backend xray_xhttp
    server x1 127.0.0.1:4443

backend xray_ws
    server x2 127.0.0.1:8443
EOF

    mkdir -p /etc/systemd/system/haproxy.service.d
    cat > /etc/systemd/system/haproxy.service.d/override.conf << 'EOF'
[Unit]
StartLimitIntervalSec=0
StartLimitBurst=0
[Service]
Restart=always
RestartSec=5s
EOF

    systemctl daemon-reload
    systemctl enable --now xray haproxy
    systemctl restart xray haproxy
    xray_sync_uuids 2>/dev/null || true
    tunnel_active xray && msg "Xray actif (port 443, path $XRAY_PATH)" \
                       || { error "Xray ne démarre pas"; journalctl -u xray -n 10 --no-pager; return 1; }
    pause
}

xray_uninstall() {
    confirm "Supprimer complètement Xray ?" || return 0
    systemctl disable --now xray 2>/dev/null || true
    rm -f /etc/systemd/system/xray.service "$XRAY_BIN"
    rm -rf "$XRAY_DIR"
    systemctl daemon-reload
    msg "Xray désinstallé"
}

xray_sync_uuids() {
    [[ -f "$DB_PATH" && -f "$XRAY_DIR/config.json" ]] || return 0
    STIVAROS_DB="$DB_PATH" STIVAROS_DEFAULT_UUID="$XRAY_UUID_DEFAULT" python3 - << 'PYEOF' 2>/dev/null || true
import json, os, sqlite3

db, default = os.environ["STIVAROS_DB"], os.environ["STIVAROS_DEFAULT_UUID"]
uuids = []
try:
    conn = sqlite3.connect(db)
    rows = conn.execute("""
        SELECT DISTINCT v.xray_uuid FROM vpn_configs v
        JOIN users u ON v.user_id = u.id
        WHERE u.active = 1 AND (u.expires_at IS NULL OR u.expires_at >= DATE('now'))
    """).fetchall()
    uuids = [r[0] for r in rows if r[0]]
    conn.close()
except Exception:
    pass
if default not in uuids:
    uuids.insert(0, default)
with open("/etc/xray/config.json") as f:
    cfg = json.load(f)
clients = [{"id": u, "email": u, "level": 0} for u in uuids]
for ib in cfg.get("inbounds", []):
    # Tous les inbounds vless (xhttp :4443 ET ws :8443) partagent les
    # mêmes comptes.
    if ib.get("protocol") == "vless":
        ib["settings"]["clients"] = clients
tmp = "/etc/xray/config.json.tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
os.replace(tmp, "/etc/xray/config.json")
PYEOF
    tunnel_installed xray && systemctl restart xray
}

# ── ZIVPN (UDP Camtel :5667, DNAT 6000-19999) ──────────────────────────
install_zivpn() {
    banner; echo -e "${BOLD}Tunnel ZIVPN (UDP Camtel)${NC}\n"

    if ! tunnel_installed zivpn; then
        info "Téléchargement de ZIVPN…"
        download_binary "$RELEASES/zivpn" "$ZIVPN_BIN" \
            || die "Échec du téléchargement de ZIVPN"
    fi

    mkdir -p "$ZIVPN_HOME"
    local domain
    domain=$(ask_domain)
    echo "$domain" > "$ZIVPN_DOMAIN_FILE"; chmod 600 "$ZIVPN_DOMAIN_FILE"

    if [[ ! -s "$ZIVPN_HOME/zivpn.crt" ]]; then
        self_signed "$ZIVPN_HOME/zivpn.key" "$ZIVPN_HOME/zivpn.crt" "$domain"
    fi

    [[ -f "$ZIVPN_USER_FILE" ]] || : > "$ZIVPN_USER_FILE"
    chmod 600 "$ZIVPN_USER_FILE"

    local stats_token
    stats_token=$(generate_secret)
    cat > "$ZIVPN_CONFIG" << EOF
{
  "listen": ":$ZIVPN_PORT",
  "cert": "$ZIVPN_HOME/zivpn.crt",
  "key": "$ZIVPN_HOME/zivpn.key",
  "obfs": "hu\`\`hqb\`c",
  "recv_window_conn": 15728640,
  "recv_window_client": 67108864,
  "disable_mtu_discovery": false,
  "max_conn_client": 4096,
  "exclude_port": [53, 5300, 4466, 36712, 5667, 20000],
  "quotaStateFile": "$ZIVPN_HOME/quota-state.json",
  "statsAPI": { "listen": "127.0.0.1:10099", "token": "$stats_token" },
  "quota": {},
  "auth": { "mode": "passwords", "config": ["zi"] }
}
EOF
    chmod 600 "$ZIVPN_CONFIG"

    # Le heredoc est déquoté (EOF, pas 'EOF') pour injecter le chemin nft;
    # la ligne contient « $ZIVPN_RANGE » encodée comme chaîne littérale.
    cat > "/etc/systemd/system/$ZIVPN_SERVICE" << 'EOF'
[Unit]
Description=Stivaros ZIVPN UDP Server (dedicated instance)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
# Recharge la table DNAT (34000-49999 -> 5668) à chaque (re)démarrage:
# les tables nft créées par ce script ne survivent jamais au reboot.
# ZIVPN sans DNAT = handshake silencieusement perdu (aucun log, aucun gRPC).
ExecStartPre=/usr/sbin/nft -f /etc/nftables/stivaros-zivpn.nft
# Restaure aussi la table slowdns (53 -> 5300) si elle y vit : elle non
# plus ne survit pas au reboot et SlowDNS mourrait silencieusement.
ExecStartPre=/bin/sh -c 'nft list table inet slowdns >/dev/null 2>&1 || [ ! -f /etc/nftables/slowdns.nft ] || nft -f /etc/nftables/slowdns.nft'
ExecStart=/usr/local/bin/zivpn server -c /etc/stivaros-zivpn/config.json
WorkingDirectory=/etc/stivaros-zivpn
Restart=always
RestartSec=10
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # nftables: accepte 5667 + DNAT de la plage clients vers 5667
    local iface tmp
    iface=$(main_iface)
    tmp=$(mktemp)
    cat > "$tmp" << EOF
# 'destroy' recrée la table à zéro: un rechargement 'nft -f' (ExecStartPre
# du service, ou réinstallation) ne duplique jamais les règles.
destroy table inet stivaros_zivpn
table inet stivaros_zivpn {
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport $ZIVPN_PORT accept
        udp dport $ZIVPN_RANGE accept
    }
    chain prerouting {
        type nat hook prerouting priority -100;
        iifname "$iface" udp dport $ZIVPN_RANGE dnat to :$ZIVPN_PORT
    }
}
EOF
    if nft -c -f "$tmp" 2>/dev/null; then
        mkdir -p /etc/nftables
        cp "$tmp" /etc/nftables/stivaros-zivpn.nft
        nft -f /etc/nftables/stivaros-zivpn.nft 2>/dev/null || true
    fi
    rm -f "$tmp"

    zivpn_update_passwords
    systemctl daemon-reload
    systemctl enable --now "$ZIVPN_SERVICE"
    systemctl restart "$ZIVPN_SERVICE"
    tunnel_active zivpn && msg "ZIVPN actif (port $ZIVPN_PORT)" \
                        || { error "ZIVPN ne démarre pas"; journalctl -u "$ZIVPN_SERVICE" -n 10 --no-pager; return 1; }
    pause
}

zivpn_uninstall() {
    confirm "Supprimer complètement ZIVPN ?" || return 0
    systemctl disable --now zivpn 2>/dev/null || true
    rm -f "/etc/systemd/system/$ZIVPN_SERVICE"
    rm -rf "$ZIVPN_HOME" /etc/nftables/stivaros-zivpn.nft
    nft delete table inet stivaros_zivpn 2>/dev/null || true
    systemctl daemon-reload
    msg "ZIVPN désinstallé"
}

zivpn_cleanup_expired() {
    [[ -f "$ZIVPN_USER_FILE" ]] || return 0
    local today tmp
    today=$(date +%F); tmp=$(mktemp)
    awk -F'|' -v t="$today" '$3 >= t' "$ZIVPN_USER_FILE" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$ZIVPN_USER_FILE"; chmod 600 "$ZIVPN_USER_FILE"
}

zivpn_update_passwords() {
    zivpn_cleanup_expired
    local tmp
    tmp=$(mktemp)
    # FUSION (et non remplacement) des mots de passe: ce serveur peut être
    # co-géré par un autre panel (install2) dont les entrées doivent
    # survivre. Les passwords stivaros expirés/supprimés sont retirés, les
    # autres préservés. Idem pour la map quota.
    STIVAROS_DB="$DB_PATH" ZIVPN_USERS="$ZIVPN_USER_FILE" \
        python3 - "$ZIVPN_CONFIG" "$tmp" << 'PYEOF' 2>/dev/null
import json, os, sqlite3, sys

cfg_path, tmp = sys.argv[1], sys.argv[2]
with open(cfg_path) as f:
    cfg = json.load(f)

# Passwords stivaros actifs (fichier users.list: uuid|pass|expire)
ours = set()
try:
    from datetime import date
    today = date.today().isoformat()
    with open(os.environ["ZIVPN_USERS"]) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 3 and parts[1] and parts[2] >= today:
                ours.add(parts[1])
except Exception:
    pass
try:
    conn = sqlite3.connect(os.environ["STIVAROS_DB"])
    rows = conn.execute("""
        SELECT v.zivpn_password FROM vpn_configs v
        JOIN users u ON v.user_id = u.id
        WHERE v.mode = 'zivpn' AND v.zivpn_password != ''
          AND u.active = 1 AND (u.expires_at IS NULL OR u.expires_at >= DATE('now'))
    """).fetchall()
    conn.close()
    ours |= {r[0] for r in rows if r[0]}
except Exception:
    pass

existing = cfg.get("auth", {}).get("config", [])
if not isinstance(existing, list):
    existing = []
stale = set()
try:
    from datetime import date
    today = date.today().isoformat()
    with open(os.environ["ZIVPN_USERS"]) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 3 and parts[1] and parts[2] < today:
                stale.add(parts[1])
except Exception:
    pass

merged = sorted((set(existing) - stale) | ours)
cfg.setdefault("auth", {})["config"] = merged

# Quota: ne gère que NOS passwords, préserve les entrées étrangères.
quota = cfg.get("quota") or {}
try:
    conn = sqlite3.connect(os.environ["STIVAROS_DB"])
    rows = conn.execute("""
        SELECT v.zivpn_password, u.quota_mb FROM vpn_configs v
        JOIN users u ON v.user_id = u.id
        WHERE v.mode = 'zivpn' AND v.zivpn_password != ''
          AND u.active = 1 AND (u.expires_at IS NULL OR u.expires_at >= DATE('now'))
    """).fetchall()
    conn.close()
    seen = set()
    for pw, mb in rows:
        if pw and mb and mb > 0:
            # zivpn exige un entier ("1GB", jamais "1.0GB").
            quota[pw] = f"{(mb + 1023) // 1024}GB"
            seen.add(pw)
    for pw in [p for p in quota if p in stale]:
        del quota[pw]
    # À nous, quota illimité (0) -> retirer la clé
    try:
        conn = sqlite3.connect(os.environ["STIVAROS_DB"])
        zeros = conn.execute("""
            SELECT DISTINCT v.zivpn_password FROM vpn_configs v
            JOIN users u ON v.user_id = u.id
            WHERE v.mode = 'zivpn' AND (u.quota_mb IS NULL OR u.quota_mb <= 0)
        """).fetchall()
        conn.close()
        for (pw,) in zeros:
            quota.pop(pw, None)
    except Exception:
        pass
except Exception:
    pass
cfg["quota"] = quota

with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
    if [[ -s "$tmp" ]] && jq empty "$tmp" 2>/dev/null; then
        chmod 600 "$tmp"; mv "$tmp" "$ZIVPN_CONFIG"
        systemctl restart "$ZIVPN_SERVICE" 2>/dev/null || true
    else
        rm -f "$tmp"
        error "Config ZIVPN invalide — inchangée"
        return 1
    fi
}

# ── SSH (base du tunnel SSH+SlowDNS) ───────────────────────────────────
install_ssh() {
    banner; echo -e "${BOLD}OpenSSH (cible du tunnel SSH+SlowDNS)${NC}\n"
    if ! tunnel_installed ssh; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server \
            || die "Échec installation openssh-server"
    fi
    # Durcissement minimal sans casser les clients SSH par mot de passe.
    local cfg=/etc/ssh/sshd_config.d/90-stivaros.conf
    mkdir -p /etc/ssh/sshd_config.d
    cat > "$cfg" << 'EOF'
PasswordAuthentication yes
PermitRootLogin prohibit-password
MaxAuthTries 6
LoginGraceTime 30
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
EOF
    chmod 644 "$cfg"
    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    tunnel_active ssh && msg "OpenSSH actif (port 22)" || { error "sshd ne démarre pas"; return 1; }
    pause
}

# ── V2Ray-DNS (VLESS/TROJAN TCP :5401, cible du tunnel V2Ray+SlowDNS) ──
install_v2ray() {
    banner; echo -e "${BOLD}V2Ray-DNS (cible du tunnel V2Ray+SlowDNS)${NC}\n"

    if ! tunnel_installed v2ray; then
        info "Téléchargement de V2Ray…"
        download_binary "$RELEASES/v2ray" "$V2RAY_BIN" \
            || die "Échec du téléchargement de V2Ray"
    fi

    mkdir -p "$V2RAY_DIR" /var/log/stivaros-v2ray
    [[ -f "$V2RAY_DIR/users.json" ]] || echo '{"vless":[],"trojan":[]}' > "$V2RAY_DIR/users.json"
    chmod 600 "$V2RAY_DIR/users.json"

    cat > "$V2RAY_DIR/config.json" << EOF
{
  "log": { "loglevel": "warning",
           "access": "/var/log/stivaros-v2ray/access.log",
           "error": "/var/log/stivaros-v2ray/error.log" },
  "stats": {},
  "api": { "tag": "api", "services": ["StatsService"] },
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    { "port": $V2RAY_PORT, "listen": "127.0.0.1", "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "none" },
      "tag": "VLESS-TCP" },
    { "tag": "api", "listen": "127.0.0.1", "port": 10087,
      "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1" } }
  ],
  "outbounds": [{ "protocol": "freedom", "settings": {} }],
  "routing": { "rules": [
    { "type": "field", "inboundTag": ["api"], "outboundTag": "api" }
  ] }
}
EOF
    chmod 600 "$V2RAY_DIR/config.json"

    cat > "/etc/systemd/system/$V2RAY_SERVICE" << EOF
[Unit]
Description=Stivaros V2Ray-DNS (instance dédiée :$V2RAY_PORT)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$V2RAY_BIN run -config $V2RAY_DIR/config.json
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$V2RAY_SERVICE"
    v2ray_sync_users
    tunnel_active v2ray && msg "V2Ray-DNS actif (port $V2RAY_PORT, loopback)" \
                        || { error "V2Ray ne démarre pas"; journalctl -u "$V2RAY_SERVICE" -n 10 --no-pager; return 1; }
    pause
}

v2ray_uninstall() {
    confirm "Supprimer complètement V2Ray-DNS ?" || return 0
    systemctl disable --now "$V2RAY_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$V2RAY_SERVICE"
    rm -rf "$V2RAY_DIR" /var/log/stivaros-v2ray
    systemctl daemon-reload
    msg "V2Ray-DNS désinstallé"
}

# clients = UUID xray des comptes actifs (réutilisés côté VLESS/TROJAN).
v2ray_sync_users() {
    [[ -f "$DB_PATH" && -f "$V2RAY_DIR/config.json" ]] || return 0
    STIVAROS_DB="$DB_PATH" python3 - << 'PYEOF' 2>/dev/null || true
import json, os, sqlite3

db = os.environ["STIVAROS_DB"]
clients = []
try:
    conn = sqlite3.connect(db)
    rows = conn.execute("""
        SELECT DISTINCT v.xray_uuid FROM vpn_configs v
        JOIN users u ON v.user_id = u.id
        WHERE u.active = 1 AND (u.expires_at IS NULL OR u.expires_at >= DATE('now'))
    """).fetchall()
    clients = [{"id": r[0], "password": r[0], "level": 0, "email": r[0]}
               for r in rows if r[0]]
    conn.close()
except Exception:
    pass
conf = "/etc/stivaros-v2ray/config.json"
with open(conf) as f:
    cfg = json.load(f)
for ib in cfg.get("inbounds", []):
    if ib.get("tag") == "VLESS-TCP":
        ib["settings"]["clients"] = clients
tmp = conf + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
os.replace(tmp, conf)
PYEOF
    tunnel_active v2ray && systemctl restart "$V2RAY_SERVICE"
}

# ── SlowDNS (dnstt NS4→SSH:22, NV4→V2Ray:5401, dnsdist routeur :5300) ──
install_slowdns() {
    banner; echo -e "${BOLD}SlowDNS (dnstt + dnsdist) — SSH & V2Ray over DNS${NC}\n"

    # Les cibles doivent exister avant le frontal DNS.
    ensure_tunnel ssh    || return 1
    ensure_tunnel v2ray  || return 1

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsdist nftables 2>/dev/null \
        || die "Échec installation dnsdist/nftables"

    if ! tunnel_installed slowdns; then
        info "Téléchargement de dnstt-server…"
        download_binary "$RELEASES/dnstt-server" "$DNSTT_BIN" \
            || die "Échec du téléchargement de dnstt-server"
    fi

    mkdir -p "$SLOWDNS_DIR" /var/log/slowdns

    # Paire de clés dnstt propre à CE serveur (jamais de clé partagée en dur).
    if [[ ! -s "$SLOWDNS_DIR/server.key" ]]; then
        "$DNSTT_BIN" -gen-key -privkey-file "$SLOWDNS_DIR/server.key" \
            -pubkey-file "$SLOWDNS_DIR/server.pub"
    fi
    chmod 600 "$SLOWDNS_DIR/server.key"; chmod 644 "$SLOWDNS_DIR/server.pub"

    # Sous-domaines NS délégués vers ce serveur.
    local ns4 nv4 domain def
    domain=$(ask_domain)
    # Compat install2.py: fichiers legacy /etc/slowdns/ns.conf et
    # /etc/slowdns/nv4/ns.conf.
    ns4=$(head -1 "$SLOWDNS_DIR/ns4.conf" 2>/dev/null || true)
    ns4=${ns4:-$(head -1 "$SLOWDNS_DIR/ns.conf" 2>/dev/null || true)}
    nv4=$(head -1 "$SLOWDNS_DIR/nv4.conf" 2>/dev/null || true)
    nv4=${nv4:-$(head -1 "$SLOWDNS_DIR/nv4/ns.conf" 2>/dev/null || true)}
    def="ns4.$domain"
    read -r -p "Sous-domaine SSH+SlowDNS [$def]: " ns4; ns4=${ns4:-$def}
    def="nv4.$domain"
    read -r -p "Sous-domaine V2Ray+SlowDNS [$def]: " nv4; nv4=${nv4:-$def}
    valid_domain "$ns4" || die "Sous-domaine NS4 invalide"
    valid_domain "$nv4" || die "Sous-domaine NV4 invalide"
    echo "$ns4" > "$SLOWDNS_DIR/ns4.conf"
    echo "$nv4" > "$SLOWDNS_DIR/nv4.conf"
    chmod 600 "$SLOWDNS_DIR"/{ns4,nv4}.conf

    local mtu
    read -r -p "MTU dnstt [$SLOWDNS_MTU_DEFAULT]: " mtu; mtu=${mtu:-$SLOWDNS_MTU_DEFAULT}
    [[ "$mtu" =~ ^[0-9]{3,4}$ ]] || mtu=$SLOWDNS_MTU_DEFAULT

    # Wrappers de démarrage (cibles lues au runtime).
    cat > /usr/local/bin/slowdns-ns4-start.sh << EOF
#!/bin/bash
NS=\$(cat $SLOWDNS_DIR/ns4.conf)
exec $DNSTT_BIN -udp 0.0.0.0:$DNSTT_NS4_PORT -mtu $mtu \\
    -privkey-file $SLOWDNS_DIR/server.key "\$NS" 127.0.0.1:22
EOF
    cat > /usr/local/bin/slowdns-nv4-start.sh << EOF
#!/bin/bash
NV4=\$(cat $SLOWDNS_DIR/nv4.conf)
exec $DNSTT_BIN -udp 0.0.0.0:$DNSTT_NV4_PORT -mtu $mtu \\
    -privkey-file $SLOWDNS_DIR/server.key "\$NV4" 127.0.0.1:$V2RAY_PORT
EOF
    chmod 755 /usr/local/bin/slowdns-ns4-start.sh /usr/local/bin/slowdns-nv4-start.sh

    for svc in slowdns-ns4 slowdns-nv4; do
        cat > "/etc/systemd/system/$svc.service" << EOF
[Unit]
Description=Stivaros SlowDNS dnstt ($svc)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStartPre=/bin/sleep 3
ExecStart=/usr/local/bin/$svc-start.sh
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    done

    # dnsdist expose :5300 et route selon le suffixe NS vers le bon dnstt.
    mkdir -p /etc/dnsdist
    cat > /etc/dnsdist/dnsdist.conf << EOF
setSecurityPollSuffix("")
setACL({"0.0.0.0/0", "::/0"})
addLocal("0.0.0.0:$DNSDIST_PORT")
newServer({address="127.0.0.1:$DNSTT_NS4_PORT", pool="ns4"})
newServer({address="127.0.0.1:$DNSTT_NV4_PORT", pool="nv4"})
addAction(makeRule("$ns4."), PoolAction("ns4"))
addAction(makeRule("$nv4."), PoolAction("nv4"))
addAction(AllRule(), RCodeAction(5))
EOF
    chmod 640 /etc/dnsdist/dnsdist.conf
    mkdir -p /etc/systemd/system/dnsdist.service.d
    cat > /etc/systemd/system/dnsdist.service.d/override.conf << 'EOF'
[Unit]
StartLimitIntervalSec=0
StartLimitBurst=0
[Service]
Restart=always
RestartSec=5
EOF

    # Port 53 (DNS) -> dnsdist :5300
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" << EOF
table inet slowdns {
    chain prerouting {
        type nat hook prerouting priority -150;
        udp dport 53 redirect to :$DNSDIST_PORT
        tcp dport 53 redirect to :$DNSDIST_PORT
    }
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport 53 accept
        udp dport $DNSDIST_PORT accept
    }
}
EOF
    if nft -c -f "$tmp" 2>/dev/null; then
        mkdir -p /etc/nftables
        cp "$tmp" /etc/nftables/slowdns.nft
        nft -f /etc/nftables/slowdns.nft 2>/dev/null || true
    fi
    rm -f "$tmp"

    systemctl daemon-reload
    systemctl enable --now slowdns-ns4 slowdns-nv4 dnsdist
    systemctl restart slowdns-ns4 slowdns-nv4 dnsdist
    sleep 2
    if tunnel_active slowdns; then
        msg "SlowDNS actif : NS4=$ns4 (SSH:22)  NV4=$nv4 (V2Ray:$V2RAY_PORT)"
        echo -e "  ${CYAN}Clé publique dnstt:${NC} $(cat "$SLOWDNS_DIR/server.pub")"
    else
        error "SlowDNS: un service n'a pas démarré"; return 1
    fi
    pause
}

slowdns_uninstall() {
    confirm "Supprimer complètement SlowDNS ?" || return 0
    systemctl disable --now slowdns-ns4 slowdns-nv4 dnsdist 2>/dev/null || true
    rm -f /etc/systemd/system/slowdns-ns4.service /etc/systemd/system/slowdns-nv4.service \
          /etc/systemd/system/dnsdist.service.d/override.conf \
          /usr/local/bin/slowdns-ns4-start.sh /usr/local/bin/slowdns-nv4-start.sh "$DNSTT_BIN"
    rm -rf "$SLOWDNS_DIR" /etc/nftables/slowdns.nft
    nft delete table inet slowdns 2>/dev/null || true
    systemctl daemon-reload
    msg "SlowDNS désinstallé"
}

# ══════════════════════════════════════════════════════════════════════
#  API D'ACTIVATION (compatible application EPHANG VPN)
# ══════════════════════════════════════════════════════════════════════

# Câble l'API derrière le HAProxy existant sur :443 (les carriers
# "gratuits" n'ouvrent souvent que 53/80/443 — les ports 8443/5443/9090
# sont reset). Deux styles de config gérés:
#   - "xray-tls" (install2): HAProxy TERMINE TLS -> backend API clair :9090
#   - "tls_in"   (panel)     : HAProxy passthrough -> backend API TLS :9443
haproxy_wire_api() {
    local cfg=/etc/haproxy/haproxy.cfg
    [[ -f "$cfg" ]] || return 0
    command -v haproxy &>/dev/null || return 0
    grep -q "stivaros_api" "$cfg" && return 0
    python3 - << 'PYEOF'
cfg_path = "/etc/haproxy/haproxy.cfg"
cfg = open(cfg_path).read()
backend_line = "127.0.0.1:9090"        # style TLS-terminé (mode http)
anchor = "    default_backend"
target = None
if "frontend xray-tls" in cfg:
    target = "frontend xray-tls\n"
elif "frontend tls_in" in cfg:
    target = "frontend tls_in\n"
    backend_line = "127.0.0.1:9443 ssl verify none"  # style passthrough
if target:
    idx = cfg.index(target) + len(target)
    # insérer les ACL juste après le premier bloc d'acl du frontend
    n = idx
    while True:
        nl = cfg.find("\n", n)
        line = cfg[n:nl] if nl != -1 else ""
        if line.startswith("    acl "):
            n = nl + 1
        else:
            break
    ins = ("    acl is_stivaros_api req.hdr(host) -i api-v1.kingom.ggff.net\n"
           "    acl is_stivaros_api ssl_fc_sni -i api-v1.kingom.ggff.net\n"
           "    use_backend stivaros_api if is_stivaros_api\n")
    cfg = cfg[:n] + ins + cfg[n:]
    cfg += ("\nbackend stivaros_api\n    server api " + backend_line + "\n")
    open(cfg_path, "w").write(cfg)
    print("patched")
PYEOF
    local out=$?
    if [[ $out -eq 0 ]] && grep -q "stivaros_api" "$cfg"; then
        haproxy -c -f "$cfg" &>/dev/null && systemctl restart haproxy \
            && info "HAProxy: api-v1.kingom.ggff.net -> API (:443)"
    fi
}

# Endpoint HTTPS dédié sur :8443 (2e hôte de l'app). Le frontend :443 est
# en mode TCP avec ALPN h2 — les clients Go négocient HTTP/2 et la réponse
# casse. Ce frontend force HTTP/1.1 et parle clair à l'API (:9090).
haproxy_api_8443() {
    command -v haproxy &>/dev/null || return 0
    local cfg=/etc/haproxy/haproxy.cfg pem=/etc/haproxy/api-v1.pem
    if [[ ! -f "$pem" ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 1095 \
            -keyout /etc/haproxy/api-v1.key -out /etc/haproxy/api-v1.crt \
            -subj "/CN=api-v1.kingom.ggff.net" \
            -addext "subjectAltName=DNS:api-v1.kingom.ggff.net" >/dev/null 2>&1 || return 0
        cat /etc/haproxy/api-v1.crt /etc/haproxy/api-v1.key > "$pem"
        chmod 600 "$pem"
    fi
    if ! grep -q "frontend stivaros_api_tls" "$cfg"; then
        cat >> "$cfg" << 'EOF'

frontend stivaros_api_tls
    bind *:8443 ssl crt /etc/haproxy/api-v1.pem alpn http/1.1
    mode http
    option httplog
    default_backend stivaros_api
EOF
    fi
    # Le backend doit être http propre même si créé par haproxy_wire_api.
    if grep -q $'backend stivaros_api\n    server' "$cfg"; then
        python3 - << 'PYEOF'
p = "/etc/haproxy/haproxy.cfg"
s = open(p).read()
old = "backend stivaros_api\n    server api 127.0.0.1:9090"
new = ("backend stivaros_api\n    mode http\n    option http-keep-alive\n"
       "    server api 127.0.0.1:9090")
if old in s:
    open(p, "w").write(s.replace(old, new))
PYEOF
    fi
    command -v ufw &>/dev/null && ufw allow 8443/tcp >/dev/null 2>&1 || true
    haproxy -c -f "$cfg" &>/dev/null && systemctl restart haproxy \
        && info "HAProxy: API HTTPS dédiée sur :8443 (HTTP/1.1)"
}


install_api_server() {
    mkdir -p "$API_DIR"
    cat > "$API_DIR/server.py" << 'PYEOF'
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
                     ("quota_mb", "INTEGER DEFAULT 0"), ("bytes_used", "INTEGER DEFAULT 0"),
                     ("plan", "TEXT DEFAULT 'BASIC'")]:
        # quota_mb/bytes_used/plan ciblent la table users
        table = "users" if col in ("quota_mb", "bytes_used", "plan") else "vpn_configs"
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

    # v2raydns -> instance V2Ray DÉDIÉE stivaros (loopback 5402, plus jamais
    # la config partagée /etc/v2ray qu'un autre panel écrase).
    conn.execute(
        "UPDATE vpn_configs SET server_port = 5402 WHERE mode = 'v2raydns'")

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

def account_card(user):
    """Bloc « Client » consommé par l'app : identité, abonnement et quota
    REELS (bytes_used est alimenté par quota.py toutes les 2 min, donc les
    données restantes évoluent avec la consommation effective)."""
    q = user["quota_mb"] or 0
    used = user["bytes_used"] or 0
    limit_b = q * 1024 * 1024
    remaining = -1 if q <= 0 else max(0, limit_b - used)
    plan = user["plan"] if "plan" in user.keys() else None
    return {
        "name": user["name"] or "",
        "phone": user["phone"] or "",
        "plan": plan or "BASIC",
        "expires_at": user["expires_at"] or "",
        "quota_mb": q,
        "bytes_used": used,
        "data_limit_bytes": limit_b,
        "data_remaining_bytes": remaining,
        "unlimited": q <= 0,
        "active": 1 if user["active"] else 0,
    }

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
                return self._send({"activated": True, "phone": user["phone"],
                                   "name": user["name"], "expires_at": user["expires_at"],
                                   "account": account_card(user),
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
                elif mode == "v2raydns":
                    label = "V2Ray + SlowDNS"
                elif mode == "sshslowdns":
                    label = "SSH + SlowDNS"
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
                               "account": account_card(user),
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
PYEOF
    chmod 750 "$API_DIR/server.py"
    msg "API server installé"
}

install_api() {
    banner; echo -e "${BOLD}Installation API d'activation${NC}\n"
    ensure_deps
    mkdir -p "$INSTALL_DIR"
    install_api_server

    # Clé API: générée une seule fois, conservée aux réinstallations.
    if [[ ! -f "$CONFIG_PATH" ]]; then
        local secret
        secret=$(generate_secret)
        cat > "$CONFIG_PATH" << EOF
{"port": $API_PORT, "db": "$DB_PATH", "api_key": "$secret", "version": "2.0.0"}
EOF
        chmod 600 "$CONFIG_PATH"
    fi

    python3 "$API_DIR/server.py" & local pid=$!
    sleep 1; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Stivaros VPN API Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$API_DIR
ExecStart=/usr/bin/env python3 $API_DIR/server.py
Restart=always
RestartSec=5
Environment="STIVAROS_DB=$DB_PATH"
Environment="STIVAROS_PORT=$API_PORT"

[Install]
WantedBy=multi-user.target
EOF
    # Certificat TLS local pour le listener :9443 (backend HAProxy SNI).
    # Auto-signé CN=api-v1... : uniquement vu entre HAProxy et l'API en
    # interne ; l'app est tolérante et journalise l'empreinte.
    if [[ ! -s "$API_DIR/api.crt" ]]; then
        self_signed "$API_DIR/api.key" "$API_DIR/api.crt" "api-v1.kingom.ggff.net"
    fi

    systemctl daemon-reload
    systemctl enable --now stivaros-api
    systemctl restart stivaros-api

    # Exposer l'API via le :443 existant (voir haproxy_wire_api).
    haproxy_wire_api || true
    haproxy_api_8443 || true

    command -v ufw &>/dev/null && ufw allow "$API_PORT/tcp" 2>/dev/null || true

    msg "API active sur le port $API_PORT"
    local show_key
    show_key=$(python3 -c 'import json;print(json.load(open("/opt/stivaros/config.json"))["api_key"])' 2>/dev/null || echo "?")
    echo -e "${YELLOW}  Clé API (à conserver) : $show_key${NC}"
    log "API installée (port $API_PORT)"
    pause
}

# ══════════════════════════════════════════════════════════════════════
#  CONFIG ORANGE ILLIMITÉ (host unique, administrable)
# ══════════════════════════════════════════════════════════════════════

orange_host_get() { [[ -f "$ORANGE_HOST_FILE" ]] && head -1 "$ORANGE_HOST_FILE" | tr -d '[:space:]' || true; }

# Définit (ou remplace) LE host Orange; propage à toutes les configs
# orange existantes. Un seul host possible: l'ancien est écrasé.
orange_host_set() {
    local h="$1"
    valid_domain "$h" || { error "Host invalide: $h"; return 1; }
    mkdir -p "$INSTALL_DIR"
    echo "$h" > "$ORANGE_HOST_FILE"; chmod 600 "$ORANGE_HOST_FILE"
    [[ -f "$DB_PATH" ]] && \
        sql "UPDATE vpn_configs SET host='$(sqlq "$h")' WHERE isp='orange' AND mode='xray';"
    msg "Host Orange défini: $h (${BOLD}remplacé partout${NC})"
    log "orange host -> $h"
}

orange_host_delete() {
    rm -f "$ORANGE_HOST_FILE"
    [[ -f "$DB_PATH" ]] && \
        sql "UPDATE vpn_configs SET host='' WHERE isp='orange' AND mode='xray';"
    warn "Host Orange supprimé (les configs orange sont incomplètes tant qu'aucun host n'est défini)"
}

orange_menu() {
    banner; echo -e "${BOLD}Config Orange Illimité — host XHTTP${NC}\n"
    echo -e "  SNI/adresse (fixes) : ${CYAN}$ORANGE_ADDR${NC}"
    echo -e "  Path                : ${CYAN}$XRAY_PATH${NC}"
    local cur
    cur=$(orange_host_get)
    echo -e "  Host actuel         : ${CYAN}${cur:-<aucun>}${NC}"
    echo
    echo "  1) Ajouter / remplacer le host"
    echo "  2) Supprimer le host"
    echo "  0) Retour"
    echo
    local c
    printf "  ${GOLD}► Option${NC} ${WHITE}:${NC} "; read -r c
    case "$c" in
        1)
            local h
            read -r -p "Host (ex: xxx.platformsh.site): " h
            [[ -n "$h" ]] && orange_host_set "$h"
            ;;
        2)
            confirm "Supprimer le host Orange ?" && orange_host_delete
            ;;
    esac
    pause
}

# ══════════════════════════════════════════════════════════════════════
#  GESTION DES COMPTES
# ══════════════════════════════════════════════════════════════════════

# Crée (ou remplace) le compte SSH système d'un utilisateur (SSH+SlowDNS).
ssh_account_upsert() { # $1 user $2 pass $3 expire (YYYY-MM-DD)
    local user="$1" pass="$2" exp="$3"
    if id "$user" &>/dev/null; then
        echo "$user:$pass" | chpasswd
        usermod -U "$user" 2>/dev/null || true
    else
        useradd -M -N -s /usr/sbin/nologin "$user"
        echo "$user:$pass" | chpasswd
    fi
    chage -E "$exp" "$user" 2>/dev/null || true
}

ssh_account_delete() { # $1 user
    id "$1" &>/dev/null && userdel -r "$1" 2>/dev/null || userdel "$1" 2>/dev/null || true
}

create_user() {
    banner; echo -e "${BOLD}Nouveau compte${NC}\n"
    [[ -f "$DB_PATH" ]] || { error "API non installée (option 1)"; pause; return 1; }

    local name uuid phone expires
    read -r -p "Nom (a-z0-9._-)      : " name
    valid_name "$name"  || { error "Nom invalide"; pause; return 1; }
    read -r -p "Téléphone            : " phone
    valid_phone "$phone" || { error "Téléphone invalide (8-15 chiffres)"; pause; return 1; }

    # ── Verrou d'appareil ────────────────────────────────────────────────
    # Le compte est verrouillé sur l'UUID de l'appareil (affichable et
    # copiable depuis l'écran d'activation de l'app). Mono : activation et
    # récupération des configs REFUSÉES depuis tout autre appareil, même
    # avec le bon téléphone et le bon code. Multi : aucun contrôle d'UUID.
    echo
    echo -e "  ${BOLD}Appareils autorisés pour ce compte :${NC}"
    echo -e "   ${CYAN}1${NC}) Mono-appareil — verrouillé sur un seul UUID"
    echo -e "   ${CYAN}2${NC}) Multi-appareils — tout UUID accepté (compte partageable)"
    local dev_mode multi_device=0 dev_uuid=""
    read -r -p "Choix [1]: " dev_mode
    case "${dev_mode:-1}" in
        1) multi_device=0 ;;
        2) multi_device=1 ;;
        *) error "Choix invalide"; pause; return 1 ;;
    esac
    if [[ "$multi_device" == "0" ]]; then
        read -r -p "UUID appareil        : " dev_uuid
        if [[ -n "$dev_uuid" ]]; then
            valid_uuid "$dev_uuid" || { error "UUID invalide (format 8-4-4-4-12 hex)"; pause; return 1; }
            dev_uuid=$(printf '%s' "$dev_uuid" | tr -d '[:space:]' | tr 'A-F' 'a-f')
        else
            info "Vide : le compte se verrouillera sur le premier appareil qui l'activera"
        fi
    fi
    # users.uuid = identifiant interne du compte, toujours généré ; le
    # verrou d'appareil vit dans device_install_id (voir init_db).
    uuid=$(gen_uuid)
    read -r -p "Expiration (YYYY-MM-DD): " expires
    valid_date "$expires" || { error "Date invalide"; pause; return 1; }
    [[ "$(date -d "$expires" +%s)" -gt "$(date +%s)" ]] \
        || { error "Date d'expiration dans le passé"; pause; return 1; }
    local quota_mb
    read -r -p "Quota data en Mo (0 = illimité): " quota_mb
    [[ "$quota_mb" =~ ^[0-9]+$ ]] || { error "Quota invalide"; pause; return 1; }

    # Sélection des configurations à servir via l'API : une, plusieurs
    # (liste séparée par des virgules) ou toutes ("0" ou "t"). L'app
    # s'adapte automatiquement : elle n'affiche que les configs présentes
    # et n'active le round-robin SlowDNS que si la paire 3+4 est servie.
    echo
    echo -e "  ${BOLD}Configs à inclure dans l'API :${NC}"
    echo -e "   ${CYAN}1${NC}) XRAY   (MTN 150/100 + Orange illimité)"
    echo -e "   ${CYAN}2${NC}) ZIVPN  (Camtel UDP)"
    echo -e "   ${CYAN}3${NC}) SSH + SlowDNS"
    echo -e "   ${CYAN}4${NC}) V2Ray + SlowDNS"
    echo -e "   ${CYAN}0${NC}) Toutes"
    local cfg_sel
    read -r -p "Choix (ex: 1,3,4 ou 0 pour tout): " cfg_sel
    cfg_sel=$(printf '%s' "$cfg_sel" | tr -d ' ')
    [[ -n "$cfg_sel" ]] || cfg_sel="0"
    case "$cfg_sel" in t|T|toutes|all) cfg_sel="0" ;; esac
    [[ "$cfg_sel" =~ ^[0-4,]+$ ]] || { error "Sélection invalide"; pause; return 1; }
    want() {                  # want <n> -> vrai si le groupe est choisi
        [[ ",$cfg_sel," == *",0,"* || ",$cfg_sel," == *",$1,"* ]]
    }
    local want_xray=0 want_zivpn=0 want_sshdns=0 want_v2dns=0
    if want 1; then want_xray=1; fi
    if want 2; then want_zivpn=1; fi
    if want 3; then want_sshdns=1; fi
    if want 4; then want_v2dns=1; fi
    [[ $((want_xray + want_zivpn + want_sshdns + want_v2dns)) -ge 1 ]] \
        || { error "Aucune config choisie"; pause; return 1; }

    # Les tunnels nécessaires sont détectés puis installés au besoin,
    # uniquement pour les familles de configs choisies.
    echo
    info "Vérification des tunnels…"
    local ok=1
    if (( want_xray )); then ensure_tunnel xray || ok=0; fi
    if (( want_zivpn )); then ensure_tunnel zivpn || ok=0; fi
    # slowdns implique ssh + v2ray
    if (( want_sshdns || want_v2dns )); then ensure_tunnel slowdns || ok=0; fi
    [[ $ok -eq 1 ]] || { error "Tunnels incomplets — voir ci-dessus"; pause; return 1; }

    local domain server_addr code xray_uuid zivpn_pass ssh_pass ns4 nv4 dnstt_pub
    domain=$(get_domain)
    server_addr=${domain:-$(hostname -I | awk '{print $1}')}
    code=$(gen_code)
    xray_uuid=$(gen_uuid)
    zivpn_pass=$(gen_pass 12)
    ssh_pass=$(gen_pass 12)
    ns4=$(head -1 "$SLOWDNS_DIR/ns4.conf" 2>/dev/null || true)
    ns4=${ns4:-$(head -1 "$SLOWDNS_DIR/ns.conf" 2>/dev/null || true)}
    nv4=$(head -1 "$SLOWDNS_DIR/nv4.conf" 2>/dev/null || true)
    nv4=${nv4:-$(head -1 "$SLOWDNS_DIR/nv4/ns.conf" 2>/dev/null || true)}
    dnstt_pub=$(cat "$SLOWDNS_DIR/server.pub" 2>/dev/null | tr -d '[:space:]')

    # Le compte SSH Linux porte le téléphone normalisé (chiffres seuls,
    # useradd n'accepte ni '+' ni espaces) avec préfixe alpha: useradd
    # refuse les noms 100% numériques ("invalid user name").
    local ssh_user="u${phone#+}"
    ssh_user="u$(printf '%s' "$phone" | tr -dc '0-9')"

    local e_name e_phone e_srv e_ns4 e_nv4 e_pub e_sshuser
    e_name=$(sqlq "$name"); e_phone=$(sqlq "$phone")
    e_srv=$(sqlq "$server_addr"); e_sshuser=$(sqlq "$ssh_user")
    e_ns4=$(sqlq "$ns4"); e_nv4=$(sqlq "$nv4"); e_pub=$(sqlq "$dnstt_pub")

    {
    cat << SQL
INSERT INTO users (uuid, phone, name, activation_code, expires_at, active, quota_mb, multi_device, device_install_id)
VALUES ('$uuid', '$e_phone', '$e_name', '$code', '$expires', 1, $quota_mb, $multi_device, '$(sqlq "$dev_uuid")');
SQL
    if (( want_xray )); then
    cat << SQL
-- MTN 150Mo (SNI fixe: mtnplay.com) et MTN 100Mo (SNI fixe: yamo.mtn.cm),
-- VLESS + WebSocket + TLS, path /vless, host = domaine du serveur.
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path)
SELECT id, '$e_srv', 443, 'vless', 'ws', 1, 'mtnplay.com', '$e_srv', 'mtn', '', '', '150', '$xray_uuid', '/vless' FROM users WHERE uuid='$uuid';
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path)
SELECT id, '$e_srv', 443, 'vless', 'ws', 1, 'yamo.mtn.cm', '$e_srv', 'mtn', '', '', '100', '$xray_uuid', '/vless' FROM users WHERE uuid='$uuid';

-- Orange illimité: SNI/adresse fixes, host XHTTP administrable (menu 8),
-- uuid propre au compte, path = path du tunnel Xray.
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path)
SELECT id, '$ORANGE_ADDR', 443, 'vless', 'xhttp', 1, '$ORANGE_ADDR', '$(sqlq "$(orange_host_get)")', 'orange', 'xray', '0', '$xray_uuid', '$XRAY_PATH' FROM users WHERE uuid='$uuid';
SQL
    fi
    if (( want_zivpn )); then
    cat << SQL
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range)
SELECT id, '$e_srv', $ZIVPN_PORT, 'zivpn', 'udp', 0, '$e_srv', '$e_srv', 'camtel', 'zivpn', '150', '$xray_uuid', '$zivpn_pass', '$ZIVPN_RANGES' FROM users WHERE uuid='$uuid';
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range)
SELECT id, '$e_srv', $ZIVPN_PORT, 'zivpn', 'udp', 0, '$e_srv', '$e_srv', '', 'zivpn', '100', '$xray_uuid', '$zivpn_pass', '$ZIVPN_RANGES' FROM users WHERE uuid='$uuid';
SQL
    fi
    if (( want_sshdns )); then
    cat << SQL
-- Deux profils identiques : l'app les combine en round-robin (2 connexions
-- dnstt parallèles -> agrégation de débit). Labels distincts posés par l'API.
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass)
SELECT id, '$e_srv', 22, 'ssh', 'dnstt', 0, '$e_srv', '$e_srv', '', 'sshslowdns', '150', '$xray_uuid', '$e_ns4', '$e_pub', '$e_sshuser', '$ssh_pass' FROM users WHERE uuid='$uuid';
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass)
SELECT id, '$e_srv', 22, 'ssh', 'dnstt', 0, '$e_srv', '$e_srv', '', 'sshslowdns', '150', '$xray_uuid', '$e_ns4', '$e_pub', '$e_sshuser', '$ssh_pass' FROM users WHERE uuid='$uuid';
SQL
    fi
    if (( want_v2dns )); then
    cat << SQL
-- Deux profils identiques pour le round-robin V2Ray+SlowDNS (même principe).
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey)
SELECT id, '$e_srv', $V2RAY_PORT, 'vless', 'dnstt', 0, '$e_srv', '$e_srv', '', 'v2raydns', '150', '$xray_uuid', '$e_nv4', '$e_pub' FROM users WHERE uuid='$uuid';
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey)
SELECT id, '$e_srv', $V2RAY_PORT, 'vless', 'dnstt', 0, '$e_srv', '$e_srv', '', 'v2raydns', '150', '$xray_uuid', '$e_nv4', '$e_pub' FROM users WHERE uuid='$uuid';
SQL
    fi
    } | sqlite3 -batch "$DB_PATH"

    # Provisionne les identifiants côté tunnels.
    if (( want_sshdns )); then
        ssh_account_upsert "$ssh_user" "$ssh_pass" "$expires"
    fi

    if (( want_zivpn )) && tunnel_active zivpn; then
        zivpn_cleanup_expired
        grep -v "^$uuid|" "$ZIVPN_USER_FILE" > "$ZIVPN_USER_FILE.tmp" 2>/dev/null || true
        echo "$uuid|$zivpn_pass|$expires" >> "$ZIVPN_USER_FILE.tmp"
        mv "$ZIVPN_USER_FILE.tmp" "$ZIVPN_USER_FILE"; chmod 600 "$ZIVPN_USER_FILE"
        zivpn_update_passwords || true
    fi
    if (( want_xray )); then xray_sync_uuids || true; fi
    if (( want_xray || want_v2dns )); then v2ray_sync_users || true; fi

    log "compte créé: $name ($phone) expire $expires"
    echo
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Compte créé${NC}"
    echo -e "  Nom        : $name"
    echo -e "  Téléphone  : $phone"
    echo -e "  Code 6 ch. : ${BOLD}$code${NC}"
    echo -e "  Expire     : $expires"
    if [[ "$multi_device" == "1" ]]; then
        echo -e "  Appareils  : ${CYAN}multi-appareils (tout UUID accepté)${NC}"
    else
        echo -e "  Appareils  : ${YELLOW}mono-appareil — verrou UUID strict${NC}"
        echo -e "  UUID lié   : ${dev_uuid:-<verrou à la première activation>}"
    fi
    echo -e "${GREEN}  ── Configs générées ──${NC}"
    if (( want_xray )); then
        echo -e "${CYAN}  XRAY       : $server_addr:443 vless+xhttp+tls uuid=$xray_uuid${NC}"
    fi
    if (( want_zivpn )); then
        echo -e "${CYAN}  ZIVPN      : $server_addr:$ZIVPN_PORT pass=$zivpn_pass${NC}"
    fi
    if (( want_sshdns )); then
        echo -e "${CYAN}  SSH+SlowDNS: NS=$ns4 user=$ssh_user pass=$ssh_pass${NC}"
    fi
    if (( want_v2dns )); then
        echo -e "${CYAN}  V2Ray+SlowDNS: NS=$nv4 uuid=$xray_uuid port=$V2RAY_PORT${NC}"
    fi
    if (( want_sshdns || want_v2dns )); then
        echo -e "${CYAN}  dnstt pub  : $dnstt_pub${NC}"
    fi
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    pause
}

list_users() {
    banner
    [[ -f "$DB_PATH" ]] || { error "API non installée (option 1)"; pause; return 1; }
    local i=0 today
    today=$(date +%F)
    box_top
    box_title "GESTION DES COMPTES"
    box_mid
    while IFS='|' read -r name phone expires active md used quota; do
        i=$((i + 1))
        local status
        if [[ "$active" -eq 0 ]]; then status="${RED}● bloqué${NC}"
        elif [[ -n "$expires" && "$expires" < "$today" ]]; then status="${YELLOW}● expiré${NC}"
        else status="${LIME}● actif${NC}"; fi
        # Quota: quota_mb est en Mo; convertir en bytes pour fmt_bytes
        local qtxt used_b quota_b
        used_b=$((used)); quota_b=$((quota * 1024 * 1024))
        if (( quota > 0 )); then
            qtxt="$(fmt_bytes "$used_b") / $(fmt_bytes "$quota_b")"
        else
            qtxt="$(fmt_bytes "$used_b") / illimité"
        fi
        # Ligne 1: nom + statut ; Ligne 2: tel + expiration + quota
        box_line "  ${WHITE}${BOLD}${name}${NC} ${status}"
        box_line "  ${GRAY}${phone}${NC} ${GRAY}exp:${WHITE} ${expires:-jamais}${NC}"
        box_line "  ${GRAY}data:${NC} ${GOLD}${qtxt}${NC}"
        box_sep
    done < <(sqlite3 -batch "$DB_PATH" \
        "SELECT COALESCE(name,''), phone, COALESCE(expires_at,''), active,
                COALESCE(multi_device,0), COALESCE(bytes_used,0), COALESCE(quota_mb,0)
           FROM users ORDER BY id;")
    if [[ $i -eq 0 ]]; then
        box_line "  ${GRAY}Aucun compte — utilisez l'option 2${NC}"
        box_sep
    fi
    box_line "  ${GRAY}Total: ${i} compte(s)${NC}"
    box_bot
    pause
}

delete_users() {
    banner; echo -e "${BOLD}Suppression de comptes${NC}\n"
    [[ -f "$DB_PATH" ]] || { error "API non installée (option 1)"; pause; return 1; }

    printf "${CYAN}%-3s | %-14s | %-36s${NC}\n" "#" "Téléphone" "UUID"
    printf -- "----|----------------|--------------------------------------\n"
    local ids=()
    while IFS='|' read -r id phone uuid; do
        ids+=("$id")
        printf "%-3s | %-14s | %-36s\n" "$id" "$phone" "$uuid"
    done < <(sqlite3 -batch "$DB_PATH" "SELECT id, phone, uuid FROM users ORDER BY id;")
    ((${#ids[@]})) || { warn "Aucun compte"; pause; return 0; }

    local input
    echo; read -r -p "Numéros à supprimer (ex: 1,3) : " input
    [[ "$input" =~ ^[0-9,\ ]+$ ]] || { error "Entrée invalide"; pause; return 1; }

    local deleted=0
    IFS=',' read -ra nums <<< "$input"
    for n in "${nums[@]}"; do
        n=$(echo "$n" | tr -d '[:space:]')
        [[ " ${ids[*]} " == *" $n "* ]] || { warn "#$n inconnu"; continue; }
        local phone
        phone=$(sqlite3 -batch "$DB_PATH" "SELECT phone FROM users WHERE id=$n;")
        sql "DELETE FROM vpn_configs WHERE user_id=$n;"
        sql "DELETE FROM users WHERE id=$n;"
        [[ -n "$phone" ]] && ssh_account_delete "u$(printf %s "$phone" | tr -dc 0-9)"
        msg "Compte #$n supprimé"
        deleted=$((deleted + 1))
    done
    if ((deleted > 0)); then
        xray_sync_uuids || true
        v2ray_sync_users || true
        tunnel_active zivpn && zivpn_update_passwords || true
    fi
    pause
}

# ══════════════════════════════════════════════════════════════════════
#  QUOTA DATA (synchrone, tous tunnels, blocage automatique)
#
#  Sources de comptage:
#    - Xray  : API stats locale (xray api statsquery, compteurs par email=uuid)
#    - V2Ray : même mécanisme (v2ray api statsquery)
#    - ZIVPN : enforcement NATIF (map quota par mot de passe) + lecture du
#              quota-state.json pour l'affichage
#  Les compteurs des process repartent à 0 à chaque restart: on accumule
#  les deltas dans users.bytes_used (state: /opt/stivaros/quota_state.json).
#  Quota atteint -> compte bloqué partout (users.active=0 + retrait des
#  credentials dans chaque tunnel + lock du compte SSH système).
# ══════════════════════════════════════════════════════════════════════

install_quota_engine() {
    cat > "$QUOTA_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""Stivaros quota engine: accumulate per-account traffic and block over-quota."""
import json, os, sqlite3, subprocess, sys

DB = os.environ.get("STIVAROS_DB", "/opt/stivaros/stivaros.db")
STATE = os.environ.get("STIVAROS_QUOTA_STATE", "/opt/stivaros/quota_state.json")
XRAY = "/usr/local/bin/xray"
V2RAY = "/usr/local/bin/v2ray"

def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(s):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.replace(tmp, STATE)
    os.chmod(STATE, 0o600)

def stats_query_xray(binary, addr):
    """Sortie proto-text Xray: name: "user>>>EMAIL>>>traffic>>>uplink" / value: N."""
    try:
        r = subprocess.run([binary, "api", "statsquery", "--server=" + addr,
                            "-pattern", "user>>>"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    out = {}
    last_name = ""
    for line in r.stdout.splitlines():
        clean = line.strip().replace('"', " ")
        parts = clean.split()
        if parts[:1] == ["name:"]:
            last_name = parts[1] if len(parts) > 1 else ""
            continue
        if parts[:1] == ["value:"] and ">>>" in last_name:
            seg = last_name.split(">>>")
            if len(seg) >= 4 and seg[0] == "user" and seg[2] == "traffic":
                try:
                    out[seg[1]] = out.get(seg[1], 0) + int(parts[1])
                except (ValueError, IndexError):
                    pass
            last_name = ""
    return out

def stats_query_v2ray(binary, addr):
    """CLI V2Ray réelle: `v2ray api stats -json ... "user>>>"`
    (le binaire n'a pas de sous-commande statsquery, et le service gRPC est
    nommé v2ray.app.*, pas xray.app.* -> le client xray ne peut pas l'appeler).
    Sortie: {"stat":[{"name": "user>>>EMAIL>>>traffic>>>uplink", "value": "N"}]}."""
    try:
        r = subprocess.run([binary, "api", "stats", "-json",
                            "--server=" + addr, "user>>>"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    out = {}
    try:
        data = json.loads(r.stdout)
    except Exception:
        return {}
    for ent in data.get("stat", []):
        seg = str(ent.get("name", "")).split(">>>")
        if len(seg) >= 4 and seg[0] == "user" and seg[2] == "traffic":
            try:
                out[seg[1]] = out.get(seg[1], 0) + int(ent.get("value") or 0)
            except (ValueError, TypeError):
                pass
    return out

# --- comptabilisation SSH par utilisateur (ssh_slowdns) -------------------
# Les tunnels SSH (directs ou via dnstt) sortent par des processus sshd
# appartenant à l'utilisateur système "u<tel>". nftables peut donc compter
# par UID (meta skuid) dans les deux sens : output (requêtes) et input
# (réponses vers la socket possédée par l'utilisateur).

NFT_TABLE = "stivaros_quota"
NFT_COMMENT_PREFIX = "stq-"

def _nft(*args):
    return subprocess.run(["nft"] + list(args),
                          capture_output=True, text=True, timeout=10)

def nft_ensure_schema():
    if _nft("list", "table", "inet", NFT_TABLE).returncode != 0:
        if _nft("add", "table", "inet", NFT_TABLE).returncode != 0:
            return False
    for hook in ("output", "input"):
        if _nft("list", "chain", "inet", NFT_TABLE, hook).returncode != 0:
            _nft("add", "chain", "inet", NFT_TABLE, hook,
                 "{", "type", "filter", "hook", hook, "priority", "0", ";",
                 "policy", "accept", ";", "}")
    return True

def nft_sync_ssh(users, state, usage_now):
    """Règles nft par login + lecture des compteurs -> usage_now[*]["ssh"]."""
    import pwd
    if not nft_ensure_schema():
        return
    wanted = {}   # login -> uid
    for u in users:
        login = "u" + "".join(c for c in (u["phone"] or "") if c.isdigit())
        if login == "u":
            continue
        try:
            wanted[login] = pwd.getpwnam(login).pw_uid
        except KeyError:
            continue
    existing = {}  # login -> {"handle": h, "bytes": b} (somme in+out)
    for hook in ("output", "input"):
        try:
            r = _nft("-j", "list", "chain", "inet", NFT_TABLE, hook)
            data = json.loads(r.stdout or "{}")
        except Exception:
            continue
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            comment = rule.get("comment") or ""
            if not comment.startswith(NFT_COMMENT_PREFIX):
                continue
            login = comment[len(NFT_COMMENT_PREFIX):]
            nbytes = 0
            for expr in rule.get("expr", []):
                counter = expr.get("counter")
                if counter:
                    nbytes = int(counter.get("bytes", 0))
            e = existing.setdefault(login, {"handles": [], "bytes": 0})
            e["handles"].append(rule.get("handle"))
            e["bytes"] += nbytes
    # Ajouter les règles manquantes.
    for login, uid in wanted.items():
        if login not in existing:
            for hook in ("output", "input"):
                _nft("add", "rule", "inet", NFT_TABLE, hook,
                     "meta", "skuid", str(uid), "counter",
                     "comment", NFT_COMMENT_PREFIX + login)
    # Retirer les règles des comptes supprimés (plus de login système).
    for hook in ("output", "input"):
        try:
            r = _nft("-j", "list", "chain", "inet", NFT_TABLE, hook)
            data = json.loads(r.stdout or "{}")
        except Exception:
            continue
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            comment = rule.get("comment") or ""
            if comment.startswith(NFT_COMMENT_PREFIX) and \
                    comment[len(NFT_COMMENT_PREFIX):] not in wanted:
                _nft("delete", "rule", "inet", NFT_TABLE, hook,
                     "handle", str(rule.get("handle")))
    # Attribuer les octets aux comptes.
    for u in users:
        login = "u" + "".join(c for c in (u["phone"] or "") if c.isdigit())
        if login in existing:
            usage_now.setdefault(u["uuid"], {})["ssh"] = existing[login]["bytes"]

def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    users = conn.execute(
        "SELECT id, uuid, name, phone, quota_mb, bytes_used, active FROM users").fetchall()

    state = load_state()
    usage_now = {}      # uuid -> bytes constatés ce cycle
    # Xray: client statsquery (proto-text). V2Ray: client stats -json.
    if os.path.exists(XRAY):
        for uuid, total in stats_query_xray(XRAY, "127.0.0.1:10085").items():
            usage_now.setdefault(uuid, {})["xray"] = total
    if os.path.exists(V2RAY):
        for uuid, total in stats_query_v2ray(V2RAY, "127.0.0.1:10087").items():
            usage_now.setdefault(uuid, {})["v2ray"] = total
    # ZIVPN: compteurs natifs par mot de passe -> retrouver l'uuid.
    # Instance dédiée stivaros (5668) d'abord, puis instance partagée
    # (5667) en complément : la valeur d'un mot de passe présent dans les
    # deux n'est pas additionnée (setdefault).
    zivpn_states = [os.environ.get("STIVAROS_ZIVPN_STATE",
                                   "/etc/stivaros-zivpn/quota-state.json"),
                    "/etc/zivpn/quota-state.json"]
    try:
        pw_rows = conn.execute(
            "SELECT v.zivpn_password, u.uuid FROM vpn_configs v"
            " JOIN users u ON v.user_id = u.id WHERE v.zivpn_password != ''").fetchall()
        pw2uuid = {r[0]: r[1] for r in pw_rows}
        pw_used = {}
        for zpath in zivpn_states:
            try:
                with open(zpath) as f:
                    zstate = json.load(f)
            except Exception:
                continue
            used_map = zstate.get("used", zstate) if isinstance(zstate, dict) else {}
            for pw, total in (used_map.items() if isinstance(used_map, dict) else []):
                try:
                    pw_used.setdefault(pw, int(total))
                except (TypeError, ValueError):
                    pass
        for pw, total in pw_used.items():
            uuid = pw2uuid.get(pw)
            if uuid:
                usage_now.setdefault(uuid, {})["zivpn"] = total
    except Exception:
        pass

    # SSH (ssh_slowdns / ssh direct): compteurs nftables par UID.
    nft_sync_ssh(users, state, usage_now)

    # Accumulation delta (compteurs remis à 0 au restart du tunnel).
    for uuid, per in usage_now.items():
        prev = state.get(uuid, {})
        delta = 0
        for src, val in per.items():
            last = int(prev.get(src, 0))
            delta += val - last if val >= last else val  # restart -> tout compte
        if delta > 0:
            conn.execute("UPDATE users SET bytes_used = COALESCE(bytes_used,0) + ? WHERE uuid = ?",
                         (delta, uuid))
        state[uuid] = per

    # Quota dépassé -> blocage du compte (tous tunnels).
    blocked = []
    for u in users:
        q = u["quota_mb"] or 0
        if q <= 0 or not u["active"]:
            continue
        used = conn.execute("SELECT bytes_used FROM users WHERE id = ?",
                            (u["id"],)).fetchone()[0] or 0
        if used >= q * 1024 * 1024:
            conn.execute("UPDATE users SET active = 0 WHERE id = ?", (u["id"],))
            blocked.append(u)
    conn.commit()

    # Purge des credentials dans chaque tunnel pour les bloqués.
    for u in blocked:
        # SSH système (le login créé par le panel est préfixé de "u").
        ssh_user = "u" + "".join(c for c in (u["phone"] or "") if c.isdigit())
        if ssh_user != "u":
            subprocess.run(["usermod", "-L", ssh_user], capture_output=True)
        sys.stderr.write("[quota] BLOQUE: %s (%s)\n" % (u["name"], u["uuid"]))
    conn.close()
    save_state(state)
    if blocked:
        # Resynchronise xray/v2ray/zivpn sans les comptes bloqués.
        os.system("/usr/local/bin/stivaros-sync 2>/dev/null || true")
    return 0

if __name__ == "__main__":
    sys.exit(main())
PYEOF
    chmod 750 "$QUOTA_SCRIPT"

    # Helper de resynchronisation appelé après blocage: recharge les
    # credentials de tous les tunnels sans rien réinstaller.
    cat > /usr/local/bin/stivaros-sync << 'EOF'
#!/bin/bash
for p in /usr/local/bin/stivaros.sh /opt/stivaros/stivaros.sh; do
    [ -f "$p" ] && exec bash "$p" --sync-only
done
# Fallback: aucune copie du panel trouvée.
exit 0
EOF
    chmod 755 /usr/local/bin/stivaros-sync

    # Timer systemd: quota vérifié toutes les 2 minutes.
    cat > /etc/systemd/system/stivaros-quota.service << EOF
[Unit]
Description=Stivaros quota accounting/enforcement

[Service]
Type=oneshot
Environment="STIVAROS_DB=$DB_PATH"
Environment="STIVAROS_QUOTA_STATE=$QUOTA_STATE"
ExecStart=/usr/bin/env python3 $QUOTA_SCRIPT
EOF
    cat > /etc/systemd/system/$QUOTA_TIMER << 'EOF'
[Unit]
Description=Stivaros quota engine (2 min)

[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$QUOTA_TIMER"
    msg "Moteur de quota actif (toutes les 2 min)"
}

fmt_bytes() {
    python3 -c "
b=float('$1' or 0)
for u in ('o','Ko','Mo','Go','To'):
    if b < 1024 or u=='To':
        print(f'{b:.1f} {u}' if u!='o' else f'{int(b)} o'); break
    b/=1024"
}

# Affiche nom / expiration / consommation quota par compte.
quotas_menu() {
    banner; echo -e "${BOLD}Quotas data par compte${NC}\n"
    [[ -f "$DB_PATH" ]] || { error "API non installée"; pause; return 1; }
    printf "${CYAN}%-3s | %-12s | %-10s | %-18s | %s${NC}\n" \
        "#" "Nom" "Expire" "Utilisé / Quota" "Statut"
    printf -- "----|--------------|------------|--------------------|----------\n"
    local today
    today=$(date +%F)
    while IFS='|' read -r id name expires quota used active; do
        local qtxt st
        if [[ "$quota" -gt 0 ]]; then
            qtxt="$(fmt_bytes "$used") / $((quota)) Mo"
        else
            qtxt="$(fmt_bytes "$used") / illimité"
        fi
        if [[ "$active" -eq 0 ]]; then st="${RED}bloqué${NC}"
        elif [[ -n "$expires" && "$expires" < "$today" ]]; then st="${YELLOW}expiré${NC}"
        else st="${GREEN}actif${NC}"; fi
        printf "%-3s | %-12s | %-10s | %-18s | %b\n" "$id" "$name" "$expires" "$qtxt" "$st"
    done < <(sqlite3 -batch "$DB_PATH" \
        "SELECT id, COALESCE(name,''), COALESCE(expires_at,''), COALESCE(quota_mb,0), COALESCE(bytes_used,0), active FROM users ORDER BY id;")
    echo
    echo "  1) Modifier le quota d'un compte"
    echo "  2) Débloquer un compte (quota réinitialisé à 0)"
    echo "  0) Retour"
    echo
    local c
    printf "  ${GOLD}► Option${NC} ${WHITE}:${NC} "; read -r c
    case "$c" in
        1)
            local id q
            read -r -p "N° compte: " id
            [[ "$id" =~ ^[0-9]+$ ]] || { error "N° invalide"; pause; return; }
            read -r -p "Nouveau quota (Mo, 0 = illimité): " q
            [[ "$q" =~ ^[0-9]+$ ]] || { error "Quota invalide"; pause; return; }
            sql "UPDATE users SET quota_mb=$q WHERE id=$id;"
            zivpn_update_passwords 2>/dev/null || true
            msg "Quota mis à jour"
            ;;
        2)
            local id
            read -r -p "N° compte: " id
            [[ "$id" =~ ^[0-9]+$ ]] || { error "N° invalide"; pause; return; }
            sql "UPDATE users SET active=1, bytes_used=0 WHERE id=$id;"
            local phone
            phone=$(sqlite3 -batch "$DB_PATH" "SELECT phone FROM users WHERE id=$id;")
            ssh_account_delete_lock "${phone#+}" 2>/dev/null || true
            xray_sync_uuids; v2ray_sync_users; zivpn_update_passwords
            msg "Compte #$id débloqué, compteur remis à zéro"
            ;;
    esac
    pause
}

ssh_account_delete_lock() {
    local u="u$(printf '%s' "$1" | tr -dc '0-9')"
    [[ -n "$u" && "$u" != "u" ]] && id "$u" &>/dev/null && usermod -U "$u" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════
#  MENUS
# ══════════════════════════════════════════════════════════════════════

tunnels_status() {
    banner; echo -e "${BOLD}État des tunnels${NC}\n"
    tunnel_badge xray    "Xray          (VLESS+XHTTP+TLS :443)"
    tunnel_badge zivpn   "ZIVPN         (UDP :$ZIVPN_PORT, DNAT $ZIVPN_RANGE)"
    tunnel_badge ssh     "SSH           (base SSH+SlowDNS, :22)"
    tunnel_badge v2ray   "V2Ray-DNS     (base V2Ray+SlowDNS, :$V2RAY_PORT)"
    tunnel_badge slowdns "SlowDNS       (dnstt + dnsdist :$DNSDIST_PORT)"
    echo
    if [[ -f "$SLOWDNS_DIR/server.pub" ]]; then
        local ns4 nv4
        ns4=$(cat "$SLOWDNS_DIR/ns4.conf" 2>/dev/null || cat "$SLOWDNS_DIR/ns.conf" 2>/dev/null || true)
        nv4=$(cat "$SLOWDNS_DIR/nv4.conf" 2>/dev/null || cat "$SLOWDNS_DIR/nv4/ns.conf" 2>/dev/null || true)
        echo -e "${CYAN}dnstt pub : $(cat "$SLOWDNS_DIR/server.pub")${NC}"
        echo -e "${CYAN}NS4 (ssh) : ${ns4:-<non configuré>}${NC}"
        echo -e "${CYAN}NV4 (v2r) : ${nv4:-<non configuré>}${NC}"
    fi
    pause
}

tunnel_menu() {
    while true; do
        banner; echo -e "${BOLD}${GOLD}Gestion des tunnels${NC}\n"
        box_top
        box_title "ÉTAT DES SERVICES"
        box_mid
        box_line "  $(tunnel_state xray    >/dev/null; tun_dot xray)    ${WHITE}Xray${NC}      ${GRAY}(VLESS+XHTTP+TLS :443)${NC}"
        box_line "  $(tunnel_state zivpn   >/dev/null; tun_dot zivpn)    ${WHITE}ZIVPN${NC}     ${GRAY}(UDP :${ZIVPN_PORT}, DNAT ${ZIVPN_RANGE})${NC}"
        box_line "  $(tunnel_state ssh     >/dev/null; tun_dot ssh)    ${WHITE}SSH${NC}       ${GRAY}(base SSH+SlowDNS, :22)${NC}"
        box_line "  $(tunnel_state v2ray   >/dev/null; tun_dot v2ray)    ${WHITE}V2Ray-DNS${NC} ${GRAY}(base V2Ray+SlowDNS, :${V2RAY_PORT})${NC}"
        box_line "  $(tunnel_state slowdns >/dev/null; tun_dot slowdns)    ${WHITE}SlowDNS${NC}   ${GRAY}(dnstt + dnsdist :${DNSDIST_PORT})${NC}"
        box_bot
        echo
        box_top
        box_title "ACTIONS"
        box_mid
        box_line "  ${GOLD}${BOLD}1${NC}${WHITE})${NC} Installer / réparer ${CYAN}Xray${NC}"
        box_line "  ${GOLD}${BOLD}2${NC}${WHITE})${NC} Installer / réparer ${CYAN}ZIVPN${NC}"
        box_line "  ${GOLD}${BOLD}3${NC}${WHITE})${NC} Installer / réparer ${CYAN}SSH${NC}"
        box_line "  ${GOLD}${BOLD}4${NC}${WHITE})${NC} Installer / réparer ${CYAN}V2Ray-DNS${NC}"
        box_line "  ${GOLD}${BOLD}5${NC}${WHITE})${NC} Installer / réparer ${CYAN}SlowDNS${NC} ${GRAY}(SSH+V2Ray/DNS)${NC}"
        box_line "  ${GOLD}${BOLD}6${NC}${WHITE})${NC} ${LIME}Tout installer${NC} ${GRAY}(dans l'ordre)${NC}"
        box_line "  ${GOLD}${BOLD}7${NC}${WHITE})${NC} État détaillé"
        box_line "  ${GOLD}${BOLD}8${NC}${WHITE})${NC} ${RED}Désinstaller un tunnel${NC}"
        box_line "  ${GOLD}${BOLD}0${NC}${WHITE})${NC} Retour"
        box_bot
        echo
        local c=""
        # EOF (entrée fermée / mode pipe) → quitter au lieu de boucler.
        printf "  ${GOLD}► Option${NC} ${WHITE}:${NC} "; read -r c || { echo; exit 0; }
        case "$c" in
            1) install_xray || true ;;
            2) install_zivpn || true ;;
            3) install_ssh || true ;;
            4) install_v2ray || true ;;
            5) install_slowdns || true ;;
            6) for t in xray zivpn ssh v2ray slowdns; do ensure_tunnel "$t" || true; done; pause ;;
            7) tunnels_status || true ;;
            8)
                local t=""
                read -r -p "Tunnel à supprimer (xray/zivpn/ssh/v2ray/slowdns): " t || true
                case "$t" in
                    xray)    xray_uninstall ;;
                    zivpn)   zivpn_uninstall ;;
                    v2ray)   v2ray_uninstall ;;
                    slowdns) slowdns_uninstall ;;
                    *) warn "Inconnu: $t" ;;
                esac
                pause ;;
            0) return ;;
            *) warn "Choix invalide" ;;
        esac
    done
}

install_all() {
    banner; echo -e "${BOLD}Installation complète${NC}\n"
    ensure_deps
    install_api_server
    # Service API
    if ! systemctl is-active --quiet stivaros-api; then
        local secret
        secret=$(generate_secret)
        cat > "$CONFIG_PATH" << EOF
{"port": $API_PORT, "db": "$DB_PATH", "api_key": "$secret", "version": "2.0.0"}
EOF
        chmod 600 "$CONFIG_PATH"
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Stivaros VPN API Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$API_DIR
ExecStart=/usr/bin/env python3 $API_DIR/server.py
Restart=always
RestartSec=5
Environment="STIVAROS_DB=$DB_PATH"
Environment="STIVAROS_PORT=$API_PORT"

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now stivaros-api
        # Cert TLS local (backend HAProxy SNI -> API).
        if [[ ! -s "$API_DIR/api.crt" ]]; then
            self_signed "$API_DIR/api.key" "$API_DIR/api.crt" "api-v1.kingom.ggff.net"
        fi
        install_quota_engine
        msg "API installée (port $API_PORT)"
        echo -e "${YELLOW}  Clé API : $secret${NC}"
        echo -e "${CYAN}  Astuce: menu 1 rejoue le câblage HAProxy (SNI api-v1 -> :9443)${NC}"
    else
        msg "API déjà installée"
    fi

    echo
    info "Tunnels (détection automatique, installation si absent)…"
    # Un tunnel en échec ne doit pas faire quitter le script: on enchaîne
    # et on rapporte à la fin.
    local failed=0
    for t in xray zivpn ssh v2ray slowdns; do
        ensure_tunnel "$t" || { error "Tunnel $t: KO"; failed=1; }
    done
    ((failed)) && warn "Certains tunnels n'ont pas abouti (voir ci-dessus)"

    # Câblage HAProxy (voir haproxy_wire_api): expose l'API sur :443.
    haproxy_wire_api || true
    haproxy_api_8443 || true
    echo
    msg "Installation terminée"
    pause
}

uninstall_all() {
    banner; echo -e "${BOLD}Désinstallation complète${NC}\n"
    echo -e "${RED}Ceci supprime l'API, la base de comptes et tous les tunnels gérés.${NC}\n"
    confirm "Confirmer ?"        || { info "Annulé"; pause; return; }
    confirm "Vraiment sûr ?"    || { info "Annulé"; pause; return; }

    systemctl disable --now stivaros-api 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    # Ne pas confirmer à nouveau: suppression silencieuse des briques.
    xray_uninstall_silent 2>/dev/null || true
    zivpn_uninstall_silent 2>/dev/null || true
    v2ray_uninstall_silent 2>/dev/null || true
    slowdns_uninstall_silent 2>/dev/null || true
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    msg "Stivaros complètement désinstallé"
    pause
}

xray_uninstall_silent()    { systemctl disable --now xray 2>/dev/null; rm -f /etc/systemd/system/xray.service "$XRAY_BIN"; rm -rf "$XRAY_DIR"; }
zivpn_uninstall_silent()   { systemctl disable --now "$ZIVPN_SERVICE" 2>/dev/null; rm -f "/etc/systemd/system/$ZIVPN_SERVICE"; rm -rf "$ZIVPN_HOME" /etc/nftables/stivaros-zivpn.nft; nft delete table inet stivaros_zivpn 2>/dev/null; }
v2ray_uninstall_silent()   { systemctl disable --now "$V2RAY_SERVICE" 2>/dev/null; rm -f "/etc/systemd/system/$V2RAY_SERVICE"; rm -rf "$V2RAY_DIR" /var/log/stivaros-v2ray; }
slowdns_uninstall_silent() { systemctl disable --now slowdns-ns4 slowdns-nv4 dnsdist 2>/dev/null; rm -f /etc/systemd/system/slowdns-ns4.service /etc/systemd/system/slowdns-nv4.service "$DNSTT_BIN" /usr/local/bin/slowdns-ns4-start.sh /usr/local/bin/slowdns-nv4-start.sh; rm -rf "$SLOWDNS_DIR" /etc/nftables/slowdns.nft; nft delete table inet slowdns 2>/dev/null; }

# ── Appareils & verrouillage UUID ────────────────────────────────────
# Gestion fine du verrou par compte :
#   1) bascule mono -> multi (tout UUID accepté)
#   2) bascule multi -> mono (verrou sur l'appareil lié ou sur un UUID fourni)
#   3) réinitialisation de l'appareil lié (ex : client a réinstallé l'app,
#      son UUID a changé) — la prochaine activation devient le nouveau verrou.
manage_devices() {
    banner; echo -e "${BOLD}Appareils & verrouillage UUID${NC}\n"
    [[ -f "$DB_PATH" ]] || { error "API non installée (option 1)"; pause; return 1; }
    printf "${CYAN}%-3s | %-12s | %-14s | %-7s | %s${NC}\n" "#" "Nom" "Téléphone" "Mode" "Appareil lié"
    printf -- "----|--------------|----------------|---------|--------------------------------------\n"
    local i=0 ids=() names=() mds=() dids=()
    while IFS='|' read -r id name phone md did; do
        i=$((i + 1))
        local m="mono" l="${did:-<aucun>}"
        [[ "$md" == "1" ]] && m="multi"
        printf "%-3s | %-12s | %-14s | %-7s | %.36s\n" "$id" "$name" "$phone" "$m" "$l"
        ids+=("$id"); names+=("$name"); mds+=("$md"); dids+=("$did")
    done < <(sqlite3 -batch "$DB_PATH" \
        "SELECT id, COALESCE(name,''), phone, COALESCE(multi_device,0), COALESCE(device_install_id,'') FROM users ORDER BY id;")
    [[ $i -eq 0 ]] && { warn "Aucun compte"; pause; return 1; }
    echo
    echo "  1) Passer un compte en multi-appareils"
    echo "  2) Verrouiller un compte en mono-appareil"
    echo "  3) Réinitialiser l'appareil lié (autorise une nouvelle activation)"
    echo "  4) Définir l'UUID de l'appareil lié"
    echo "  0) Retour"
    echo
    local action
    printf "  ${GOLD}► Option${NC} ${WHITE}:${NC} "; read -r action
    [[ "$action" == "0" ]] && return 0
    [[ "$action" =~ ^[1-4]$ ]] || { warn "Choix invalide"; pause; return 1; }
    local pick
    read -r -p "N° du compte : " pick
    [[ "$pick" =~ ^[0-9]+$ ]] || { error "N° invalide"; pause; return 1; }
    local id="" md="" did=""
    local j
    for ((j = 0; j < ${#ids[@]}; j++)); do
        if [[ "${ids[$j]}" == "$pick" ]]; then id="${ids[$j]}"; md="${mds[$j]}"; did="${dids[$j]}"; break; fi
    done
    [[ -n "$id" ]] || { error "Compte introuvable"; pause; return 1; }
    case "$action" in
        1)
            sql "UPDATE users SET multi_device = 1 WHERE id = $pick;"
            msg "Compte #$pick passé en multi-appareils (tout UUID accepté)"
            log "appareil: compte #$pick -> multi"
            ;;
        2)
            if [[ -z "$did" ]]; then
                local nu=""
                read -r -p "UUID de l'appareil (vide = verrouillage à la prochaine activation): " nu
                if [[ -n "$nu" ]]; then
                    valid_uuid "$nu" || { error "UUID invalide"; pause; return 1; }
                    nu=$(printf '%s' "$nu" | tr -d '[:space:]' | tr 'A-F' 'a-f')
                    sql "UPDATE users SET multi_device = 0, device_install_id = '$(sqlq "$nu")' WHERE id = $pick;"
                    msg "Compte #$pick verrouillé sur $nu"
                else
                    sql "UPDATE users SET multi_device = 0 WHERE id = $pick;"
                    msg "Compte #$pick en mono — se verrouillera à la prochaine activation"
                fi
            else
                # En multi, l'appareil lié est une LISTE séparée par des
                # virgules : en repassant en mono on ne conserve que le
                # dernier appareil activé (le plus récent = le plus probable).
                local last="${did##*,}"
                sql "UPDATE users SET multi_device = 0, device_install_id = '$(sqlq "$last")' WHERE id = $pick;"
                msg "Compte #$pick verrouillé en mono sur le dernier appareil connu : $last"
            fi
            log "appareil: compte #$pick -> mono"
            ;;
        3)
            sql "UPDATE users SET device_install_id = '' WHERE id = $pick;"
            msg "Appareil lié au compte #$pick réinitialisé (prochaine activation = nouveau verrou)"
            log "appareil: compte #$pick reset device_install_id"
            ;;
        4)
            local nu=""
            read -r -p "UUID de l'appareil : " nu
            valid_uuid "$nu" || { error "UUID invalide (format 8-4-4-4-12 hex)"; pause; return 1; }
            nu=$(printf '%s' "$nu" | tr -d '[:space:]' | tr 'A-F' 'a-f')
            sql "UPDATE users SET device_install_id = '$(sqlq "$nu")' WHERE id = $pick;"
            msg "Appareil lié au compte #$pick -> $nu"
            log "appareil: compte #$pick device_install_id=$nu"
            ;;
    esac
    pause
}

menu() {
    while true; do
        banner
        # Un seul cadre: supervision (dashboard) + options du menu.
        dashboard
        box_line "  ${GOLD}${BOLD}1${NC} ${WHITE})${NC} Installer / réparer le panel ${GRAY}(API + tunnels)${NC}"
        box_line "  ${GOLD}${BOLD}2${NC} ${WHITE})${NC} ${LIME}Créer un compte${NC}"
        box_line "  ${GOLD}${BOLD}3${NC} ${WHITE})${NC} Lister les comptes"
        box_line "  ${GOLD}${BOLD}4${NC} ${WHITE})${NC} Supprimer des comptes"
        box_sep
        box_line "  ${GOLD}${BOLD}5${NC} ${WHITE})${NC} Gestion des tunnels"
        box_line "  ${GOLD}${BOLD}6${NC} ${WHITE})${NC} État des tunnels"
        box_sep
        box_line "  ${GOLD}${BOLD}7${NC} ${WHITE})${NC} Appareils & verrou UUID"
        box_line "  ${GOLD}${BOLD}8${NC} ${WHITE})${NC} Config Orange ${GRAY}(host)${NC}"
        box_line "  ${GOLD}${BOLD}9${NC} ${WHITE})${NC} Quotas & consommation"
        box_sep
        box_line " ${RED}${BOLD}10${NC} ${WHITE})${NC} ${RED}Désinstaller tout${NC}"
        box_line "  ${GOLD}${BOLD}0${NC} ${WHITE})${NC} Quitter"
        box_bot
        echo
        local c=""
        # EOF (entrée fermée / mode pipe) → quitter au lieu de boucler.
        printf "  ${GOLD}► Option${NC} ${WHITE}:${NC} "; read -r c || { echo; exit 0; }
        case "$c" in
            1) install_all || true ;;
            2) create_user || true ;;
            3) list_users || true ;;
            4) delete_users || true ;;
            5) tunnel_menu || true ;;
            6) tunnels_status || true ;;
            7) manage_devices || true ;;
            8) orange_menu || true ;;
            9) quotas_menu || true ;;
            10) uninstall_all || true ;;
            0) echo "Au revoir."; exit 0 ;;
            *) warn "Choix invalide" ;;
        esac
    done
}

# ── Entrée ─────────────────────────────────────────────────────────────
main() {
    check_root
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" && chmod 640 "$LOG_FILE"
    case "${1:-}" in
        --api)       install_api || true ;;
        --create)    create_user || true ;;
        --list)      list_users || true ;;
        --tunnels)   tunnel_menu || true ;;
        --zivpn)     install_zivpn || true ;;
        --sync-only)
            # Appelé par le moteur de quota après un blocage.
            xray_sync_uuids 2>/dev/null || true
            v2ray_sync_users 2>/dev/null || true
            zivpn_update_passwords 2>/dev/null || true
            ;;
        *) menu ;;
    esac
}

main "$@"
