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
#      SSH+SlowDNS (dnstt NS -> SSH:22), V2Ray+SlowDNS (dnstt NV -> V2Ray:5401).
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
readonly ZIVPN_SERVICE="zivpn.service"
readonly ZIVPN_CONFIG="/etc/zivpn/config.json"
readonly ZIVPN_USER_FILE="/etc/zivpn/users.list"
readonly ZIVPN_DOMAIN_FILE="/etc/zivpn/domain.txt"
readonly ZIVPN_PORT=5667
# DNAT serveur (nft) — couvre toutes les sous-plages clients.
readonly ZIVPN_RANGE="6000-19999"
# Plages clients round-robin (8 sous-plages, un processus par plage).
readonly ZIVPN_RANGES="6000-7750,7751-9500,9501-11250,11251-13000,13001-14750,14751-16500,16501-18250,18251-19999"

# SlowDNS (dnstt + dnsdist)
readonly SLOWDNS_DIR="/etc/slowdns"
readonly DNSTT_BIN="/usr/local/bin/dnstt-server"
readonly DNSDIST_PORT=5300
readonly DNSTT_NS4_PORT=5353   # NS4 -> SSH (127.0.0.1:22)
readonly DNSTT_NV4_PORT=5354   # NV4 -> V2Ray (127.0.0.1:5401)
readonly SLOWDNS_MTU_DEFAULT=1232

# V2Ray-DNS
readonly V2RAY_BIN="/usr/local/bin/v2ray"
readonly V2RAY_DIR="/etc/v2ray"
readonly V2RAY_PORT=5401

# Orange illimité: SNI/adresse FIXES, seul le host XHTTP est administrable
# (exactement UN host à la fois, partagé par toutes les configs orange).
readonly ORANGE_ADDR="reprise.orange-business.com"
readonly ORANGE_HOST_FILE="$INSTALL_DIR/orange_host.txt"

# Stats/quota (xray/v2ray exposent leurs compteurs via l'API gRPC locale)
readonly XRAY_STATS_ADDR="127.0.0.1:10085"
readonly V2RAY_STATS_ADDR="127.0.0.1:10086"
readonly QUOTA_STATE="$INSTALL_DIR/quota_state.json"
readonly QUOTA_SCRIPT="$API_DIR/quota.py"
readonly QUOTA_TIMER="stivaros-quota.timer"

# ── Couleurs / sortie ──────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; WHITE=$'\033[1;37m'; NC=$'\033[0m'; BOLD=$'\033[1m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; WHITE=""; NC=""; BOLD=""
fi

log()  { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE" 2>/dev/null || true; }
msg()   { echo -e "${GREEN}[✓]${NC} $1"; log "OK   $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; log "WARN $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; log "ERR  $1"; }
info()  { echo -e "${CYAN}[i]${NC} $1"; log "INFO $1"; }
die()   { error "$1"; exit 1; }

banner() {
    clear
    echo -e "${CYAN}"
    echo '  ╔════════════════════════════════════════════════╗'
    echo '  ║          STIVAROS VPN PANEL  v2.0              ║'
    echo '  ║     Activation API + Gestion des tunnels       ║'
    echo '  ╚════════════════════════════════════════════════╝'
    echo -e "${NC}"
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
        v2ray)   [[ -x "$V2RAY_BIN" && -f /etc/systemd/system/v2ray.service ]] ;;
        ssh)     dpkg -s openssh-server &>/dev/null || command -v sshd &>/dev/null ;;
        *)       return 1 ;;
    esac
}

tunnel_active() {
    case "$1" in
        xray)    systemctl is-active --quiet xray ;;
        zivpn)   systemctl is-active --quiet zivpn ;;
        slowdns) systemctl is-active --quiet slowdns-ns4 \
              && systemctl is-active --quiet slowdns-nv4 \
              && systemctl is-active --quiet dnsdist ;;
        v2ray)   systemctl is-active --quiet v2ray ;;
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

    mkdir -p /etc/zivpn
    local domain
    domain=$(ask_domain)
    echo "$domain" > "$ZIVPN_DOMAIN_FILE"; chmod 600 "$ZIVPN_DOMAIN_FILE"

    if [[ ! -s /etc/zivpn/zivpn.crt ]]; then
        self_signed /etc/zivpn/zivpn.key /etc/zivpn/zivpn.crt "$domain"
    fi

    [[ -f "$ZIVPN_USER_FILE" ]] || : > "$ZIVPN_USER_FILE"
    chmod 600 "$ZIVPN_USER_FILE"

    local stats_token
    stats_token=$(generate_secret)
    cat > "$ZIVPN_CONFIG" << EOF
{
  "listen": ":$ZIVPN_PORT",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "hu\`\`hqb\`c",
  "recv_window_conn": 15728640,
  "recv_window_client": 67108864,
  "disable_mtu_discovery": false,
  "max_conn_client": 4096,
  "exclude_port": [53, 5300, 4466, 36712, 20000],
  "quotaStateFile": "/etc/zivpn/quota-state.json",
  "statsAPI": { "listen": "127.0.0.1:10088", "token": "$stats_token" },
  "quota": {},
  "auth": { "mode": "passwords", "config": ["zi"] }
}
EOF
    chmod 600 "$ZIVPN_CONFIG"

    cat > "/etc/systemd/system/$ZIVPN_SERVICE" << 'EOF'
[Unit]
Description=Stivaros ZIVPN UDP Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
WorkingDirectory=/etc/zivpn
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
table inet zivpn {
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
        cp "$tmp" /etc/nftables/zivpn.nft
        nft -f /etc/nftables/zivpn.nft 2>/dev/null || true
    fi
    rm -f "$tmp"

    zivpn_update_passwords
    systemctl daemon-reload
    systemctl enable --now zivpn
    systemctl restart zivpn
    tunnel_active zivpn && msg "ZIVPN actif (port $ZIVPN_PORT)" \
                        || { error "ZIVPN ne démarre pas"; journalctl -u zivpn -n 10 --no-pager; return 1; }
    pause
}

zivpn_uninstall() {
    confirm "Supprimer complètement ZIVPN ?" || return 0
    systemctl disable --now zivpn 2>/dev/null || true
    rm -f "/etc/systemd/system/$ZIVPN_SERVICE" "$ZIVPN_BIN"
    rm -rf /etc/zivpn /etc/nftables/zivpn.nft
    nft delete table inet zivpn 2>/dev/null || true
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
    local pw tmp
    pw=$(awk -F'|' 'NF>=2 {print $2}' "$ZIVPN_USER_FILE" 2>/dev/null | sort -u | paste -sd, -)
    [[ -z "$pw" ]] && pw="zi"
    tmp=$(mktemp)
    # auth.config = passwords actifs ; quota = map mot-de-passe -> "NGB"
    # (enforcement natif zivpn, compté par authID = password).
    STIVAROS_DB="$DB_PATH" python3 - "$ZIVPN_CONFIG" "$tmp" << 'PYEOF' 2>/dev/null
import json, os, sqlite3, sys

cfg_path, tmp = sys.argv[1], sys.argv[2]
with open(cfg_path) as f:
    cfg = json.load(f)
quota = {}
try:
    conn = sqlite3.connect(os.environ["STIVAROS_DB"])
    rows = conn.execute("""
        SELECT v.zivpn_password, u.quota_mb FROM vpn_configs v
        JOIN users u ON v.user_id = u.id
        WHERE v.mode = 'zivpn' AND v.zivpn_password != ''
          AND u.active = 1 AND (u.expires_at IS NULL OR u.expires_at >= DATE('now'))
    """).fetchall()
    conn.close()
    for pw, mb in rows:
        if mb and mb > 0:
            quota[pw] = f"{mb / 1024:.1f}GB"
except Exception:
    pass
cfg["quota"] = quota
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
    if [[ -s "$tmp" ]] && jq --arg p "$pw" '.auth.config = ($p | split(","))' "$tmp" > "$tmp.2" 2>/dev/null \
       && jq empty "$tmp.2" 2>/dev/null; then
        chmod 600 "$tmp.2"; mv "$tmp.2" "$ZIVPN_CONFIG"; rm -f "$tmp"
        tunnel_active zivpn && systemctl restart zivpn
    else
        rm -f "$tmp" "$tmp.2"
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

    mkdir -p "$V2RAY_DIR" /var/log/v2ray
    [[ -f "$V2RAY_DIR/users.json" ]] || echo '{"vless":[],"trojan":[]}' > "$V2RAY_DIR/users.json"
    chmod 600 "$V2RAY_DIR/users.json"

    cat > "$V2RAY_DIR/config.json" << EOF
{
  "log": { "loglevel": "warning",
           "access": "/var/log/v2ray/access.log",
           "error": "/var/log/v2ray/error.log" },
  "stats": {},
  "api": { "tag": "api", "services": ["StatsService"] },
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    { "port": $V2RAY_PORT, "listen": "0.0.0.0", "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "none" },
      "tag": "VLESS-TCP" },
    { "port": $V2RAY_PORT, "listen": "0.0.0.0", "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "tcp", "security": "none" },
      "tag": "TROJAN-TCP" },
    { "tag": "api", "listen": "127.0.0.1", "port": 10086,
      "protocol": "dokodemo-door", "settings": { "address": "127.0.0.1" } }
  ],
  "outbounds": [{ "protocol": "freedom", "settings": {} }],
  "routing": { "rules": [
    { "type": "field", "inboundTag": ["api"], "outboundTag": "api" }
  ] }
}
EOF
    chmod 600 "$V2RAY_DIR/config.json"

    cat > /etc/systemd/system/v2ray.service << 'EOF'
[Unit]
Description=Stivaros V2Ray-DNS
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/v2ray run -config /etc/v2ray/config.json
Restart=always
RestartSec=5
LimitNOFILE=65536
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now v2ray
    v2ray_sync_users
    tunnel_active v2ray && msg "V2Ray-DNS actif (port $V2RAY_PORT)" \
                        || { error "V2Ray ne démarre pas"; journalctl -u v2ray -n 10 --no-pager; return 1; }
    pause
}

v2ray_uninstall() {
    confirm "Supprimer complètement V2Ray-DNS ?" || return 0
    systemctl disable --now v2ray 2>/dev/null || true
    rm -f /etc/systemd/system/v2ray.service "$V2RAY_BIN"
    rm -rf "$V2RAY_DIR"
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
with open("/etc/v2ray/config.json") as f:
    cfg = json.load(f)
for ib in cfg.get("inbounds", []):
    if ib.get("tag") in ("VLESS-TCP", "TROJAN-TCP"):
        ib["settings"]["clients"] = clients
tmp = "/etc/v2ray/config.json.tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
os.replace(tmp, "/etc/v2ray/config.json")
PYEOF
    tunnel_active v2ray && systemctl restart v2ray
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


install_api_server() {
    mkdir -p "$API_DIR"
    cat > "$API_DIR/server.py" << 'PYEOF'
#!/usr/bin/env python3
"""Stivaros activation API (compat EPHANG VPN)."""
import json, os, sqlite3, sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
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
            bytes_used INTEGER DEFAULT 0
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
                     ("quota_mb", "INTEGER DEFAULT 0"), ("bytes_used", "INTEGER DEFAULT 0")]:
        # quota_mb/bytes_used ciblent la table users
        table = "users" if col in ("quota_mb", "bytes_used") else "vpn_configs"
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
        except Exception:
            pass
    conn.commit()
    conn.close()

def find_user(identifier):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE uuid = ?", (identifier,)).fetchone()
    if not row:
        row = conn.execute("SELECT * FROM users WHERE device_install_id = ?", (identifier,)).fetchone()
    if not row:
        row = conn.execute("SELECT * FROM users WHERE phone = ?", (identifier,)).fetchone()
    conn.close()
    return row

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
        user = find_user(uuid)
        if not user or not user["active"]:
            return None, ({"success": False, "message": "User not found or inactive"}, 404)
        if user["activation_code"] != code:
            return None, ({"success": False, "message": "Invalid activation code"}, 403)
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
                        "6000-7750,7751-9500,9501-11250,11251-13000," \
                        "13001-14750,14751-16500,16501-18250,18251-19999"
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
            uuid = body.get("device_install_id") or body.get("uuid", "")
            phone = str(body.get("phone_number", ""))[:20]
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
            conn.execute("UPDATE users SET device_install_id=?, app_version=? WHERE id=?",
                         (uuid, str(body.get("app_version", ""))[:20], user["id"]))
            conn.commit()
            conn.close()
            return self._send({"success": True, "message": "Device activated successfully",
                               "phone": phone, "expires_at": exp})

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

    httpd = HTTPServer(("0.0.0.0", port), APIHandler)
    print(f"[stivaros-api] HTTP on 0.0.0.0:{port}")

    if os.path.exists(cert) and os.path.exists(key):
        tlsd = HTTPServer(("127.0.0.1", tls_port), APIHandler)
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
    read -r -p "Choix: " c
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
    read -r -p "UUID appareil        : " uuid
    valid_uuid "$uuid"  || { error "UUID invalide (format 8-4-4-4-12 hex)"; pause; return 1; }
    read -r -p "Téléphone            : " phone
    valid_phone "$phone" || { error "Téléphone invalide (8-15 chiffres)"; pause; return 1; }
    read -r -p "Expiration (YYYY-MM-DD): " expires
    valid_date "$expires" || { error "Date invalide"; pause; return 1; }
    [[ "$(date -d "$expires" +%s)" -gt "$(date +%s)" ]] \
        || { error "Date d'expiration dans le passé"; pause; return 1; }
    local quota_mb
    read -r -p "Quota data en Mo (0 = illimité): " quota_mb
    [[ "$quota_mb" =~ ^[0-9]+$ ]] || { error "Quota invalide"; pause; return 1; }

    # Les tunnels nécessaires sont détectés puis installés au besoin.
    echo
    info "Vérification des tunnels…"
    local ok=1
    ensure_tunnel xray    || ok=0
    ensure_tunnel zivpn   || ok=0
    ensure_tunnel slowdns || ok=0   # implique ssh + v2ray
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

    sqlite3 -batch "$DB_PATH" << SQL
INSERT INTO users (uuid, phone, name, activation_code, expires_at, active, quota_mb)
VALUES ('$uuid', '$e_phone', '$e_name', '$code', '$expires', 1, $quota_mb);

-- MTN 150Mo (SNI fixe: mtnplay.com) et MTN 100Mo (SNI fixe: yamo.mtn.cm),
-- VLESS + WebSocket + TLS, path /vless, host = domaine du serveur.
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path)
SELECT id, '$e_srv', 443, 'vless', 'ws', 1, 'mtnplay.com', '$e_srv', 'mtn', '', '', '150', '$xray_uuid', '/vless' FROM users WHERE uuid='$uuid';
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, flow, tier, xray_uuid, path)
SELECT id, '$e_srv', 443, 'vless', 'ws', 1, 'yamo.mtn.cm', '$e_srv', 'mtn', '', '', '100', '$xray_uuid', '/vless' FROM users WHERE uuid='$uuid';

INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range)
SELECT id, '$e_srv', $ZIVPN_PORT, 'zivpn', 'udp', 0, '$e_srv', '$e_srv', 'camtel', 'zivpn', '150', '$xray_uuid', '$zivpn_pass', '$ZIVPN_RANGES' FROM users WHERE uuid='$uuid';
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, zivpn_password, port_range)
SELECT id, '$e_srv', $ZIVPN_PORT, 'zivpn', 'udp', 0, '$e_srv', '$e_srv', '', 'zivpn', '100', '$xray_uuid', '$zivpn_pass', '$ZIVPN_RANGES' FROM users WHERE uuid='$uuid';

-- Orange illimité: SNI/adresse fixes, host XHTTP administrable (menu 8),
-- uuid propre au compte, path = path du tunnel Xray.
INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, path)
SELECT id, '$ORANGE_ADDR', 443, 'vless', 'xhttp', 1, '$ORANGE_ADDR', '$(sqlq "$(orange_host_get)")', 'orange', 'xray', '0', '$xray_uuid', '$XRAY_PATH' FROM users WHERE uuid='$uuid';

INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey, ssh_user, ssh_pass)
SELECT id, '$e_srv', 22, 'ssh', 'dnstt', 0, '$e_srv', '$e_srv', '', 'sshslowdns', '150', '$xray_uuid', '$e_ns4', '$e_pub', '$e_sshuser', '$ssh_pass' FROM users WHERE uuid='$uuid';

INSERT INTO vpn_configs (user_id, server_address, server_port, protocol, transport, tls, sni, host, isp, mode, tier, xray_uuid, nameserver, slowdns_pubkey)
SELECT id, '$e_srv', $V2RAY_PORT, 'vless', 'dnstt', 0, '$e_srv', '$e_srv', '', 'v2raydns', '150', '$xray_uuid', '$e_nv4', '$e_pub' FROM users WHERE uuid='$uuid';
SQL

    # Provisionne les identifiants côté tunnels.
    ssh_account_upsert "$ssh_user" "$ssh_pass" "$expires"

    if tunnel_active zivpn; then
        zivpn_cleanup_expired
        grep -v "^$uuid|" "$ZIVPN_USER_FILE" > "$ZIVPN_USER_FILE.tmp" 2>/dev/null || true
        echo "$uuid|$zivpn_pass|$expires" >> "$ZIVPN_USER_FILE.tmp"
        mv "$ZIVPN_USER_FILE.tmp" "$ZIVPN_USER_FILE"; chmod 600 "$ZIVPN_USER_FILE"
        zivpn_update_passwords || true
    fi
    xray_sync_uuids || true
    v2ray_sync_users || true

    log "compte créé: $name ($phone) expire $expires"
    echo
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Compte créé${NC}"
    echo -e "  Nom        : $name"
    echo -e "  Téléphone  : $phone"
    echo -e "  UUID       : $uuid"
    echo -e "  Code 6 ch. : ${BOLD}$code${NC}"
    echo -e "  Expire     : $expires"
    echo -e "${GREEN}  ── Configs générées ──${NC}"
    echo -e "${CYAN}  XRAY       : $server_addr:443 vless+xhttp+tls uuid=$xray_uuid${NC}"
    echo -e "${CYAN}  ZIVPN      : $server_addr:$ZIVPN_PORT pass=$zivpn_pass${NC}"
    echo -e "${CYAN}  SSH+SlowDNS: NS=$ns4 user=$ssh_user pass=$ssh_pass${NC}"
    echo -e "${CYAN}  V2Ray+SlowDNS: NS=$nv4 uuid=$xray_uuid port=$V2RAY_PORT${NC}"
    echo -e "${CYAN}  dnstt pub  : $dnstt_pub${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    pause
}

list_users() {
    banner; echo -e "${BOLD}Comptes${NC}\n"
    [[ -f "$DB_PATH" ]] || { error "API non installée (option 1)"; pause; return 1; }
    printf "${CYAN}%-3s | %-12s | %-14s | %-10s | %s${NC}\n" "#" "Nom" "Téléphone" "Expire" "Statut"
    printf -- "----|--------------|----------------|------------|---------\n"
    local i=0 today
    today=$(date +%F)
    while IFS='|' read -r id name phone expires active; do
        i=$((i + 1))
        local status
        if [[ "$active" -eq 0 ]]; then status="${RED}désactivé${NC}"
        elif [[ -n "$expires" && "$expires" < "$today" ]]; then status="${YELLOW}expiré${NC}"
        else status="${GREEN}actif${NC}"; fi
        printf "%-3s | %-12s | %-14s | %-10s | %b\n" "$id" "$name" "$phone" "$expires" "$status"
    done < <(sqlite3 -batch "$DB_PATH" \
        "SELECT id, COALESCE(name,''), phone, COALESCE(expires_at,''), active FROM users ORDER BY id;")
    [[ $i -eq 0 ]] && warn "Aucun compte"
    echo -e "\n${CYAN}Total: $i${NC}"
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

def stats_query(binary, addr):
    """Compteurs user>>>email>>>traffic>>>u{plink,downlink} -> {email: bytes}."""
    try:
        r = subprocess.run([binary, "api", "statsquery", "--server=" + addr,
                            "-pattern", "user>>>"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    out = {}
    last_name = ""
    for line in r.stdout.splitlines():
        # sortie proto-text (multiligne):
        #   stat: <
        #     name: "user>>>EMAIL>>>traffic>>>uplink"
        #     value: 1234
        #   >
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

def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    users = conn.execute(
        "SELECT id, uuid, name, phone, quota_mb, bytes_used, active FROM users").fetchall()
    by_uuid = {u["uuid"]: u for u in users}

    state = load_state()
    usage_now = {}      # uuid -> bytes constatés ce cycle
    # Xray / V2Ray: compteurs par email (= uuid)
    for key, binary, addr in (("xray", XRAY, "127.0.0.1:10085"),
                              ("v2ray", V2RAY, "127.0.0.1:10086")):
        if not os.path.exists(binary):
            continue
        for uuid, total in stats_query(binary, addr).items():
            usage_now.setdefault(uuid, {})[key] = total
    # ZIVPN: compteurs natifs par mot de passe -> retrouver l'uuid
    try:
        with open("/etc/zivpn/quota-state.json") as f:
            zstate = json.load(f)
        pw_rows = conn.execute(
            "SELECT v.zivpn_password, u.uuid FROM vpn_configs v"
            " JOIN users u ON v.user_id = u.id WHERE v.zivpn_password != ''").fetchall()
        pw2uuid = {r[0]: r[1] for r in pw_rows}
        used_map = zstate.get("used", zstate) if isinstance(zstate, dict) else {}
        for pw, total in (used_map.items() if isinstance(used_map, dict) else []):
            uuid = pw2uuid.get(pw)
            if uuid:
                try:
                    usage_now.setdefault(uuid, {})["zivpn"] = int(total)
                except (TypeError, ValueError):
                    pass
    except Exception:
        pass

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
        # SSH système
        ssh_user = "u" + "".join(c for c in (u["phone"] or "") if c.isdigit())
        if ssh_user:
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
    read -r -p "Choix: " c
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
        banner; echo -e "${BOLD}Gestion des tunnels${NC}\n"
        tunnel_badge xray    "Xray"
        tunnel_badge zivpn   "ZIVPN"
        tunnel_badge ssh     "SSH"
        tunnel_badge v2ray   "V2Ray-DNS"
        tunnel_badge slowdns "SlowDNS"
        echo
        echo "  1) Installer / réparer Xray"
        echo "  2) Installer / réparer ZIVPN"
        echo "  3) Installer / réparer SSH"
        echo "  4) Installer / réparer V2Ray-DNS"
        echo "  5) Installer / réparer SlowDNS (SSH + V2Ray over DNS)"
        echo "  6) Tout installer (dans l'ordre)"
        echo "  7) État détaillé"
        echo "  8) Désinstaller un tunnel"
        echo "  0) Retour"
        echo
        local c=""
        # EOF (entrée fermée / mode pipe) → quitter au lieu de boucler.
        read -r -p "Choix: " c || { echo; exit 0; }
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
zivpn_uninstall_silent()   { systemctl disable --now zivpn 2>/dev/null; rm -f "/etc/systemd/system/$ZIVPN_SERVICE" "$ZIVPN_BIN"; rm -rf /etc/zivpn /etc/nftables/zivpn.nft; nft delete table inet zivpn 2>/dev/null; }
v2ray_uninstall_silent()   { systemctl disable --now v2ray 2>/dev/null; rm -f /etc/systemd/system/v2ray.service "$V2RAY_BIN"; rm -rf "$V2RAY_DIR"; }
slowdns_uninstall_silent() { systemctl disable --now slowdns-ns4 slowdns-nv4 dnsdist 2>/dev/null; rm -f /etc/systemd/system/slowdns-ns4.service /etc/systemd/system/slowdns-nv4.service "$DNSTT_BIN" /usr/local/bin/slowdns-ns4-start.sh /usr/local/bin/slowdns-nv4-start.sh; rm -rf "$SLOWDNS_DIR" /etc/nftables/slowdns.nft; nft delete table inet slowdns 2>/dev/null; }

menu() {
    while true; do
        banner
        echo -e "${BOLD}Menu principal${NC}\n"
        local api_state="${RED}hors ligne${NC}"
        systemctl is-active --quiet stivaros-api && api_state="${GREEN}actif :$API_PORT${NC}"
        echo -e "  API d'activation : $api_state"
        echo
        echo "  1) Installer / réparer le panel (API + tunnels)"
        echo "  2) Créer un compte"
        echo "  3) Lister les comptes"
        echo "  4) Supprimer des comptes"
        echo "  5) Gestion des tunnels"
        echo "  6) État des tunnels"
        echo "  7) Désinstaller tout"
        echo "  8) Config Orange (host)"
        echo "  9) Quotas & consommation"
        echo "  0) Quitter"
        echo
        local c=""
        # EOF (entrée fermée / mode pipe) → quitter au lieu de boucler.
        read -r -p "Choix: " c || { echo; exit 0; }
        case "$c" in
            1) install_all || true ;;
            2) create_user || true ;;
            3) list_users || true ;;
            4) delete_users || true ;;
            5) tunnel_menu || true ;;
            6) tunnels_status || true ;;
            7) uninstall_all || true ;;
            8) orange_menu || true ;;
            9) quotas_menu || true ;;
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
