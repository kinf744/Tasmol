package com.borum.vpn;

/**
 * Un seul événement du journal d'activité BORUM VPN.
 * Aucune donnée sensible (mot de passe, clé, token, payload, adresse serveur)
 * n'est stockée ici : le message est nettoyé à l'insertion.
 */
public final class VpnEvent {
    public final long id;
    public final long timestamp; // epoch millis
    public final String level; // info, connection, success, warning, error, stop
    public final String component;
    public final String message; // déjà nettoyé des données sensibles
    public final String category; // "connexion", "application", "problemes"
    public final String title;
    public final String description;

    private static long sNextId = 1;

    public VpnEvent(long timestamp, String level, String component, String message) {
        this.id = sNextId++;
        this.timestamp = timestamp;
        this.level = level == null ? "info" : level;
        this.component = component == null ? "app" : component;
        this.message = redact(message == null ? "" : message);
        this.category = categorize(this.level, this.component);
        String[] t = titleFor(this.level, this.component, this.message);
        this.title = t[0];
        this.description = t[1];
    }

    private static String categorize(String level, String component) {
        String l = level.toLowerCase();
        if ("error".equals(l) || "warning".equals(l)) {
            return "problemes";
        }
        if ("connection".equals(l) || "success".equals(l) || "ready".equals(l)
                || "udp-ok".equals(l)) {
            return "connexion";
        }
        if ("app".equals(component.toLowerCase())) {
            return "application";
        }
        return "connexion";
    }

    private static String[] titleFor(String level, String component, String message) {
        String l = level.toLowerCase();
        String m = message.toLowerCase();
        switch (l) {
            case "error":
                return new String[]{"Échec", message};
            case "warning":
                return new String[]{"Avertissement", message};
            case "success":
            case "udp-ok":
            case "ready":
                return new String[]{"Succès", message};
            case "connection":
                return new String[]{"Connexion", message};
            case "stop":
                return new String[]{"Arrêt", message};
            default:
                if (m.contains("connecté") || m.contains("connected")) {
                    return new String[]{"VPN connecté", message};
                }
                if (m.contains("tunnel") || m.contains("tunnel actif")) {
                    return new String[]{"Tunnel VPN", message};
                }
                if (m.contains("authentif") || m.contains("auth")) {
                    return new String[]{"Authentification", message};
                }
                if (m.contains("dns")) {
                    return new String[]{"Résolution DNS", message};
                }
                if (m.contains("démarr") || m.contains("start")) {
                    return new String[]{"Démarrage", message};
                }
                if (m.contains("arrêt") || m.contains("stop") || m.contains("déconnect")) {
                    return new String[]{"Arrêt", message};
                }
                return new String[]{"Événement", message};
        }
    }

    /** Nettoie les données sensibles potentielles du message. */
    private static String redact(String msg) {
        if (msg == null) {
            return "";
        }
        String s = msg;
        // Masque les paires clé=valeur sensibles et tokens/payloads.
        s = s.replaceAll("(?i)(password|pass|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\\s*[:=]\\s*\\S+", "$1=***");
        s = s.replaceAll("(?i)(payload|payload_data|http_payload)\\s*[:=]\\s*\\S+", "$1=***");
        s = s.replaceAll("(?i)(ssh[_-]?user|ssh[_-]?pass|username|login)\\s*[:=]\\s*\\S+", "$1=***");
        // Masque les références aux protocoles/moteurs sensibles (pas de détails de config).
        s = s.replaceAll("(?i)(ssh[_-]?payload|slowdns|zivpn|v2ray|xray|hysteria|clash|libuz)", "[protocole]");
        // Masque les bannières SSH et versions de serveur.
        s = s.replaceAll("(?i)SSH-2\\.0-[^\\s]+", "SSH-2.0-***");
        s = s.replaceAll("(?i)banner[:=]\\s*\\S+", "banner=***");
        // Masque les adresses IPv4 explicites pour éviter de révéler le serveur.
        s = s.replaceAll("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b", "***.***.***");
        return s.trim();
    }

    public boolean matchesFilter(String filter) {
        if (filter == null || "tout".equals(filter)) {
            return true;
        }
        if ("problemes".equals(filter)) {
            return "problemes".equals(category);
        }
        if ("connexion".equals(filter)) {
            return "connexion".equals(category);
        }
        if ("application".equals(filter)) {
            return "application".equals(category);
        }
        return true;
    }

    public int color() {
        String l = level.toLowerCase();
        switch (l) {
            case "success":
            case "udp-ok":
            case "ready":
                return 0xFF34D399; // vert
            case "error":
                return 0xFFF87171; // rouge
            case "warning":
                return 0xFFFB923C; // orange
            case "connection":
                return 0xFF22D3EE; // cyan
            case "stop":
                return 0xFF94A3B8; // gris
            default:
                return 0xFF94A3B8;
        }
    }
}
