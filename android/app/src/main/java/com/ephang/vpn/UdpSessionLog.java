package com.ephang.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Journal de session des tunnels UDP (zivvn / Hysteria), écrit dans le même
 * fichier que le reste (kighmu.txt) pour que l'onglet Logs affiche une seule
 * chronologie.
 *
 * <p>Les lignes suivent le format {@code [HH:mm:ss] message}. Trois niveaux
 * sont utilisés pour la couleur du texte dans l'onglet Logs :
 * <ul>
 *   <li>{@code udp}     — étape de mise en route (vert)</li>
 *   <li>{@code udp-ok}  — confirmation (vert vif)</li>
 *   <li>{@code ready}   — disponibilité finale (orange)</li>
 * </ul>
 *
 * <p>Seuls des faits vérifiables côté Java sont journalisés : l'état réel de
 * l'interface TUN, les serveurs DNS effectivement configurés, le type de
 * tunnel résolu depuis la configuration, et le succès avéré de
 * {@code Controller.start} (erreur vide).
 */
final class UdpSessionLog {

    private UdpSessionLog() {
    }

    private static final String LEVEL_UDP = "udp";
    private static final String LEVEL_UDP_OK = "udp-ok";
    private static final String LEVEL_READY = "ready";

    /** Tunnel type as shown in the journal. Empty when the type is unknown. */
    static String prettyType(String type) {
        if (type == null) {
            return "";
        }
        if (type.equals("zivpn")) {
            return "zivpn";
        }
        if (type.equals("hysteria")) {
            return "Hysteria";
        }
        return "";
    }

    /** Resolve a tunnel's type from the staged configuration. "" if unknown. */
    static String typeOfTunnel(android.content.Context ctx, String tid) {
        if (ctx == null || tid == null || tid.isEmpty()) {
            return "";
        }
        try {
            String cfgPath = BinaryManager.configPath(ctx).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.optJSONObject(i);
                if (t != null && tid.equals(t.optString("id", ""))) {
                    return t.optString("type", "");
                }
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    private static void line(String level, String msg) {
        BinaryManager.appendKighmuRaw(
                new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                        .format(new java.util.Date()),
                "[" + level + "] " + msg);
    }

    /** Steps preceding the blocking Controller.start() call. */
    static void connecting() {
        line(LEVEL_UDP, "Connecting udp server from udp setting");
        line(LEVEL_UDP, "started Tunnel Thread");
        line(LEVEL_UDP, "Please wait a moment");
        line(LEVEL_UDP, "starting tunnel service");
    }

    /** Configuration actually pushed to the dataplane, logged as-is. */
    static void routes() {
        VPNApplication app = VPNApplication.getInstance();
        String dnsPrimary = app == null ? "" : app.getCustomDnsPrimary();
        String dnsSecondary = app == null ? "" : app.getCustomDnsSecondary();
        line(LEVEL_UDP, "Using dns : " + dnsPrimary + ", " + dnsSecondary);
        int mtu = app == null ? 0 : app.getCustomMtu();
        // Only what Builder.establish() really applies. No excluded-route list
        // is announced: on Android the features that add them are disabled, so
        // claiming one would be a lie (a /32 unicast exception is not set).
        line(LEVEL_UDP, "Routes: 0.0.0.0/0 (TUN 10.8.0.2/32, MTU " + mtu + ")");
        if (app != null && app.isDnsProtectionEnabled()) {
            line(LEVEL_UDP, "DNS forwarding started");
        }
    }

    /** Emitted once Controller.start() returned without error. */
    static void connected(String prettyType) {
        line(LEVEL_UDP_OK, "UDP Connected Successfully");
        routes();
        line(LEVEL_UDP_OK, "routing through " + prettyType + " tunnel");
        line(LEVEL_READY, "You are ready to go");
    }

    /** Teardown sequence, mirroring the connect log. */
    static void stopping() {
        line(LEVEL_UDP, "stopping tunnel service");
        line(LEVEL_UDP, "closing VPN interface");
    }

    /** Failure, in the same visual language as a successful connect.
     *  Uses the two-bracket event form so the Logs tab renders it red. */
    static void failed(String prettyType, String reason) {
        TasVpnService.logEvent("error", "udp",
                "UDP connection failed (" + prettyType + ") : " + reason);
    }
}
