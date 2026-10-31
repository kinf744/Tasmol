package com.ephang.vpn;

import org.json.JSONArray;
import org.json.JSONObject;


final class UdpSessionLog {

    private UdpSessionLog() {
    }

    private static final String LEVEL_UDP = "udp";
    private static final String LEVEL_UDP_OK = "udp-ok";
    private static final String LEVEL_READY = "ready";

    
    private static final class Kind {
        final String family;
        final String name;

        Kind(String family, String name) {
            this.family = family;
            this.name = name;
        }
    }

    private static Kind kindOf(String type) {
        if (type == null) {
            return null;
        }
        if (type.equals("zivpn")) {
            return new Kind("UDP", "zivpn");
        }
        if (type.equals("hysteria")) {
            return new Kind("UDP", "Hysteria");
        }
        if (type.equals("utunnel")) {
            return new Kind("UDP", "Utunnel");
        }
        if (type.equals("xray")) {
            return new Kind("XRAY", "Xray");
        }
        if (type.equals("xray_slowdns")) {
            return new Kind("XRAY", "Xray slowdns");
        }
        if (type.equals("ssh")) {
            return new Kind("SSH", "SSH");
        }
        if (type.equals("ssh_slowdns")) {
            return new Kind("SSH", "SSH slowdns");
        }
        return null;
    }

    
    static String prettyType(String type) {
        Kind k = kindOf(type);
        return k == null ? "" : k.name;
    }

    
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
        BinaryManager.appendLogRaw(
                new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                        .format(new java.util.Date()),
                "[" + level + "] " + msg);
    }

    
    static void connecting() {
        line(LEVEL_UDP, "Connecting udp server from udp setting");
        line(LEVEL_UDP, "started Tunnel Thread");
        line(LEVEL_UDP, "Please wait a moment");
        line(LEVEL_UDP, "starting tunnel service");
    }

    
    static void routes() {
        VPNApplication app = VPNApplication.getInstance();
        String dnsPrimary = app == null ? "" : app.getCustomDnsPrimary();
        String dnsSecondary = app == null ? "" : app.getCustomDnsSecondary();
        line(LEVEL_UDP, "Using dns : " + dnsPrimary + ", " + dnsSecondary);
        int mtu = app == null ? 0 : app.getCustomMtu();
        
        
        
        line(LEVEL_UDP, "Routes: 0.0.0.0/0 (TUN 10.8.0.2/32, MTU " + mtu + ")");
        if (app != null && app.isDnsProtectionEnabled()) {
            line(LEVEL_UDP, "DNS forwarding started");
        }
    }

    
    static void connected(String type) {
        Kind k = kindOf(type);
        if (k == null) {
            return;
        }
        line(LEVEL_UDP_OK, k.family + " Connected Successfully");
        routes();
        line(LEVEL_UDP_OK, "routing through " + k.name);
        line(LEVEL_READY, "You are ready to go");
    }

    
    static void stopping() {
        line(LEVEL_UDP, "stopping tunnel service");
        line(LEVEL_UDP, "closing VPN interface");
    }

    
    static void failed(String prettyType, String reason) {
        TasVpnService.logEvent("error", "udp",
                prettyType + " connection failed : " + reason);
    }
}
