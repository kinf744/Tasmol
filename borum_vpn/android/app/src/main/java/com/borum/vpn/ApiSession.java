package com.borum.vpn;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.UUID;

public final class ApiSession {
    private static final String K_UUID = "api_device_uuid";
    private static final String K_ACTIVE_TUNNEL = "api_active_tunnel_id";
    private static final String K_SELECTED_CONFIG = "api_selected_config_id";

    private static final String K_ACTIVE_IDS = "api_active_tunnel_ids";

    private static final String V_PHONE = "phone";
    private static final String V_CODE = "code";
    private static final String V_EXPIRES = "expires";
    private static final String V_CONFIGS = "configs";

    private static final String K_SERVER_TIME_MS = "api_server_time_ms";
    private static final String K_DEVICE_TIME_AT_CHECK = "api_device_time_at_check_ms";

    public static final String ADV_API_MANAGED = "api_managed";

    public static final String MTN_UNLIMITED_UUID_DEFAULT =
            "aaaa0000-1111-4222-8333-444455556666";
    public static final String MTN_UNLIMITED_PATH_DEFAULT = "/@kighmu";
    public static final String MTN_UNLIMITED_SNI_DEFAULT = "findschoolnews.blogspot.com";
    public static final String MTN_UNLIMITED_HOST_DEFAULT =
            "kighmu-vpn-919282834024.asia-south1.run.app";

    
    public static final String ORANGE_FAST_UUID_DEFAULT =
            "aaaa0000-1111-4222-8333-444455556666";
    public static final String ORANGE_FAST_PATH_DEFAULT = "/@kighmu";
    public static final String ORANGE_FAST_SNI_DEFAULT =
            "crashlyticsreports-pa.googleapis.com";
    public static final String ORANGE_FAST_HOST_DEFAULT =
            "kighmu-vpn-919282834024.asia-south1.run.app";

    private ApiSession() {
    }

    private static SharedPreferences p(Context ctx) {
        return ctx.getSharedPreferences("borum_api_prefs", Context.MODE_PRIVATE);
    }

    public static String deviceUuid(Context ctx) {
        return DeviceIdentity.getUuid(ctx);
    }

    public static void saveAuth(Context ctx, String phone, String code, String expiresAt) {
        String id = deviceUuid(ctx);
        PhoHelper.vaultPut(ctx, id, V_PHONE, phone);
        PhoHelper.vaultPut(ctx, id, V_CODE, code);
        PhoHelper.vaultPut(ctx, id, V_EXPIRES, expiresAt == null ? "" : expiresAt);
        p(ctx).edit().putBoolean(K_AUTHED, true).apply();
    }

    public static boolean isAuthenticated(Context ctx) {
        if (p(ctx).getBoolean(K_AUTHED, false)) {
            return true; 
        }
        boolean ok = !code(ctx).isEmpty() && !phone(ctx).isEmpty();
        if (ok) {
            p(ctx).edit().putBoolean(K_AUTHED, true).apply(); 
        }
        return ok;
    }

    public static String phone(Context ctx) {
        return PhoHelper.vaultGet(deviceUuid(ctx), V_PHONE);
    }

    public static String code(Context ctx) {
        return PhoHelper.vaultGet(deviceUuid(ctx), V_CODE);
    }

    public static String expiresAt(Context ctx) {
        return PhoHelper.vaultGet(deviceUuid(ctx), V_EXPIRES);
    }

    public static void saveServerTime(Context ctx, long serverTimeMs, long deviceTimeMs) {
        p(ctx).edit()
                .putLong(K_SERVER_TIME_MS, serverTimeMs)
                .putLong(K_DEVICE_TIME_AT_CHECK, deviceTimeMs)
                .apply();
    }

    public static long estimatedServerTimeMs(Context ctx) {
        long serverTime = p(ctx).getLong(K_SERVER_TIME_MS, -1);
        long deviceAtCheck = p(ctx).getLong(K_DEVICE_TIME_AT_CHECK, -1);
        if (serverTime < 0 || deviceAtCheck < 0) {
            return -1;
        }
        return serverTime + (System.currentTimeMillis() - deviceAtCheck);
    }

    public static void clearServerTime(Context ctx) {
        p(ctx).edit().remove(K_SERVER_TIME_MS).remove(K_DEVICE_TIME_AT_CHECK).apply();
    }

    public static void logout(Context ctx) {
        clearActive(ctx);
        clearAccountCard(ctx);
        p(ctx).edit().putBoolean(K_AUTHED, false).apply();
        PhoHelper.vaultClear(deviceUuid(ctx));
        SecurityGuard.resetSecurity(ctx);
        clearServerTime(ctx);
    }

    public static void resetAll(Context ctx) {
        String uuid = deviceUuid(ctx); 
        logout(ctx);
        p(ctx).edit().clear().apply();

        lastConfigsRaw.remove(uuid);
        lastConfigsParsed.remove(uuid);
    }

    private static final String K_ACCOUNT_CARD = "api_account_card";

    private static final String K_AUTHED = "api_authed";

    public static void saveAccountCard(Context ctx, JSONObject card) {
        p(ctx).edit().putString(K_ACCOUNT_CARD,
                card == null ? "" : card.toString()).apply();
    }

    public static JSONObject accountCard(Context ctx) {
        try {
            String s = p(ctx).getString(K_ACCOUNT_CARD, "");
            if (s == null || s.isEmpty()) {
                return null;
            }
            return new JSONObject(s);
        } catch (Exception e) {
            return null;
        }
    }

    public static void clearAccountCard(Context ctx) {
        p(ctx).edit().remove(K_ACCOUNT_CARD).apply();
    }

    public static void saveConfigs(Context ctx, JSONArray configs) {
        PhoHelper.vaultPut(ctx, deviceUuid(ctx), V_CONFIGS,
                configs == null ? "[]" : configs.toString());
        lastConfigsRaw.remove(deviceUuid(ctx));
        lastConfigsParsed.remove(deviceUuid(ctx));
    }

    private static final java.util.Map<String, String> lastConfigsRaw = new java.util.HashMap<>();
    private static final java.util.Map<String, JSONArray> lastConfigsParsed = new java.util.HashMap<>();

    public static JSONArray configs(Context ctx) {
        String uuid = deviceUuid(ctx);
        String raw = PhoHelper.vaultGet(uuid, V_CONFIGS);
        String cachedRaw = lastConfigsRaw.get(uuid);
        if (raw != null && raw.equals(cachedRaw)) {
            JSONArray cached = lastConfigsParsed.get(uuid);
            if (cached != null) {
                return cached;
            }
        }
        JSONArray parsed;
        try {
            parsed = new JSONArray(raw);
        } catch (Exception e) {
            parsed = new JSONArray();
        }
        lastConfigsRaw.put(uuid, raw);
        lastConfigsParsed.put(uuid, parsed);
        return parsed;
    }

    public static String activeTunnelId(Context ctx) {
        return p(ctx).getString(K_ACTIVE_TUNNEL, "");
    }

    public static boolean isApiActive(Context ctx) {
        java.util.LinkedHashSet<String> sel = VPNApplication.getInstance().getSelectedIds();
        for (String id : activeTunnelIds(ctx)) {
            if (sel.contains(id)) {
                return true;
            }
        }
        return false;
    }

    public static java.util.List<String> activeTunnelIds(Context ctx) {
        java.util.List<String> out = new java.util.ArrayList<>();
        String csv = p(ctx).getString(K_ACTIVE_IDS, "");
        if (csv.isEmpty()) {
            csv = p(ctx).getString(K_ACTIVE_TUNNEL, "");
        }
        for (String id : csv.split(",")) {
            id = id.trim();
            if (!id.isEmpty()) {
                out.add(id);
            }
        }
        return out;
    }

    public static String activate(Context ctx, JSONObject apiCfg) throws Exception {
        String tunnelId = materialize(ctx, apiCfg, activeTunnelId(ctx));

        VPNApplication app = VPNApplication.getInstance();
        java.util.LinkedHashSet<String> sel = new java.util.LinkedHashSet<>();
        sel.add(tunnelId);
        app.setSelectedIds(sel);
        app.setActiveTunnelId(tunnelId);

        p(ctx).edit()
                .putString(K_ACTIVE_TUNNEL, tunnelId)
                .putString(K_ACTIVE_IDS, tunnelId)
                .putString(K_SELECTED_CONFIG,
                        String.valueOf(apiCfg.optInt("config_id", 0)))
                .apply();
        return tunnelId;
    }

    public static String activateRoundRobin(Context ctx, JSONObject cfgA, JSONObject cfgB)
            throws Exception {
        java.util.List<JSONObject> cfgs = new java.util.ArrayList<>();
        cfgs.add(cfgA);
        cfgs.add(cfgB);
        return activateRoundRobinN(ctx, cfgs);
    }

    public static String activateRoundRobinN(Context ctx, java.util.List<JSONObject> cfgs)
            throws Exception {
        if (cfgs == null || cfgs.isEmpty()) {
            throw new Exception("aucune config fournie");
        }
        java.util.List<JSONObject> use = cfgs.size() > 4
                ? cfgs.subList(0, 4) : cfgs;

        String[] stored = p(ctx).getString(K_ACTIVE_IDS, "").split(",", -1);

        java.util.List<String> ids = new java.util.ArrayList<>();
        java.util.List<String> cfgIds = new java.util.ArrayList<>();
        for (int i = 0; i < use.size(); i++) {
            JSONObject c = use.get(i);
            String reuse = (stored.length > i && stored[i] != null) ? stored[i].trim() : "";
            ids.add(materialize(ctx, c, reuse));
            cfgIds.add(String.valueOf(c.optInt("config_id", 0)));
        }
        String csv = android.text.TextUtils.join(",", ids);

        VPNApplication app = VPNApplication.getInstance();
        java.util.LinkedHashSet<String> sel = new java.util.LinkedHashSet<>();
        sel.addAll(ids);
        app.setSelectedIds(sel);
        app.setActiveTunnelId(ids.get(0));

        p(ctx).edit()
                .putString(K_ACTIVE_TUNNEL, ids.get(0))
                .putString(K_ACTIVE_IDS, csv)
                .putString(K_SELECTED_CONFIG, android.text.TextUtils.join(",", cfgIds))
                .apply();
        return csv;
    }

    private static String materialize(Context ctx, JSONObject apiCfg, String reuseId)
            throws Exception {
        String cfgPath = BinaryManager.configPath(ctx).getAbsolutePath();
        String json = toTunnelJson(apiCfg).toString();

        if (reuseId != null && !reuseId.isEmpty()) {
            try {
                String res = VpnlibHelper.configUpdate(cfgPath, reuseId, json);
                if (res != null && !res.contains("\"error\"")) {
                    return reuseId;
                }
            } catch (Exception ignored) {
            }
        }
        String res = VpnlibHelper.configAdd(cfgPath, json);
        if (res == null) {
            throw new Exception("configAdd failed");
        }
        JSONObject r = new JSONObject(res);
        if (r.has("error")) {
            throw new Exception(r.optString("error", "configAdd failed"));
        }
        String tunnelId = r.optString("id", "");
        if (tunnelId.isEmpty()) {
            JSONObject t = r.optJSONObject("tunnel");
            if (t != null) {
                tunnelId = t.optString("id", "");
            }
        }
        if (tunnelId.isEmpty()) {
            throw new Exception("no tunnel id returned");
        }
        return tunnelId;
    }

    public static void clearActive(Context ctx) {
        java.util.List<String> ids = activeTunnelIds(ctx);
        if (!ids.isEmpty()) {
            VPNApplication app = VPNApplication.getInstance();
            java.util.LinkedHashSet<String> sel = app.getSelectedIds();
            sel.removeAll(ids);
            app.setSelectedIds(sel);
            if (ids.contains(app.getActiveTunnelId())) {
                app.setActiveTunnelId(sel.isEmpty() ? "" : sel.iterator().next());
            }
        }
        p(ctx).edit().remove(K_ACTIVE_TUNNEL).remove(K_ACTIVE_IDS)
                .remove(K_SELECTED_CONFIG).apply();
    }

    public static void onManualSelection(Context ctx) {
        if (isApiActive(ctx)) {
            clearActive(ctx);
        }
    }

    static JSONObject toTunnelJson(JSONObject c) throws Exception {
        String label = c.optString("label", "API config");
        String mode = c.optString("mode", "xray");
        String address = c.optString("address", "");
        int port = c.optInt("port", 443);

        JSONObject server = new JSONObject();
        server.put("host", address);
        server.put("port", port);
        String sni = c.optString("sni", "");
        if (!sni.isEmpty()) {
            server.put("sni", sni);
        }
        String pk = c.optString("public_key", "");
        if (!pk.isEmpty()) {
            server.put("public_key", pk);
        }
        String sid = c.optString("short_id", "");
        if (!sid.isEmpty()) {
            server.put("short_id", sid);
        }

        JSONObject auth = new JSONObject();
        JSONObject transport = new JSONObject();

        String type;
        if ("zivpn".equalsIgnoreCase(mode) || "zivpn".equalsIgnoreCase(c.optString("protocol", ""))) {
            type = "zivpn";
            auth.put("password", c.optString("zivpn_password", ""));

            String ranges = c.optString("port_range", "");
            if (ranges.isEmpty()) {
                ranges = "6000-9499,9500-12999,13000-16499,16500-19999";
            }
            server.put("port_range", ranges);
        } else if ("sshslowdns".equalsIgnoreCase(mode)) {

            type = "ssh_slowdns";
            String ns = c.optString("nameserver", "");
            if (!ns.isEmpty()) {
                server.put("nameserver", ns);
                server.put("dns_resolver", "8.8.8.8:53");
            }
            auth.put("username", c.optString("ssh_user", ""));
            auth.put("password", c.optString("ssh_pass", ""));
        } else if ("v2raydns".equalsIgnoreCase(mode)) {

            type = "xray_slowdns";
            String ns = c.optString("nameserver", "");
            if (!ns.isEmpty()) {
                server.put("nameserver", ns);
                server.put("dns_resolver", "8.8.8.8:53");
            }
            auth.put("uuid", c.optString("xray_uuid", ""));
            transport.put("network", "tcp");
            transport.put("security", "none");
        } else {
            type = "xray";
            auth.put("uuid", c.optString("xray_uuid", ""));
            String flow = c.optString("flow", "");
            if (!flow.isEmpty()) {
                auth.put("flow", flow);
            }
            String net = c.optString("transport", "xhttp");
            if (net.isEmpty()) {
                net = "xhttp";
            }
            transport.put("network", net);
            transport.put("security", c.optBoolean("tls", true) ? "tls" : "none");
            String host = c.optString("host", "");
            if (!host.isEmpty()) {
                transport.put("host", host);
            }
            String path = c.optString("path", "");
            if (!path.isEmpty()) {
                transport.put("path", path);
            }
        }

        JSONObject advanced = new JSONObject();
        advanced.put(ADV_API_MANAGED, true);
        advanced.put("api_config_id", c.optInt("config_id", 0));
        advanced.put("api_mode", mode);
        advanced.put("api_label", label);
        advanced.put("api_isp", c.optString("isp", ""));
        advanced.put("api_tier", c.optString("tier", ""));

        String dnsttPub = c.optString("slowdns_pubkey", "");
        if (!dnsttPub.isEmpty()) {
            advanced.put("slowdns_pubkey", dnsttPub);
        }

        
        if ("orange_fast".equalsIgnoreCase(mode)) {
            BinaryManager.appendLog("[Orange Fast] Début construction config tunnel Orange Fast");
            try {
                String ofHost = c.optString("host", "");
                if (ofHost.isEmpty()) {
                    ofHost = ORANGE_FAST_HOST_DEFAULT;
                }
                BinaryManager.appendLog("[Orange Fast] Host WS: " + ofHost);
                String ofUuid = c.optString("xray_uuid", ORANGE_FAST_UUID_DEFAULT);
                String ofPath = c.optString("path", ORANGE_FAST_PATH_DEFAULT);
                String ofSni = c.optString("sni", ORANGE_FAST_SNI_DEFAULT);
                BinaryManager.appendLog("[Orange Fast] UUID: " + ofUuid);
                BinaryManager.appendLog("[Orange Fast] Path: " + ofPath);
                BinaryManager.appendLog("[Orange Fast] SNI: " + ofSni);

                
                
                server.put("host", c.optString("address", "192.179.18.100"));
                server.put("port", c.optInt("port", 443));
                server.put("sni", ofSni);
                auth.put("uuid", ofUuid);
                auth.put("flow", "");
                transport.put("network", "ws");
                transport.put("security", "tls");
                transport.put("host", ofHost);
                transport.put("path", ofPath);

                JSONObject tlsSettings = new JSONObject();
                tlsSettings.put("serverName", ofSni);
                tlsSettings.put("allowInsecure", true);

                JSONObject wsSettings = new JSONObject();
                JSONObject wsHeaders = new JSONObject();
                wsHeaders.put("Host", ofHost);
                wsSettings.put("headers", wsHeaders);
                wsSettings.put("path", ofPath);

                JSONObject streamSettings = new JSONObject();
                streamSettings.put("network", "ws");
                streamSettings.put("security", "tls");
                streamSettings.put("tlsSettings", tlsSettings);
                streamSettings.put("wsSettings", wsSettings);

                
                
                BinaryManager.appendLog("[Orange Fast] Config VLESS WS TLS construit");
                BinaryManager.appendLog("[Orange Fast] Config prêt pour le tunnel Go");
            } catch (Exception e) {
                BinaryManager.appendLog("[Orange Fast] ERREUR construction config: " + e.getMessage());
            }
        }

        if ("mtn_unlimited".equalsIgnoreCase(mode)) {
            BinaryManager.appendLog("[MTN] Début construction config tunnel MTN Illimité");
            try {
                String mtnHost = c.optString("host", "");
                if (mtnHost.isEmpty()) {
                    mtnHost = "kighmu-vpn-919282834024.asia-south1.run.app";
                }
                BinaryManager.appendLog("[MTN] Host WS: " + mtnHost);
                String xrayUuid = c.optString("xray_uuid", MTN_UNLIMITED_UUID_DEFAULT);
                String wsPath = c.optString("path", MTN_UNLIMITED_PATH_DEFAULT);
                String mtnSni = c.optString("sni", MTN_UNLIMITED_SNI_DEFAULT);
                BinaryManager.appendLog("[MTN] UUID: " + xrayUuid);
                BinaryManager.appendLog("[MTN] Path: " + wsPath);
                BinaryManager.appendLog("[MTN] SNI: " + mtnSni);

                JSONObject httpHeaders = new JSONObject();
                httpHeaders.put("Host", "findschoolnews.blogspot.com:443");
                httpHeaders.put("Proxy-Connection", "keep-alive");
                httpHeaders.put("User-Agent",
                        "Mozilla/5.0 (Linux; Android 14; SM-A245F Build/UP1A.231005.007; wv) "
                                + "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/133.0.6943.122 "
                                + "Mobile Safari/537.36 [FBAN/InternetOrgApp;FBAV/166.0.0.0.169;]");
                httpHeaders.put("X-iorg-bsid", "@kighmu");

                JSONObject httpOutbound = new JSONObject();
                httpOutbound.put("domainStrategy", "AsIs");
                httpOutbound.put("protocol", "http");
                JSONObject httpSettings = new JSONObject();
                JSONArray httpServers = new JSONArray();
                JSONObject httpServer = new JSONObject();
                httpServer.put("address", "157.240.9.39");
                httpServer.put("port", 8080);
                httpServers.put(httpServer);
                httpSettings.put("servers", httpServers);
                httpSettings.put("headers", httpHeaders);
                httpOutbound.put("settings", httpSettings);
                httpOutbound.put("tag", "alrufaaey");

                JSONObject vlessSettings = new JSONObject();
                JSONArray vnext = new JSONArray();
                JSONObject vnextEntry = new JSONObject();
                vnextEntry.put("address", "findschoolnews.blogspot.com");
                vnextEntry.put("port", 443);
                JSONArray users = new JSONArray();
                JSONObject user = new JSONObject();
                user.put("encryption", "none");
                user.put("flow", "");
                user.put("id", xrayUuid);
                user.put("level", 8);
                users.put(user);
                vnextEntry.put("users", users);
                vnext.put(vnextEntry);
                vlessSettings.put("vnext", vnext);

                JSONObject tlsSettings = new JSONObject();
                tlsSettings.put("serverName", mtnSni);
                tlsSettings.put("allowInsecure", true);

                JSONObject wsSettings = new JSONObject();
                JSONObject wsHeaders = new JSONObject();
                wsHeaders.put("Host", mtnHost);
                wsSettings.put("headers", wsHeaders);
                wsSettings.put("path", wsPath);

                JSONObject streamSettings = new JSONObject();
                streamSettings.put("network", "ws");
                streamSettings.put("security", "tls");
                streamSettings.put("tlsSettings", tlsSettings);
                streamSettings.put("wsSettings", wsSettings);

                JSONObject sockopt = new JSONObject();
                sockopt.put("dialerProxy", "alrufaaey");
                streamSettings.put("sockopt", sockopt);

                JSONObject vlessOutbound = new JSONObject();
                vlessOutbound.put("mux", new JSONObject().put("enabled", false));
                vlessOutbound.put("protocol", "vless");
                vlessOutbound.put("settings", vlessSettings);
                vlessOutbound.put("streamSettings", streamSettings);
                vlessOutbound.put("tag", "VLESS");

                JSONArray outbounds = new JSONArray();
                outbounds.put(vlessOutbound);
                outbounds.put(httpOutbound);

                JSONObject dns = new JSONObject();
                JSONArray dnsServers = new JSONArray();
                dnsServers.put("localhost");
                dns.put("servers", dnsServers);

                JSONObject policyLevels = new JSONObject();
                JSONObject level8 = new JSONObject();
                level8.put("connIdle", 300);
                level8.put("downlinkOnly", 1);
                level8.put("handshake", 4);
                level8.put("uplinkOnly", 1);
                policyLevels.put("8", level8);
                JSONObject policy = new JSONObject();
                policy.put("levels", policyLevels);

                JSONObject fullCfg = new JSONObject();
                fullCfg.put("dns", dns);
                JSONArray inbounds = new JSONArray();
                JSONObject socksInbound = new JSONObject();
                socksInbound.put("listen", "127.0.0.1");
                socksInbound.put("port", 10808);
                socksInbound.put("protocol", "socks");
                JSONObject socksSettings = new JSONObject();
                socksSettings.put("auth", "noauth");
                socksSettings.put("udp", true);
                socksInbound.put("settings", socksSettings);
                socksInbound.put("tag", "socks-inbound");
                inbounds.put(socksInbound);
                fullCfg.put("inbounds", inbounds);
                fullCfg.put("outbounds", outbounds);
                fullCfg.put("policy", policy);

                advanced.put("outbound_json", fullCfg.toString());
                BinaryManager.appendLog("[MTN] Config Xray complet construit (outbound_json)");
                BinaryManager.appendLog("[MTN] Outbounds: VLESS WS TLS (sockopt.dialerProxy=alrufaaey) + HTTP proxy 157.240.9.39:8080");
                BinaryManager.appendLog("[MTN] Config prêt pour le tunnel Go");
            } catch (Exception e) {
                BinaryManager.appendLog("[MTN] ERREUR construction config: " + e.getMessage());

            }
        }
        JSONObject routing = new JSONObject(
                "{\"domain_strategy\":\"AsIs\",\"rules\":[],\"dns\":{\"servers\":[\"1.1.1.1\",\"8.8.8.8\"]}}");

        JSONObject t = new JSONObject();
        t.put("name", label);
        t.put("type", type);
        t.put("enabled", true);
        t.put("priority", 0);
        t.put("server", server);
        t.put("auth", auth);
        t.put("ssh", new JSONObject());
        t.put("transport", transport);
        t.put("advanced", advanced);
        t.put("routing", routing);
        return t;
    }
}
