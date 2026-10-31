package com.ephang.vpn;

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

    public static final String ADV_API_MANAGED = "api_managed";

    private ApiSession() {
    }

    private static SharedPreferences p(Context ctx) {
        return ctx.getSharedPreferences("ephang_api_prefs", Context.MODE_PRIVATE);
    }

    

    
    public static String deviceUuid(Context ctx) {
        SharedPreferences sp = p(ctx);
        String u = sp.getString(K_UUID, null);
        if (u == null || u.isEmpty()) {
            u = UUID.randomUUID().toString();
            sp.edit().putString(K_UUID, u).apply();
        }
        return u;
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

    
    public static void logout(Context ctx) {
        clearActive(ctx);
        clearAccountCard(ctx);
        p(ctx).edit().putBoolean(K_AUTHED, false).apply();
        PhoHelper.vaultClear(deviceUuid(ctx));
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
        lastConfigsRaw = null; 
    }

    
    
    private static String lastConfigsRaw = null;
    private static JSONArray lastConfigsParsed = new JSONArray();

    public static JSONArray configs(Context ctx) {
        String raw = PhoHelper.vaultGet(deviceUuid(ctx), V_CONFIGS);
        if (raw != null && raw.equals(lastConfigsRaw)) {
            return lastConfigsParsed;
        }
        try {
            lastConfigsParsed = new JSONArray(raw);
        } catch (Exception e) {
            lastConfigsParsed = new JSONArray();
        }
        lastConfigsRaw = raw;
        return lastConfigsParsed;
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
        } else if ("utunnel".equalsIgnoreCase(mode)) {
            
            
            
            
            type = "utunnel";
            auth.put("password", c.optString("utunnel_secret", ""));
            String ranges = c.optString("port_range", "");
            if (ranges.isEmpty()) {
                ranges = "50000-59999";
            }
            server.put("port_range", ranges);
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
        
        if (c.has("utunnel_hop")) {
            advanced.put("utunnel_hop", c.optInt("utunnel_hop", 10));
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
