package com.ephang.vpn;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.UUID;

/**
 * Persistent API-auth state + helpers bridging remote configs into the
 * local tunnel store.
 *
 * Mode model:
 *  - "API mode"    = an API-materialized tunnel is the (single) selected
 *                    profile. Manual profiles must not be selectable.
 *  - "Manual mode" = user picked profiles in CONFIGS: the API config is
 *                    withdrawn automatically (standby).
 */
public final class ApiSession {
    private static final String K_UUID = "api_device_uuid";
    private static final String K_ACTIVE_TUNNEL = "api_active_tunnel_id";
    private static final String K_SELECTED_CONFIG = "api_selected_config_id";
    // Round-robin (2 profils API) : ids des tunnels matérialisés, csv.
    private static final String K_ACTIVE_IDS = "api_active_tunnel_ids";
    // Les valeurs sensibles (téléphone, code, configs) ne vivent que dans
    // le vault chiffré de libpho (jamais de SharedPreferences en clair).
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

    // --- Identity / auth state ---

    /** Device UUID, generated once on first use, stable afterwards. */
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
    }

    public static boolean isAuthenticated(Context ctx) {
        return !code(ctx).isEmpty() && !phone(ctx).isEmpty();
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

    /** Full logout: forget credentials and detach any active API tunnel. */
    public static void logout(Context ctx) {
        clearActive(ctx);
        PhoHelper.vaultClear(deviceUuid(ctx));
    }

    // --- Remote configs cache ---

    public static void saveConfigs(Context ctx, JSONArray configs) {
        PhoHelper.vaultPut(ctx, deviceUuid(ctx), V_CONFIGS,
                configs == null ? "[]" : configs.toString());
    }

    public static JSONArray configs(Context ctx) {
        try {
            return new JSONArray(PhoHelper.vaultGet(deviceUuid(ctx), V_CONFIGS));
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    // --- Active API tunnel ---

    public static String activeTunnelId(Context ctx) {
        return p(ctx).getString(K_ACTIVE_TUNNEL, "");
    }

    /** True when an API config currently owns the profile selection. */
    public static boolean isApiActive(Context ctx) {
        java.util.LinkedHashSet<String> sel = VPNApplication.getInstance().getSelectedIds();
        for (String id : activeTunnelIds(ctx)) {
            if (sel.contains(id)) {
                return true;
            }
        }
        return false;
    }

    /** All materialized API tunnel ids (1 in single mode, 2 in round-robin). */
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

    /**
     * Materialize a remote config (from /user/configs) as a local tunnel
     * and make it the single selected profile. Returns the tunnel id.
     */
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

    /**
     * Round-robin over the two SlowDNS API profiles (SSH + SlowDNS and
     * V2Ray + SlowDNS): both are materialized locally and selected
     * together, so the connection runs in round-robin mode. Selecting
     * either of the two API configs activates the pair. Returns the
     * comma-separated tunnel ids.
     */
    public static String activateRoundRobin(Context ctx, JSONObject cfgA, JSONObject cfgB)
            throws Exception {
        // Reuse previously stored ids (update in place) when possible.
        String[] stored = p(ctx).getString(K_ACTIVE_IDS, "").split(",", -1);
        String idA = materialize(ctx, cfgA, stored.length >= 1 ? stored[0] : "");
        String idB = materialize(ctx, cfgB, stored.length >= 2 ? stored[1] : "");
        String csv = idA + "," + idB;

        VPNApplication app = VPNApplication.getInstance();
        java.util.LinkedHashSet<String> sel = new java.util.LinkedHashSet<>();
        sel.add(idA);
        sel.add(idB);
        app.setSelectedIds(sel);
        app.setActiveTunnelId(idA);

        p(ctx).edit()
                .putString(K_ACTIVE_TUNNEL, idA)
                .putString(K_ACTIVE_IDS, csv)
                .putString(K_SELECTED_CONFIG,
                        cfgA.optInt("config_id", 0) + "," + cfgB.optInt("config_id", 0))
                .apply();
        return csv;
    }

    /** Insert or update the local tunnel backing an API config. */
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

    /**
     * Withdraw the API config: selection cleared, API mode to standby.
     * The materialized tunnels stay on disk (cheap, re-usable on re-select).
     */
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

    /** Called when the user manually selects a profile in CONFIGS. */
    public static void onManualSelection(Context ctx) {
        if (isApiActive(ctx)) {
            clearActive(ctx);
        }
    }

    // --- Mapping API config -> TunnelConfig JSON (mirrors TunnelEditorActivity) ---

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
            // Multi-range round-robin: 8 sub-ranges covering 6000-19999
            // (server DNATs them all to :5667). API may override.
            String ranges = c.optString("port_range", "");
            if (ranges.isEmpty()) {
                ranges = "6000-7750,7751-9500,9501-11250,11251-13000,"
                        + "13001-14750,14751-16500,16501-18250,18251-19999";
            }
            server.put("port_range", ranges);
        } else if ("sshslowdns".equalsIgnoreCase(mode)) {
            // SSH over SlowDNS (dnstt): server = nameserver/pubkey + ssh creds.
            type = "ssh_slowdns";
            String ns = c.optString("nameserver", "");
            if (!ns.isEmpty()) {
                server.put("nameserver", ns);
                server.put("dns_resolver", "8.8.8.8:53");
            }
            auth.put("username", c.optString("ssh_user", ""));
            auth.put("password", c.optString("ssh_pass", ""));
        } else if ("v2raydns".equalsIgnoreCase(mode)) {
            // V2Ray/Xray over SlowDNS (dnstt): VLESS uuid + nameserver/pubkey.
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
        // SlowDNS modes carry the dnstt server public key.
        String dnsttPub = c.optString("slowdns_pubkey", "");
        if (!dnsttPub.isEmpty()) {
            advanced.put("slowdns_pubkey", dnsttPub);
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
