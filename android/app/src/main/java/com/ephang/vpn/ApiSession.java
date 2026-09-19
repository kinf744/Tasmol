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
    private static final String K_PHONE = "api_phone";
    private static final String K_CODE = "api_code";
    private static final String K_EXPIRES = "api_expires_at";
    private static final String K_CONFIGS = "api_configs_cache";
    private static final String K_ACTIVE_TUNNEL = "api_active_tunnel_id";
    private static final String K_SELECTED_CONFIG = "api_selected_config_id";

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
        p(ctx).edit()
                .putString(K_PHONE, phone)
                .putString(K_CODE, code)
                .putString(K_EXPIRES, expiresAt == null ? "" : expiresAt)
                .apply();
    }

    public static boolean isAuthenticated(Context ctx) {
        SharedPreferences sp = p(ctx);
        String code = sp.getString(K_CODE, "");
        String phone = sp.getString(K_PHONE, "");
        return code != null && !code.isEmpty() && phone != null && !phone.isEmpty();
    }

    public static String phone(Context ctx) {
        return p(ctx).getString(K_PHONE, "");
    }

    public static String code(Context ctx) {
        return p(ctx).getString(K_CODE, "");
    }

    public static String expiresAt(Context ctx) {
        return p(ctx).getString(K_EXPIRES, "");
    }

    /** Full logout: forget credentials and detach any active API tunnel. */
    public static void logout(Context ctx) {
        clearActive(ctx);
        p(ctx).edit()
                .remove(K_PHONE).remove(K_CODE).remove(K_EXPIRES)
                .remove(K_CONFIGS)
                .apply();
    }

    // --- Remote configs cache ---

    public static void saveConfigs(Context ctx, JSONArray configs) {
        p(ctx).edit().putString(K_CONFIGS,
                configs == null ? "[]" : configs.toString()).apply();
    }

    public static JSONArray configs(Context ctx) {
        try {
            return new JSONArray(p(ctx).getString(K_CONFIGS, "[]"));
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
        String id = activeTunnelId(ctx);
        return !id.isEmpty()
                && VPNApplication.getInstance().getSelectedIds().contains(id);
    }

    /**
     * Materialize a remote config (from /user/configs) as a local tunnel
     * and make it the single selected profile. Returns the tunnel id.
     */
    public static String activate(Context ctx, JSONObject apiCfg) throws Exception {
        String cfgPath = BinaryManager.configPath(ctx).getAbsolutePath();
        String tunnelId = activeTunnelId(ctx);
        String json = toTunnelJson(apiCfg).toString();

        boolean updated = false;
        if (!tunnelId.isEmpty()) {
            String res = VpnlibHelper.configUpdate(cfgPath, tunnelId, json);
            updated = res != null && res.contains("\"ok\":true") || res != null && !res.contains("\"error\"");
        }
        if (!updated) {
            String res = VpnlibHelper.configAdd(cfgPath, json);
            if (res == null) {
                throw new Exception("configAdd failed");
            }
            JSONObject r = new JSONObject(res);
            if (r.has("error")) {
                throw new Exception(r.optString("error", "configAdd failed"));
            }
            tunnelId = r.optString("id", "");
            if (tunnelId.isEmpty()) {
                JSONObject t = r.optJSONObject("tunnel");
                if (t != null) {
                    tunnelId = t.optString("id", "");
                }
            }
        }
        if (tunnelId.isEmpty()) {
            throw new Exception("no tunnel id returned");
        }

        VPNApplication app = VPNApplication.getInstance();
        java.util.LinkedHashSet<String> sel = new java.util.LinkedHashSet<>();
        sel.add(tunnelId);
        app.setSelectedIds(sel);
        app.setActiveTunnelId(tunnelId);

        p(ctx).edit()
                .putString(K_ACTIVE_TUNNEL, tunnelId)
                .putString(K_SELECTED_CONFIG, apiCfg.optString("config_id", ""))
                .apply();
        return tunnelId;
    }

    /**
     * Withdraw the API config: selection cleared, API mode to standby.
     * The materialized tunnel stays on disk (cheap, re-usable on re-select).
     */
    public static void clearActive(Context ctx) {
        String id = activeTunnelId(ctx);
        if (!id.isEmpty()) {
            VPNApplication app = VPNApplication.getInstance();
            java.util.LinkedHashSet<String> sel = app.getSelectedIds();
            sel.remove(id);
            app.setSelectedIds(sel);
            if (id.equals(app.getActiveTunnelId())) {
                app.setActiveTunnelId(sel.isEmpty() ? "" : sel.iterator().next());
            }
        }
        p(ctx).edit().remove(K_ACTIVE_TUNNEL).remove(K_SELECTED_CONFIG).apply();
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
        }

        JSONObject advanced = new JSONObject();
        advanced.put(ADV_API_MANAGED, true);
        advanced.put("api_config_id", c.optInt("config_id", 0));
        advanced.put("api_mode", mode);
        advanced.put("api_label", label);
        advanced.put("api_isp", c.optString("isp", ""));
        advanced.put("api_tier", c.optString("tier", ""));

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
