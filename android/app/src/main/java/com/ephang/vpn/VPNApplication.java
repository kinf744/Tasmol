package com.ephang.vpn;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

public class VPNApplication extends Application {
    private static VPNApplication instance;
    private SharedPreferences prefs;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        prefs = getSharedPreferences("ephang_vpn_prefs", Context.MODE_PRIVATE);

        // Stage binaries + config.yaml on app launch so the Servers/Home/Editor
        // screens work before any VPN connection (fixes "no such file" when
        // reading /data/user/0/.../config.yaml on first run).
        try {
            BinaryManager.ensureReady(this);
        } catch (Exception e) {
            Log.e("VPNApplication", "ensureReady failed on launch", e);
        }
    }

    public static VPNApplication getInstance() {
        return instance;
    }

    public SharedPreferences getPrefs() {
        return prefs;
    }

    public String getServerUrl() {
        return prefs.getString("server_url", "http://127.0.0.1:" + getManagePort() + "/");
    }

    public int getManagePort() {
        return prefs.getInt("manage_port", 18080);
    }

    public void setManagePort(int port) {
        prefs.edit().putInt("manage_port", port).apply();
    }

    public String getActiveTunnelId() {
        return prefs.getString("active_tunnel_id", "");
    }

    public void setActiveTunnelId(String id) {
        prefs.edit().putString("active_tunnel_id", id == null ? "" : id).apply();
    }

    /** Round-robin profile set as comma-separated ids (2+ = RR mode). */
    public String getRoundRobinIds() {
        return prefs.getString("round_robin_ids", "");
    }

    public void setRoundRobinIds(String csv) {
        prefs.edit().putString("round_robin_ids", csv == null ? "" : csv).apply();
    }

    /** Toggle one id in the round-robin set. Returns the new set. */
    public java.util.LinkedHashSet<String> toggleRoundRobin(String id) {
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>();
        for (String part : getRoundRobinIds().split(",")) {
            part = part.trim();
            if (!part.isEmpty()) {
                set.add(part);
            }
        }
        if (!set.remove(id)) {
            set.add(id);
        }
        StringBuilder sb = new StringBuilder();
        for (String s : set) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(s);
        }
        setRoundRobinIds(sb.toString());
        return set;
    }

    public boolean isInRoundRobin(String id) {
        for (String part : getRoundRobinIds().split(",")) {
            if (part.trim().equals(id)) {
                return true;
            }
        }
        return false;
    }

    public void setTunnelPing(String id, long ms) {
        prefs.edit().putLong("ping_" + id, ms)
                .putLong("last_ping_time", System.currentTimeMillis()).apply();
    }

    public long getTunnelPing(String id) {
        return prefs.getLong("ping_" + id, -1);
    }

    public String getLastPingDate() {
        long t = prefs.getLong("last_ping_time", 0);
        if (t == 0) {
            return "--";
        }
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
                .format(new java.util.Date(t));
    }

    public void setServerUrl(String url) {
        prefs.edit().putString("server_url", url).apply();
    }

    public boolean isAutoStartEnabled() {
        return prefs.getBoolean("auto_start", true);
    }

    public void setAutoStartEnabled(boolean enabled) {
        prefs.edit().putBoolean("auto_start", enabled).apply();
    }

    public boolean isDarkModeEnabled() {
        return prefs.getBoolean("dark_mode", true);
    }

    public void setDarkModeEnabled(boolean enabled) {
        prefs.edit().putBoolean("dark_mode", enabled).apply();
    }
}