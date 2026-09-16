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

    /** Selected profiles (multi-select). 1 selected = single mode,
     *  2+ = round-robin mode: Home connects ALL of them at once. */
    public java.util.LinkedHashSet<String> getSelectedIds() {
        String csv = prefs.getString("selected_ids", null);
        if (csv == null) {
            // One-time migration from the old round-robin key.
            csv = prefs.getString("round_robin_ids", "");
            prefs.edit().putString("selected_ids", csv).remove("round_robin_ids").apply();
        }
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>();
        for (String part : csv.split(",")) {
            part = part.trim();
            if (!part.isEmpty()) {
                set.add(part);
            }
        }
        return set;
    }

    public void setSelectedIds(java.util.Collection<String> ids) {
        StringBuilder sb = new StringBuilder();
        if (ids != null) {
            for (String s : ids) {
                if (s == null || s.trim().isEmpty()) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append(',');
                }
                sb.append(s.trim());
            }
        }
        prefs.edit().putString("selected_ids", sb.toString()).apply();
    }

    /** Toggle one id in the selection. Returns the new set. */
    public java.util.LinkedHashSet<String> toggleSelected(String id) {
        java.util.LinkedHashSet<String> set = getSelectedIds();
        if (!set.remove(id)) {
            set.add(id);
        }
        setSelectedIds(set);
        return set;
    }

    public boolean isSelected(String id) {
        return id != null && getSelectedIds().contains(id);
    }

    /** Selection as comma-separated ids (for the Go round_robin param). */
    public String getSelectedCsv() {
        java.util.LinkedHashSet<String> set = getSelectedIds();
        StringBuilder sb = new StringBuilder();
        for (String s : set) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(s);
        }
        return sb.toString();
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

    // --- App settings (Settings menu, Picko-style, adapted) ---

    public boolean isDnsProtectionEnabled() {
        return prefs.getBoolean("set_dns_protection", true);
    }

    public void setDnsProtectionEnabled(boolean v) {
        prefs.edit().putBoolean("set_dns_protection", v).apply();
    }

    public boolean isStopOnNetworkLossEnabled() {
        return prefs.getBoolean("set_stop_on_loss", true);
    }

    public void setStopOnNetworkLossEnabled(boolean v) {
        prefs.edit().putBoolean("set_stop_on_loss", v).apply();
    }

    public boolean isAutoReconnectEnabled() {
        return prefs.getBoolean("set_auto_reconnect", true);
    }

    public void setAutoReconnectEnabled(boolean v) {
        prefs.edit().putBoolean("set_auto_reconnect", v).apply();
    }

    public boolean isLaunchOnBootEnabled() {
        return prefs.getBoolean("set_launch_on_boot", false);
    }

    public void setLaunchOnBootEnabled(boolean v) {
        prefs.edit().putBoolean("set_launch_on_boot", v).apply();
    }

    public boolean isVerboseDiagnosticsEnabled() {
        return prefs.getBoolean("set_verbose_diag", false);
    }

    public void setVerboseDiagnosticsEnabled(boolean v) {
        prefs.edit().putBoolean("set_verbose_diag", v).apply();
    }

    public boolean isConfirmDisconnectEnabled() {
        return prefs.getBoolean("set_confirm_disconnect", true);
    }

    public void setConfirmDisconnectEnabled(boolean v) {
        prefs.edit().putBoolean("set_confirm_disconnect", v).apply();
    }

    public int getReconnectDelaySeconds() {
        int v = prefs.getInt("set_reconnect_delay", 5);
        if (v < 1) {
            v = 1;
        }
        if (v > 30) {
            v = 30;
        }
        return v;
    }

    public void setReconnectDelaySeconds(int v) {
        if (v < 1) {
            v = 1;
        }
        if (v > 30) {
            v = 30;
        }
        prefs.edit().putInt("set_reconnect_delay", v).apply();
    }

    public void resetSettings() {
        prefs.edit()
                .putBoolean("set_dns_protection", true)
                .putBoolean("set_stop_on_loss", true)
                .putBoolean("set_auto_reconnect", true)
                .putBoolean("set_launch_on_boot", false)
                .putBoolean("set_verbose_diag", false)
                .putBoolean("set_confirm_disconnect", true)
                .putInt("set_reconnect_delay", 5)
                .apply();
    }

    public boolean isDarkModeEnabled() {
        return prefs.getBoolean("dark_mode", true);
    }

    public void setDarkModeEnabled(boolean enabled) {
        prefs.edit().putBoolean("dark_mode", enabled).apply();
    }
}