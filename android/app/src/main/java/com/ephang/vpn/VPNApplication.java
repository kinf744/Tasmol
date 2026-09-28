package com.ephang.vpn;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;

public class VPNApplication extends Application {
    private static VPNApplication instance;
    private SharedPreferences prefs;

    @Override
    public void onCreate() {
        // Captureur de crash AVANT tout : toute exception non interceptée
        // finit dans Download/kighmu.txt avec sa stacktrace complète —
        // indispensable pour diagnostiquer les fermetures brutales
        // (ex. « l'app se ferme à la déconnexion »).
        Thread.UncaughtExceptionHandler previous =
                Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, err) -> {
            writeCrashReport(thread, err);
            try {
                if (previous != null) {
                    previous.uncaughtException(thread, err);
                    return;
                }
            } catch (Throwable ignored) {
            }
            android.os.Process.killProcess(android.os.Process.myPid());
        });
        // Initialise le coffre chiffré + client API durci (libpho).
        PhoHelper.init(this);
        // Self-check runtime (non bloquant): trace/émulateur -> log.
        PhoHelper.selfCheck((r, e) -> {
            if (r != null && r.optBoolean("traced", false)) {
                TasVpnService.logEvent("warning", "app", "Debugger détecté (mode dégradé silencieux)");
            }
        });
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

    /**
     * Rapport de crash détaillé dans Download/crash.txt : horodatage,
     * appareil, version app, état VPN au moment du crash, stacktrace
     * complète et les dernières lignes du journal de connexion. Le fichier
     * est réécrit à chaque crash (le plus récent prime pour le support).
     */
    private void writeCrashReport(Thread thread, Throwable err) {
        try {
            StringWriter sw = new StringWriter();
            err.printStackTrace(new PrintWriter(sw));
            StringBuilder sb = new StringBuilder();
            sb.append("========== EPHANG VPN CRASH ==========\n");
            java.text.SimpleDateFormat fmt =
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS",
                            java.util.Locale.US);
            sb.append("Date       : ").append(fmt.format(new java.util.Date())).append('\n');
            sb.append("Thread     : ").append(thread.getName()).append('\n');
            sb.append("Exception  : ").append(err).append('\n');
            sb.append("Appareil   : ").append(Build.MANUFACTURER).append(' ')
                    .append(Build.MODEL).append(" (Android ").append(Build.VERSION.RELEASE)
                    .append(", API ").append(Build.VERSION.SDK_INT).append(")\n");
            try {
                android.content.pm.PackageInfo pi = getPackageManager()
                        .getPackageInfo(getPackageName(), 0);
                sb.append("App        : ").append(pi.versionName).append('\n');
            } catch (Throwable ignored) {
            }
            sb.append("VPN état   : running=").append(TasVpnService.isRunning())
                    .append(" starting=").append(TasVpnService.isStarting())
                    .append(" active=").append(String.valueOf(TasVpnService.getActiveTunnelId()))
                    .append('\n');
            sb.append("--------------------------------------\n");
            sb.append("STACKTRACE:\n").append(sw).append('\n');
            sb.append("--------------------------------------\n");
            sb.append("DERNIERS ÉVÉNEMENTS (journal):\n");
            sb.append(TasVpnService.getLog()).append('\n');

            // App-private storage: Download/ is read-only for the app on
            // Android 10+ (scoped storage, and WRITE_EXTERNAL_STORAGE is
            // capped at maxSdkVersion 28), so the report was silently lost.
            try (java.io.FileOutputStream out =
                         new java.io.FileOutputStream(
                                 new java.io.File(BinaryManager.logDir(), "crash.txt"), false)) {
                out.write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            TasVpnService.logEvent("error", "app", "CRASH " + thread.getName() + ": " + err
                    + " — rapport dans " + BinaryManager.logDir().getAbsolutePath());
        } catch (Throwable ignored) {
        }
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
        return prefs.getBoolean("set_confirm_disconnect", false);
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

    public String getCustomDnsPrimary() {
        String v = prefs.getString("set_dns_primary", "8.8.8.8");
        return v == null || v.isEmpty() ? "8.8.8.8" : v;
    }

    public void setCustomDnsPrimary(String v) {
        prefs.edit().putString("set_dns_primary", v == null ? "" : v.trim()).apply();
    }

    public String getCustomDnsSecondary() {
        String v = prefs.getString("set_dns_secondary", "1.1.1.1");
        return v == null || v.isEmpty() ? "1.1.1.1" : v;
    }

    public void setCustomDnsSecondary(String v) {
        prefs.edit().putString("set_dns_secondary", v == null ? "" : v.trim()).apply();
    }

    public int getCustomMtu() {
        int v = prefs.getInt("set_mtu", 1500);
        if (v < 1280) {
            v = 1280;
        }
        if (v > 9000) {
            v = 9000;
        }
        return v;
    }

    public void setCustomMtu(int v) {
        if (v < 1280) {
            v = 1280;
        }
        if (v > 9000) {
            v = 9000;
        }
        prefs.edit().putInt("set_mtu", v).apply();
    }

    public boolean isWakeLockEnabled() {
        return prefs.getBoolean("set_wakelock", true);
    }

    public void setWakeLockEnabled(boolean v) {
        prefs.edit().putBoolean("set_wakelock", v).apply();
    }

    public boolean isSlowDnsBoostEnabled() {
        return prefs.getBoolean("set_slowdns_boost", false);
    }

    public void setSlowDnsBoostEnabled(boolean v) {
        prefs.edit().putBoolean("set_slowdns_boost", v).apply();
    }

    public boolean isTcpNoDelayEnabled() {
        return prefs.getBoolean("set_tcp_nodelay", true);
    }

    public void setTcpNoDelayEnabled(boolean v) {
        prefs.edit().putBoolean("set_tcp_nodelay", v).apply();
    }

    public void resetSettings() {
        prefs.edit()
                .putBoolean("set_dns_protection", true)
                .putBoolean("set_stop_on_loss", true)
                .putBoolean("set_auto_reconnect", true)
                .putBoolean("set_launch_on_boot", false)
                .putBoolean("set_verbose_diag", false)
                .putBoolean("set_confirm_disconnect", false)
                .putInt("set_reconnect_delay", 5)
                .putString("set_dns_primary", "8.8.8.8")
                .putString("set_dns_secondary", "1.1.1.1")
                .putInt("set_mtu", 1500)
                .putBoolean("set_wakelock", true)
                .putBoolean("set_slowdns_boost", false)
                .putBoolean("set_tcp_nodelay", true)
                .apply();
    }

    public boolean isDarkModeEnabled() {
        return prefs.getBoolean("dark_mode", true);
    }

    public void setDarkModeEnabled(boolean enabled) {
        prefs.edit().putBoolean("dark_mode", enabled).apply();
    }
}