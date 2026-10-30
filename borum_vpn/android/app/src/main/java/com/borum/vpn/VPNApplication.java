package com.borum.vpn;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;

import vpnlib.Vpnlib;

public class VPNApplication extends Application {
    private static VPNApplication instance;
    private SharedPreferences prefs;

    @Override
    public void onCreate() {

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

        UiPrefs.applySavedTheme(this);
        UiPrefs.applySavedLang(this);

        PhoHelper.init(this);

        IntegrityGuard.start(this);

        new Thread(() -> {
            try {
                DeviceIdentity.getUuid(VPNApplication.this);
            } catch (Throwable ignored) {
            }
        }, "device-identity").start();

        registerActivityLifecycleCallbacks(new android.app.Application.ActivityLifecycleCallbacks() {
            @Override
            public void onActivityResumed(android.app.Activity a) {
                currentActivity = a.getClass().getSimpleName();
            }

            @Override
            public void onActivityPaused(android.app.Activity a) {
            }

            @Override
            public void onActivityCreated(android.app.Activity a, android.os.Bundle b) {
            }

            @Override
            public void onActivityStarted(android.app.Activity a) {
            }

            @Override
            public void onActivityStopped(android.app.Activity a) {
            }

            @Override
            public void onActivitySaveInstanceState(android.app.Activity a, android.os.Bundle b) {
            }

            @Override
            public void onActivityDestroyed(android.app.Activity a) {
            }
        });
        super.onCreate();
        instance = this;
        prefs = getSharedPreferences("borum_vpn_prefs", Context.MODE_PRIVATE);

        try {
            String prev = getSharedPreferences("crash_report", Context.MODE_PRIVATE)
                    .getString("last", "");
            if (prev != null && !prev.isEmpty()) {
                lastCrashReport = prev;
                hasPendingCrash = true;
            }
        } catch (Throwable ignored) {
        }

        try {
            BinaryManager.ensureReady(this);
        } catch (Exception e) {
            Log.e("VPNApplication", "ensureReady failed on launch", e);
        }

        ExpiryGuard.getInstance(this).start();
    }

    public static VPNApplication getInstance() {
        return instance;
    }

    private void writeCrashReport(Thread thread, Throwable err) {
        try {
            StringBuilder sb = new StringBuilder();
            java.text.SimpleDateFormat fmt =
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS",
                            java.util.Locale.US);
            sb.append("========== borum VPN CRASH ==========\n");
            sb.append("Date       : ").append(fmt.format(new java.util.Date())).append('\n');
            sb.append("Thread     : ").append(thread.getName()).append('\n');
            sb.append("Exception  : ").append(err).append('\n');
            sb.append("Cause      : ").append(rootCause(err)).append('\n');
            sb.append("Appareil   : ").append(Build.MANUFACTURER).append(' ')
                    .append(Build.MODEL).append(" (Android ").append(Build.VERSION.RELEASE)
                    .append(", API ").append(Build.VERSION.SDK_INT).append(")\n");
            try {
                android.content.pm.PackageInfo pi = getPackageManager()
                        .getPackageInfo(getPackageName(), 0);
                sb.append("App        : ").append(pi.versionName).append('\n');
            } catch (Throwable ignored) {
            }
            sb.append("VPN etat   : running=").append(TasVpnService.isRunning())
                    .append(" starting=").append(TasVpnService.isStarting())
                    .append(" active=").append(String.valueOf(TasVpnService.getActiveTunnelId()))
                    .append('\n');

            Runtime rt = Runtime.getRuntime();
            long total = rt.totalMemory() / (1024 * 1024);
            long free = rt.freeMemory() / (1024 * 1024);
            sb.append("Memoire    : ").append(free).append("M libre / ").append(total)
                    .append("M, max=").append(rt.maxMemory() / (1024 * 1024)).append("M\n");
            sb.append("Threads    : ").append(Thread.activeCount()).append(" actifs\n");
            sb.append("Activite   : ").append(String.valueOf(currentActivityName())).append('\n');
            sb.append("--------------------------------------\n");
            sb.append("STACKTRACE COMPLETE:\n").append(fullStack(err)).append('\n');
            sb.append("--------------------------------------\n");
            sb.append("CAUSE RACINE:\n").append(causeChain(err)).append('\n');
            sb.append("--------------------------------------\n");
            sb.append("DERNIERS EVENEMENTS (journal):\n");
            sb.append(TasVpnService.getLog()).append('\n');

            String report = sb.toString();
            try (java.io.FileOutputStream out =
                         new java.io.FileOutputStream(
                                 new java.io.File(BinaryManager.logDir(), "crash.txt"), false)) {
                out.write(report.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

            getSharedPreferences("crash_report", Context.MODE_PRIVATE)
                    .edit().putString("last", report).apply();

            boolean published = CrashShare.publishToDownload(this,
                    CrashShare.timestampedName("borum-crash", ".txt"), report);
            lastCrashReport = report;
            hasPendingCrash = true;
            TasVpnService.logEvent("error", "app", "CRASH " + thread.getName() + ": " + err
                    + " (rapport " + (published ? "copie dans Download" : "interne")
                    + " : " + BinaryManager.logDir().getAbsolutePath() + "/crash.txt)");
        } catch (Throwable ignored) {
        }
    }

    private static String fullStack(Throwable err) {
        StringWriter sw = new StringWriter();
        err.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    private static String causeChain(Throwable err) {
        StringBuilder sb = new StringBuilder();
        Throwable t = err;
        int depth = 0;
        while (t != null && depth < 10) {
            sb.append("  [").append(depth).append("] ").append(t.getClass().getName())
                    .append(": ").append(String.valueOf(t.getMessage())).append('\n');
            StackTraceElement[] st = t.getStackTrace();
            for (int i = 0; i < Math.min(st.length, 12); i++) {
                sb.append("        at ").append(st[i]).append('\n');
            }
            Throwable cause = t.getCause();
            t = (cause == t) ? null : cause;
            depth++;
        }
        return sb.toString();
    }

    private static String rootCause(Throwable err) {
        Throwable t = err;
        int depth = 0;
        while (t != null && depth < 20) {
            Throwable cause = t.getCause();
            if (cause == null || cause == t) {
                break;
            }
            t = cause;
            depth++;
        }
        return t == null ? "?" : t.getClass().getName() + ": " + String.valueOf(t.getMessage());
    }

    private static String currentActivityName() {
        return currentActivity.isEmpty() ? "n/d" : currentActivity;
    }

    private static volatile String currentActivity = "";

    private static volatile String lastCrashReport = "";
    private static volatile boolean hasPendingCrash = false;

    public boolean hasPendingCrash() {
        return hasPendingCrash;
    }

    public String consumeLastCrashReport() {
        String r = lastCrashReport;
        hasPendingCrash = false;
        return r == null ? "" : r;
    }

    public boolean shareLastCrashReport() {
        String report = lastCrashReport;
        if (report == null || report.isEmpty()) {
            return false;
        }
        boolean ok = CrashShare.publishToDownload(this,
                CrashShare.timestampedName("borum-crash", ".txt"), report);
        if (ok) {
            hasPendingCrash = false;
        }
        return ok;
    }

    public SharedPreferences getPrefs() {
        return prefs;
    }

    public String getServerUrl() {
        return prefs.getString("server_url", "http://127.0.0.1:" + getManagePort() + "/");
    }

    public int getManagePort() {

        return prefs.getInt("manage_port", nativeManagePort());
    }

    private int nativeManagePort() {
        try {
            return (int) Vpnlib.phoPortManage();
        } catch (Throwable t) {
            return 18080;
        }
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

    public java.util.LinkedHashSet<String> getSelectedIds() {
        String csv = prefs.getString("selected_ids", null);
        if (csv == null) {

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

    public static final String ORANGE_FAST_HOST_KEY = "orange_fast_host";
    public static final String ORANGE_FAST_DEFAULT_HOST =
            "kighmu-vpn-919282834024.asia-south1.run.app";

    public String getOrangeFastHost() {
        return prefs.getString(ORANGE_FAST_HOST_KEY, ORANGE_FAST_DEFAULT_HOST);
    }

    public void setOrangeFastHost(String host) {
        prefs.edit().putString(ORANGE_FAST_HOST_KEY, host == null
                ? ORANGE_FAST_DEFAULT_HOST : host.trim()).apply();
    }

    public static final String MTN_UNLIMITED_HOST_KEY = "mtn_unlimited_host";
    public static final String MTN_UNLIMITED_DEFAULT_HOST =
            "kighmu-vpn-919282834024.asia-south1.run.app";

    public String getMtnUnlimitedHost() {
        return prefs.getString(MTN_UNLIMITED_HOST_KEY, MTN_UNLIMITED_DEFAULT_HOST);
    }

    public void setMtnUnlimitedHost(String host) {
        prefs.edit().putString(MTN_UNLIMITED_HOST_KEY, host == null
                ? MTN_UNLIMITED_DEFAULT_HOST : host.trim()).apply();
    }

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
        int v = prefs.getInt("set_reconnect_delay", 2);
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
                .putInt("set_reconnect_delay", 2)
                .putString("set_dns_primary", "8.8.8.8")
                .putString("set_dns_secondary", "1.1.1.1")
                .putInt("set_mtu", 1500)
                .putBoolean("set_wakelock", true)
                .putBoolean("set_slowdns_boost", false)
                .putBoolean("set_tcp_nodelay", true)
                .apply();
    }

    public void resetAll() {

        String theme = prefs.getString("set_theme", "system");
        String lang = prefs.getString("set_lang", "system");
        prefs.edit().clear().apply();
        prefs.edit()
                .putString("set_theme", theme)
                .putString("set_lang", lang)
                .putBoolean("set_dns_protection", true)
                .putBoolean("set_stop_on_loss", true)
                .putBoolean("set_auto_reconnect", true)
                .putBoolean("set_launch_on_boot", false)
                .putBoolean("set_verbose_diag", false)
                .putBoolean("set_confirm_disconnect", false)
                .putInt("set_reconnect_delay", 2)
                .putString("set_dns_primary", "8.8.8.8")
                .putString("set_dns_secondary", "1.1.1.1")
                .putInt("set_mtu", 1500)
                .putBoolean("set_wakelock", true)
                .putBoolean("set_slowdns_boost", false)
                .putBoolean("set_tcp_nodelay", true)
                .putString(ORANGE_FAST_HOST_KEY, ORANGE_FAST_DEFAULT_HOST)
                .apply();
    }

    public void resetConfigFile(android.content.Context ctx) {
        try {
            java.io.File cfg = BinaryManager.configPath(ctx);
            if (cfg != null && cfg.exists()) {
                cfg.delete();
            }
        } catch (Exception ignored) {
        }
    }

}
