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
        // Suivi de l'activite courante : un crash arrive presque toujours
        // dans un ecran precis, son nom rend la stack trace parlante.
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
        prefs = getSharedPreferences("ephang_vpn_prefs", Context.MODE_PRIVATE);

        // Reprendre un crash du lancement precedent : le rapport est deja
        // dans les preferences, on peut donc l'afficher meme si l'ecriture
        // sur disque a ete interrompue par la mort du processus.
        try {
            String prev = getSharedPreferences("crash_report", Context.MODE_PRIVATE)
                    .getString("last", "");
            if (prev != null && !prev.isEmpty()) {
                lastCrashReport = prev;
                hasPendingCrash = true;
            }
        } catch (Throwable ignored) {
        }

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
     * Rapport de crash détaillé : horodatage, appareil, version app, etat
     * VPN au moment du crash, stacktrace complète (cause racine incluse),
     * etat memoire/thread, activite courante et dernier journal.
     *
     * Le rapport est ecrit dans le stockage prive de l'app (seul emplacement
     * fiable) puis DIFFUSE dans Download/ via MediaStore, car depuis
     * Android 10 l'ecriture directe y est interdite et le fichier restait
     * invisible pour l'utilisateur. Il est aussi rejoue au demarrage suivant
     * (banniere + bouton de partage) pour ne dependre d'aucun timing.
     */
    private void writeCrashReport(Thread thread, Throwable err) {
        try {
            StringBuilder sb = new StringBuilder();
            java.text.SimpleDateFormat fmt =
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS",
                            java.util.Locale.US);
            sb.append("========== EPHANG VPN CRASH ==========\n");
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
            // Contexte memoire/process : un OutOfMemory ou un deadlock se
            // diagnose beaucoup plus vite avec ces chiffres.
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
            // Relire au demarrage suivant : l'ecriture pendant le crash peut
            // etre interrompue par la mort du processus.
            getSharedPreferences("crash_report", Context.MODE_PRIVATE)
                    .edit().putString("last", report).apply();
            // Rendre le rapport visible par l'utilisateur (Download).
            boolean published = CrashShare.publishToDownload(this,
                    CrashShare.timestampedName("ephang-crash", ".txt"), report);
            lastCrashReport = report;
            hasPendingCrash = true;
            TasVpnService.logEvent("error", "app", "CRASH " + thread.getName() + ": " + err
                    + " (rapport " + (published ? "copie dans Download" : "interne")
                    + " : " + BinaryManager.logDir().getAbsolutePath() + "/crash.txt)");
        } catch (Throwable ignored) {
        }
    }

    /** Trace complet : exception + toutes les causes enchainees. */
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

    // Nom de l'activite resume : un crash arrive presque toujours dans un
    // ecran precis, son nom rend la stack trace immédiatement parlante.
    private static volatile String currentActivity = "";

    /** Dernier rapport de crash, rejoue au demarrage suivant. */
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

    /**
     * Publie le dernier rapport de crash dans Download et le marque comme
     * traite. Appele depuis la bannière de demarrage.
     */
    public boolean shareLastCrashReport() {
        String report = lastCrashReport;
        if (report == null || report.isEmpty()) {
            return false;
        }
        boolean ok = CrashShare.publishToDownload(this,
                CrashShare.timestampedName("ephang-crash", ".txt"), report);
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