package com.borum.vpn;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.KeyStore;

import vpnlib.Vpnlib;

public final class IntegrityGuard {
    private static final String TAG = "IntegrityGuard";
    private static final long INTERVAL_MS = 4000;
    private static final long KILL_DELAY_MS = 900;

    private static final boolean KILL_ON_HARD = true;
    private static final String SIG_VAULT_KEY = "integrity.sig";

    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile boolean started = false;
    private static volatile boolean hard = false;
    private static volatile boolean killed = false;
    private static volatile String lastVerdict = "{}";

    private IntegrityGuard() {
    }

    private static String s(int[] cp) {
        StringBuilder sb = new StringBuilder(cp.length);
        for (int c : cp) {
            sb.append((char) c);
        }
        return sb.toString();
    }

    private static final String N_FRIDA = s(new int[]{102, 114, 105, 100, 97});
    private static final String N_XPOSED_FRAME =
            s(new int[]{100, 101, 46, 114, 111, 98, 118, 46, 97, 110, 100, 114, 111, 105, 100, 46, 120, 112, 111, 115, 101, 100});
    private static final String N_SU = s(new int[]{47, 115, 121, 115, 116, 101, 109, 47, 98, 105, 110, 47, 115, 117}); 
    private static final String N_XSU = s(new int[]{47, 115, 121, 115, 116, 101, 109, 47, 120, 98, 105, 110, 47, 115, 117}); 
    private static final String N_MAGISK = s(new int[]{47, 100, 97, 116, 97, 47, 97, 100, 98, 47, 109, 97, 103, 105, 115, 107}); 

    public static synchronized void start(Context ctx) {
        if (started) {
            return;
        }
        started = true;
        Thread t = new Thread(() -> loop(ctx.getApplicationContext()), "integrity-guard");
        t.setDaemon(true);
        t.start();
    }

    public static boolean hardBlocked() {
        return hard;
    }

    public static String lastVerdict() {
        return lastVerdict;
    }

    private static void loop(Context ctx) {

        while (true) {
            try {
                evaluate(ctx);
            } catch (Throwable th) {
                Log.w(TAG, "evaluate failed: " + th);
            }
            if (hard && KILL_ON_HARD && !killed) {
                killed = true;
                terminate("hard");
                return;
            }
            try {
                Thread.sleep(INTERVAL_MS);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private static void evaluate(Context ctx) {

        boolean gHard = false, gFrida = false, gHook = false, gTraced = false;
        boolean gRoot = false, gEmu = false, gMagisk = false;
        try {
            JSONObject v = new JSONObject(Vpnlib.phoSelfCheck());
            lastVerdict = v.toString();
            gFrida = v.optBoolean("frida", false);
            gHook = v.optBoolean("hook", false);
            gTraced = v.optBoolean("traced", false);
            gRoot = v.optBoolean("root", false);
            gEmu = v.optBoolean("emulator", false);
            gMagisk = v.optBoolean("magisk", false);
            gHard = v.optBoolean("hard", false) || gFrida || gHook || gTraced;
        } catch (Throwable ignored) {
        }

        boolean jDebugger = false;
        try {
            jDebugger = Debug.isDebuggerConnected() || Debug.waitingForDebugger();
        } catch (Throwable ignored) {
        }
        boolean jXposed = stackHasHook();
        boolean jRoot = new java.io.File(N_SU).exists()
                || new java.io.File(N_XSU).exists()
                || new java.io.File(N_MAGISK).exists();
        boolean jProxy = globalProxySet(ctx);
        boolean jUserCa = userCaInstalled();
        boolean jVpn = foreignVpnActive(ctx);

        boolean sigBad = false;
        try {
            sigBad = signatureMismatch(ctx);
        } catch (Throwable ignored) {
        }

        hard = gHard || jDebugger || jXposed || sigBad;

        if (hard) {
            TasVpnService.logEvent("error", "security",
                    "environnement non autorisé — session protégée");
        } else if (gRoot || gEmu || gMagisk || jRoot || jProxy || jUserCa || jVpn) {

            lastVerdict = mergeSoft(lastVerdict, jProxy, jUserCa, jVpn);
        }
    }

    private static String mergeSoft(String verdict, boolean proxy, boolean ca, boolean vpn) {
        try {
            JSONObject v = new JSONObject(verdict);
            v.put("proxy_set", proxy);
            v.put("user_ca", ca);
            v.put("foreign_vpn", vpn);
            return v.toString();
        } catch (Exception e) {
            return verdict;
        }
    }

    private static boolean stackHasHook() {
        try {
            throw new IllegalStateException();
        } catch (IllegalStateException e) {
            for (StackTraceElement el : e.getStackTrace()) {
                String cn = el.getClassName();
                if (cn != null && cn.contains(N_XPOSED_FRAME)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean globalProxySet(Context ctx) {
        try {
            String p = android.provider.Settings.Global.getString(
                    ctx.getContentResolver(), android.provider.Settings.Global.HTTP_PROXY);
            return p != null && !p.trim().isEmpty();
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean userCaInstalled() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            java.util.Enumeration<String> en = ks.aliases();
            while (en.hasMoreElements()) {
                if (en.nextElement().startsWith("user:")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean foreignVpnActive(Context ctx) {
        try {
            if (TasVpnService.isRunning() || TasVpnService.isStarting()) {
                return false;
            }
            ConnectivityManager cm =
                    (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return false;
            }
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean signatureMismatch(Context ctx) throws Exception {
        String uuid = ApiSession.deviceUuid(ctx);
        if (uuid == null || uuid.isEmpty()) {
            return false;
        }
        PackageInfo pi = ctx.getPackageManager().getPackageInfo(
                ctx.getPackageName(), PackageManager.GET_SIGNATURES);
        if (pi == null || pi.signatures == null || pi.signatures.length == 0) {
            return false;
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(pi.signatures[0].toByteArray());
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) {
            sb.append(String.format("%02X", b));
        }
        String cur = sb.toString();
        String pinned = PhoHelper.vaultGet(uuid, SIG_VAULT_KEY);
        if (pinned == null || pinned.isEmpty()) {
            PhoHelper.vaultPut(ctx, uuid, SIG_VAULT_KEY, cur);
            return false;
        }
        return !pinned.equals(cur);
    }

    private static void terminate(String why) {
        try {
            TasVpnService.logEvent("error", "security",
                    "session terminée — environnement non autorisé");
        } catch (Throwable ignored) {
        }
        MAIN.postDelayed(() -> {
            try {
                android.os.Process.killProcess(android.os.Process.myPid());
            } catch (Throwable ignored) {
            }
            System.exit(0);
        }, KILL_DELAY_MS);
    }
}
