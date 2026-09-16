package com.ephang.vpn;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Environment;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Stages the official tunnel binaries for execution and builds the JSON
 * start parameters consumed by golib/vpnlib.
 *
 * Binaries ship inside the APK as native libraries
 * (jniLibs/armeabi-v7a/lib_{xray,zivpn,slowdns}.so). At runtime they are
 * copied once to <filesDir>/bin/{xray,zivpn,slowdns} with the executable
 * bit (nativeLibraryDir itself is read-only), alongside
 * geoip.dat/geosite.dat from assets for Xray routing rules.
 */
public class BinaryManager {
    private static final String TAG = "BinaryManager";

    // The Xray binary runs as a child process fed by the TUN fd
    // (Go ExtraFiles -> fd 3 + XRAY_TUN_FD=3).
    private static final String[][] NATIVE_LIBS = {
            {"lib_xray.so", "xray"},
            {"lib_zivpn.so", "zivpn"},
            {"lib_slowdns.so", "slowdns"},
    };

    private static final String[] ASSET_DATS = {"geoip.dat", "geosite.dat"};

    public static File binDir(Context ctx) {
        return new File(ctx.getFilesDir(), "bin");
    }

    public static File configPath(Context ctx) {
        return new File(ctx.getFilesDir(), "config.yaml");
    }

    /** Copy bundled binaries + data files on first run (or when sizes differ). */
    public static synchronized void ensureReady(Context ctx) throws Exception {
        File dir = binDir(ctx);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("cannot create " + dir);
        }

        ApplicationInfo ai = ctx.getApplicationInfo();
        String nativeLibDir = ai.nativeLibraryDir;
        Log.i(TAG, "nativeLibraryDir=" + nativeLibDir);

        for (String[] pair : NATIVE_LIBS) {
            File src = findNativeLibrary(nativeLibDir, pair[0]);
            if (src == null) {
                throw new IllegalStateException("bundled binary missing: " + pair[0]);
            }
            File dst = new File(dir, pair[1]);
            if (!dst.exists() || dst.length() != src.length()) {
                copyFile(src, dst);
            }
            if (!dst.setExecutable(true, true)) {
                Log.w(TAG, "setExecutable failed for " + dst);
            }
            if (!dst.canExecute()) {
                throw new IllegalStateException("binary not executable: " + dst);
            }
        }

        for (String dat : ASSET_DATS) {
            File dst = new File(dir, dat);
            if (!dst.exists()) {
                try {
                    copyAsset(ctx, "bin/" + dat, dst);
                } catch (Exception e) {
                    Log.w(TAG, "asset bin/" + dat + " missing, Xray geo rules unavailable");
                }
            }
        }

        ensureDefaultConfig(ctx);
    }

    /** Search for a native library in the native library directory and its
     *  architecture-specific subdirectories (arm, armeabi-v7a, arm64-v8a, etc.). */
    private static File findNativeLibrary(String nativeLibDir, String libName) {
        File direct = new File(nativeLibDir, libName);
        if (direct.exists()) {
            return direct;
        }
        // Common architecture subdirectories where the library might be
        String[] archSubdirs = {"arm", "armeabi-v7a", "arm64-v8a", "x86", "x86_64"};
        for (String arch : archSubdirs) {
            File candidate = new File(nativeLibDir, arch + File.separator + libName);
            if (candidate.exists()) {
                return candidate;
            }
        }
        return null;
    }

    private static void copyFile(File src, File dst) throws Exception {
        try (InputStream in = Files.newInputStream(src.toPath());
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
    }

    private static void copyAsset(Context ctx, String asset, File dst) throws Exception {
        try (InputStream in = ctx.getAssets().open(asset);
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
    }

    /** Minimal config.yaml pointing at the staged bundle (created once). */
    private static void ensureDefaultConfig(Context ctx) throws Exception {
        File cfg = configPath(ctx);
        if (cfg.exists()) {
            return;
        }
        String binDir = binDir(ctx).getAbsolutePath().replace("\\", "/");
        String dataDir = ctx.getFilesDir().getAbsolutePath().replace("\\", "/");
        String yaml =
                "app:\n" +
                "  name: \"Ephang VPN\"\n" +
                "  version: \"1.0.0\"\n" +
                "  web_port: 0\n" +
                "  web_host: \"127.0.0.1\"\n" +
                "  log_level: \"info\"\n" +
                "  data_dir: \"" + dataDir + "\"\n" +
                "  bin_dir: \"" + binDir + "\"\n" +
                "tunnels: []\n" +
                "network:\n" +
                "  interface: \"tun0\"\n" +
                "  mtu: 1500\n" +
                "  dns: [\"8.8.8.8\", \"1.1.1.1\"]\n" +
                "features:\n" +
                "  kill_switch: false\n" +
                "  split_tunneling: false\n" +
                "  dns_leak_protection: false\n" +
                "  auto_reconnect: true\n" +
                "  reconnect_interval: 5\n" +
                "  max_retries: 10\n" +
                "udpgw:\n" +
                "  enabled: true\n" +
                "  listen_addr: \"127.0.0.1:7300\"\n" +
                "  max_clients: 100\n" +
                "  timeout: 30\n" +
                "  mtu: 1500\n";
        Files.write(cfg.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
    }

    /** Build the vpnlib start-params JSON document. */
    public static String buildStartParams(Context ctx, String tunnelId, int tunFd) throws Exception {
        ensureReady(ctx);
        JSONObject p = new JSONObject();
        p.put("config_path", configPath(ctx).getAbsolutePath());

        // Execute the shipped .so binaries straight from the native library
        // dir (like the reference app). They were extracted there by the
        // PackageManager with an SELinux context that allows execution,
        // unlike filesDir copies on hardened devices (itel/Transsion).
        // bin_names maps the logical name to the on-disk .so name.
        String nativeDir = ctx.getApplicationInfo().nativeLibraryDir;
        p.put("bin_dir", nativeDir);
        JSONObject names = new JSONObject();
        names.put("zivpn", "lib_zivpn.so");
        names.put("xray", "lib_xray.so");
        names.put("slowdns", "lib_slowdns.so");
        p.put("bin_names", names);

        p.put("native_ssh", true);
        p.put("tun_fd", tunFd);
        p.put("mtu", 1500);
        p.put("manage_port", VPNApplication.getInstance().getManagePort());
        p.put("active_tunnel", tunnelId == null ? "" : tunnelId);
        p.put("auto_follow", true);
        // Selected profile set (comma ids). <2 ids = single-profile mode,
        // 2+ = round-robin: Home connects ALL of them at once.
        String selCsv = VPNApplication.getInstance().getSelectedCsv();
        int selCount = selCsv.isEmpty() ? 0 : selCsv.split(",").length;
        p.put("round_robin", selCount >= 2 ? selCsv : "");
        // Writable app-private temp dir (cache dir) for xray configs.
        // Android has no /tmp and CWD is read-only.
        p.put("tmp_dir", ctx.getCacheDir().getAbsolutePath());
        // Diagnostic log file in the public Download folder.
        p.put("log_dir", downloadDir());
        // Forced DNS resolver for port-53 traffic (link-local/carrier DNS
        // is unreachable through the tunnel).
        p.put("dns_ip", "8.8.8.8");
        p.put("dns_protect", VPNApplication.getInstance().isDnsProtectionEnabled());
        return p.toString();
    }

    /** Public Download directory (where kighmu.txt is written). */
    public static String downloadDir() {
        File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (d == null) {
            return "";
        }
        return d.getAbsolutePath();
    }

    /** Append one line to Download/kighmu.txt (unified connection journal).
     *  Best-effort: never throws, never blocks the caller long. */
    public static synchronized void appendKighmu(String line) {
        try {
            File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (d == null) {
                return;
            }
            if (!d.exists() && !d.mkdirs()) {
                return;
            }
            java.text.SimpleDateFormat fmt =
                    new java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US);
            String row = fmt.format(new java.util.Date()) + "  " + line + "\n";
            try (java.io.FileOutputStream out =
                         new java.io.FileOutputStream(new File(d, "kighmu.txt"), true)) {
                out.write(row.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
        }
    }

    /** Read the tail of Download/kighmu.txt ("" when missing/unreadable). */
    public static String readKighmuTail(int maxChars) {
        try {
            File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (d == null) {
                return "";
            }
            File f = new File(d, "kighmu.txt");
            if (!f.exists()) {
                return "";
            }
            long len = f.length();
            long skip = Math.max(0, len - maxChars);
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r")) {
                raf.seek(skip);
                byte[] buf = new byte[(int) (len - skip)];
                int n = raf.read(buf);
                if (n <= 0) {
                    return "";
                }
                String text = new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8);
                // Drop the first (possibly partial) line when we skipped.
                if (skip > 0) {
                    int nl = text.indexOf('\n');
                    if (nl >= 0) {
                        text = text.substring(nl + 1);
                    }
                }
                return text;
            }
        } catch (Exception ignored) {
            return "";
        }
    }

    /** Truncate Download/kighmu.txt. */
    public static void clearKighmu() {
        try {
            File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (d == null) {
                return;
            }
            File f = new File(d, "kighmu.txt");
            if (f.exists()) {
                new java.io.FileOutputStream(f, false).close();
            }
        } catch (Exception ignored) {
        }
    }
    /** Tunnel list (id/name/type) via the Go parser (reliable, offline). */
    public static List<Map<String, String>> listTunnels(Context ctx) {
        List<Map<String, String>> out = new ArrayList<>();
        try {
            ensureReady(ctx);
            String cfgPath = configPath(ctx).getAbsolutePath();
            org.json.JSONArray arr = new org.json.JSONArray(VpnlibHelper.listTunnels(cfgPath));
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject t = arr.optJSONObject(i);
                if (t == null) {
                    continue;
                }
                Map<String, String> m = new HashMap<>();
                m.put("id", t.optString("id", ""));
                m.put("name", t.optString("name", ""));
                m.put("type", t.optString("type", ""));
                if (!m.get("id").isEmpty()) {
                    out.add(m);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "listTunnels failed", e);
        }
        return out;
    }

    public static String firstTunnelId(Context ctx) {
        List<Map<String, String>> tunnels = listTunnels(ctx);
        if (!tunnels.isEmpty() && tunnels.get(0).containsKey("id")) {
            return tunnels.get(0).get("id");
        }
        return null;
    }

    private static String unquote(String s) {
        s = s.trim();
        if (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\"")) ||
                (s.startsWith("'") && s.endsWith("'")))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }
}
