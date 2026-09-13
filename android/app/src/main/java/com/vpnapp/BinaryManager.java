package com.vpnapp;

import android.content.Context;
import android.content.pm.ApplicationInfo;
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

    // NOTE: Xray runs in-process (xray-core library + XRAY_TUN_FD), so only
    // the helper binaries that must stay external are staged here.
    private static final String[][] NATIVE_LIBS = {
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
            File src = new File(nativeLibDir, pair[0]);
            File dst = new File(dir, pair[1]);
            if (!src.exists()) {
                throw new IllegalStateException("bundled binary missing: " + pair[0]);
            }
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
                "  name: \"TasVPN\"\n" +
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
        p.put("bin_dir", binDir(ctx).getAbsolutePath());
        p.put("bin_names", new JSONObject());
        p.put("native_ssh", true);
        p.put("tun_fd", tunFd);
        p.put("mtu", 1500);
        p.put("manage_port", VPNApplication.getInstance().getManagePort());
        p.put("active_tunnel", tunnelId == null ? "" : tunnelId);
        p.put("auto_follow", true);
        return p.toString();
    }

    /** Light tunnel list (id/name/type) parsed from config.yaml for the picker. */
    public static List<Map<String, String>> listTunnels(Context ctx) {
        List<Map<String, String>> out = new ArrayList<>();
        try {
            ensureReady(ctx);
            String text = new String(Files.readAllBytes(configPath(ctx).toPath()), StandardCharsets.UTF_8);
            // Minimal YAML scan: split on "- name:" entries. Full parsing
            // happens in Go once the service runs.
            String[] lines = text.split("\n");
            Map<String, String> cur = null;
            for (String raw : lines) {
                String line = raw.trim();
                if (line.startsWith("- name:") || line.startsWith("- name :")) {
                    if (cur != null && cur.containsKey("name")) {
                        out.add(cur);
                    }
                    cur = new HashMap<>();
                    cur.put("name", unquote(line.substring(line.indexOf(':') + 1).trim()));
                } else if (cur != null && line.startsWith("type:")) {
                    cur.put("type", unquote(line.substring(5).trim()));
                } else if (cur != null && (line.startsWith("id:") || line.startsWith("ID:"))) {
                    cur.put("id", unquote(line.substring(3).trim()));
                }
            }
            if (cur != null && cur.containsKey("name")) {
                out.add(cur);
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
