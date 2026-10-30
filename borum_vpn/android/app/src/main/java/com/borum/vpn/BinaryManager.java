package com.borum.vpn;

import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BinaryManager {
    private static final String TAG = "BinaryManager";

    private static final String[][] NATIVE_LIBS = {
            {"lib_xray.so", "xray"},
            {"lib_zivpn.so", "zivpn"},
            {"lib_slowdns.so", "slowdns"},
    };

    public static File binDir(Context ctx) {
        return new File(ctx.getFilesDir(), "bin");
    }

    public static File configPath(Context ctx) {
        return new File(ctx.getFilesDir(), "config.yaml");
    }

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

            if (!dst.exists() || !sameDigest(src, dst)) {
                copyFile(src, dst);
                if (!sameDigest(src, dst)) {
                    throw new IllegalStateException("binary integrity check failed: " + pair[1]);
                }
            }
            if (!dst.setExecutable(true, true)) {
                Log.w(TAG, "setExecutable failed for " + dst);
            }
            if (!dst.canExecute()) {
                throw new IllegalStateException("binary not executable: " + dst);
            }
        }

        new File(dir, "geoip.dat").delete();
        new File(dir, "geosite.dat").delete();

        ensureDefaultConfig(ctx);
    }

    private static File findNativeLibrary(String nativeLibDir, String libName) {
        File direct = new File(nativeLibDir, libName);
        if (direct.exists()) {
            return direct;
        }

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

    private static boolean sameDigest(File a, File b) {
        if (a.length() != b.length()) {
            return false;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(a.toPath())) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            }
            byte[] expected = md.digest();
            md.reset();
            try (InputStream in = Files.newInputStream(b.toPath())) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            }
            return MessageDigest.isEqual(expected, md.digest());
        } catch (Exception e) {
            return false;
        }
    }

    private static void ensureDefaultConfig(Context ctx) throws Exception {
        File cfg = configPath(ctx);
        if (cfg.exists()) {
            return;
        }
        String binDir = binDir(ctx).getAbsolutePath().replace("\\", "/");
        String dataDir = ctx.getFilesDir().getAbsolutePath().replace("\\", "/");
        String yaml =
                "app:\n" +
                "  name: \"borum VPN\"\n" +
                "  version: \"1.0.0\"\n" +
                "  web_port: 0\n" +
                "  web_host: \"127.0.0.1\"\n" +
                "  log_level: \"info\"\n" +
                "  data_dir: \"" + dataDir + "\"\n" +
                "  bin_dir: \"" + binDir + "\"\n" +
                "tunnels:\n" +
                "  - id: \"orange_fast\"\n" +
                "    name: \"Orange Fast\"\n" +
                "    type: \"xray\"\n" +
                "    enabled: true\n" +
                "    priority: 0\n" +
                "    server:\n" +
                "      host: \"192.179.18.100\"\n" +
                "      port: 443\n" +
                "      sni: \"crashlyticsreports-pa.googleapis.com\"\n" +
                "    auth:\n" +
                "      uuid: \"aaaa0000-1111-4222-8333-444455556666\"\n" +
                "      flow: \"\"\n" +
                "    transport:\n" +
                "      network: \"ws\"\n" +
                "      security: \"tls\"\n" +
                "      path: \"/@kighmu\"\n" +
                "      host: \"kighmu-vpn-919282834024.asia-south1.run.app\"\n" +
                "    routing:\n" +
                "      domain_strategy: \"AsIs\"\n" +
                "      rules: []\n" +
                "      dns:\n" +
                "        servers: [\"1.1.1.1\", \"8.8.8.8\"]\n" +
                "    advanced:\n" +
                "      orange_fast: true\n" +
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
                "  listen_addr: \"127.0.0.1:" + nativeUdpgwPort() + "\"\n" +
                "  max_clients: 100\n" +
                "  timeout: 30\n" +
                "  mtu: 1500\n";
        Files.write(cfg.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
    }

    private static int nativeUdpgwPort() {
        try {
            return (int) vpnlib.Vpnlib.phoPortUdpgw();
        } catch (Throwable t) {
            return 7300;
        }
    }

    private static volatile String sLogName = null;

    private static String logFileName() {
        String n = sLogName;
        if (n != null) {
            return n;
        }
        try {
            String v = vpnlib.Vpnlib.phoLogFileName();
            if (v != null && !v.trim().isEmpty()) {
                n = v.trim();
            }
        } catch (Throwable ignored) {
        }
        if (n == null || n.isEmpty()) {
            n = "kighmu.txt";
        }
        sLogName = n;
        return n;
    }

    public static String buildStartParams(Context ctx, String tunnelId, int tunFd) throws Exception {
        ensureReady(ctx);
        JSONObject p = new JSONObject();
        p.put("config_path", configPath(ctx).getAbsolutePath());

        String nativeDir = ctx.getApplicationInfo().nativeLibraryDir;
        p.put("bin_dir", nativeDir);
        JSONObject names = new JSONObject();
        names.put("zivpn", "lib_zivpn.so");
        names.put("xray", "lib_xray.so");
        names.put("slowdns", "lib_slowdns.so");
        p.put("bin_names", names);

        p.put("native_ssh", true);
        p.put("tun_fd", tunFd);
        p.put("mtu", VPNApplication.getInstance().getCustomMtu());
        p.put("manage_port", VPNApplication.getInstance().getManagePort());
        p.put("active_tunnel", tunnelId == null ? "" : tunnelId);
        p.put("auto_follow", true);

        String selCsv = VPNApplication.getInstance().getSelectedCsv();
        int selCount = selCsv.isEmpty() ? 0 : selCsv.split(",").length;
        p.put("round_robin", selCount >= 2 ? selCsv : "");

        p.put("tmp_dir", ctx.getCacheDir().getAbsolutePath());

        p.put("log_dir", logDir().getAbsolutePath());

        p.put("log_quiet", true);

        p.put("dns_ip", VPNApplication.getInstance().getCustomDnsPrimary());
        p.put("dns_protect", VPNApplication.getInstance().isDnsProtectionEnabled());
        p.put("dns_secondary", VPNApplication.getInstance().getCustomDnsSecondary());
        p.put("tcp_nodelay", VPNApplication.getInstance().isTcpNoDelayEnabled());
        p.put("dnstt_tcp", VPNApplication.getInstance().isSlowDnsBoostEnabled());

        String tid = tunnelId != null ? tunnelId
                : VPNApplication.getInstance().getActiveTunnelId();
        JSONObject adv = activeProfileAdvanced(ctx, tid);
        if (adv != null) {
            Object port = adv.opt("udpgw_port");
            if (port != null && !String.valueOf(port).trim().isEmpty()) {
                p.put("udpgw_listen", String.valueOf(port).trim());
            }
            if (adv.has("udpgw_dns")) {
                p.put("udpgw_enabled", adv.optBoolean("udpgw_dns", true));
            }
        }
        return p.toString();
    }

    private static JSONObject activeProfileAdvanced(Context ctx, String id) {
        if (id == null || id.isEmpty()) {
            return null;
        }
        try {
            JSONArray arr = new JSONArray(
                    VpnlibHelper.listTunnels(configPath(ctx).getAbsolutePath()).trim());
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.optJSONObject(i);
                if (t != null && id.equals(t.optString("id", ""))) {
                    return t.optJSONObject("advanced");
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static String downloadDir() {
        File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (d == null) {
            return "";
        }
        return d.getAbsolutePath();
    }

    public static File logDir() {
        File d = new File(VPNApplication.getInstance().getFilesDir(), "logs");
        if (!d.exists()) {

            d.mkdirs();
        }
        return d;
    }

    public static File logFile() {
        return new File(logDir(), logFileName());
    }

    public static synchronized void appendKighmu(String line) {
        appendKighmuRaw(null, line);
    }

    public static synchronized void appendKighmuRaw(String timePrefix, String line) {
        String row;
        try {
            File d = logDir();
            if (!d.exists() && !d.mkdirs()) {
                return;
            }
            String stamp = timePrefix != null ? timePrefix
                    : new java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US)
                    .format(new java.util.Date());
            row = stamp + "  " + line + "\n";
            try (java.io.FileOutputStream out =
                          new java.io.FileOutputStream(logFile(), true)) {
                out.write(row.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

        } catch (Exception e) {
            android.util.Log.w("Tasmol", "appendKighmu: " + e);
        }
    }

    private static void appendKighmuToDownload(String row) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Context ctx = VPNApplication.getInstance();
                if (ctx == null) return;
                Uri uri = downloadKighmuUri(ctx);
                if (uri != null) {
                    try (OutputStream out = ctx.getContentResolver()
                            .openOutputStream(uri, "wa")) {
                        if (out != null) {
                            out.write(row.getBytes(StandardCharsets.UTF_8));
                            out.flush();
                        }
                    }
                }
            } else {

                File downloadDir = Environment.getExternalStoragePublicDirectory(
                        Environment.DIRECTORY_DOWNLOADS);
                if (downloadDir != null && downloadDir.exists()) {
                    File f = new File(downloadDir, "kighmu.txt");
                    try (FileOutputStream out = new FileOutputStream(f, true)) {
                        out.write(row.getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
        } catch (Exception e) {
            android.util.Log.w("Tasmol", "appendKighmuToDownload: " + e);
        }
    }

    private static synchronized Uri downloadKighmuUri(Context ctx) {
        Uri uri = sDownloadKighmuUri;
        if (uri != null) {
            return uri;
        }
        try {

            String[] proj = { MediaStore.MediaColumns._ID };
            String sel = MediaStore.MediaColumns.DISPLAY_NAME + "=? AND "
                    + MediaStore.MediaColumns.RELATIVE_PATH + " LIKE ?";
            String[] args = { "kighmu.txt", "Download%" };
            try (Cursor c = ctx.getContentResolver().query(
                    MediaStore.Downloads.getContentUri(
                            MediaStore.VOLUME_EXTERNAL_PRIMARY),
                    proj, sel, args, null)) {
                if (c != null && c.moveToFirst()) {
                    long id = c.getLong(0);
                    uri = ContentUris.withAppendedId(
                            MediaStore.Downloads.getContentUri(
                                    MediaStore.VOLUME_EXTERNAL_PRIMARY), id);
                    sDownloadKighmuUri = uri;
                    return uri;
                }
            }

            ContentValues values = new ContentValues();
            values.put(MediaStore.MediaColumns.DISPLAY_NAME, "kighmu.txt");
            values.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            values.put(MediaStore.MediaColumns.RELATIVE_PATH,
                    Environment.DIRECTORY_DOWNLOADS);
            uri = ctx.getContentResolver().insert(
                    MediaStore.Downloads.getContentUri(
                            MediaStore.VOLUME_EXTERNAL_PRIMARY),
                    values);
            sDownloadKighmuUri = uri;
            return uri;
        } catch (Exception e) {
            android.util.Log.w("Tasmol", "downloadKighmuUri: " + e);
            return null;
        }
    }

    private static volatile Uri sDownloadKighmuUri = null;

    private static volatile long sMirrorOffset = -2L;
    private static volatile boolean sMirrorThread = false;
    private static final Object sMirrorLock = new Object();

    public static void startDownloadMirror() {
        if (sMirrorThread) {
            return;
        }
        synchronized (sMirrorLock) {
            if (sMirrorThread) {
                return;
            }
            sMirrorThread = true;
        }
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        mirrorTick();
                    } catch (Throwable th) {

                        mirrorDiag("tick failed: " + th);
                    }
                    try {
                        Thread.sleep(700);
                    } catch (InterruptedException ignored) {

                        sMirrorThread = false;
                        return;
                    }
                }
            }
        }, "kighmu-mirror");
        t.setDaemon(true);
        t.start();
    }

    private static void mirrorTick() {
        Context ctx = VPNApplication.getInstance();
        if (ctx == null) {
            return;
        }
        File src;
        try {
            src = logFile();
        } catch (Throwable ignored) {
            return;
        }
        if (src == null) {
            return;
        }
        long srcLen = src.exists() ? src.length() : -1L;
        if (srcLen < 0) {

            resetDownloadKighmu(ctx, false);
            sMirrorOffset = -2L;
            return;
        }
        if (sMirrorOffset == -2L) {

            resetDownloadKighmu(ctx, true);
            sMirrorOffset = 0;
        }
        if (srcLen < sMirrorOffset) {

            sMirrorOffset = 0;
            resetDownloadKighmu(ctx, true);
            return;
        }
        if (srcLen == sMirrorOffset) {
            return; 
        }
        long from = sMirrorOffset;
        long remaining = srcLen - from;

        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(src, "r")) {
            raf.seek(from);
            byte[] buf = new byte[65536];
            long written = 0;
            int n;
            while (written < remaining && (n = raf.read(buf)) > 0) {
                String chunk = new String(buf, 0, n, StandardCharsets.UTF_8);
                appendKighmuToDownload(chunk);
                written += n;
            }
            sMirrorOffset = from + written;
        } catch (Exception e) {

            Log.w(TAG, "kighmu-mirror read: " + e);
        }
    }

    private static synchronized void resetDownloadKighmu(Context ctx,
                                                         boolean createIfMissing) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            File downloadDir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            if (downloadDir != null) {
                File f = new File(downloadDir, "kighmu.txt");
                try {
                    if (f.exists()) {
                        new FileOutputStream(f, false).close();
                    }
                } catch (Exception e) {
                    Log.w(TAG, "resetDownloadKighmu(preQ): " + e);
                }
                return;
            }
        }
        Uri uri = sDownloadKighmuUri;
        if (uri == null && createIfMissing) {
            uri = downloadKighmuUri(ctx);
        }
        if (uri == null) {
            return;
        }
        try (OutputStream out = ctx.getContentResolver()
                .openOutputStream(uri, "wt")) {

        } catch (Exception e) {
            Log.w(TAG, "resetDownloadKighmu: " + e);
        }
    }

    private static void mirrorDiag(String cause) {
        long now = System.currentTimeMillis();
        if (now - sLastMirrorDiag < 30_000L) {
            return;
        }
        sLastMirrorDiag = now;
        try {
            appendKighmu("[warning] [mirror] copie Download/kighmu.txt en échec: "
                    + cause + " (le journal privé filesDir/logs/kighmu.txt reste "
                    + "la source complète — mode Verbose)");
        } catch (Throwable ignored) {
        }
    }

    private static volatile long sLastMirrorDiag = 0L;

    public static long kighmuStamp() {
        try {
            File f = logFile();
            return f.exists() ? (f.length() ^ (f.lastModified() << 1)) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    public static String readKighmuTail(int maxChars) {
        try {
            File f = logFile();
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

                if (skip > 0) {
                    int nl = text.indexOf('\n');
                    if (nl >= 0) {
                        text = text.substring(nl + 1);
                    }
                }
                return text;
            }
        } catch (Exception e) {
            return "";
        }
    }

    public static void clearKighmu() {
        try {
            File f = logFile();
            if (f.exists()) {
                new java.io.FileOutputStream(f, false).close();
            }
        } catch (Exception e) {
            android.util.Log.w("Tasmol", "clearKighmu: " + e);
        }

        try {
            Context ctx = VPNApplication.getInstance();
            if (ctx == null) return;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Uri uri = sDownloadKighmuUri; 

                if (uri == null) {
                    uri = downloadKighmuUri(ctx); 
                }
                if (uri != null) {
                    try (OutputStream out = ctx.getContentResolver()
                            .openOutputStream(uri, "wt")) { 

                    }
                }
            } else {
                File downloadDir = Environment.getExternalStoragePublicDirectory(
                        Environment.DIRECTORY_DOWNLOADS);
                if (downloadDir != null) {
                    File f2 = new File(downloadDir, "kighmu.txt");
                    if (f2.exists()) {
                        new FileOutputStream(f2, false).close();
                    }
                }
            }
        } catch (Exception e) {
            android.util.Log.w("Tasmol", "clearKighmu(Download): " + e);
        }
    }

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
