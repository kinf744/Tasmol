package com.ephang.vpn;

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
 * bit (nativeLibraryDir itself is read-only).
 *
 * geoip.dat/geosite.dat ne sont PLUS embarqués (~30 Mo économisés) :
 * aucune config générée par l'app n'utilise de règle geoip:/geosite:.
 */
public class BinaryManager {
    private static final String TAG = "BinaryManager";

    // The Xray binary runs as a child process fed by the TUN fd
    // (Go ExtraFiles -> fd 3 + XRAY_TUN_FD=3).
    private static final String[][] NATIVE_LIBS = {
            {"lib_xray.so", "xray"},
            {"lib_zivpn.so", "zivpn"},
            {"lib_slowdns.so", "slowdns"},
            {"lib_hysteria.so", "hysteria"},
            {"lib_utunnel.so", "utunnel"},
    };

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

        // Nettoie les legacy geo .dat laissés par les versions précédentes
        // (libère ~30 Mo sur les appareils mis à jour).
        new File(dir, "geoip.dat").delete();
        new File(dir, "geosite.dat").delete();

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
        names.put("hysteria", "lib_hysteria.so");
        names.put("utunnel", "lib_utunnel.so");
        p.put("bin_names", names);

        p.put("native_ssh", true);
        p.put("tun_fd", tunFd);
        p.put("mtu", VPNApplication.getInstance().getCustomMtu());
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
        // Diagnostic log file. MUST be app-private: the Go logger opens
        // <log_dir>/kighmu.txt for append and silently disables itself
        // (makeFileLogger returns nil) if the path is not writable, which
        // is what happened with Download/ on Android 10+.
        p.put("log_dir", logDir().getAbsolutePath());
        // Forced DNS resolver for port-53 traffic (link-local/carrier DNS
        // is unreachable through the tunnel).
        p.put("dns_ip", VPNApplication.getInstance().getCustomDnsPrimary());
        p.put("dns_protect", VPNApplication.getInstance().isDnsProtectionEnabled());
        p.put("dns_secondary", VPNApplication.getInstance().getCustomDnsSecondary());
        p.put("tcp_nodelay", VPNApplication.getInstance().isTcpNoDelayEnabled());
        p.put("dnstt_tcp", VPNApplication.getInstance().isSlowDnsBoostEnabled());
        // Per-profile UDPGW ("Udpgw Port" + "Enable UDPGW transparent DNS"
        // in the SSH editor). Absent => the config.yaml value applies.
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

    /** advanced{} map of the given profile, or null when unreadable. */
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

    /** Public Download directory (where kighmu.txt is written). */
    public static String downloadDir() {
        File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (d == null) {
            return "";
        }
        return d.getAbsolutePath();
    }

    /** Journal directory. The live journal MUST live in app-private storage:
     *  Download/ is read-only for the app on Android 10+ (API 29) with
     *  targetSdk 34, and WRITE_EXTERNAL_STORAGE is capped at maxSdkVersion 28.
     *  Writing there silently failed (scoped storage), so appendKighmu threw
     *  into an empty catch and the Go logger returned nil — the Logs tab
     *  simply never received a single line. The public Download copy is now
     *  an explicit user action (shareJournal), not the live sink. */
    public static File logDir() {
        File d = new File(VPNApplication.getInstance().getFilesDir(), "logs");
        if (!d.exists()) {
            //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        }
        return d;
    }

    public static File logFile() {
        return new File(logDir(), "kighmu.txt");
    }

    /** Append one line to the journal (unified connection journal).
     *  Best-effort: never throws, never blocks the caller long. */
    public static synchronized void appendKighmu(String line) {
        appendKighmuRaw(null, line);
    }

    /** Append a journal row with a caller-supplied timestamp column.
     *  @param timePrefix "HH:mm:ss.SSS" (null = now) — the row is written
     *  verbatim so a caller can control the exact journal layout.
     *
     *  NOTE: this ONLY writes the app-private file (filesDir/logs/
     *  kighmu.txt). Mirroring to Download is owned EXCLUSIVELY by the
     *  background kighmu-mirror thread (startDownloadMirror), which copies
     *  new bytes of the private file to the single Download entry on a
     *  short cadence. Tunnelling through one owner eliminates double content
     *  (Go DirectLog + this mirror would otherwise duplicate lines) and
     *  several duplicate files ("kighmu.txt", "kighmu (1).ppt", …) that the
     *  per-line MediaStore.insert() previously created. */
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
            // Lazy-start the live mirror so the Download copy receives the
            // rich Go detail too (see startDownloadMirror). Starting here
            // on the first write covers both app start and VPN reconnects.
            startDownloadMirror();
        } catch (Exception e) {
            android.util.Log.w("Tasmol", "appendKighmu: " + e);
        }
    }

    /** Write the same journal line to Download/kighmu.txt via MediaStore.
     *  On Android 10+ (API 29) this uses MediaStore with a SINGLE stable
     *  entry: we query for the existing kighmu.txt first (append to it),
     *  and only insert a new one when none exists. The previous version did
     *  a fresh MediaStore.insert() per line, which created many duplicate
     *  files in Download ("kighmu.txt", "kighmu (1).txt", "kighmu (2).txt"…)
     *  — the "plusieurs fichiers kighmu.txt avec un contenu très médiocre"
     *  symptom the user reported. On older Android it falls back to direct
     *  file write (permission granted by maxSdkVersion=28). */
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
                // Android 9 and below: direct file write (WRITE_EXTERNAL_STORAGE granted)
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

    /** Find (or lazily create) the SINGLE MediaStore entry for
     *  Download/kighmu.txt and cache its Uri. Returns null when unavailable. */
    private static synchronized Uri downloadKighmuUri(Context ctx) {
        Uri uri = sDownloadKighmuUri;
        if (uri != null) {
            return uri;
        }
        try {
            // Look for an existing kighmu.txt this app owns in Download/.
            // RELATIVE_PATH filter avoids adopting an unrelated kighmu.txt
            // created by another app (openOutputStream on a foreign entry
            // throws on Android 10+ scoped storage).
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
            // Not found: create it once.
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

    /** Cached Uri of the single Download/kighmu.txt entry. */
    private static volatile Uri sDownloadKighmuUri = null;

    // ────────────────────────────────────────────────────────────────────
    //  Live Download mirroring (background kighmu-mirror thread)
    //
    //  The Go data plane writes a RICH log into filesDir/logs/kighmu.txt
    //  (utunnel traces, child-process stdout/stderr, connection milestones).
    //  That private file is the ONLY sink of detail: before this mirror,
    //  Download/kighmu.txt only received the coarse Java logEvent() lines,
    //  which is exactly the "contenu très médiocre" the user reported.
    //
    //  The mirror opens the SAME single MediaStore entry in Download
    //  (query-first, insert-once — no more "kighmu (1).txt", "kighmu (2).txt"
    //  proliferatition) and appends any NEW bytes appended to the private
    //  file since the last tick (~700 ms). Truncation (clearKighmu) resets
    //  the offset and rewrites from byte 0 so the Download copy never mixes
    //  stale sessions with the live one.
    // ────────────────────────────────────────────────────────────────────

    // Byte offset up to which the private journal has already been mirrored.
    // -2 = "not started yet" (triggers the initial copy of the whole file).
    private static volatile long sMirrorOffset = -2L;
    private static volatile boolean sMirrorThread = false;
    private static final Object sMirrorLock = new Object();

    /** Start the background mirror if not running. Safe to call repeatedly.
     *  Called from appendKighmuRaw and from the VPN session start. */
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
                        // One broken tick must NEVER kill the mirror — and
                        // the cause must be VISIBLE to the user (logcat is
                        // invisible on the phone). Log into the private
                        // journal, throttled.
                        mirrorDiag("tick failed: " + th);
                    }
                    try {
                        Thread.sleep(700);
                    } catch (InterruptedException ignored) {
                        // interrupted: app is shutting down; exit thread.
                        sMirrorThread = false;
                        return;
                    }
                }
            }
        }, "kighmu-mirror");
        t.setDaemon(true);
        t.start();
    }

    /** One mirror tick: copy new bytes of the private journal to Download.
     *  Synchronized on the SAME lock as appendKighmuRaw, so a Java write +
     *  the tick can never interleave half a row (Go writes are atomic per
     *  O_APPEND write, which interleaves safely). */
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
            // Private file gone (app reinstall / clear): reset the mirror.
            resetDownloadKighmu(ctx, false);
            sMirrorOffset = -2L;
            return;
        }
        if (sMirrorOffset == -2L) {
            // First tick: TRUNCATE (never delete) the stale Download copy
            // from a previous app version, then mirror the existing content
            // from byte 0. Deleting would force a fresh MediaStore insert
            // while the ContentResolver output-FD cache may still point at
            // the deleted entry — silent "wa" failures. Truncating keeps
            // ONE entry and reuses it.
            resetDownloadKighmu(ctx, true);
            sMirrorOffset = 0;
        }
        if (srcLen < sMirrorOffset) {
            // Truncated externally (e.g. clearKighmu): restart from 0 and
            // truncate the Download copy to keep both files in sync.
            sMirrorOffset = 0;
            resetDownloadKighmu(ctx, true);
            return;
        }
        if (srcLen == sMirrorOffset) {
            return; // nothing new
        }
        long from = sMirrorOffset;
        long remaining = srcLen - from;
        // RandomAccessFile.seek is deterministic (FileInputStream.skip can
        // skip short and its return value must be checked — a short skip
        // here would copy from the wrong offset and corrupt the Download
        // copy silently).
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
            // NOT advanced: the next tick retries the exact same bytes.
            Log.w(TAG, "kighmu-mirror read: " + e);
        }
    }

    /** Truncate (never delete) the Download/kighmu.txt entry so the single
     *  MediaStore entry survives and the ContentResolver FD cache stays
     *  valid. When createIfMissing is set, a missing entry is inserted. */
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
            // empty write = truncation only
        } catch (Exception e) {
            Log.w(TAG, "resetDownloadKighmu: " + e);
        }
    }

    /** Mirror failure diagnostics, written into the private journal (visible
     *  in the app LOGS tab) and throttled to one row per 30 s so a broken
     *  MediaStore never floods the journal. */
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

    /** Stamp bon marché du journal (taille ^ mtime) : 0 si absent. Les écrans
     *  l'utilisent pour sauter les re-rendus quand rien n'a changé. */
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
                // Drop the first (possibly partial) line when we skipped.
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

    /** Truncate the journal. */
    public static void clearKighmu() {
        try {
            File f = logFile();
            if (f.exists()) {
                new java.io.FileOutputStream(f, false).close();
            }
        } catch (Exception e) {
            android.util.Log.w("Tasmol", "clearKighmu: " + e);
        }
        // Reset the Download copy too: without this the stale content from a
        // previous analysis stays appended in Download/kighmu.txt forever
        // and the next session's log is preceded by garbage. We reopen the
        // entry in "wt" (truncate) mode — mode "" rewrite — on MediaStore,
        // which truncates the file. On pre-Q we truncate the file directly.
        try {
            Context ctx = VPNApplication.getInstance();
            if (ctx == null) return;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Uri uri = sDownloadKighmuUri; // reuse cached; do NOT query
                        // (the file may have been emptied, but the entry still
                        // exists — querying could re-create it unnecessarily)
                if (uri == null) {
                    uri = downloadKighmuUri(ctx); // lazily create on first use
                }
                if (uri != null) {
                    try (OutputStream out = ctx.getContentResolver()
                            .openOutputStream(uri, "wt")) { // wt = truncate
                        // empty write = truncation only
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
