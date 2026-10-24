package com.borum.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;

import androidx.core.app.NotificationCompat;

import org.json.JSONObject;

import vpnlib.Vpnlib;

/**
 * Real Android VPN service (Voie B, no root required).
 *
 * Captures device traffic into a TUN interface and hands its file
 * descriptor to the Go data plane (golib/vpnlib, tun2socks over the local
 * SOCKS5 of the active tunnel). The app's own UID is excluded from the VPN
 * via addDisallowedApplication so upstream sockets (tunnel processes,
 * SOCKS dials) never loop back into the TUN.
 */
public class TasVpnService extends VpnService {
    private static final String TAG = "TasVpnService";
    private static final String CHANNEL_ID = "tasvpn_channel";
    private static final int NOTIFICATION_ID = 42;

    public static final String ACTION_CONNECT = "com.borum.vpn.action.CONNECT";
    public static final String ACTION_DISCONNECT = "com.borum.vpn.action.DISCONNECT";
    /** Fast, forceful disconnect: short teardown bound, no waiting around. */
    public static final String ACTION_NUCLEAR_DISCONNECT = "com.borum.vpn.action.NUCLEAR_DISCONNECT";
    public static final String EXTRA_TUNNEL_ID = "tunnel_id";

    private static volatile Object controller = null;
    private static volatile String activeTunnelId = null;
    private static volatile String lastError = null;
    // True while a session is being established (connecting / reconnecting).
    // The Home tab shows a red CONNECTING status while this is set.
    private static volatile boolean starting = false;
    private static volatile int startGen = -1;
    // Controller of a start that is still in flight, published the moment
    // Vpnlib.newController() returns and BEFORE the (blocking) start() call.
    // Without it, a disconnect arriving during CONNECTING saw
    // controller == null, took the "nothing to stop" fast path, and the start
    // went on to build the whole data plane and re-post its notification
    // after stopForeground(true) — the ghost VPN key the user reported.
    private static final java.util.concurrent.atomic.AtomicReference<Object> pendingController =
            new java.util.concurrent.atomic.AtomicReference<>(null);
    // Bornes d'attente Java. Le Stop() Go est désormais non bloquant
    // (TryLock + hard-kill du fd TUN, retour < 300 ms même pendant un
    // Start() en vol) : ces bornes ne servent que de plafond, la vraie
    // déconnexion « pro » se joue en < 2.5 s. En cas de stop vraiment
    // coincé, le watchdog ci-dessous reste le recours.
    private static final long STOP_TIMEOUT_S = 3;
    private static final long STOP_TIMEOUT_NUCLEAR_S = 2;
    // Cleanup between two retry attempts runs on the connect thread, so it gets
    // a much shorter bound than a user-initiated disconnect.
    private static final long RETRY_STOP_TIMEOUT_S = 2;
    // Hard deadline of the teardown, after which the process is ended outright
    // so the key cannot survive. Nuclear uses the short one (the user asked for
    // an immediate kill); the normal disconnect gets a longer grace so a
    // perfectly healthy teardown is never interrupted.
    //
    // Even with a bounded Go teardown, Controller.stop() can block on the
    // controller mutex while a start() is in flight, and a Java interrupt
    // cannot unwind a gomobile call. If the Go stop has still not returned by
    // then, the only reliable way to make the VPN key disappear is to end the
    // process: Android always revokes the key of a dead VpnService.
    private static final long WATCHDOG_KILL_NORMAL_MS = 8000;
    private static final long WATCHDOG_KILL_NUCLEAR_MS = 5000;
    // Délai de la seconde passe de déconnexion (double disconnect).
    private static final long SECOND_PASS_DELAY_MS = 2000;
    // Number of Go stop() calls currently in flight (refcount, NOT a boolean).
    // Deux arrêts peuvent viser le même contrôleur en même temps : le stop
    // async de stopSession ET le stop borné du catch du thread de connexion.
    // Avec un simple booléen, le premier stop qui retourne effaçait le drapeau
    // pendant que l'autre restait coincé sur le mutex Go — le watchdog était
    // alors désarmé à tort et personne ne tuait le processus : la clé VPN
    // restait collée (TUN fd détenu par Go). Le compteur ne tombe à zéro que
    // lorsque TOUS les arrêts sont réellement terminés.
    private static final java.util.concurrent.atomic.AtomicInteger goStopCount =
            new java.util.concurrent.atomic.AtomicInteger(0);
    // Service-scoped main-thread handler: the nuclear watchdog must not depend
    // on any Activity, otherwise leaving the app while a teardown is stuck
    // leaves the key with nobody left able to remove it.
    private final android.os.Handler serviceHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    // True pendant qu'un thread de connexion existe (y compris pendant le
    // retry-sleep entre deux essais et AVANT la publication du contrôleur Go).
    // Sans ce marqueur, un nucléaire arrivé dans cette fenêtre ne voyait rien
    // à tuer : la tentative reprenait et bâtissait la session malgré tout.
    private static final java.util.concurrent.atomic.AtomicBoolean connectInFlight =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    // Connection attempts: CONNECTING stays on across retries until the
    // session is up or the user disconnects (disconnect supersedes via
    // sessionGen, nuclear kill ends the process outright).
    private static final int MAX_START_ATTEMPTS = 6;
    private static final long RETRY_DELAY_MS = 3000;
    private static volatile int startAttempt = 0;

    private static final java.util.ArrayDeque<String> eventLog = new java.util.ArrayDeque<>();
    private static final int MAX_LOG_LINES = 40;

    /**
     * Raison courte et non technique (affichage/toast/journal) : les
     * erreurs brutes Go (dial, TLS, stack) ne vont plus à l'écran.
     */
    public static String shortReason(String raw) {
        if (raw == null) {
            return "";
        }
        String l = raw.toLowerCase(java.util.Locale.US);
        if (l.contains("serveur injoignable") || l.contains("refused")
                || l.contains("all endpoints")) {
            return "serveur injoignable";
        }
        if (l.contains("timeout") || l.contains("deadline")) {
            return "délai dépassé";
        }
        if (l.contains("unreachable") || l.contains("no route")
                || l.contains("network")) {
            return "réseau indisponible";
        }
        if (l.contains("auth") || l.contains("password") || l.contains("denied")
                || l.contains("permission")) {
            return "accès refusé";
        }
        if (l.contains("tls") || l.contains("x509") || l.contains("certificate")
                || l.contains("pin")) {
            return "connexion sécurisée échouée";
        }
        if (l.contains("binary") || l.contains("executable")
                || l.contains("not found")) {
            return "composant manquant";
        }
        String s = raw.trim();
        int nl = s.indexOf('\n');
        if (nl > 0) {
            s = s.substring(0, nl);
        }
        return s.length() > 60 ? s.substring(0, 60) + "…" : s;
    }

    /** Append a timestamped event to the in-memory connection log. */
    public static synchronized void logEvent(String msg) {
        logEvent("info", "app", msg);
    }

    /**
     * Leveled journal event. Journal MINIMAL : les événements "info"
     * (bavardage technique) ne sont plus journalisés — le journal ne
     * contient que les jalons de connexion, les avertissements, les
     * erreurs et la sécurité, lisibles d'un seul regard.
     */
    public static synchronized void logEvent(String level, String component, String msg) {
        if ("info".equals(level) || "trace".equals(level)) {
            return;
        }
        java.text.SimpleDateFormat fmt =
                new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
        eventLog.addLast(fmt.format(new java.util.Date()) + "  " + msg);
        while (eventLog.size() > MAX_LOG_LINES) {
            eventLog.removeFirst();
        }
        BinaryManager.appendKighmu("[" + level + "] [" + component + "] " + msg);
    }

    public static synchronized String getLog() {
        if (eventLog.isEmpty()) {
            return "No events yet.";
        }
        StringBuilder sb = new StringBuilder();
        for (String line : eventLog) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    public static synchronized void clearLog() {
        eventLog.clear();
    }

    private volatile ParcelFileDescriptor tunFd = null;
    private volatile int detachedFd = -1;

    public static Object getController() {
        return controller;
    }

    public static String getActiveTunnelId() {
        return activeTunnelId;
    }

    public static String getLastError() {
        return lastError;
    }

    public static boolean isRunning() {
        return controller != null;
    }

    public static boolean isStarting() {
        return starting;
    }

    /**
     * True while a controller has been handed to the Go teardown and that call
     * has not returned yet.
     *
     * <p>Callers must not use isRunning()/isStarting() alone to decide whether
     * a disconnect finished: stopSession() clears both immediately, so a
     * wedged teardown would look "all good" to a watchdog and the VPN key would
     * survive with nobody left to remove it.
     */
    public static boolean isTeardownHanging() {
        return goStopCount.get() > 0;
    }

    public static int getStartAttempt() {
        return startAttempt;
    }

    public static int getMaxStartAttempts() {
        VPNApplication app = VPNApplication.getInstance();
        if (app != null && !app.isAutoReconnectEnabled()) {
            return 1;
        }
        return MAX_START_ATTEMPTS;
    }

    private static long retryDelayMs() {
        VPNApplication app = VPNApplication.getInstance();
        if (app == null) {
            return RETRY_DELAY_MS;
        }
        return app.getReconnectDelaySeconds() * 1000L;
    }

    private static final java.util.concurrent.atomic.AtomicInteger sessionGen =
            new java.util.concurrent.atomic.AtomicInteger(0);

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        String action = intent.getAction();
        if (ACTION_NUCLEAR_DISCONNECT.equals(action)) {
            sessionGen.incrementAndGet();
            stopSession(true);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_DISCONNECT.equals(action)) {
            // Invalidate any in-flight connect so a late background thread
            // can never publish a zombie session (stuck VPN key).
            sessionGen.incrementAndGet();
            stopSession();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CONNECT.equals(action)) {
            String tunnelId = intent.getStringExtra(EXTRA_TUNNEL_ID);
            startSession(tunnelId);
            // START_NOT_STICKY : si le processus est tué (déconnexion
            // nucléaire), Android ne doit PAS relivrer cet intent — sinon
            // le service ressuscite et la clé VPN revient aussitôt
            // (c'était la cause du "nuclear inefficace en CONNECTING").
            return START_NOT_STICKY;
        }
        return START_NOT_STICKY;
    }

    private void startSession(String tunnelId) {
        if (controller != null || starting) {
            Log.i(TAG, "session start already in progress/running, ignoring duplicate");
            return;
        }
        // Une déconnexion récente a peut-être armé le watchdog kill (8s) ou
        // la seconde passe (2s) : une nouvelle connexion légitime ne doit
        // PAS être tuée ni re-nettoyée par eux.
        disarmNuclearWatchdog();
        cancelSecondPass();
        // RASP : instrumentation/débogage/re-signature détectés — aucune
        // session VPN (le plan de données ne doit pas tourner sous hook).
        if (IntegrityGuard.hardBlocked()) {
            lastError = "Environnement non autorisé";
            logEvent("error", "security", "démarrage refusé — environnement non autorisé");
            stopSelf();
            return;
        }
        lastError = null;
        // Foreground immediately: the data plane can take 5-20s (process
        // startups, readiness probes). Blocking the main thread here is an
        // ANR ("wait / force close"), and the system kills services that
        // don't call startForeground() in time.
        startForeground(NOTIFICATION_ID, buildNotification("Connecting..."));
        final String requestedId = tunnelId;
        final int gen = sessionGen.incrementAndGet();
        starting = true;
        startGen = gen;
        startAttempt = 0;
        connectInFlight.set(true);
        logEvent("connection", "app",
                ">>> CONNEXION demandee tunnel=" + (requestedId == null ? "?" : requestedId)
                + " gen=" + gen + " autoReconnect=" + VPNApplication.getInstance().isAutoReconnectEnabled());
        new Thread(() -> startSessionBackground(gen, requestedId), "borum-connect").start();
    }

    private void startSessionBackground(int gen, String tunnelId) {
        Exception lastFailure = null;
        int attempt = 0;
        final int maxAttempts = getMaxStartAttempts();
        final long retryDelay = retryDelayMs();
        logEvent("connection", "app",
                ">>> demarrage boucle de connexion gen=" + gen + " tunnel=" + tunnelId
                + " maxAttempts=" + maxAttempts + " retryDelayMs=" + retryDelay
                + " autoReconnect=" + (VPNApplication.getInstance() != null
                && VPNApplication.getInstance().isAutoReconnectEnabled()));
        try {
            while (attempt < maxAttempts && !isSuperseded(gen)) {
                attempt++;
                startAttempt = attempt;
                notifyText("Connecting...");
                logEvent("connection", "app",
                        "tentative " + attempt + "/" + maxAttempts + " gen=" + gen
                        + " tunnel=" + tunnelId);
                Object ctrl = null;
                try {
                    // Ensure bundled official binaries + config are staged.
                    BinaryManager.ensureReady(this);

                    String tid = tunnelId;
                    if (tid == null || tid.isEmpty()) {
                        tid = VPNApplication.getInstance().getActiveTunnelId();
                    }
                    if (tid == null || tid.isEmpty()) {
                        tid = BinaryManager.firstTunnelId(this);
                    }
                    if (tid == null || tid.isEmpty()) {
                        throw new IllegalStateException("no tunnel configured: add one in the app first");
                    }
                    if (isSuperseded(gen)) {
                        return;
                    }

                    Builder builder = new Builder()
                            .setSession("borum VPN")
                            .setMtu(VPNApplication.getInstance().getCustomMtu())
                            .addAddress("10.8.0.2", 32)
                            .addRoute("0.0.0.0", 0)
                            .addDnsServer(validDnsOrDefault(
                                    VPNApplication.getInstance().getCustomDnsPrimary()))
                            // Exclude our own UID so upstream sockets (xray, zivpn,
                            // dnstt, ssh, SOCKS dials) never loop into the TUN.
                            .addDisallowedApplication(getPackageName());

                    tunFd = builder.establish();
                    if (tunFd == null) {
                        throw new IllegalStateException("VpnService.Builder.establish() returned null");
                    }
                    int fd = tunFd.detachFd();
                    detachedFd = fd;
                    logEvent("connection", "app",
                            "TUN etablie fd=" + fd + " gen=" + gen + " tentative=" + attempt);

                    String params = BinaryManager.buildStartParams(this, tid, fd);
                    Log.i(TAG, "starting data plane, active=" + tid + " attempt=" + attempt);

                    // Journal de session par tunnel (zivvn, Hysteria, Xray,
                    // Xray slowdns, SSH, SSH slowdns) : same layout as the rest
                    // of the file so the Logs tab shows one chronology. An
                    // unrecognised type yields "" and the block is skipped.
                    final String tunnelType = UdpSessionLog.typeOfTunnel(this, tid);
                    if (!UdpSessionLog.prettyType(tunnelType).isEmpty()) {
                        UdpSessionLog.connecting();
                    }

                    ctrl = Vpnlib.newController();
                    // Publish BEFORE the blocking start() so a disconnect
                    // arriving during CONNECTING can reach this controller.
                    // stopSession() used to see a null controller here, do
                    // nothing, and let the data plane build itself to the end.
                    pendingController.set(ctrl);
                    logEvent("connection", "app",
                            "controleur Go publie gen=" + gen + " tentative=" + attempt);
                    if (isSuperseded(gen)) {
                        // Déconnexion arrivée pile avant le start() Go : ne
                        // jamais lancer le plan de données, tout démonter.
                        abortSupersededStart(gen, ctrl);
                        return;
                    }
                    String err = invokeStart(ctrl, params);
                    // Go now owns the fd; clear our tracker.
                    detachedFd = -1;
                    if (err != null && !err.isEmpty()) {
                        logEvent("error", "app",
                                "plan de données ECHEC gen=" + gen + " tentative=" + attempt
                                + " tunnel=" + tid + " erreur=" + err);
                        pendingController.compareAndSet(ctrl, null);
                        closeTunQuietly();
                        if (!UdpSessionLog.prettyType(tunnelType).isEmpty()) {
                            UdpSessionLog.failed(UdpSessionLog.prettyType(tunnelType), err);
                        }
                        throw new IllegalStateException("data plane: " + err);
                    }
                    logEvent("connection", "app",
                            "plan de données demarre gen=" + gen + " tentative=" + attempt
                            + " tunnel=" + tid);
                    SecurityGuard.noteSuccessfulCheck(this);

                    if (isSuperseded(gen)) {
                        // A disconnect (or newer connect) arrived while starting:
                        // tear down instead of publishing a zombie session.
                        abortSupersededStart(gen, ctrl);
                        return;
                    }

                    controller = ctrl;
                    pendingController.compareAndSet(ctrl, null);
                    ctrl = null;
                    activeTunnelId = tid;
                    VPNApplication.getInstance().setActiveTunnelId(tid);
                    acquireWakeLock();
                    showCustomBanner(tid);

                    // Re-check as late as possible, immediately before posting
                    // the notification. setActiveTunnelId (SharedPreferences),
                    // acquireWakeLock and showCustomBanner (file read plus a
                    // gomobile call) sit between the test above and this post,
                    // which made the window wide enough for a disconnect to
                    // land in it — and the notification was then re-posted
                    // AFTER stopForeground(true), leaving a ghost VPN key that
                    // nothing was left to remove.
                    if (isSuperseded(gen)) {
                        abortSupersededStart(gen, null);
                        return;
                    }

                    notifyText("Connected");
                    Log.i(TAG, "VPN session running");
                    if (!UdpSessionLog.prettyType(tunnelType).isEmpty()) {
                        UdpSessionLog.connected(tunnelType);
                    }
                    logEvent("connection", "app", "connected (" + tid + ")");
                    return;
                } catch (Exception e) {
                    lastFailure = e;
                    Log.e(TAG, "startSession attempt " + attempt + " failed", e);
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    logEvent("error", "app",
                            "tentative " + attempt + "/" + maxAttempts + " ECHEC gen=" + gen
                            + " tunnel=" + tunnelId + " type=" + e.getClass().getName()
                            + " msg=" + String.valueOf(e.getMessage())
                            + " stack=" + sw.toString());
                    if (ctrl != null) {
                        // Never leak an unpublished controller across attempts.
                        pendingController.compareAndSet(ctrl, null);
                        // Bounded: the next attempt needs the SOCKS ports back,
                        // so we do have to wait here — but not forever, or a
                        // wedged Go teardown would keep this connect thread
                        // (and its "Connecting..." post) alive indefinitely.
                        stopControllerBoundedSync(ctrl, RETRY_STOP_TIMEOUT_S,
                                "retry cleanup");
                    }
                    closeTunQuietly();
                    // Close detached fd on error (not handed to Go).
                    if (detachedFd >= 0) {
                        try {
                            android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
                        } catch (Exception ignored) {
                        } finally {
                            detachedFd = -1;
                        }
                    }
                    if (isSuperseded(gen)) {
                        // Sweep the shade: the "Connecting..." post from this
                        // attempt may still be the visible one.
                        cancelNotification();
                        releaseWakeLock();
                        return;
                    }
                    if (attempt < maxAttempts) {
                        logEvent("warning", "app", "connect attempt " + attempt + "/"
                                + maxAttempts + " failed: " + e.getMessage() + " - retrying");
                        try {
                            Thread.sleep(retryDelay);
                        } catch (InterruptedException ie) {
                            return;
                        }
                    }
                }
            }
            if (!isSuperseded(gen) && lastFailure != null) {
                lastError = shortReason(lastFailure.getMessage());
                logEvent("error", "app",
                        ">>> ECHEC DEFINITIF gen=" + gen + " tentatives=" + attempt
                        + "/" + maxAttempts + " tunnel=" + tunnelId
                        + " raison=" + lastError);
                stopForeground(true);
                cancelNotification();
                releaseWakeLock();
                stopSelf();
            }
        } finally {
            connectInFlight.set(false);
            pendingController.set(null);
            // Safety: close detached fd if still open (e.g., max attempts reached without supersede).
            if (detachedFd >= 0) {
                try {
                    android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
                } catch (Exception ignored) {
                } finally {
                    detachedFd = -1;
                }
            }
            // Last line of defence: if this attempt was superseded at any
            // point, make sure no "Connecting..." / "Connected" post of ours
            // outlived the disconnect. Generation-guarded, so a newer connect
            // that legitimately re-posted its own notification is untouched.
            if (isSuperseded(gen)) {
                cancelNotification();
            }
            clearStarting(gen);
        }
    }

    private void closeTunQuietly() {
        try {
            if (tunFd != null) {
                tunFd.close();
            }
        } catch (Exception ignored) {
        } finally {
            tunFd = null;
        }
    }

    /** Clear the connecting flag, but only if no newer session took over. */
    private static void clearStarting(int gen) {
        if (sessionGen.get() == gen) {
            starting = false;
        }
    }

    /** Custom banner of the profile (Backup "Custom Banner" + Note). */
    private void showCustomBanner(String tunnelId) {
        try {
            String cfgPath = BinaryManager.configPath(this).getAbsolutePath();
            org.json.JSONArray arr = new org.json.JSONArray(
                    VpnlibHelper.listTunnels(cfgPath));
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject t = arr.getJSONObject(i);
                if (!tunnelId.equals(t.optString("id", ""))) {
                    continue;
                }
                String banner = ProfileTransfer.customBanner(t);
                if (!banner.isEmpty()) {
                    logEvent("connection", "app", "banner: " + banner);
                    final String text = banner;
                    new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                        try {
                            android.widget.Toast.makeText(getApplicationContext(),
                                    text, android.widget.Toast.LENGTH_LONG).show();
                        } catch (Exception ignored) {
                        }
                    });
                }
                break;
            }
        } catch (Exception ignored) {
        }
    }

    /** True when a newer start/stop request superseded this generation. */
    private boolean isSuperseded(int gen) {
        return gen != sessionGen.get();
    }

    private static String validDnsOrDefault(String ip) {
        if (ip != null && ip.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return ip;
        }
        return "8.8.8.8";
    }

    private android.os.PowerManager.WakeLock wakeLock = null;

    private synchronized void acquireWakeLock() {
        releaseWakeLock();
        VPNApplication app = VPNApplication.getInstance();
        if (app == null || !app.isWakeLockEnabled()) {
            return;
        }
        try {
            android.os.PowerManager pm =
                    (android.os.PowerManager) getSystemService(POWER_SERVICE);
            if (pm == null) {
                return;
            }
            wakeLock = pm.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "borumVPN:session");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(12 * 60 * 60 * 1000L);
        } catch (Exception e) {
            Log.w(TAG, "wakelock failed", e);
        }
    }

    private synchronized void releaseWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
            }
        } catch (Exception ignored) {
        } finally {
            wakeLock = null;
        }
    }

    /**
     * Sweep the notification for good.
     *
     * stopForeground(true) is not a reliable guarantee on its own: the
     * connect thread can re-post the very same notification afterwards (see
     * abortSupersededStart), and the notification is built with
     * setOngoing(true), so a survivor cannot even be swiped away. cancel() is
     * the only authoritative removal, and it is idempotent and cheap.
     */
    private void cancelNotification() {
        try {
            android.app.NotificationManager nm =
                    (android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.cancel(NOTIFICATION_ID);
            }
        } catch (Exception ignored) {
        }
    }

    private void stopSession() {
        stopSession(false);
    }

    /**
     * Tear the session down.
     *
     * @param nuclear short teardown bound — the user asked for an immediate
     *               kill, so we drop the notification straight away and stop
     *               waiting on the Go teardown sooner.
     */
    private void stopSession(boolean nuclear) {
        // Invalidate any in-flight connect first.
        sessionGen.incrementAndGet();
        starting = false;
        // Journal de session UDP : la séquence d'arrêt complète la ligne de
        // connexion. Résolu avant que activeTunnelId ne soit effacé. Bloc
        // entièrement défensif : un crash ICI (main thread, dans le chemin
        // nucléaire) fermerait l'app sans libérer proprement la session.
        try {
            if (controller != null && activeTunnelId != null) {
                String t = UdpSessionLog.prettyType(UdpSessionLog.typeOfTunnel(this, activeTunnelId));
                if (!t.isEmpty()) {
                    UdpSessionLog.stopping();
                }
            }
        } catch (Exception ignored) {
        }
        // 1) RELEASE THE KEY IMMEDIATELY: fermer le TUN et quitter le
        // foreground fait disparaître l'icône clé sur le champ, même si
        // l'arrêt lourd du plan Go traîne ensuite (ou plante).
        try {
            if (tunFd != null) {
                tunFd.close();
            }
        } catch (Exception ignored) {
        } finally {
            tunFd = null;
        }
        // Also close detached fd if it was never handed to Go (CONNECTING abort path).
        if (detachedFd >= 0) {
            try {
                android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
            } catch (Exception ignored) {
            } finally {
                detachedFd = -1;
            }
        }
        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        // ...then sweep the shade for good: a notification re-posted by the
        // connect thread (or an OEM where stopForeground races the notify)
        // would otherwise stay forever, ongoing and un-swipeable.
        cancelNotification();

        // 2) Heavy teardown (Go process kills, stack drain) off main thread
        // — jamais d'ANR, jamais de crash de l'UI quand la session a duré.
        // Take BOTH the live session and a start that is still in flight:
        // during CONNECTING the live one is null and the in-flight one is the
        // only thing that can be stopped. Controller.stop() blocks until the
        // concurrent start() releases its mutex, so this waits rather than
        // tears resources out from under it; the bound below caps the wait.
        final Object ctrl = controller;
        final String tidAtStop = activeTunnelId;
        controller = null;
        final Object inflight = pendingController.getAndSet(null);
        activeTunnelId = null;
        // Les appels API repassent en direct (le chemin tunnel va mourir).
        updateApiProxy();
        final Object target = ctrl != null ? ctrl : inflight;
        if (target == null) {
            // Nothing visible to stop — mais une tentative peut être en vol
            // (retry-sleep ou entre newController() et pendingController.set :
            // dans cette fenêtre getAndSet() retourne null alors qu'un start()
            // va démarrer !). Le watchdog est DONC ARMÉ DANS TOUS LES CAS :
            // au moment où il tire (5s nucléaire, 8s normal), toute activité
            // restante (teardown coincé, thread de connexion encore vivant,
            // contrôleur publié entre-temps) provoque la mort du processus —
            // le noyau ferme alors TOUS les fd, l'interface VPN est détruite
            // et la clé disparaît (méthode officielle AOSP : la clé ne
            // survit jamais à un processus mort). Si tout est propre,
            // hasSessionActivity() est faux et l'app survit.
            logEvent("warning", "app",
                    "watchdog armed (" + (nuclear ? "nuclear" : "normal") + ", no visible target)");
            armNuclearWatchdog(nuclear ? WATCHDOG_KILL_NUCLEAR_MS : WATCHDOG_KILL_NORMAL_MS);
            // Double disconnect : même sans cible visible, un résidu peut
            // survivre (course getAndSet/pendingController.set) — la seconde
            // passe re-tue à 2s si hasSessionActivity() est encore vrai.
            armSecondPass();
            logEvent("connection", "app",
                    "disconnect tunnel=" + (tidAtStop == null ? "?" : tidAtStop)
                    + " nuclear=" + nuclear + " target=null");
            releaseWakeLock();
            cancelNotification();
            stopSelf();
            return;
        }
        final long timeoutS = nuclear ? STOP_TIMEOUT_NUCLEAR_S : STOP_TIMEOUT_S;
        if (nuclear) {
            logEvent("warning", "app", "nuclear disconnect (bound " + timeoutS + "s)");
            armNuclearWatchdog(WATCHDOG_KILL_NUCLEAR_MS);
        } else {
            // Armed on the normal path too, with a long grace: a healthy
            // teardown disarms it by finishing, and a wedged one still cannot
            // leave the key in the shade with nobody left to remove it.
            armNuclearWatchdog(WATCHDOG_KILL_NORMAL_MS);
        }
        // Double disconnect (déconnexion pro) : la seconde passe à 2s
        // re-ferme le fd original (adoptFd), re-Stop le contrôleur et
        // re-sweep la notification si la première passe a laissé un résidu.
        armSecondPass();
        stopControllerAsync(target, timeoutS, nuclear ? "nuclear" : "disconnect");
        logEvent("connection", "app",
                "disconnect tunnel=" + (tidAtStop == null ? "?" : tidAtStop)
                + " nuclear=" + nuclear + " target=" + (target != null ? "ctrl+inflight" : "none"));
        releaseWakeLock();
        stopSelf();
        // Le thread de connexion peut encore re-poster la notification (et
        // re-rattacher le TUN) APRÈS ce point — il vérifie isSuperseded()
        // et démonte aussi. Balayage de sécurité différé : rien ne doit
        // survivre à une déconnexion, surtout pendant CONNECTING.
        serviceHandler.postDelayed(() -> {
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
        }, 1500);
    }

    /**
     * Hand a controller to the Go teardown on a background thread, with a hard
     * bound.
     *
     * <p>{@code Future.cancel(true)} only sets a Java interrupt flag, which
     * cannot unwind a gomobile call: if the Go side is wedged the underlying
     * thread stays blocked forever. That is exactly why {@link #goStopCount}
     * is cleared inside the task and not by the waiting thread — the nuclear
     * watchdog must learn the truth about whether the teardown really
     * finished, not whether we stopped waiting for it.
     */
    private void stopControllerAsync(final Object target, long timeoutS, String what) {
        goStopCount.incrementAndGet();
        new Thread(() -> {
            try {
                java.util.concurrent.ExecutorService exec =
                        java.util.concurrent.Executors.newSingleThreadExecutor();
                java.util.concurrent.Future<?> f = exec.submit(() -> {
                    try {
                        invokeStop(target);
                    } finally {
                        goStopCount.decrementAndGet();
                    }
                });
                exec.shutdown();
                try {
                    f.get(timeoutS, java.util.concurrent.TimeUnit.SECONDS);
                } catch (java.util.concurrent.TimeoutException te) {
                    Log.e(TAG, "controller stop timed out (" + what + ")");
                    logEvent("warning", "app",
                            "stop hung (" + what + ") - forcing cleanup");
                    f.cancel(true);
                } catch (Exception e) {
                    Log.e(TAG, "controller stop failed (" + what + ")", e);
                }
            } catch (Exception e) {
                Log.e(TAG, "controller stop failed (" + what + ")", e);
            }
            // The connect thread may have re-posted its notification while we
            // were tearing down. Sweep once more, now that nothing else can.
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
            releaseWakeLock();
            // Ne désarmer le watchdog kill QUE si le teardown Go a réellement
            // retourné. En CONNECTING, Controller.stop() attend le mutex d'un
            // start() encore en vol (attentes SOCKS/dnstt jusqu'à ~20 s) : le
            // Future a expiré mais l'appel gomobile reste coincé et
            // goStopCount reste > 0. Désarmer ici supprimait le
            // seul recours (kill du processus) et laissait le start()
            // construire la session jusqu'au bout — c'était la cause du
            // "nucléaire qui ne marche pas à tous les coups en CONNECTING".
            // (Refcount : un second stop concurrent qui se termine ne fait
            // plus tomber le compteur du premier.)
            if (goStopCount.get() <= 0) {
                disarmNuclearWatchdog();
            }
        }, "borum-disconnect").start();
    }

    /**
     * Bounded synchronous variant, used by the connect thread's own cleanup
     * between two retry attempts. The next attempt needs the SOCKS ports back,
     * so waiting is genuinely required — but the wait is capped, otherwise a
     * wedged Go teardown pins the connect thread and its "Connecting..."
     * notification for good.
     */
    private void stopControllerBoundedSync(final Object target, long timeoutS, String what) {
        goStopCount.incrementAndGet();
        java.util.concurrent.ExecutorService exec = null;
        try {
            exec = java.util.concurrent.Executors.newSingleThreadExecutor();
            java.util.concurrent.Future<?> f = exec.submit(() -> {
                try {
                    invokeStop(target);
                } finally {
                    goStopCount.decrementAndGet();
                }
            });
            f.get(timeoutS, java.util.concurrent.TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException te) {
            Log.e(TAG, "controller stop timed out (" + what + ")");
            logEvent("warning", "app", "stop hung (" + what + ")");
        } catch (Exception e) {
            Log.e(TAG, "controller stop failed (" + what + ")", e);
        } finally {
            if (exec != null) {
                exec.shutdownNow();
            }
        }
    }

    /**
     * Last resort of the nuclear path: if the Go teardown has still not
     * returned once the deadline passed, end the process. The notification is
     * swept first — it is built with setOngoing(true), so it cannot be swiped
     * away — and the kill follows immediately.
     *
     * <p>Posted on the service's own handler rather than an Activity's: the
     * user may well have left the app by then, and a watchdog bound to a dead
     * Activity is precisely why the key used to survive.
     */
    /**
     * Kill-process de dernier recours (voie nucléaire ET voie normale).
     * Il ne tire que si une session reste VIVANTE au moment du délai :
     * teardown Go coincé, tentative de connexion encore en vol (retry-sleep
     * ou start() bloqué), contrôleur publié non arrêté. S'il n'y a plus rien,
     * l'app survit — le nucléaire ne doit pas fermer l'application quand la
     * déconnexion a réussi proprement.
     */
    private final Runnable nuclearKill = new Runnable() {
        @Override
        public void run() {
            // Si une session est active (même en cours de connexion sur une
            // nouvelle instance de service après destroy/recréation), on ne
            // tue JAMAIS le processus. Le watchdog est juste un filet de
            // sécurité : il désarme et laisse le processus vivre.
            if (hasSessionActivity()) {
                disarmNuclearWatchdog();
                return;
            }
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
            logEvent("warning", "app", "teardown still running - keeping process alive");
            Log.w(TAG, "Go teardown still running, but not killing process (would crash app)");
        }
    };

    /**
     * Vrai tant que quelque chose doit encore mourir avant que la clé VPN
     * puisse survivre : session active, tentative en cours (même entre deux
     * essais), contrôleur publié mais pas encore promu, ou teardown Go coincé.
     * Utilisé par le watchdog service ET par le kill de la voie Activity.
     */
    public static boolean hasSessionActivity() {
        return controller != null
                || starting
                || pendingController.get() != null
                || connectInFlight.get()
                || goStopCount.get() > 0;
    }

    private void armNuclearWatchdog(long delayMs) {
        serviceHandler.removeCallbacks(nuclearKill);
        serviceHandler.postDelayed(nuclearKill, delayMs);
    }

    private void disarmNuclearWatchdog() {
        serviceHandler.removeCallbacks(nuclearKill);
    }

    // --- Double passe de déconnexion (« double disconnect ») ---
    //
    // Ledisconnect professionnel ne compte pas sur une seule passe : ~2 s
    // après la première, si quelque chose a survécu (fd TUN résiduel,
    // contrôleur non arrêté, start Go encore en vol), une SECONDE passe
    // complète re-tue : re-close du fd, re-Stop, re-sweep de la
    // notification. Idempotent et générationnel : une nouvelle connexion
    // légitime (sessionGen changé) neutralise la seconde passe.
    private volatile int secondPassGen = -1;

    private final Runnable secondPass = this::runSecondPass;

    private void armSecondPass() {
        secondPassGen = sessionGen.get();
        serviceHandler.removeCallbacks(secondPass);
        serviceHandler.postDelayed(secondPass, SECOND_PASS_DELAY_MS);
    }

    private void cancelSecondPass() {
        secondPassGen = -1;
        serviceHandler.removeCallbacks(secondPass);
    }

    private void runSecondPass() {
        // Une nouvelle connexion a démarré depuis : rien à re-tuer ici.
        if (secondPassGen != sessionGen.get()) {
            return;
        }
        if (!hasSessionActivity()) {
            return; // la première passe a tout nettoyé
        }
        Log.w(TAG, "disconnect second pass: residue detected");
        logEvent("warning", "app", "second disconnect pass (residue after first pass)");
        // 1) Re-fermer les fd résiduels (le true fix : adoptFd ferme le fd
        // ORIGINAL, fromFd ne fermait qu'un dup — la clé survivait via le fd
        // original toujours ouvert quand la stack gVisor retenait l'epoll).
        closeTunQuietly();
        if (detachedFd >= 0) {
            try {
                android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
            } catch (Exception ignored) {
            } finally {
                detachedFd = -1;
            }
        }
        // 2) Re-Stop le contrôleur survivant (idempotent côté Go : fast path
        // ou contended → hard-kill du fd TUN).
        final Object live = controller;
        controller = null;
        final Object inflight = pendingController.getAndSet(null);
        final Object target = live != null ? live : inflight;
        if (target != null) {
            stopControllerAsync(target, STOP_TIMEOUT_S, "second pass");
        }
        // 3) Sweep final de la notification.
        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        cancelNotification();
        releaseWakeLock();
    }

    /**
     * A disconnect arrived while this connect attempt was still running:
     * tear the half-built session down and leave neither a notification nor a
     * VPN key behind. Connect thread only.
     *
     * <p>The generation may have changed again since {@link #startSession}, so
     * every step re-checks it: posting "Connected" after a disconnect is
     * exactly how the ghost key came back.
     */
    private void abortSupersededStart(int gen, Object localCtrl) {
        // 1) Drop the key and the notification FIRST, and unconditionally.
        // The previous order stopped the Go controller inline, before any
        // sweep: that call can block forever on the controller mutex, and when
        // it did the sweep below was never reached — leaving an ongoing
        // notification (i.e. the VPN key) in the shade with nothing left able
        // to remove it. Order is the whole fix here.
        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        cancelNotification();
        releaseWakeLock();

        // 2) Then collect whatever controller this attempt left behind.
        Object live = controller;
        controller = null;
        Object victim = live != null ? live : localCtrl;
        pendingController.compareAndSet(localCtrl, null);
        closeTunQuietly();
        // 2b) Close detached fd if it was never handed to Go (superseded before invokeStart)
        if (detachedFd >= 0) {
            try {
                android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
            } catch (Exception ignored) {
            } finally {
                detachedFd = -1;
            }
        }

        // 3) Never block the connect thread on the Go teardown — hand it to a
        // bounded background stop and return immediately, so the connect
        // thread reaches its own finally{} (which sweeps the shade again).
        if (victim != null) {
            stopControllerAsync(victim, STOP_TIMEOUT_S, "superseded start " + gen);
            // Filet de sécurité OBLIGATOIRE : ce chemin n'arme aucun watchdog
            // ailleurs. Si le stop() Go reste coincé sur le mutex d'un start()
            // en vol, le fd TUN reste ouvert et la clé VPN avec lui. Un
            // stop sain se termine en ~1-3s et désarme le watchdog (le
            // compteur tombe à zéro) ; un stop coincé laisse le compteur > 0
            // et le kill tire : le noyau ferme tous les fd, la clé disparaît.
            armNuclearWatchdog(WATCHDOG_KILL_NORMAL_MS);
        }
        Log.i(TAG, "connect attempt " + gen + " superseded - session aborted");
        logEvent("connection", "app",
                "connect aborted gen=" + gen + " disconnect-while-connecting"
                + " liveCtrl=" + (live != null ? "yes" : "no")
                + " localCtrl=" + (localCtrl != null ? "yes" : "no")
                + " victim=" + (victim != null ? "yes" : "no"));
    }

    @Override
    public void onDestroy() {
        logEvent("connection", "app", "service detruit (onDestroy)");
        stopSession();
        releaseWakeLock();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        logEvent("connection", "app", "systeme a revoque le VPN (onRevoke)");
        stopSession();
        super.onRevoke();
    }

    // --- gomobile Controller calls (kept reflective-free: direct calls) ---

    private static String invokeStart(Object ctrl, String params) {
        String err = ((vpnlib.Controller) ctrl).start(params);
        if (err == null || err.isEmpty()) {
            // Session UP : les appels API de l'app passent désormais par le
            // SOCKS du tunnel (consommation consultable via le propre VPN).
            updateApiProxy();
        }
        return err;
    }

    /**
     * Route les appels API de libpho via le SOCKS local du tunnel actif
     * (front round-robin si actif, sinon SOCKS du profil) : la consommation
     * est consultable À TRAVERS le propre VPN de l'app — l'UID de l'app
     * étant exclu du TUN (anti-boucle), sans ce routage les appels sortent
     * par la connexion sous-jacente (bloquée sur certains opérateurs).
     * À appeler après connexion, après un switch de tunnel, à la
     * déconnexion et avant chaque rafraîchissement API.
     */
    public static void updateApiProxy() {
        String socks = "";
        Object ctrl = controller;
        if (ctrl != null) {
            try {
                String id = activeTunnelId;
                socks = ((vpnlib.Controller) ctrl).apiSocksAddr(id == null ? "" : id);
            } catch (Throwable ignored) {
                socks = "";
            }
        }
        try {
            Vpnlib.phoSetProxy(socks == null ? "" : socks);
        } catch (Throwable ignored) {
        }
    }

    private static void invokeStop(Object ctrl) {
        ((vpnlib.Controller) ctrl).stop();
    }

    public static String controllerStatus() {
        Object ctrl = controller;
        if (ctrl == null) {
            return "{\"running\":false}";
        }
        try {
            return ((vpnlib.Controller) ctrl).getStatus();
        } catch (Exception e) {
            return "{\"running\":false,\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    /** Switch the data plane to another tunnel without restarting the VPN. */
    public static String setActiveTunnel(String tunnelId) {
        Object ctrl = controller;
        if (ctrl == null) {
            return "{\"error\":\"not running\"}";
        }
        try {
            String err = ((vpnlib.Controller) ctrl).setActiveTunnel(tunnelId);
            if (err == null || err.isEmpty()) {
                activeTunnelId = tunnelId;
                VPNApplication.getInstance().setActiveTunnelId(tunnelId);
                updateApiProxy();
                logEvent("connection", "app", "switched to tunnel " + tunnelId);
            }
            return err;
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    // --- notification ---

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "borum VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("borum VPN connection status");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(ch);
            }
        }
    }

    private Notification buildNotification(String text) {
        createChannel();
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
                this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        Intent disc = new Intent(this, TasVpnService.class);
        disc.setAction(ACTION_DISCONNECT);
        PendingIntent discPi = PendingIntent.getService(
                this, 1, disc, PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("borum VPN")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentIntent(pi)
                .addAction(0, "Disconnect", discPi)
                .setOngoing(true)
                .build();
    }

    /** Refresh the foreground notification text (call from any thread). */
    private void notifyText(String text) {
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.notify(NOTIFICATION_ID, buildNotification(text));
            }
        } catch (Exception e) {
            Log.w(TAG, "notify failed", e);
        }
    }

    /** Best-effort pretty status for the native UI. */
    public static String statusSummary() {
        if (controller == null) {
            if (lastError != null) {
                return "error: " + lastError;
            }
            return "disconnected";
        }
        try {
            JSONObject st = new JSONObject(controllerStatus());
            if (!st.optBoolean("running", false)) {
                return "disconnected";
            }
            return "connected";
        } catch (Exception e) {
            return "connected";
        }
    }
}
