package com.ephang.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

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

    public static final String ACTION_CONNECT = "com.ephang.vpn.action.CONNECT";
    public static final String ACTION_DISCONNECT = "com.ephang.vpn.action.DISCONNECT";
    /** Fast, forceful disconnect: short teardown bound, no waiting around. */
    public static final String ACTION_NUCLEAR_DISCONNECT = "com.ephang.vpn.action.NUCLEAR_DISCONNECT";
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
    // Bound on the Go controller.stop() call, in seconds. Nuclear uses a
    // short one: the user asked for an immediate kill, so we should not sit
    // there waiting on a wedged teardown before falling back to killing the
    // process.
    private static final long STOP_TIMEOUT_S = 15;
    private static final long STOP_TIMEOUT_NUCLEAR_S = 4;
    // Cleanup between two retry attempts runs on the connect thread, so it gets
    // a much shorter bound than a user-initiated disconnect.
    private static final long RETRY_STOP_TIMEOUT_S = 5;
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
    private static final long WATCHDOG_KILL_NORMAL_MS = 20000;
    private static final long WATCHDOG_KILL_NUCLEAR_MS = 5000;
    // True from the moment a controller is handed to the Go stop until that
    // call actually returns. This distinguishes "teardown finished" from "we
    // stopped waiting for it", which is exactly what decides whether killing
    // the process is warranted.
    private static final java.util.concurrent.atomic.AtomicBoolean goStopHanging =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    // Service-scoped main-thread handler: the nuclear watchdog must not depend
    // on any Activity, otherwise leaving the app while a teardown is stuck
    // leaves the key with nobody left able to remove it.
    private final android.os.Handler serviceHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    // Connection attempts: CONNECTING stays on across retries until the
    // session is up or the user disconnects (disconnect supersedes via
    // sessionGen, nuclear kill ends the process outright).
    private static final int MAX_START_ATTEMPTS = 10;
    private static final long RETRY_DELAY_MS = 3000;
    private static volatile int startAttempt = 0;

    private static final java.util.ArrayDeque<String> eventLog = new java.util.ArrayDeque<>();
    private static final int MAX_LOG_LINES = 200;

    /** Append a timestamped event to the in-memory connection log. */
    public static synchronized void logEvent(String msg) {
        logEvent("info", "app", msg);
    }

    /**
     * Leveled journal event, mirrored to Download/kighmu.txt so the Logs
     * tab shows one unified journal (levels: info/connection/warning/error).
     */
    public static synchronized void logEvent(String level, String component, String msg) {
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

    private ParcelFileDescriptor tunFd = null;

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
        return goStopHanging.get();
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
        new Thread(() -> startSessionBackground(gen, requestedId), "ephang-connect").start();
    }

    private void startSessionBackground(int gen, String tunnelId) {
        Exception lastFailure = null;
        int attempt = 0;
        final int maxAttempts = getMaxStartAttempts();
        final long retryDelay = retryDelayMs();
        try {
            while (attempt < maxAttempts && !isSuperseded(gen)) {
                attempt++;
                startAttempt = attempt;
                notifyText("Connecting...");
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
                            .setSession("Ephang VPN")
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
                    if (isSuperseded(gen)) {
                        // Déconnexion arrivée pile avant le start() Go : ne
                        // jamais lancer le plan de données, tout démonter.
                        abortSupersededStart(gen, ctrl);
                        return;
                    }
                    String err = invokeStart(ctrl, params);
                    if (err != null && !err.isEmpty()) {
                        pendingController.compareAndSet(ctrl, null);
                        closeTunQuietly();
                        if (!UdpSessionLog.prettyType(tunnelType).isEmpty()) {
                            UdpSessionLog.failed(UdpSessionLog.prettyType(tunnelType), err);
                        }
                        throw new IllegalStateException("data plane: " + err);
                    }

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
                lastError = lastFailure.getMessage();
                logEvent("error", "app", "connect failed after " + attempt
                        + " attempts: " + lastFailure.getMessage());
                stopForeground(true);
                cancelNotification();
                releaseWakeLock();
                stopSelf();
            }
        } finally {
            pendingController.set(null);
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
                    android.os.PowerManager.PARTIAL_WAKE_LOCK, "EphangVPN:session");
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
        // connexion. Résolu avant que activeTunnelId ne soit effacé.
        if (controller != null && activeTunnelId != null) {
            String t = UdpSessionLog.prettyType(UdpSessionLog.typeOfTunnel(this, activeTunnelId));
            if (!t.isEmpty()) {
                UdpSessionLog.stopping();
            }
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
        controller = null;
        final Object inflight = pendingController.getAndSet(null);
        activeTunnelId = null;
        final Object target = ctrl != null ? ctrl : inflight;
        if (target == null) {
            // Nothing was up and nothing is starting. En nucléaire, armer le
            // kill-process DANS TOUS LES CAS — pas seulement si un teardown
            // est visible : la tentative de connexion peut être en vol sans
            // contrôleur publié (dans le retry-sleep entre deux essais, ou
            // entre la création du TUN et pendingController.set). Sans ce
            // kill garanti, l'attempt reprend après le stopSession et finit
            // par construire la session malgré le nucléaire — c'était la
            // cause du "nucléaire intermittant en CONNECTING" (configs API
            // round-robin : le start() Go peut durer des dizaines de
            // secondes, la fenêtre est énorme). Le nucléaire est un
            // force-close explicite : mourir même quand tout semblait propre
            // est le comportement voulu.
            if (nuclear) {
                logEvent("warning", "app",
                        "nuclear disconnect (no live target - process kill armed)");
                armNuclearHardKill(WATCHDOG_KILL_NUCLEAR_MS);
            }
            logEvent("connection", "app", "disconnected");
            releaseWakeLock();
            cancelNotification();
            stopSelf();
            return;
        }
        final long timeoutS = nuclear ? STOP_TIMEOUT_NUCLEAR_S : STOP_TIMEOUT_S;
        if (nuclear) {
            logEvent("warning", "app", "nuclear disconnect (bound " + timeoutS + "s)");
            armNuclearWatchdog(WATCHDOG_KILL_NUCLEAR_MS);
            // Kill-process garanti aussi quand le teardown Go est visible :
            // il peut retourner "proprement" pendant qu'une NOUVELLE
            // tentative (non supersédée) re-bâtit la session.
            armNuclearHardKill(WATCHDOG_KILL_NUCLEAR_MS);
        } else {
            // Armed on the normal path too, with a long grace: a healthy
            // teardown disarms it by finishing, and a wedged one still cannot
            // leave the key in the shade with nobody left to remove it.
            armNuclearWatchdog(WATCHDOG_KILL_NORMAL_MS);
        }
        stopControllerAsync(target, timeoutS, nuclear ? "nuclear" : "disconnect");
        logEvent("connection", "app", "disconnected");
        releaseWakeLock();
        stopSelf();
    }

    /**
     * Hand a controller to the Go teardown on a background thread, with a hard
     * bound.
     *
     * <p>{@code Future.cancel(true)} only sets a Java interrupt flag, which
     * cannot unwind a gomobile call: if the Go side is wedged the underlying
     * thread stays blocked forever. That is exactly why {@link #goStopHanging}
     * is cleared inside the task and not by the waiting thread — the nuclear
     * watchdog must learn the truth about whether the teardown really
     * finished, not whether we stopped waiting for it.
     */
    private void stopControllerAsync(final Object target, long timeoutS, String what) {
        goStopHanging.set(true);
        new Thread(() -> {
            try {
                java.util.concurrent.ExecutorService exec =
                        java.util.concurrent.Executors.newSingleThreadExecutor();
                java.util.concurrent.Future<?> f = exec.submit(() -> {
                    try {
                        invokeStop(target);
                    } finally {
                        goStopHanging.set(false);
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
            // goStopHanging est toujours vrai. Désarmer ici supprimait le
            // seul recours (kill du processus) et laissait le start()
            // construire la session jusqu'au bout — c'était la cause du
            // "nucléaire qui ne marche pas à tous les coups en CONNECTING".
            if (!goStopHanging.get()) {
                disarmNuclearWatchdog();
            }
        }, "ephang-disconnect").start();
    }

    /**
     * Bounded synchronous variant, used by the connect thread's own cleanup
     * between two retry attempts. The next attempt needs the SOCKS ports back,
     * so waiting is genuinely required — but the wait is capped, otherwise a
     * wedged Go teardown pins the connect thread and its "Connecting..."
     * notification for good.
     */
    private void stopControllerBoundedSync(final Object target, long timeoutS, String what) {
        goStopHanging.set(true);
        java.util.concurrent.ExecutorService exec = null;
        try {
            exec = java.util.concurrent.Executors.newSingleThreadExecutor();
            java.util.concurrent.Future<?> f = exec.submit(() -> {
                try {
                    invokeStop(target);
                } finally {
                    goStopHanging.set(false);
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
    private final Runnable nuclearKill = new Runnable() {
        @Override
        public void run() {
            if (!goStopHanging.get()) {
                return; // Teardown completed on its own: nothing to kill.
            }
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
            logEvent("warning", "app", "teardown still running - killing process");
            Log.e(TAG, "Go teardown never returned, killing process");
            android.os.Process.killProcess(android.os.Process.myPid());
        }
    };

    /**
     * Kill-process GARANTI du chemin nucléaire : aucune condition sur l'état
     * du teardown. Le nucléaire est un force-close explicite (dialogue de
     * confirmation) — seule la mort du processus garantit que la clé VPN est
     * révoquée, que les processus enfants meurent et qu'aucune tentative de
     * connexion en vol ne peut re-bâtir la session derrière. Jamais désarmé
     * par un teardown propre : c'est voulu.
     */
    private final Runnable nuclearHardKill = new Runnable() {
        @Override
        public void run() {
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
            logEvent("warning", "app", "nuclear: ending process");
            android.os.Process.killProcess(android.os.Process.myPid());
        }
    };

    private void armNuclearHardKill(long delayMs) {
        serviceHandler.removeCallbacks(nuclearHardKill);
        serviceHandler.postDelayed(nuclearHardKill, delayMs);
    }

    private void armNuclearWatchdog(long delayMs) {
        serviceHandler.removeCallbacks(nuclearKill);
        serviceHandler.postDelayed(nuclearKill, delayMs);
    }

    private void disarmNuclearWatchdog() {
        serviceHandler.removeCallbacks(nuclearKill);
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

        // 3) Never block the connect thread on the Go teardown — hand it to a
        // bounded background stop and return immediately, so the connect
        // thread reaches its own finally{} (which sweeps the shade again).
        if (victim != null) {
            stopControllerAsync(victim, STOP_TIMEOUT_S, "superseded start " + gen);
        }
        Log.i(TAG, "connect attempt " + gen + " superseded - session aborted");
        logEvent("connection", "app", "connect aborted (disconnected while connecting)");
    }

    @Override
    public void onDestroy() {
        stopSession();
        releaseWakeLock();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopSession();
        super.onRevoke();
    }

    // --- gomobile Controller calls (kept reflective-free: direct calls) ---

    private static String invokeStart(Object ctrl, String params) {
        return ((vpnlib.Controller) ctrl).start(params);
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
                    CHANNEL_ID, "Ephang VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("Ephang VPN connection status");
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
                .setContentTitle("Ephang VPN")
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
