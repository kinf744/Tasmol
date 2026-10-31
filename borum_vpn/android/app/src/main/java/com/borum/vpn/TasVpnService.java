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

public class TasVpnService extends VpnService {
    private static final String TAG = "TasVpnService";
    private static final String CHANNEL_ID = "tasvpn_channel";
    private static final int NOTIFICATION_ID = 42;

    public static final String ACTION_CONNECT = "com.borum.vpn.action.CONNECT";
    public static final String ACTION_DISCONNECT = "com.borum.vpn.action.DISCONNECT";

    public static final String ACTION_NUCLEAR_DISCONNECT = "com.borum.vpn.action.NUCLEAR_DISCONNECT";
    public static final String EXTRA_TUNNEL_ID = "tunnel_id";

    private static volatile Object controller = null;
    private static volatile String activeTunnelId = null;
    private static volatile String lastError = null;

    private static volatile boolean starting = false;
    private static volatile boolean stopping = false; 
    private static volatile int startGen = -1;

    private static final java.util.concurrent.atomic.AtomicReference<Object> pendingController =
            new java.util.concurrent.atomic.AtomicReference<>(null);

    private static final long STOP_TIMEOUT_S = 3;
    private static final long STOP_TIMEOUT_NUCLEAR_S = 2;

    private static final long RETRY_STOP_TIMEOUT_S = 2;

    private static final long WATCHDOG_KILL_NORMAL_MS = 8000;
    private static final long WATCHDOG_KILL_NUCLEAR_MS = 5000;

    private static final long SECOND_PASS_DELAY_MS = 2000;

    private static final java.util.concurrent.atomic.AtomicInteger goStopCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    private final android.os.Handler serviceHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());

    private static final java.util.concurrent.atomic.AtomicBoolean connectInFlight =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private static final int MAX_START_ATTEMPTS = 6;
    private static final long RETRY_DELAY_MS = 3000;
    private static volatile int startAttempt = 0;

    private static final java.util.ArrayDeque<String> eventLog = new java.util.ArrayDeque<>();
    private static final int MAX_LOG_LINES = 40;

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

    public static synchronized void logEvent(String msg) {
        logEvent("info", "app", msg);
    }

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
        BinaryManager.appendLog("[" + level + "] [" + component + "] " + msg);
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

            sessionGen.incrementAndGet();
            stopSession();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CONNECT.equals(action)) {
            String tunnelId = intent.getStringExtra(EXTRA_TUNNEL_ID);
            startSession(tunnelId);

            return START_NOT_STICKY;
        }
        return START_NOT_STICKY;
    }

    private void startSession(String tunnelId) {
        if (controller != null || starting) {
            Log.i(TAG, "session start already in progress/running, ignoring duplicate");
            return;
        }
        stopping = false;

        disarmNuclearWatchdog();
        cancelSecondPass();

        if (IntegrityGuard.hardBlocked()) {
            lastError = "Environnement non autorisé";
            logEvent("error", "security", "démarrage refusé — environnement non autorisé");
            stopSelf();
            return;
        }
        lastError = null;

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

                    final String tunnelType = UdpSessionLog.typeOfTunnel(this, tid);
                    if (!UdpSessionLog.prettyType(tunnelType).isEmpty()) {
                        UdpSessionLog.connecting();
                    }

                    ctrl = Vpnlib.newController();

                    pendingController.set(ctrl);
                    logEvent("connection", "app",
                            "controleur Go publie gen=" + gen + " tentative=" + attempt);
                    if (isSuperseded(gen)) {

                        abortSupersededStart(gen, ctrl);
                        return;
                    }
                    String err = invokeStart(ctrl, params);

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

                    if (stopping) {
                        logEvent("warning", "app",
                                "start() terminé après déconnexion, contrôleur abandonné gen=" + gen);
                        abortSupersededStart(gen, ctrl);
                        return;
                    }
                    logEvent("connection", "app",
                            "plan de données demarre gen=" + gen + " tentative=" + attempt
                            + " tunnel=" + tid);
                    SecurityGuard.noteSuccessfulCheck(this);

                    if (isSuperseded(gen)) {

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

                        pendingController.compareAndSet(ctrl, null);

                        stopControllerBoundedSync(ctrl, RETRY_STOP_TIMEOUT_S,
                                "retry cleanup");
                    }
                    closeTunQuietly();

                    if (detachedFd >= 0) {
                        try {
                            android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
                        } catch (Exception ignored) {
                        } finally {
                            detachedFd = -1;
                        }
                    }
                    if (isSuperseded(gen)) {

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

            if (detachedFd >= 0) {
                try {
                    android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
                } catch (Exception ignored) {
                } finally {
                    detachedFd = -1;
                }
            }

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

    private static void clearStarting(int gen) {
        if (sessionGen.get() == gen) {
            starting = false;
        }
    }

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

    private void stopSession(boolean nuclear) {

        sessionGen.incrementAndGet();
        starting = false;
        stopping = true;
        boolean wasConnecting = connectInFlight.getAndSet(false);

        try {
            if (controller != null && activeTunnelId != null) {
                String t = UdpSessionLog.prettyType(UdpSessionLog.typeOfTunnel(this, activeTunnelId));
                if (!t.isEmpty()) {
                    UdpSessionLog.stopping();
                }
            }
        } catch (Exception ignored) {
        }

        try {
            if (tunFd != null) {
                tunFd.close();
            }
        } catch (Exception ignored) {
        } finally {
            tunFd = null;
        }

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

        cancelNotification();

        final Object ctrl = controller;
        final String tidAtStop = activeTunnelId;
        controller = null;
        final Object inflight = pendingController.getAndSet(null);
        activeTunnelId = null;

        updateApiProxy();
        final Object target = ctrl != null ? ctrl : inflight;
        if (target == null) {

            logEvent("warning", "app",
                    "watchdog armed (" + (nuclear ? "nuclear" : "normal") + ", no visible target)");
            armNuclearWatchdog(nuclear ? WATCHDOG_KILL_NUCLEAR_MS : WATCHDOG_KILL_NORMAL_MS);

            armSecondPass();
            logEvent("connection", "app",
                    "disconnect tunnel=" + (tidAtStop == null ? "?" : tidAtStop)
                    + " nuclear=" + nuclear + " target=null");
            releaseWakeLock();
            cancelNotification();

            if (!wasConnecting) {
                stopSelf();
            }
            return;
        }
        final long timeoutS = nuclear ? STOP_TIMEOUT_NUCLEAR_S : STOP_TIMEOUT_S;
        if (nuclear) {
            logEvent("warning", "app", "nuclear disconnect (bound " + timeoutS + "s)");
            armNuclearWatchdog(WATCHDOG_KILL_NUCLEAR_MS);
        } else {

            armNuclearWatchdog(WATCHDOG_KILL_NORMAL_MS);
        }

        armSecondPass();
        stopControllerAsync(target, timeoutS, nuclear ? "nuclear" : "disconnect");
        logEvent("connection", "app",
                "disconnect tunnel=" + (tidAtStop == null ? "?" : tidAtStop)
                + " nuclear=" + nuclear + " target=" + (target != null ? "ctrl+inflight" : "none"));
        releaseWakeLock();
        stopSelf();

        serviceHandler.postDelayed(() -> {
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
        }, 1500);
    }

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

            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            cancelNotification();
            releaseWakeLock();

            if (goStopCount.get() <= 0) {
                disarmNuclearWatchdog();
            }
        }, "borum-disconnect").start();
    }

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

    private final Runnable nuclearKill = new Runnable() {
        @Override
        public void run() {

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

        if (secondPassGen != sessionGen.get()) {
            return;
        }
        if (!hasSessionActivity()) {
            return; 
        }
        Log.w(TAG, "disconnect second pass: residue detected");
        logEvent("warning", "app", "second disconnect pass (residue after first pass)");

        closeTunQuietly();
        if (detachedFd >= 0) {
            try {
                android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
            } catch (Exception ignored) {
            } finally {
                detachedFd = -1;
            }
        }

        final Object live = controller;
        controller = null;
        final Object inflight = pendingController.getAndSet(null);
        final Object target = live != null ? live : inflight;
        if (target != null) {
            stopControllerAsync(target, STOP_TIMEOUT_S, "second pass");
        }

        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        cancelNotification();
        releaseWakeLock();
    }

    private void abortSupersededStart(int gen, Object localCtrl) {

        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        cancelNotification();
        releaseWakeLock();

        Object live = controller;
        controller = null;
        Object victim = live != null ? live : localCtrl;
        pendingController.compareAndSet(localCtrl, null);
        closeTunQuietly();

        if (detachedFd >= 0) {
            try {
                android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
            } catch (Exception ignored) {
            } finally {
                detachedFd = -1;
            }
        }

        if (victim != null) {
            stopControllerAsync(victim, STOP_TIMEOUT_S, "superseded start " + gen);

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

    private static String invokeStart(Object ctrl, String params) {
        String err = ((vpnlib.Controller) ctrl).start(params);
        if (err == null || err.isEmpty()) {

            updateApiProxy();
        }
        return err;
    }

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
