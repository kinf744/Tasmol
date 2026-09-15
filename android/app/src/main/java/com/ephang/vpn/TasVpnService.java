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
    public static final String EXTRA_TUNNEL_ID = "tunnel_id";

    private static volatile Object controller = null;
    private static volatile String activeTunnelId = null;
    private static volatile String lastError = null;
    // True while a session is being established (connecting / reconnecting).
    // The Home tab shows a red CONNECTING status while this is set.
    private static volatile boolean starting = false;
    private static volatile int startGen = -1;

    private static final java.util.ArrayDeque<String> eventLog = new java.util.ArrayDeque<>();
    private static final int MAX_LOG_LINES = 200;

    /** Append a timestamped event to the in-memory connection log. */
    public static synchronized void logEvent(String msg) {
        java.text.SimpleDateFormat fmt =
                new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
        eventLog.addLast(fmt.format(new java.util.Date()) + "  " + msg);
        while (eventLog.size() > MAX_LOG_LINES) {
            eventLog.removeFirst();
        }
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

    private static final java.util.concurrent.atomic.AtomicInteger sessionGen =
            new java.util.concurrent.atomic.AtomicInteger(0);

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        String action = intent.getAction();
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
            return START_STICKY;
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
        new Thread(() -> startSessionBackground(gen, requestedId), "ephang-connect").start();
    }

    private void startSessionBackground(int gen, String tunnelId) {
        Object ctrl = null;
        try {
            // Ensure bundled official binaries + config are staged.
            BinaryManager.ensureReady(this);

            if (tunnelId == null || tunnelId.isEmpty()) {
                tunnelId = VPNApplication.getInstance().getActiveTunnelId();
            }
            if (tunnelId == null || tunnelId.isEmpty()) {
                tunnelId = BinaryManager.firstTunnelId(this);
            }
            if (tunnelId == null || tunnelId.isEmpty()) {
                throw new IllegalStateException("no tunnel configured: add one in the app first");
            }
            if (isSuperseded(gen)) {
                return;
            }

            Builder builder = new Builder()
                    .setSession("Ephang VPN")
                    .setMtu(1500)
                    .addAddress("10.8.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    // Exclude our own UID so upstream sockets (xray, zivpn,
                    // dnstt, ssh, SOCKS dials) never loop into the TUN.
                    .addDisallowedApplication(getPackageName());

            tunFd = builder.establish();
            if (tunFd == null) {
                throw new IllegalStateException("VpnService.Builder.establish() returned null");
            }
            int fd = tunFd.detachFd();

            String params = BinaryManager.buildStartParams(this, tunnelId, fd);
            Log.i(TAG, "starting data plane, active=" + tunnelId);

            ctrl = Vpnlib.newController();
            String err = invokeStart(ctrl, params);
            if (err != null && !err.isEmpty()) {
                try {
                    tunFd.close();
                } catch (Exception ignored) {
                }
                tunFd = null;
                throw new IllegalStateException("data plane: " + err);
            }

            if (isSuperseded(gen)) {
                // A disconnect (or newer connect) arrived while starting:
                // tear down instead of publishing a zombie session.
                try {
                    invokeStop(ctrl);
                } catch (Exception ignored) {
                }
                try {
                    tunFd.close();
                } catch (Exception ignored) {
                }
                tunFd = null;
                return;
            }

            controller = ctrl;
            ctrl = null;
            activeTunnelId = tunnelId;
            VPNApplication.getInstance().setActiveTunnelId(tunnelId);

            notifyText("Connected");
            Log.i(TAG, "VPN session running");
            logEvent("connected (" + tunnelId + ")");
        } catch (Exception e) {
            Log.e(TAG, "startSession failed", e);
            if (!isSuperseded(gen)) {
                lastError = e.getMessage();
                logEvent("connect failed: " + e.getMessage());
                stopForeground(true);
                stopSelf();
            }
        } finally {
            if (ctrl != null) {
                // Never leak an unpublished controller.
                try {
                    invokeStop(ctrl);
                } catch (Exception ignored) {
                }
            }
            clearStarting(gen);
        }
    }

    /** Clear the connecting flag, but only if no newer session took over. */
    private static void clearStarting(int gen) {
        if (sessionGen.get() == gen) {
            starting = false;
        }
    }

    /** True when a newer start/stop request superseded this generation. */
    private boolean isSuperseded(int gen) {
        return gen != sessionGen.get();
    }

    private void stopSession() {
        // Invalidate any in-flight connect first.
        sessionGen.incrementAndGet();
        starting = false;
        // Heavy teardown (process kills, stack drain) runs off the main
        // thread to avoid ANR dialogs.
        new Thread(() -> {
            try {
                if (controller != null) {
                    // Bounded: a wedged data-plane stop must never hang
                    // this thread forever (that left the VPN key stuck).
                    // The Go side is time-bounded too; this is belt & braces.
                    final Object ctrl = controller;
                    java.util.concurrent.ExecutorService exec =
                            java.util.concurrent.Executors.newSingleThreadExecutor();
                    java.util.concurrent.Future<?> f =
                            exec.submit(() -> invokeStop(ctrl));
                    exec.shutdown();
                    try {
                        f.get(15, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (java.util.concurrent.TimeoutException te) {
                        Log.e(TAG, "controller stop timed out, forcing cleanup");
                        logEvent("stop hung - forcing cleanup");
                        f.cancel(true);
                    } catch (Exception e) {
                        Log.e(TAG, "controller stop failed", e);
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "controller stop failed", e);
            } finally {
                controller = null;
                activeTunnelId = null;
            }
            try {
                if (tunFd != null) {
                    tunFd.close();
                }
            } catch (Exception ignored) {
            } finally {
                tunFd = null;
            }
            logEvent("disconnected");
            stopForeground(true);
            stopSelf();
        }, "ephang-disconnect").start();
    }

    @Override
    public void onDestroy() {
        stopSession();
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
                logEvent("switched to tunnel " + tunnelId);
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
