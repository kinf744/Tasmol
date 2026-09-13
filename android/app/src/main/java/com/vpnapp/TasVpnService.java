package com.vpnapp;

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

    public static final String ACTION_CONNECT = "com.vpnapp.action.CONNECT";
    public static final String ACTION_DISCONNECT = "com.vpnapp.action.DISCONNECT";
    public static final String EXTRA_TUNNEL_ID = "tunnel_id";

    private static volatile Object controller = null;
    private static volatile String activeTunnelId = null;
    private static volatile String lastError = null;

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

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        String action = intent.getAction();
        if (ACTION_DISCONNECT.equals(action)) {
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
        if (controller != null) {
            Log.i(TAG, "session already running");
            return;
        }
        lastError = null;
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

            Builder builder = new Builder()
                    .setSession("TasVPN")
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

            Object ctrl = Vpnlib.newController();
            String err = invokeStart(ctrl, params);
            if (err != null && !err.isEmpty()) {
                try {
                    tunFd.close();
                } catch (Exception ignored) {
                }
                tunFd = null;
                throw new IllegalStateException("data plane: " + err);
            }

            controller = ctrl;
            activeTunnelId = tunnelId;
            VPNApplication.getInstance().setActiveTunnelId(tunnelId);

            startForeground(NOTIFICATION_ID, buildNotification("Connected (" + tunnelId + ")"));
            Log.i(TAG, "VPN session running");
        } catch (Exception e) {
            Log.e(TAG, "startSession failed", e);
            lastError = e.getMessage();
            controller = null;
            activeTunnelId = null;
            stopSelf();
        }
    }

    private void stopSession() {
        try {
            if (controller != null) {
                invokeStop(controller);
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
        stopForeground(true);
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

    // --- notification ---

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "TasVPN", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("TasVPN connection status");
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
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("TasVPN")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
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
