package com.ephang.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Hotspot sharing without root: relays a SOCKS endpoint (ours or another
 * VPN app's) onto the LAN (0.0.0.0, random port). Works with or without our
 * VPN connected. Requires the system Wi-Fi hotspot on: the app checks and
 * redirects to the tethering settings otherwise. A notification shows while
 * the relay is active. TCP only.
 */
public class HotspotFragment extends Fragment {
    private static final String CHANNEL_ID = "ephang_hotspot";
    private static final int NOTIFICATION_ID = 43;

    private TextView statusText;
    private TextView ipsText;
    private TextView portText;
    private Button toggleBtn;
    private EditText targetHost;
    private EditText targetPort;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private static final TcpRelay RELAY = new TcpRelay();
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 2000);
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_hotspot, container, false);
        statusText = v.findViewById(R.id.hotspot_status);
        ipsText = v.findViewById(R.id.hotspot_ips);
        portText = v.findViewById(R.id.hotspot_port);
        toggleBtn = v.findViewById(R.id.hotspot_toggle);
        targetHost = v.findViewById(R.id.hotspot_target_host);
        targetPort = v.findViewById(R.id.hotspot_target_port);
        toggleBtn.setOnClickListener(view -> {
            if (RELAY.isRunning()) {
                stopRelay();
            } else {
                ensureAccessPointThenStart();
            }
        });
        refresh();
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    public void onPause() {
        super.onPause();
        handler.removeCallbacks(tick);
    }

    private void refresh() {
        if (statusText == null || getContext() == null) {
            return;
        }
        ipsText.setText(localIps());
        // Prefill the target with our live SOCKS when connected.
        if (!RELAY.isRunning() && targetPort.getText().toString().trim().isEmpty()
                && TasVpnService.isRunning()) {
            int live = activeSocksPort();
            if (live > 0) {
                targetHost.setText("127.0.0.1");
                targetPort.setText(String.valueOf(live));
            }
        }
        if (RELAY.isRunning()) {
            statusText.setText("Partage actif");
            statusText.setTextColor(0xFF00E676);
            portText.setText(String.valueOf(RELAY.getListenPort()));
            toggleBtn.setText("Arrêter le partage");
        } else {
            statusText.setText("Arrêté");
            statusText.setTextColor(0xFFFFFFFF);
            portText.setText("—");
            toggleBtn.setText("Démarrer le partage");
        }
    }

    /** Step 1: the system access point must be on — check, else redirect. */
    private void ensureAccessPointThenStart() {
        if (isWifiApEnabled()) {
            startRelay();
            return;
        }
        new AlertDialog.Builder(requireContext())
                .setTitle("Point d'accès requis")
                .setMessage("Activez le point d'accès Wi-Fi système pour que "
                        + "d'autres appareils rejoignent ce téléphone, puis revenez ici.")
                .setPositiveButton("Ouvrir réglages", (d, w) -> {
                    try {
                        startActivity(new Intent("android.settings.TETHER_SETTINGS"));
                    } catch (Exception e1) {
                        try {
                            startActivity(new Intent(
                                    android.provider.Settings.ACTION_WIFI_SETTINGS));
                        } catch (Exception ignored) {
                        }
                    }
                    toast("Activez le point d'accès, puis Démarrer");
                })
                .setNeutralButton("Continuer quand même", (d, w) -> startRelay())
                .setNegativeButton("Annuler", null)
                .show();
    }

    /** Best-effort hotspot check via hidden API (may fail per ROM). */
    private boolean isWifiApEnabled() {
        try {
            WifiManager wm = (WifiManager) requireContext().getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm == null) {
                return false;
            }
            Method m = wm.getClass().getDeclaredMethod("getWifiApState");
            m.setAccessible(true);
            Object state = m.invoke(wm);
            // WIFI_AP_STATE_ENABLED == 13
            return state instanceof Integer && ((Integer) state) == 13;
        } catch (Exception e) {
            return false;
        }
    }

    private void startRelay() {
        String host = targetHost.getText().toString().trim();
        if (host.isEmpty()) {
            host = "127.0.0.1";
        }
        int port;
        try {
            port = Integer.parseInt(targetPort.getText().toString().trim());
        } catch (NumberFormatException e) {
            port = 0;
        }
        if (port <= 0 || port > 65535) {
            // Fall back to our live SOCKS when connected.
            port = activeSocksPort();
            if (port <= 0) {
                toast("Port cible invalide (et VPN non connecté)");
                return;
            }
            targetPort.setText(String.valueOf(port));
        }
        if (RELAY.start(host, port)) {
            TasVpnService.logEvent("connection", "app",
                    "hotspot relay on 0.0.0.0:" + RELAY.getListenPort()
                            + " -> " + host + ":" + port);
            showNotification(RELAY.getListenPort());
            toast("Partage actif :" + RELAY.getListenPort());
        } else {
            toast("Échec du démarrage");
        }
        refresh();
    }

    private void stopRelay() {
        RELAY.stop();
        hideNotification();
        TasVpnService.logEvent("connection", "app", "hotspot relay stopped");
        refresh();
    }

    private void showNotification(int port) {
        try {
            Context ctx = requireContext();
            NotificationManager nm =
                    (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nm.createNotificationChannel(new NotificationChannel(
                        CHANNEL_ID, "Partage Hotspot",
                        NotificationManager.IMPORTANCE_LOW));
            }
            Intent intent = new Intent(ctx, MainActivity.class);
            PendingIntent pi = PendingIntent.getActivity(
                    ctx, 0, intent, PendingIntent.FLAG_IMMUTABLE);
            Notification n = new NotificationCompat.Builder(ctx, CHANNEL_ID)
                    .setContentTitle("Partage Hotspot actif")
                    .setContentText("SOCKS5 sur le réseau local :" + port + " (TCP)")
                    .setSmallIcon(R.drawable.ic_vpn)
                    .setContentIntent(pi)
                    .setOngoing(true)
                    .build();
            nm.notify(NOTIFICATION_ID, n);
        } catch (Exception ignored) {
        }
    }

    private void hideNotification() {
        try {
            NotificationManager nm = (NotificationManager) requireContext()
                    .getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.cancel(NOTIFICATION_ID);
            }
        } catch (Exception ignored) {
        }
    }

    /** Live SOCKS port of the active tunnel (from controller status). */
    private int activeSocksPort() {
        try {
            JSONObject st = new JSONObject(TasVpnService.controllerStatus());
            String active = st.optString("active_tunnel", "");
            JSONArray tunnels = st.optJSONArray("tunnels");
            if (tunnels == null) {
                return 0;
            }
            for (int i = 0; i < tunnels.length(); i++) {
                JSONObject t = tunnels.getJSONObject(i);
                if (t.optString("id", "").equals(active)) {
                    String socks = t.optString("socks", "");
                    int colon = socks.lastIndexOf(':');
                    if (colon >= 0) {
                        return Integer.parseInt(socks.substring(colon + 1));
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    /** Non-loopback IPv4 addresses (no permission needed). */
    private static String localIps() {
        try {
            List<String> out = new ArrayList<>();
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()
                            && !addr.isLinkLocalAddress()) {
                        out.add(addr.getHostAddress());
                    }
                }
            }
            if (out.isEmpty()) {
                return "—";
            }
            StringBuilder sb = new StringBuilder();
            for (String ip : out) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ip);
            }
            return sb.toString();
        } catch (Exception e) {
            return "—";
        }
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
