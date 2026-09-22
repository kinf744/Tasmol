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
import java.util.Random;

/**
 * Hotspot sharing without root: relays a SOCKS endpoint (ours or another
 * VPN app's) onto the LAN (0.0.0.0, FIXED port 8080). A fresh proxy IP in
 * the 172.16.x.x range is assigned at every launch and shown to the user,
 * together with the real-time sent/received traffic counters. Works with
 * or without our VPN connected. Requires the system Wi-Fi hotspot on: the
 * app checks and redirects to the tethering settings otherwise. TCP only.
 */
public class HotspotFragment extends Fragment {
    private static final String CHANNEL_ID = "ephang_hotspot";
    private static final int NOTIFICATION_ID = 43;
    private static final int PROXY_PORT = TcpRelay.FIXED_PORT; // 8080, fixe
    private static final Random RNG = new Random();

    private TextView statusText;
    private TextView proxyText;
    private TextView portText;
    private TextView ipsText;
    private TextView upText;
    private TextView downText;
    private TextView totalText;
    private Button toggleBtn;
    private String proxyIp = "";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private static final TcpRelay RELAY = new TcpRelay();
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1000);
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_hotspot, container, false);
        statusText = v.findViewById(R.id.hotspot_status);
        proxyText = v.findViewById(R.id.hotspot_proxy);
        portText = v.findViewById(R.id.hotspot_port);
        ipsText = v.findViewById(R.id.hotspot_ips);
        upText = v.findViewById(R.id.hotspot_up);
        downText = v.findViewById(R.id.hotspot_down);
        totalText = v.findViewById(R.id.hotspot_total);
        toggleBtn = v.findViewById(R.id.hotspot_toggle);
        toggleBtn.setOnClickListener(view -> {
            if (RELAY.isRunning()) {
                stopRelay();
            } else {
                ensureAccessPointThenStart();
            }
        });
        // Tap the proxy address to copy it to the clipboard.
        proxyText.setOnClickListener(view -> {
            String t = proxyText.getText().toString();
            if (!t.isEmpty() && !t.equals("—") && getContext() != null) {
                android.content.ClipboardManager cm = (android.content.ClipboardManager)
                        getContext().getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("proxy", t));
                    toast("Proxy copié : " + t);
                }
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
        if (RELAY.isRunning()) {
            statusText.setText("ACTIF");
            statusText.setTextColor(0xFF00E676);
            proxyText.setText(RELAY.getProxyIp());
            portText.setText(String.valueOf(RELAY.getListenPort()));
            upText.setText(formatBytes(RELAY.getUpBytes()));
            downText.setText(formatBytes(RELAY.getDownBytes()));
            totalText.setText(formatBytes(RELAY.getTotalBytes()));
            toggleBtn.setText("ARRÊTER LE PARTAGE");
        } else {
            statusText.setText("ARRÊTÉ");
            statusText.setTextColor(0xFF9E9E9E);
            proxyText.setText("—");
            // Port affiché en permanence : il ne change jamais (8080).
            portText.setText(String.valueOf(PROXY_PORT));
            upText.setText("0 B");
            downText.setText("0 B");
            totalText.setText("0 B");
            toggleBtn.setText("DÉMARRER LE PARTAGE");
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
        // Cible automatique : le SOCKS de notre tunnel actif (127.0.0.1).
        // Sans VPN connecté, on peut partager la connexion d'UNE AUTRE
        // app VPN : on demande alors son proxy local (host:port).
        int port = activeSocksPort();
        if (port > 0) {
            launch("127.0.0.1", port);
            return;
        }
        if (getContext() == null) {
            return;
        }
        final EditText input = new EditText(getContext());
        input.setHint("127.0.0.1:10808");
        input.setText("127.0.0.1:");
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT);
        new AlertDialog.Builder(getContext())
                .setTitle("Partager une autre app VPN")
                .setMessage("Notre VPN n'est pas connecté. Indiquez le proxy "
                        + "local de l'autre application (SOCKS5/HTTP), "
                        + "format hôte:port — ex : 127.0.0.1:10808")
                .setView(input)
                .setPositiveButton("Démarrer", (d, w) -> {
                    String v = input.getText().toString().trim();
                    String host = "127.0.0.1";
                    int p = 0;
                    int colon = v.lastIndexOf(':');
                    if (colon > 0) {
                        host = v.substring(0, colon).trim();
                        try {
                            p = Integer.parseInt(v.substring(colon + 1).trim());
                        } catch (NumberFormatException ignored) {
                        }
                    }
                    if (host.isEmpty()) {
                        host = "127.0.0.1";
                    }
                    if (p <= 0 || p > 65535) {
                        toast("Port invalide (ex : 127.0.0.1:10808)");
                        return;
                    }
                    launch(host, p);
                })
                .setNegativeButton("Annuler", null)
                .show();
    }

    private void launch(String host, int port) {
        // Nouvelle IP proxy 172.16.x.x à chaque lancement.
        proxyIp = pickProxyIp();
        if (RELAY.start(host, port, proxyIp)) {
            TasVpnService.logEvent("connection", "app",
                    "hotspot relay " + proxyIp + ":" + RELAY.getListenPort()
                            + " -> " + host + ":" + port);
            showNotification(RELAY.getListenPort());
            toast("Partage actif : " + proxyIp + ":" + RELAY.getListenPort());
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
                    .setContentText("Proxy " + proxyIp + ":" + port + " (SOCKS5/TCP)")
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

    /**
     * Proxy IP advertised for this launch. Prefers a real hotspot address
     * already in the 172.16.0.0/12 range (some ROMs/carriers use it);
     * otherwise a fresh random 172.16.x.x alias — a new one at every
     * launch. The relay itself listens on 0.0.0.0 so clients can also use
     * any of the phone's real LAN addresses with the same fixed port.
     */
    private static String pickProxyIp() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) {
                        continue;
                    }
                    byte[] b = addr.getAddress();
                    int b0 = b[0] & 0xFF;
                    int b1 = b[1] & 0xFF;
                    // 172.16.0.0 – 172.31.255.255 (plage demandée 172.16.x.x)
                    if (b0 == 172 && b1 >= 16 && b1 <= 31) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return "172.16." + (1 + RNG.nextInt(255)) + "." + (1 + RNG.nextInt(255));
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

    private static String formatBytes(long bytes) {
        if (bytes <= 0) {
            return "0 B";
        }
        final String[] units = {"B", "KB", "MB", "GB"};
        int i = 0;
        double v = bytes;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(java.util.Locale.US, i == 0 ? "%d %s" : "%.1f %s",
                i == 0 ? (long) v : v, units[i]);
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
