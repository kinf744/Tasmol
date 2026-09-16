package com.ephang.vpn;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Hotspot sharing without root: relays the active tunnel's local SOCKS onto
 * the LAN (0.0.0.0, random port). Clients on the same Wi-Fi set a manual
 * SOCKS5 proxy to this phone's IP. TCP only.
 */
public class HotspotFragment extends Fragment {
    private TextView statusText;
    private TextView ipsText;
    private TextView portText;
    private Button toggleBtn;
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
        toggleBtn.setOnClickListener(view -> {
            if (RELAY.isRunning()) {
                RELAY.stop();
                refresh();
            } else {
                startRelay();
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
        // Auto-stop when the VPN is gone: relaying nowhere is useless.
        if (RELAY.isRunning() && !TasVpnService.isRunning()) {
            RELAY.stop();
        }
        ipsText.setText(localIps());
        if (RELAY.isRunning()) {
            statusText.setText("Partage actif");
            statusText.setTextColor(0xFF00E676);
            portText.setText(String.valueOf(RELAY.getListenPort()));
            toggleBtn.setText("Arrêter le partage");
        } else {
            statusText.setText(TasVpnService.isRunning() ? "Prêt" : "Arrêté (VPN requis)");
            statusText.setTextColor(0xFFFFFFFF);
            portText.setText("—");
            toggleBtn.setText("Démarrer le partage");
        }
    }

    private void startRelay() {
        if (!TasVpnService.isRunning()) {
            Toast.makeText(getContext(), "Connectez le VPN d'abord", Toast.LENGTH_SHORT).show();
            return;
        }
        int socksPort = activeSocksPort();
        if (socksPort <= 0) {
            Toast.makeText(getContext(), "SOCKS actif introuvable", Toast.LENGTH_SHORT).show();
            return;
        }
        if (RELAY.start("127.0.0.1", socksPort)) {
            TasVpnService.logEvent("connection", "app",
                    "hotspot relay on 0.0.0.0:" + RELAY.getListenPort() + " -> 127.0.0.1:" + socksPort);
            Toast.makeText(getContext(), "Partage actif :" + RELAY.getListenPort(), Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(getContext(), "Échec du démarrage", Toast.LENGTH_SHORT).show();
        }
        refresh();
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
}
