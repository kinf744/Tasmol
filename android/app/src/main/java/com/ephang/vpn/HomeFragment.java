package com.ephang.vpn;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import org.json.JSONArray;
import org.json.JSONObject;

/** HOME tab (NPV Tunnel style): power ring, bracket status, active config. */
public class HomeFragment extends Fragment {
    private View ring;
    private ImageButton connectBtn;
    private TextView statusText;
    private TextView serverText;
    private TextView serverDetail;
    private TextView serverType;
    private TextView uptimeText;
    private TextView downText;
    private TextView upText;
    private Button pingBtn;
    private final Handler bg = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_home, container, false);
        ring = v.findViewById(R.id.home_ring);
        connectBtn = v.findViewById(R.id.home_connect_btn);
        statusText = v.findViewById(R.id.home_status);
        serverText = v.findViewById(R.id.home_server);
        serverDetail = v.findViewById(R.id.home_server_detail);
        serverType = v.findViewById(R.id.home_server_type);
        uptimeText = v.findViewById(R.id.home_uptime);
        downText = v.findViewById(R.id.home_down);
        upText = v.findViewById(R.id.home_up);
        pingBtn = v.findViewById(R.id.home_ping);

        connectBtn.setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).toggleVpn();
            }
        });
        v.findViewById(R.id.home_config_card).setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).goToConfigs();
            }
        });
        v.findViewById(R.id.home_premium).setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).goToMore();
            }
        });
        pingBtn.setOnClickListener(view -> pingActive());

        refreshStatus();
        return v;
    }

    public void refreshStatus() {
        if (connectBtn == null || getActivity() == null) {
            return;
        }
        boolean running = TasVpnService.isRunning();
        if (!running) {
            String err = TasVpnService.getLastError();
            ring.setBackgroundResource(R.drawable.ring_power_off);
            statusText.setText(err != null ? "[ ERROR ]" : "[ NOT CONNECTED ]");
            uptimeText.setText("--:--:--");
            downText.setText("0 B");
            upText.setText("0 B");
            showSelectedServer();
            return;
        }

        try {
            JSONObject st = new JSONObject(TasVpnService.controllerStatus());
            boolean ctrlRunning = st.optBoolean("running", false);
            if (!ctrlRunning) {
                ring.setBackgroundResource(R.drawable.ring_power_off);
                statusText.setText("[ STARTING ]");
                return;
            }
            ring.setBackgroundResource(R.drawable.ring_power_on);
            statusText.setText("[ CONNECTED ]");

            String activeId = st.optString("active_tunnel", "");
            org.json.JSONArray rr = st.optJSONArray("round_robin");
            final int rrCount = rr != null ? rr.length() : 0;
            uptimeText.setText(formatDuration(st.optLong("uptime", 0)));
            downText.setText(formatBytes(st.optLong("bytes_down", 0)));
            upText.setText(formatBytes(st.optLong("bytes_up", 0)));

            JSONArray tunnels = st.optJSONArray("tunnels");
            if (tunnels != null) {
                for (int i = 0; i < tunnels.length(); i++) {
                    JSONObject t = tunnels.getJSONObject(i);
                    if (t.optString("id", "").equals(activeId)) {
                        serverText.setText(t.optString("name", "Server"));
                        String type = TunnelAdapter.prettyType(t.optString("type", ""));
                        serverType.setText(rrCount >= 2 ? type + "  •  RR(" + rrCount + ")" : type);
                        break;
                    }
                }
            }
            if (rrCount >= 2) {
                serverDetail.setText("round-robin over " + rrCount + " profiles");
            }
        } catch (Exception e) {
            ring.setBackgroundResource(R.drawable.ring_power_on);
            statusText.setText("[ CONNECTED ]");
        }
    }

    private void showSelectedServer() {
        try {
            String cfgPath = BinaryManager.configPath(requireContext()).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath));
            String active = VPNApplication.getInstance().getActiveTunnelId();
            JSONObject pick = null;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (active != null && !active.isEmpty()) {
                    if (t.optString("id", "").equals(active)) {
                        pick = t;
                        break;
                    }
                } else if (pick == null) {
                    pick = t;
                }
            }
            if (pick == null) {
                serverText.setText("No server selected");
                serverDetail.setText("");
                serverType.setText("");
                return;
            }
            serverText.setText(pick.optString("name", "Server"));
            JSONObject server = pick.optJSONObject("server");
            String host = server != null ? server.optString("host", "") : "";
            int port = server != null ? PingUtil.dialPort(server) : 0;
            serverDetail.setText(host.isEmpty() ? "" : host + (port > 0 ? ":" + port : ""));
            serverType.setText(TunnelAdapter.prettyType(pick.optString("type", "")));
        } catch (Exception e) {
            serverText.setText("No server selected");
            serverDetail.setText("");
            serverType.setText("");
        }
    }

    private void pingActive() {
        pingBtn.setEnabled(false);
        pingBtn.setText("...");
        JSONObject target = null;
        String active = VPNApplication.getInstance().getActiveTunnelId();
        try {
            String cfgPath = BinaryManager.configPath(requireContext()).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if ((active != null && !active.isEmpty() && !t.optString("id", "").equals(active))
                        || (active == null || active.isEmpty()) && i > 0) {
                    continue;
                }
                target = t;
                break;
            }
        } catch (Exception ignored) {
        }
        if (target == null) {
            pingBtn.setEnabled(true);
            pingBtn.setText("PING");
            Toast.makeText(getContext(), "No server selected", Toast.LENGTH_SHORT).show();
            return;
        }
        final String tid = target.optString("id", "");
        final String label = target.optString("name", "");
        TunnelPing.ping(requireContext(), target, (ms, via) -> {
            pingBtn.setEnabled(true);
            pingBtn.setText("PING");
            if (ms >= 0) {
                if (!tid.isEmpty()) {
                    VPNApplication.getInstance().setTunnelPing(tid, ms);
                }
                Toast.makeText(getContext(), label + ": " + ms + " ms", Toast.LENGTH_SHORT).show();
            } else if (ms == -2) {
                Toast.makeText(getContext(), "UDP server: TCP port closed (normal). Connect, then PING measures real latency.", Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(getContext(), "Ping failed", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private static String prettyType(String type) {
        return TunnelAdapter.prettyType(type);
    }

    public static String formatBytes(long bytes) {
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
        return String.format(java.util.Locale.US, i == 0 ? "%d %s" : "%.1f %s", i == 0 ? (long) v : v, units[i]);
    }

    private static String formatDuration(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        return String.format(java.util.Locale.US, "%02d:%02d:%02d", h, m, s);
    }
}
