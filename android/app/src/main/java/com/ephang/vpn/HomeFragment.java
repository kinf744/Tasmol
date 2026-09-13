package com.ephang.vpn;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import org.json.JSONArray;
import org.json.JSONObject;

/** Home tab: big connect button, selected server, live stats. */
public class HomeFragment extends Fragment {
    private ImageButton connectBtn;
    private TextView statusText;
    private TextView tapHint;
    private TextView serverText;
    private TextView serverDetail;
    private TextView uptimeText;
    private TextView downText;
    private TextView upText;
    private Button changeServerBtn;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_home, container, false);
        connectBtn = v.findViewById(R.id.home_connect_btn);
        statusText = v.findViewById(R.id.home_status);
        tapHint = v.findViewById(R.id.home_tap_hint);
        serverText = v.findViewById(R.id.home_server);
        serverDetail = v.findViewById(R.id.home_server_detail);
        uptimeText = v.findViewById(R.id.home_uptime);
        downText = v.findViewById(R.id.home_down);
        upText = v.findViewById(R.id.home_up);
        changeServerBtn = v.findViewById(R.id.home_change_server);

        connectBtn.setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).toggleVpn();
            }
        });
        changeServerBtn.setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).pickTunnelAndConnect();
            }
        });

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
            connectBtn.setBackgroundResource(R.drawable.circle_idle);
            connectBtn.setImageResource(android.R.drawable.ic_media_play);
            statusText.setText(err != null ? "Error: " + err : "Disconnected");
            tapHint.setText("TAP TO CONNECT");
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
                connectBtn.setBackgroundResource(R.drawable.circle_idle);
                connectBtn.setImageResource(android.R.drawable.ic_media_play);
                statusText.setText("Starting...");
                tapHint.setText("PLEASE WAIT");
                return;
            }
            connectBtn.setBackgroundResource(R.drawable.circle_disconnect);
            connectBtn.setImageResource(android.R.drawable.ic_media_pause);
            statusText.setText("Connected");
            tapHint.setText("TAP TO DISCONNECT");

            String activeId = st.optString("active_tunnel", "");
            long uptime = st.optLong("uptime", 0);
            uptimeText.setText(formatDuration(uptime));

            JSONArray tunnels = st.optJSONArray("tunnels");
            if (tunnels != null) {
                for (int i = 0; i < tunnels.length(); i++) {
                    JSONObject t = tunnels.getJSONObject(i);
                    if (t.optString("id", "").equals(activeId)) {
                        serverText.setText(t.optString("name", "Server"));
                        serverDetail.setText(prettyType(t.optString("type", "")) + "  •  " + t.optString("status", ""));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            statusText.setText("Connected");
            connectBtn.setBackgroundResource(R.drawable.circle_disconnect);
            connectBtn.setImageResource(android.R.drawable.ic_media_pause);
            tapHint.setText("TAP TO DISCONNECT");
        }
    }

    private void showSelectedServer() {
        try {
            String cfgPath = BinaryManager.configPath(requireContext()).getAbsolutePath();
            String json = VpnlibHelper.listTunnels(cfgPath);
            JSONArray arr = new JSONArray(json);
            String active = VPNApplication.getInstance().getActiveTunnelId();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (active != null && !active.isEmpty() && !t.optString("id", "").equals(active)) {
                    continue;
                }
                serverText.setText(t.optString("name", "No server selected"));
                JSONObject server = t.optJSONObject("server");
                String host = server != null ? server.optString("host", "") : "";
                serverDetail.setText(prettyType(t.optString("type", "")) + (host.isEmpty() ? "" : "  •  " + host));
                if (active == null || active.isEmpty()) {
                    break;
                }
            }
            if (arr.length() == 0) {
                serverText.setText("No server selected");
                serverDetail.setText("Add one in the Servers tab");
            }
        } catch (Exception e) {
            serverText.setText("No server selected");
            serverDetail.setText("");
        }
    }

    private static String prettyType(String type) {
        switch (type) {
            case "ssh": return "SSH";
            case "ssh_slowdns": return "SSH + SlowDNS";
            case "xray": return "Xray";
            case "xray_slowdns": return "Xray + SlowDNS";
            case "zivpn": return "Zivpn UDP";
            default: return type;
        }
    }

    private static String formatDuration(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        return String.format(java.util.Locale.US, "%02d:%02d:%02d", h, m, s);
    }
}
