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
    private View apiSection;
    private android.widget.Spinner apiSpinner;
    // Rangées visibles du spinner (paires SlowDNS fusionnées en une entrée).
    private java.util.List<JSONObject> visibleApiConfigs = new java.util.ArrayList<>();
    private android.widget.ImageButton removeActiveBtn;
    private boolean spinnerGuard = false;
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
        // Long-press the power button: nuclear disconnect. Kills every
        // tunnel process and the app itself so a stuck VPN key is always
        // released, even when the service refuses to stop.
        connectBtn.setOnLongClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                        .setTitle("Nuclear disconnect?")
                        .setMessage("Force-close the app and kill ALL tunnel "
                                + "processes (xray, zivpn, slowdns, ssh)? "
                                + "Use this when the VPN refuses to disconnect "
                                + "and the key icon stays stuck.")
                        .setPositiveButton("NUCLEAR", (d, w) ->
                                ((MainActivity) getActivity()).nuclearDisconnect())
                        .setNegativeButton("Cancel", null)
                        .show();
                return true;
            }
            return false;
        });
        v.findViewById(R.id.home_config_card).setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).goToConfigs();
            }
        });
        // Trophy icon (top-right): API activation / account screen.
        v.findViewById(R.id.home_premium).setOnClickListener(view ->
                startActivity(new android.content.Intent(getContext(), AuthActivity.class)));
        pingBtn.setOnClickListener(view -> pingActive());

        // SERVER CONFIGS (API) section.
        apiSection = v.findViewById(R.id.home_api_section);
        apiSpinner = v.findViewById(R.id.home_api_spinner);
        removeActiveBtn = v.findViewById(R.id.home_remove_active);
        v.findViewById(R.id.home_api_update).setOnClickListener(view -> refreshApiConfigs(true));
        // La flèche ouvre le menu déroulant (spinner masqué).
        v.findViewById(R.id.home_api_dropdown).setOnClickListener(view -> {
            if (apiSpinner != null) {
                apiSpinner.performClick();
            }
        });
        apiSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View view,
                                       int position, long rowId) {
                if (spinnerGuard) {
                    return; // programmatic population, not a user choice
                }
                onApiConfigChosen(position);
            }

            @Override
            public void onNothingSelected(android.widget.AdapterView<?> parent) {
            }
        });
        removeActiveBtn.setOnClickListener(view -> {
            ApiSession.clearActive(requireContext());
            VPNApplication.getInstance().setSelectedIds(new java.util.LinkedHashSet<>());
            VPNApplication.getInstance().setActiveTunnelId("");
            Toast.makeText(getContext(), "Config retirée", Toast.LENGTH_SHORT).show();
            refreshStatus();
        });

        refreshStatus();
        return v;
    }

    public void refreshStatus() {
        // !isAdded() : fragment détaché pendant un refresh différé (ex. après
        // une déconnexion longue) — requireContext() planterait sinon.
        if (connectBtn == null || getActivity() == null || !isAdded()) {
            return;
        }
        updateApiSection();
        boolean hasSelection = !VPNApplication.getInstance().getSelectedIds().isEmpty();
        if (removeActiveBtn != null) {
            removeActiveBtn.setVisibility(hasSelection ? View.VISIBLE : View.GONE);
        }
        int green = androidx.core.content.ContextCompat.getColor(requireContext(), R.color.npv_green);
        int red = androidx.core.content.ContextCompat.getColor(requireContext(), R.color.npv_red);
        boolean running = TasVpnService.isRunning();
        if (!running) {
            // Launching / (re)connecting: stay on CONNECTING in red,
            // with the attempt counter across the retry loop.
            if (TasVpnService.isStarting()) {
                ring.setBackgroundResource(R.drawable.ring_power_off);
                statusText.setText("[ CONNECTING ]");
                statusText.setTextColor(red);
                uptimeText.setText("--:--:--");
                downText.setText("0 B");
                upText.setText("0 B");
                return;
            }
            // VPN never launched (or stopped): no status at all.
            // Failures are reported via toast + Logs tab, never as a
            // persistent on-screen state.
            ring.setBackgroundResource(R.drawable.ring_power_off);
            statusText.setText("");
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
                statusText.setText("[ CONNECTING ]");
                statusText.setTextColor(red);
                return;
            }
            ring.setBackgroundResource(R.drawable.ring_power_on);
            statusText.setText("[ CONNECTED ]");
            statusText.setTextColor(green);

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
            try {
                statusText.setTextColor(androidx.core.content.ContextCompat.getColor(
                        requireContext(), R.color.npv_green));
            } catch (Exception ignored) {
            }
        }
    }

    private void showSelectedServer() {
        try {
            String cfgPath = BinaryManager.configPath(requireContext()).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath));
            java.util.LinkedHashSet<String> selected =
                    VPNApplication.getInstance().getSelectedIds();
            if (selected.isEmpty()) {
                serverText.setText("No server selected");
                serverDetail.setText("Pick profiles in Configs");
                serverType.setText("");
                return;
            }
            if (selected.size() >= 2) {
                StringBuilder names = new StringBuilder();
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject t = arr.getJSONObject(i);
                    if (selected.contains(t.optString("id", ""))) {
                        if (names.length() > 0) {
                            names.append("  •  ");
                        }
                        names.append(t.optString("name", "Server"));
                    }
                }
                serverText.setText(selected.size() + " profiles");
                serverDetail.setText(names.toString());
                serverType.setText("round-robin");
                return;
            }
            String active = selected.iterator().next();
            JSONObject pick = null;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (t.optString("id", "").equals(active)) {
                    pick = t;
                    break;
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
            boolean hidden = ProfileTransfer.isHideServer(pick)
                    || ProfileTransfer.isApiManaged(pick);
            // Configs API : jamais d'host:port à l'écran — le nom seul suffit
            // (ex. "Camtel UDP", "MTN 150Mo"), les adresses restent côté
            // plan de contrôle.
            serverDetail.setText(hidden ? ""
                    : (host.isEmpty() ? "" : host + (port > 0 ? ":" + port : "")));
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
                Toast.makeText(getContext(), "UDP-only server and VPN not connected: connect first, then PING shows live latency.", Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(getContext(), "Ping failed", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private static String prettyType(String type) {
        return TunnelAdapter.prettyType(type);
    }

    // ------------------------------------------------------------------
    // SERVER CONFIGS (remote API) section
    // ------------------------------------------------------------------

    /** Visible only once the device is activated (trophy screen). */
    private void updateApiSection() {
        if (apiSection == null || getContext() == null) {
            return;
        }
        boolean authed = ApiSession.isAuthenticated(requireContext());
        apiSection.setVisibility(authed ? View.VISIBLE : View.GONE);
        if (authed) {
            populateApiSpinner();
        }
    }

    private void populateApiSpinner() {
        org.json.JSONArray cfgs = ApiSession.configs(requireContext());
        java.util.List<String> labels = new java.util.ArrayList<>();
        labels.add(cfgs.length() == 0 ? "— UPDATE —" : " ••• ");
        // Affichage professionnel : les paires SlowDNS (2 profils servis
        // pour le round-robin) apparaissent comme UNE SEULE entrée déjà
        // suffixée « 2 » par l'API (ex. "SSH + SlowDNS 2"), ce qui signifie
        // "2 profils combinés". L'entrée "… 1" est masquée.
        java.util.List<JSONObject> visible = new java.util.ArrayList<>();
        for (int i = 0; i < cfgs.length(); i++) {
            JSONObject c = cfgs.optJSONObject(i);
            if (c == null) {
                continue;
            }
            String mode = c.optString("mode", "");
            if ("sshslowdns".equalsIgnoreCase(mode) || "v2raydns".equalsIgnoreCase(mode)) {
                // Garder uniquement le dernier profil du mode = « … 2 ».
                boolean hasMore = false;
                for (int j = i + 1; j < cfgs.length(); j++) {
                    JSONObject n = cfgs.optJSONObject(j);
                    if (n != null && mode.equalsIgnoreCase(n.optString("mode", ""))) {
                        hasMore = true;
                        break;
                    }
                }
                if (hasMore) {
                    continue; // masque « … 1 »
                }
            }
            visible.add(c);
            labels.add(c.optString("label", "config"));
        }
        visibleApiConfigs = visible;
        android.widget.ArrayAdapter<String> ad = new android.widget.ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_dropdown_item, labels);
        spinnerGuard = true;
        apiSpinner.setAdapter(ad);
        apiSpinner.setSelection(0, false);
        spinnerGuard = false;
    }

    /** UPDATE button: pull the freshest config list from the API. */
    private void refreshApiConfigs(boolean announce) {
        if (getContext() == null || !ApiSession.isAuthenticated(requireContext())) {
            return;
        }
        if (announce) {
            Toast.makeText(getContext(), "Mise à jour…", Toast.LENGTH_SHORT).show();
        }
        PhoHelper.configs(ApiSession.deviceUuid(requireContext()),
                ApiSession.code(requireContext()), (resp, err) -> {
                    if (getContext() == null) {
                        return;
                    }
                    if (err != null) {
                        Toast.makeText(getContext(), "API: " + err.getMessage(),
                                Toast.LENGTH_LONG).show();
                        return;
                    }
                    if (resp == null || !resp.optBoolean("success", false)) {
                        String msg = resp != null
                                ? resp.optString("message", "échec de récupération")
                                : "réponse vide";
                        Toast.makeText(getContext(), "API: " + msg, Toast.LENGTH_LONG).show();
                        return;
                    }
                    ApiSession.saveConfigs(requireContext(), resp.optJSONArray("configs"));
                    populateApiSpinner();
                    if (announce) {
                        Toast.makeText(getContext(), "Configs mises à jour",
                                Toast.LENGTH_SHORT).show();
                    }
                });
    }

    /** Dropdown selection: materialize + select the chosen remote config. */
    private void onApiConfigChosen(int position) {
        if (position <= 0 || getContext() == null) {
            return; // placeholder row
        }
        java.util.List<JSONObject> visible = visibleApiConfigs;
        if (visible == null || position - 1 >= visible.size()) {
            return;
        }
        JSONObject c = visible.get(position - 1);
        if (c == null) {
            return;
        }
        org.json.JSONArray cfgs = ApiSession.configs(requireContext());
        try {
            String mode = c.optString("mode", "");
            // Round-robin PAR FAMILLE : choisir une config SlowDNS active
            // ses 2 profils DE MÊME MODE (SSH SlowDNS 1+2 ensemble, ou
            // V2Ray SlowDNS 1+2 ensemble) — 2 connexions dnstt parallèles
            // sur le même canal = agrégation de débit. Jamais de mix
            // SSH+V2Ray.
            if ("sshslowdns".equalsIgnoreCase(mode) || "v2raydns".equalsIgnoreCase(mode)) {
                JSONObject first = null;
                JSONObject second = null;
                for (int i = 0; i < cfgs.length(); i++) {
                    JSONObject it = cfgs.optJSONObject(i);
                    if (it == null) {
                        continue;
                    }
                    if (mode.equalsIgnoreCase(it.optString("mode", ""))) {
                        if (first == null) {
                            first = it;
                        } else {
                            second = it;
                            break;
                        }
                    }
                }
                if (first != null && second != null) {
                    ApiSession.activateRoundRobin(requireContext(), first, second);
                    Toast.makeText(getContext(),
                            "Round-Robin ×2: " + first.optString("label", mode),
                            Toast.LENGTH_SHORT).show();
                    refreshStatus();
                    return;
                }
                Toast.makeText(getContext(),
                        "2 profils requis pour le round-robin — mode simple",
                        Toast.LENGTH_LONG).show();
            }
            ApiSession.activate(requireContext(), c);
            Toast.makeText(getContext(),
                    "Active: " + c.optString("label", "config"), Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(getContext(), "Config API invalide: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        }
        refreshStatus();
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
