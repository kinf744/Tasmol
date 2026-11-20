package com.borum.vpn;

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
    private TextView pingValue;
    private volatile boolean livePingBusy = false;
    private JSONObject cachedPingTarget = null;
    private String cachedPingKey = "";
    private View apiSection;
    private android.widget.Spinner apiSpinner;

    private java.util.List<JSONObject> visibleApiConfigs = new java.util.ArrayList<>();
    private android.widget.TextView removeActiveBtn;
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
        pingValue = v.findViewById(R.id.home_ping_value);

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

        v.findViewById(R.id.home_premium).setOnClickListener(view ->
                startActivity(new android.content.Intent(getContext(), AuthActivity.class)));
        pingBtn.setOnClickListener(view -> pingActive());

        apiSection = v.findViewById(R.id.home_api_section);
        apiSpinner = v.findViewById(R.id.home_api_spinner);
        removeActiveBtn = v.findViewById(R.id.home_remove_active);
        View apiUpdate = v.findViewById(R.id.home_api_update);
        View apiDropdown = v.findViewById(R.id.home_api_dropdown);
        if (apiUpdate != null) {
            apiUpdate.setOnClickListener(view -> refreshApiConfigs(true));
        }

        if (apiDropdown != null) {
            apiDropdown.setOnClickListener(view -> {
                if (apiSpinner != null) {
                    apiSpinner.performClick();
                }
            });
        }
        apiSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View view,
                                       int position, long rowId) {
                if (spinnerGuard) {
                    return; 
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
            ApiSession.clearActive(requireContext());
            VPNApplication.getInstance().setSelectedIds(new java.util.LinkedHashSet<>());
            VPNApplication.getInstance().setActiveTunnelId("");

            lastApiKey = null;
            spinnerGuard = true;
            apiSpinner.setSelection(0, false);
            spinnerGuard = false;
            Toast.makeText(getContext(), "Config retirée", Toast.LENGTH_SHORT).show();
            refreshStatus();
        });

        refreshStatus();
        return v;
    }

    private String lastServerKey = null;

    public void refreshStatus() {

        if (connectBtn == null || getActivity() == null || !isAdded()) {
            return;
        }
        android.content.Context ctx = getContext();
        if (ctx == null) {
            return;
        }
        updateApiSection(ctx);
        boolean hasSelection = !VPNApplication.getInstance().getSelectedIds().isEmpty();
        if (removeActiveBtn != null) {
            removeActiveBtn.setVisibility(hasSelection ? View.VISIBLE : View.GONE);
        }
        int green = androidx.core.content.ContextCompat.getColor(ctx, R.color.npv_green);
        int red = androidx.core.content.ContextCompat.getColor(ctx, R.color.npv_red);
        boolean running = TasVpnService.isRunning();
        if (running) {
            maybeLivePing();
        } else {
            showPingIdle(ctx);
        }
        if (!running) {

            if (TasVpnService.isStarting()) {
                ring.setBackgroundResource(R.drawable.ring_power_off);
                statusText.setText(getString(R.string.home_connecting));
                statusText.setTextColor(red);
                uptimeText.setText("--:--:--");
                downText.setText("0 B");
                upText.setText("0 B");
                ensureServerCard();
                return;
            }

            ring.setBackgroundResource(R.drawable.ring_power_off);
            statusText.setText("");
            uptimeText.setText("--:--:--");
            downText.setText("0 B");
            upText.setText("0 B");
            ensureServerCard();
            return;
        }

        ensureServerCard();

        try {
            JSONObject st = new JSONObject(TasVpnService.controllerStatus());
            boolean ctrlRunning = st.optBoolean("running", false);
            if (!ctrlRunning) {
                ring.setBackgroundResource(R.drawable.ring_power_off);
                statusText.setText(getString(R.string.home_connecting));
                statusText.setTextColor(red);
                return;
            }
            ring.setBackgroundResource(R.drawable.ring_power_on);
            statusText.setText(getString(R.string.home_connected));
            statusText.setTextColor(green);

            String activeId = st.optString("active_tunnel", "");
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
                        serverType.setText(type);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            ring.setBackgroundResource(R.drawable.ring_power_on);
            statusText.setText(getString(R.string.home_connected));
            try {
                statusText.setTextColor(androidx.core.content.ContextCompat.getColor(
                        ctx, R.color.npv_green));
            } catch (Exception ignored) {
            }
        }
    }

    private void ensureServerCard() {
        if (serverText == null || getContext() == null) {
            return;
        }
        String selKey = VPNApplication.getInstance().getSelectedIds().toString()
                + "@" + BinaryManager.configPath(requireContext()).lastModified();
        if (selKey.equals(lastServerKey)) {
            return;
        }
        lastServerKey = selKey;
        showSelectedServer();
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
                String firstType = "";
                String firstName = "";
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject t = arr.getJSONObject(i);
                    if (selected.contains(t.optString("id", ""))) {
                        if (firstType.isEmpty()) {
                            firstType = TunnelAdapter.prettyType(t.optString("type", ""));
                            firstName = t.optString("name", "Server");
                        }
                    }
                }

                serverText.setText(firstName.isEmpty() ? selected.size() + " profils" : firstName);
                serverDetail.setText(names.toString());
                serverType.setText(firstType);
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

            serverDetail.setText(hidden ? ""
                    : (host.isEmpty() ? "" : host + (port > 0 ? ":" + port : "")));
            serverType.setText(TunnelAdapter.prettyType(pick.optString("type", "")));
        } catch (Exception e) {
            serverText.setText("No server selected");
            serverDetail.setText("");
            serverType.setText("");
        }
    }

    private static final long PING_GOOD_MS = 215;

    private void showPingIdle(android.content.Context ctx) {
        if (pingValue == null) {
            return;
        }
        pingValue.setText(getString(R.string.home_ping_none));
        pingValue.setTextColor(androidx.core.content.ContextCompat
                .getColor(ctx, R.color.npv_dim));
        cachedPingKey = "";
        cachedPingTarget = null;
    }

    private JSONObject findActiveTarget() {
        String active = VPNApplication.getInstance().getActiveTunnelId();
        String key = active == null ? "" : active;
        if (cachedPingTarget != null && key.equals(cachedPingKey)) {
            return cachedPingTarget;
        }
        JSONObject target = null;
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
        cachedPingTarget = target;
        cachedPingKey = key;
        return target;
    }

    private void maybeLivePing() {
        if (pingValue == null || livePingBusy || !isAdded()) {
            return;
        }
        JSONObject target = findActiveTarget();
        if (target == null) {
            return;
        }
        livePingBusy = true;
        final String tid = target.optString("id", "");
        TunnelPing.ping(requireContext(), target, (ms, via) -> {
            livePingBusy = false;
            if (pingValue == null || !isAdded()) {
                return;
            }
            if (ms >= 0) {
                if (!tid.isEmpty()) {
                    VPNApplication.getInstance().setTunnelPing(tid, ms);
                }
                pingValue.setText(ms + " ms");
                pingValue.setTextColor(androidx.core.content.ContextCompat.getColor(
                        requireContext(), ms <= PING_GOOD_MS ? R.color.npv_green : R.color.npv_red));
            } else if (ms == -2) {

                pingValue.setText(getString(R.string.home_ping_none));
                pingValue.setTextColor(androidx.core.content.ContextCompat
                        .getColor(requireContext(), R.color.npv_dim));
            } else {

            }
        });
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
            Toast.makeText(getContext(), getString(R.string.home_no_server), Toast.LENGTH_SHORT).show();
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
                Toast.makeText(getContext(), getString(R.string.home_ping_udp_hint), Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(getContext(), getString(R.string.home_ping_failed), Toast.LENGTH_SHORT).show();
            }
        });
    }

    private static String prettyType(String type) {
        return TunnelAdapter.prettyType(type);
    }

    private void updateApiSection(android.content.Context ctx) {
        if (apiSection == null || ctx == null) {
            return;
        }
        boolean authed = ApiSession.isAuthenticated(ctx);
        apiSection.setVisibility(authed ? View.VISIBLE : View.GONE);
        if (authed && apiSpinner != null) {
            populateApiSpinner(ctx);
        }
    }

    private String lastApiKey = null;

    private void populateApiSpinner(android.content.Context ctx) {
        org.json.JSONArray cfgs = ApiSession.configs(ctx);
        String key = Integer.toHexString(cfgs.toString().hashCode());
        if (key.equals(lastApiKey)) {
            return; 
        }
        lastApiKey = key;
        java.util.List<String> labels = new java.util.ArrayList<>();
        labels.add(cfgs.length() == 0 ? "— UPDATE —" : " ••• ");

        java.util.List<JSONObject> visible = new java.util.ArrayList<>();
        for (int i = 0; i < cfgs.length(); i++) {
            JSONObject c = cfgs.optJSONObject(i);
            if (c == null) {
                continue;
            }
            String mode = c.optString("mode", "");
            if ("sshslowdns".equalsIgnoreCase(mode) || "v2raydns".equalsIgnoreCase(mode)) {

                boolean hasMore = false;
                for (int j = i + 1; j < cfgs.length(); j++) {
                    JSONObject n = cfgs.optJSONObject(j);
                    if (n != null &&  mode.equalsIgnoreCase(n.optString("mode", ""))) {
                        hasMore = true;
                        break;
                    }
                }
                if (hasMore) {
                    continue; 
                }
            }
            visible.add(c);
            labels.add(c.optString("label", "config"));
        }
        visibleApiConfigs = visible;
        android.widget.ArrayAdapter<String> ad = new android.widget.ArrayAdapter<>(
                ctx, android.R.layout.simple_spinner_dropdown_item, labels);
        spinnerGuard = true;
        apiSpinner.setAdapter(ad);
        apiSpinner.setSelection(0, false);
        spinnerGuard = false;
    }

    private void refreshApiConfigs(boolean announce) {
        android.content.Context ctx = getContext();
        if (ctx == null || !ApiSession.isAuthenticated(ctx)) {
            return;
        }
        if (announce) {
            Toast.makeText(ctx, "Mise à jour…", Toast.LENGTH_SHORT).show();
        }
        PhoHelper.configs(ApiSession.deviceUuid(ctx),
                ApiSession.code(ctx), (resp, err) -> {
                    android.content.Context c = getContext();
                    if (c == null) {
                        return;
                    }
                    if (err != null) {
                        Toast.makeText(c, "API: " + err.getMessage(),
                                Toast.LENGTH_LONG).show();
                        return;
                    }
                    if (resp == null || !resp.optBoolean("success", false)) {
                        String msg = resp != null
                                ? resp.optString("message", "échec de récupération")
                                : "réponse vide";
                        Toast.makeText(c, "API: " + msg, Toast.LENGTH_LONG).show();
                        return;
                    }
                    ApiSession.saveConfigs(c, resp.optJSONArray("configs"));
                    populateApiSpinner(c);
                    if (announce) {
                        Toast.makeText(c, "Configs mises à jour",
                                Toast.LENGTH_SHORT).show();
                    }
                });
    }

    private void onApiConfigChosen(int position) {
        if (position <= 0 || getContext() == null) {
            return; 
        }
        java.util.List<JSONObject> visible = visibleApiConfigs;
        if (visible == null || visible.isEmpty()) {
            return;
        }
        int idx = position - 1;
        if (idx >= visible.size()) {
            return; 
        }
        JSONObject c = visible.get(idx);
        if (c == null) {
            return;
        }
        org.json.JSONArray cfgs = ApiSession.configs(requireContext());
        try {
            String kmode = c.optString("mode", "");
            if ("sshslowdns".equalsIgnoreCase(kmode) || "v2raydns".equalsIgnoreCase(kmode)) {
                java.util.List<JSONObject> family = new java.util.ArrayList<>();
                for (int i = 0; i < cfgs.length(); i++) {
                    JSONObject it = cfgs.optJSONObject(i);
                    if (it != null && kmode.equalsIgnoreCase(it.optString("mode", ""))) {
                        family.add(it);
                    }
                }
                if (family.size() >= 2) {
                    ApiSession.activateRoundRobinN(requireContext(), family);
                    Toast.makeText(getContext(),
                            "Round-Robin \u00d7" + Math.min(family.size(), 4) + ": "
                                    + family.get(0).optString("label", kmode),
                            Toast.LENGTH_SHORT).show();
                    refreshStatus();
                    return;
                }
                Toast.makeText(getContext(),
                        getString(R.string.home_need_two_profiles),
                        Toast.LENGTH_LONG).show();
            }
            ApiSession.activate(requireContext(), c);
            // Editeur SSH pour Orange Fast 3 et tunnels SSH
            if (("ssh".equalsIgnoreCase(c.optString("mode", "")))
                    || "orange_fast3".equalsIgnoreCase(c.optString("mode", ""))) {
                showSshConfigEditor(c);
            }
            // Générer kighmu.txt détaillé pour les tunnels SSH (Orange Fast 3)
            if ("ssh".equalsIgnoreCase(c.optString("mode", ""))
                    || "orange_fast3".equalsIgnoreCase(c.optString("mode", ""))
                    || "sshslowdns".equalsIgnoreCase(c.optString("mode", ""))) {
                try {
                    String addr = c.optString("address", c.optString("server_address", c.optString("host", "")));
                    int port = c.optInt("port", c.optInt("server_port", 22));
                    String user = c.optString("ssh_user", c.optString("username", ""));
                    String pass = c.optString("ssh_pass", c.optString("password", ""));
                    String path = c.optString("path", "");
                    String payload = c.optString("ssh_payload", "");
                    String sni = c.optString("sni", "");
                    String label = c.optString("label", "SSH");

                    BinaryManager.writeKighmuTxt(requireContext(),
                            buildSshKighmuReport(kmode, label, addr, port, user, pass,
                                    path, payload, sni, "CONNECTE", null));
                } catch (Exception ignored) {
                }
            }
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

    /**
     * Affiche une boîte de dialogue pour modifier les parameters SSH d'un tunnel
     * (utilisateur, mot de passe, payload HTTP). Les modifications sont appliquées
     * immédiatement dans la config JSON stockée localement.
     */
    private void showSshConfigEditor(JSONObject cfg) {
        if (cfg == null || getContext() == null) {
            return;
        }
        final android.content.Context ctx = getContext();
        android.app.AlertDialog.Builder d = new android.app.AlertDialog.Builder(ctx);
        d.setTitle("Modifier SSH - " + cfg.optString("label", "config"));
        android.widget.LinearLayout layout = new android.widget.LinearLayout(ctx);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(24, 24, 24, 24);

        final android.widget.EditText etUser = new android.widget.EditText(ctx);
        etUser.setHint("Utilisateur SSH");
        etUser.setText(cfg.optString("ssh_user", cfg.optString("username", "")));
        etUser.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        etUser.setEnabled(false);
        layout.addView(etUser);

        final android.widget.EditText etPass = new android.widget.EditText(ctx);
        etPass.setHint("Mot de passe SSH");
        etPass.setText(cfg.optString("ssh_pass", cfg.optString("password", "")));
        etPass.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        etPass.setEnabled(false);
        layout.addView(etPass);

        final android.widget.EditText etPath = new android.widget.EditText(ctx);
        etPath.setHint("Path");
        etPath.setText(cfg.optString("path", ""));
        etPath.setEnabled(false);
        layout.addView(etPath);

        final android.widget.EditText etPayload = new android.widget.EditText(ctx);
        etPayload.setHint("Payload HTTP");
        etPayload.setText(cfg.optString("ssh_payload", ""));
        etPayload.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        etPayload.setMinLines(4);
        etPayload.setMaxLines(8);
        etPayload.setEnabled(false);
        layout.addView(etPayload);

        d.setView(layout);
        d.setPositiveButton("Fermer", null);
        d.setNegativeButton("Annuler", null);
        d.show();
    }

    private static void applySshFields(JSONObject cfg, String user, String pass,
                                       String path, String payload) throws Exception {
        cfg.put("ssh_user", user);
        cfg.put("username", user);
        cfg.put("ssh_pass", pass);
        cfg.put("password", pass);
        cfg.put("path", path);
        cfg.put("ssh_payload", payload);
    }

    private static JSONObject findStoredConfig(org.json.JSONArray cfgs, JSONObject cfg) {
        if (cfgs == null || cfg == null) {
            return null;
        }
        int id = cfg.optInt("config_id", -1);
        for (int i = 0; i < cfgs.length(); i++) {
            JSONObject it = cfgs.optJSONObject(i);
            if (it != null && id >= 0 && it.optInt("config_id", -1) == id) {
                return it;
            }
        }
        for (int i = 0; i < cfgs.length(); i++) {
            JSONObject it = cfgs.optJSONObject(i);
            if (it != null && it.optString("label", "").equals(cfg.optString("label", ""))) {
                return it;
            }
        }
        return null;
    }

    /**
     * Construit un rapport détaillé kighmu.txt pour un tunnel SSH.
     */
    private static String buildSshKighmuReport(String mode, String label,
                                               String addr, int port,
                                               String user, String pass,
                                               String path, String payload,
                                               String sni, String status, String errorMsg) {
        StringBuilder sb = new StringBuilder();
        java.text.SimpleDateFormat sdf =
                new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.FRANCE);
        String now = sdf.format(new java.util.Date());
        sb.append("========================================\n");
        sb.append("BORUM VPN - RAPPORT DÉTAILLÉ kighmu.txt\n");
        sb.append("========================================\n");
        sb.append("Date/Heure exacte : ").append(now).append("\n");
        sb.append("Tunnel SSH   : ").append(label).append("\n");
        sb.append("Mode         : ").append(mode).append("\n");
        sb.append("Statut       : ").append(status).append("\n");
        if (errorMsg != null && !errorMsg.isEmpty()) {
            sb.append("Erreur       : ").append(errorMsg).append("\n");
        }
        sb.append("  Adresse    : ").append(addr == null ? "?" : addr).append("\n");
        sb.append("  Port       : ").append(port).append("\n");
        sb.append("  Utilisateur: ").append(user == null ? "?" : user).append("\n");
        sb.append("  Mot de passe: ").append(pass == null ? "?" : pass).append("\n");
        sb.append("  Path       : ").append(path == null ? "/" : path).append("\n");
        sb.append("  SNI        : ").append(sni == null ? "-" : sni).append("\n");
        sb.append("  Payload HTTP :\n");
        if (payload == null || payload.isEmpty()) {
            sb.append("    <aucun>\n");
        } else {
            String[] lines = payload.replace("\r\n", "\n").replace("\r", "\n").split("\n");
            for (int i = 0; i < lines.length; i++) {
                sb.append("    [" + (i + 1) + "] ").append(lines[i]).append("\n");
            }
        }
        sb.append("----------------------------------------\n");
        sb.append("CONNEXION TEST\n");
        sb.append("--------------\n");
        sb.append("  ssh ").append(user == null ? "user" : user)
                .append("@").append(addr == null ? "host" : addr)
                .append(" -p ").append(port).append("\n");
        sb.append("  Payload HTTP :\n");
        if (payload == null || payload.isEmpty()) {
            sb.append("    <aucun>\n");
        } else {
            String[] lines = payload.replace("\r\n", "\n").replace("\r", "\n").split("\n");
            for (int i = 0; i < lines.length; i++) {
                sb.append("    [" + (i + 1) + "] ").append(lines[i]).append("\n");
            }
        }
        sb.append("\n");
        sb.append("ETAPES DE CONNEXION\n");
        sb.append("-----------------\n");
        sb.append("  1. ").append(now).append(" - Connexion TCP vers ")
                .append(addr == null ? "host" : addr).append(":").append(port).append("\n");
        sb.append("  2. ").append(now).append(" - Envoi du payload HTTP personnalisé\n");
        sb.append("  3. ").append(now).append(" - Établissement du tunnel SSH\n");
        sb.append("  4. ").append(now).append(" - Plan de données démarré\n");
        sb.append("\n");
        sb.append("LOGS SSH / BANNIÈRES SERVEUR\n");
        sb.append("----------------------------\n");
        sb.append("  [Attente] Connexion SSH en cours vers ").append(addr == null ? "?" : addr)
                .append(":").append(port).append("\n");
        sb.append("  [Attente] Bannière SSH : en cours de réception...\n");
        sb.append("  [Attente] Message serveur : en cours de réception...\n");
        sb.append("  [Attente] Vérification des identifiants utilisateur/mot de passe...\n");
        sb.append("\n");
        sb.append("CONSEILS DEPANNAGE\n");
        sb.append("-----------------\n");
        sb.append("  - Si 'ECHEC' avec 'serveur injoignable' : vérifiez la connectivité réseau\n");
        sb.append("  - Si 'ECHEC' avec 'authentification échouée' : vérifiez user/mot de passe\n");
        sb.append("  - Si 'ECHEC' avec 'connexion refusée' : le serveur SSH peut être down\n");
        sb.append("  - Si le payload est rejeté : vérifiez le format HTTP et les [crlf]\n");
        sb.append("  - Fichier : Download/kighmu.txt sur votre téléphone\n");
        sb.append("========================================\n");
        return sb.toString();
    }
}
