package com.ephang.vpn;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** CONFIGS tab (NPV Tunnel style): last ping, active card, saved group. */
public class ConfigsFragment extends Fragment {
    private TextView lastPingText;
    private LinearLayout activeCard;
    private TextView activeName;
    private TextView activeDetail;
    private TextView activeType;
    private TextView savedTitle;
    private RecyclerView list;
    private TunnelAdapter adapter;
    private boolean sortByType = false;
    private String query = "";
    private String typeFilter = "all";
    private boolean groupExpanded = true;
    private final Handler bg = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_configs, container, false);
        lastPingText = v.findViewById(R.id.configs_last_ping);
        activeCard = v.findViewById(R.id.configs_active_card);
        activeName = v.findViewById(R.id.configs_active_name);
        activeDetail = v.findViewById(R.id.configs_active_detail);
        activeType = v.findViewById(R.id.configs_active_type);
        savedTitle = v.findViewById(R.id.configs_saved_title);
        list = v.findViewById(R.id.configs_list);
        list.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new TunnelAdapter(new TunnelAdapter.Listener() {
            @Override
            public void onTap(JSONObject tunnel) {
                tapTunnel(tunnel);
            }

            @Override
            public void onShare(JSONObject tunnel) {
                shareTunnel(tunnel);
            }

            @Override
            public void onEdit(JSONObject tunnel) {
                Intent i = new Intent(getContext(), TunnelEditorActivity.class);
                i.putExtra(TunnelEditorActivity.EXTRA_TUNNEL_ID, tunnel.optString("id", ""));
                startActivity(i);
            }

            @Override
            public void onDelete(JSONObject tunnel) {
                confirmDelete(tunnel.optString("id", ""), tunnel.optString("name", "Server"));
            }
        });
        list.setAdapter(adapter);

        v.findViewById(R.id.configs_ping_btn).setOnClickListener(view -> pingActive());
        activeCard.setOnClickListener(view -> {
            String id = VPNApplication.getInstance().getActiveTunnelId();
            if (id != null && !id.isEmpty() && getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).connectTunnel(id);
            }
        });
        v.findViewById(R.id.configs_group_toggle).setOnClickListener(view -> {
            groupExpanded = !groupExpanded;
            list.setVisibility(groupExpanded ? View.VISIBLE : View.GONE);
            v.findViewById(R.id.configs_group_chevron).setRotation(groupExpanded ? 0 : -90);
        });
        v.findViewById(R.id.configs_group_menu).setOnClickListener(view -> showSortMenu());

        v.findViewById(R.id.configs_refresh).setOnClickListener(view -> reload());
        v.findViewById(R.id.bar_connect).setOnClickListener(view -> {
            String id = VPNApplication.getInstance().getActiveTunnelId();
            if ((id == null || id.isEmpty()) && getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).pickTunnelAndConnect();
            } else if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).connectTunnel(id);
            }
        });
        v.findViewById(R.id.bar_sort).setOnClickListener(view -> {
            sortByType = !sortByType;
            reload();
        });
        v.findViewById(R.id.bar_refresh).setOnClickListener(view -> reload());
        v.findViewById(R.id.bar_search).setOnClickListener(view -> showSearch());
        v.findViewById(R.id.bar_filter).setOnClickListener(view -> showFilter());
        v.findViewById(R.id.bar_add).setOnClickListener(view -> {
            startActivity(new Intent(getContext(), TunnelEditorActivity.class));
        });
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        reload();
    }

    private String cfgPath() {
        return BinaryManager.configPath(requireContext()).getAbsolutePath();
    }

    private void reload() {
        if (getContext() == null) {
            return;
        }
        try {
            lastPingText.setText(VPNApplication.getInstance().getLastPingDate());
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath()));
            String active = VPNApplication.getInstance().getActiveTunnelId();

            List<JSONObject> items = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (!typeFilter.equals("all") && !typeMatches(t.optString("type", ""))) {
                    continue;
                }
                if (!query.isEmpty() && !t.optString("name", "").toLowerCase().contains(query)) {
                    continue;
                }
                items.add(t);
            }
            if (sortByType) {
                Collections.sort(items, (a, b) -> a.optString("type", "").compareTo(b.optString("type", "")));
            } else {
                Collections.sort(items, (a, b) -> a.optString("name", "").compareToIgnoreCase(b.optString("name", "")));
            }
            // Active first.
            for (int i = 0; i < items.size(); i++) {
                if (items.get(i).optString("id", "").equals(active)) {
                    JSONObject top = items.remove(i);
                    items.add(0, top);
                    break;
                }
            }

            savedTitle.setText("Saved  (" + arr.length() + ")");

            JSONObject pick = null;
            for (int i = 0; i < items.size(); i++) {
                if (items.get(i).optString("id", "").equals(active)) {
                    pick = items.get(i);
                    break;
                }
            }
            if (pick == null && !items.isEmpty()) {
                pick = items.get(0);
            }
            if (pick != null) {
                activeCard.setVisibility(View.VISIBLE);
                activeName.setText(pick.optString("name", "Server"));
                JSONObject server = pick.optJSONObject("server");
                String host = server != null ? server.optString("host", "") : "";
                int port = server != null ? PingUtil.dialPort(server) : 0;
                activeDetail.setText(host.isEmpty() ? "" : host + (port > 0 ? ":" + port : ""));
                activeType.setText(TunnelAdapter.prettyType(pick.optString("type", "")));
                activeCard.setBackgroundResource(
                        pick.optString("id", "").equals(active) ? R.drawable.card_bg_active : R.drawable.card_bg);
            } else {
                activeCard.setVisibility(View.GONE);
            }

            JSONArray live = new JSONArray();
            java.util.Map<String, String> liveMap = new java.util.HashMap<>();
            if (TasVpnService.isRunning()) {
                try {
                    JSONObject st = new JSONObject(TasVpnService.controllerStatus());
                    live = st.optJSONArray("tunnels");
                    if (live != null) {
                        for (int i = 0; i < live.length(); i++) {
                            JSONObject t = live.getJSONObject(i);
                            liveMap.put(t.optString("id", ""), t.optString("status", ""));
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            JSONArray shown = new JSONArray();
            for (JSONObject o : items) {
                shown.put(o);
            }
            adapter.setItems(shown, active, liveMap);
        } catch (Exception e) {
            Toast.makeText(getContext(), "Load failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private boolean typeMatches(String type) {
        switch (typeFilter) {
            case "ssh":
                return type.equals("ssh") || type.equals("ssh_slowdns");
            case "xray":
                return type.equals("xray") || type.equals("xray_slowdns");
            case "zivpn":
                return type.equals("zivpn");
            default:
                return true;
        }
    }

    private void pingActive() {
        new Thread(() -> {
            long ms = -1;
            String id = "";
            try {
                JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath()));
                String active = VPNApplication.getInstance().getActiveTunnelId();
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject t = arr.getJSONObject(i);
                    if (active != null && !active.isEmpty() && !t.optString("id", "").equals(active)) {
                        continue;
                    }
                    if (active == null || active.isEmpty()) {
                        if (i > 0) {
                            continue;
                        }
                        id = t.optString("id", "");
                    } else {
                        id = active;
                    }
                    JSONObject server = t.optJSONObject("server");
                    if (server == null) {
                        continue;
                    }
                    String host = server.optString("host", "");
                    int port = PingUtil.dialPort(server);
                    if (!host.isEmpty() && port > 0) {
                        ms = PingUtil.ping(host, port, 4000);
                    }
                    break;
                }
            } catch (Exception ignored) {
            }
            final long result = ms;
            final String tid = id;
            bg.post(() -> {
                if (result >= 0 && !tid.isEmpty()) {
                    VPNApplication.getInstance().setTunnelPing(tid, result);
                    Toast.makeText(getContext(), result + " ms", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(getContext(), "Ping failed", Toast.LENGTH_SHORT).show();
                }
                reload();
            });
        }).start();
    }

    private void tapTunnel(JSONObject tunnel) {
        String id = tunnel.optString("id", "");
        String name = tunnel.optString("name", "Server");
        boolean isActive = id.equals(VPNApplication.getInstance().getActiveTunnelId());
        String[] options = isActive
                ? new String[]{"Connect", "Ping", "Edit"}
                : new String[]{"Set active", "Connect", "Ping", "Edit"};
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle(name)
                .setItems(options, (d, which) -> {
                    String action = options[which];
                    switch (action) {
                        case "Set active":
                            VPNApplication.getInstance().setActiveTunnelId(id);
                            if (TasVpnService.isRunning()) {
                                TasVpnService.setActiveTunnel(id);
                            }
                            toast("Active server set");
                            reload();
                            break;
                        case "Connect":
                            VPNApplication.getInstance().setActiveTunnelId(id);
                            if (getActivity() instanceof MainActivity) {
                                ((MainActivity) getActivity()).connectTunnel(id);
                            }
                            break;
                        case "Ping":
                            pingOne(tunnel);
                            break;
                        case "Edit": {
                            Intent i = new Intent(getContext(), TunnelEditorActivity.class);
                            i.putExtra(TunnelEditorActivity.EXTRA_TUNNEL_ID, id);
                            startActivity(i);
                            break;
                        }
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void shareTunnel(JSONObject tunnel) {
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TEXT, tunnel.toString());
        i.putExtra(Intent.EXTRA_SUBJECT, tunnel.optString("name", "Server"));
        startActivity(Intent.createChooser(i, "Share via"));
    }

    private void showActions(JSONObject tunnel) {
        tapTunnel(tunnel);
    }

    private void pingOne(JSONObject tunnel) {
        String id = tunnel.optString("id", "");
        JSONObject server = tunnel.optJSONObject("server");
        if (server == null) {
            return;
        }
        String host = server.optString("host", "");
        int port = PingUtil.dialPort(server);
        if (host.isEmpty() || port <= 0) {
            toast("Nothing to ping");
            return;
        }
        new Thread(() -> {
            long ms = PingUtil.ping(host, port, 4000);
            bg.post(() -> {
                if (ms >= 0) {
                    VPNApplication.getInstance().setTunnelPing(id, ms);
                    toast(ms + " ms");
                } else {
                    toast("Ping failed");
                }
                reload();
            });
        }).start();
    }

    private void confirmDelete(String id, String name) {
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Delete server?")
                .setMessage("Delete \"" + name + "\"?")
                .setPositiveButton("Delete", (d, w) -> {
                    String err = VpnlibHelper.configDelete(cfgPath(), id);
                    if (err != null && !err.isEmpty()) {
                        toast("Delete failed");
                    } else {
                        if (id.equals(VPNApplication.getInstance().getActiveTunnelId())) {
                            VPNApplication.getInstance().setActiveTunnelId("");
                        }
                        toast("Deleted");
                        reload();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showSearch() {
        EditText input = new EditText(getContext());
        input.setHint("Filter by name");
        input.setText(query);
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Search")
                .setView(input)
                .setPositiveButton("OK", (d, w) -> {
                    query = input.getText().toString().trim().toLowerCase();
                    reload();
                })
                .setNegativeButton("Clear", (d, w) -> {
                    query = "";
                    reload();
                })
                .show();
    }

    private void showFilter() {
        String[] opts = {"All", "SSH", "Xray", "Zivpn UDP"};
        String[] vals = {"all", "ssh", "xray", "zivpn"};
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Filter by type")
                .setItems(opts, (d, which) -> {
                    typeFilter = vals[which];
                    reload();
                })
                .show();
    }

    private void showSortMenu() {
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Saved configs")
                .setItems(new String[]{"Sort: Name", "Sort: Type"}, (d, which) -> {
                    sortByType = which == 1;
                    reload();
                })
                .show();
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
