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
                // Tap = select / deselect (green frame). No round-robin
                // menu: every selected profile connects from Home.
                toggleSelect(tunnel);
            }

            @Override
            public void onActions(JSONObject tunnel) {
                showActions(tunnel);
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
        // Connection happens from Home only: tapping the header card
        // explains selection instead of connecting.
        activeCard.setOnClickListener(view ->
                toast("Tap profiles below to select them (green = will connect)"));
        v.findViewById(R.id.configs_group_toggle).setOnClickListener(view -> {
            groupExpanded = !groupExpanded;
            list.setVisibility(groupExpanded ? View.VISIBLE : View.GONE);
            view.setRotation(groupExpanded ? 0 : -90);
        });
        v.findViewById(R.id.configs_group_menu).setOnClickListener(view -> showSortMenu());

        v.findViewById(R.id.configs_refresh).setOnClickListener(view -> reload());
        // No connect button on this screen: connection happens from Home only.
        v.findViewById(R.id.bar_connect).setVisibility(View.GONE);
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

            // Prune selections pointing at deleted profiles.
            java.util.Set<String> existing = new java.util.HashSet<>();
            for (int i = 0; i < arr.length(); i++) {
                existing.add(arr.getJSONObject(i).optString("id", ""));
            }
            java.util.LinkedHashSet<String> selected =
                    VPNApplication.getInstance().getSelectedIds();
            selected.retainAll(existing);
            VPNApplication.getInstance().setSelectedIds(selected);
            // Keep the single-active pointer on the first selected profile
            // (Home display, restart flow).
            String first = selected.isEmpty() ? "" : selected.iterator().next();
            VPNApplication.getInstance().setActiveTunnelId(first);

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
            // Selected first.
            for (int i = items.size() - 1; i >= 0; i--) {
                if (selected.contains(items.get(i).optString("id", ""))) {
                    JSONObject top = items.remove(i);
                    items.add(0, top);
                }
            }

            savedTitle.setText("Saved  (" + arr.length() + ")");

            activeCard.setVisibility(View.VISIBLE);
            if (selected.isEmpty()) {
                activeName.setText("No server selected");
                activeDetail.setText("Tap profiles below to select them");
                activeType.setText("");
                activeCard.setBackgroundResource(R.drawable.card_bg);
            } else if (selected.size() == 1) {
                JSONObject pick = null;
                for (int i = 0; i < items.size(); i++) {
                    if (items.get(i).optString("id", "").equals(first)) {
                        pick = items.get(i);
                        break;
                    }
                }
                if (pick == null && !items.isEmpty()) {
                    pick = items.get(0);
                }
                if (pick != null) {
                    activeName.setText(pick.optString("name", "Server"));
                    JSONObject server = pick.optJSONObject("server");
                    String host = server != null ? server.optString("host", "") : "";
                    int port = server != null ? PingUtil.dialPort(server) : 0;
                    activeDetail.setText(host.isEmpty() ? "" : host + (port > 0 ? ":" + port : ""));
                    activeType.setText(TunnelAdapter.prettyType(pick.optString("type", "")));
                }
                activeCard.setBackgroundResource(R.drawable.card_bg_active);
            } else {
                activeName.setText(selected.size() + " profiles selected");
                StringBuilder names = new StringBuilder();
                for (JSONObject o : items) {
                    if (selected.contains(o.optString("id", ""))) {
                        if (names.length() > 0) {
                            names.append("  •  ");
                        }
                        names.append(o.optString("name", "Server"));
                    }
                }
                activeDetail.setText(names.toString());
                activeType.setText("round-robin");
                activeCard.setBackgroundResource(R.drawable.card_bg_active);
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
            adapter.setItems(shown, selected, liveMap);
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
        JSONObject target = null;
        try {
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath()));
            java.util.LinkedHashSet<String> selected =
                    VPNApplication.getInstance().getSelectedIds();
            String first = selected.isEmpty() ? "" : selected.iterator().next();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (!first.isEmpty()) {
                    if (t.optString("id", "").equals(first)) {
                        target = t;
                        break;
                    }
                } else if (target == null) {
                    target = t;
                }
            }
        } catch (Exception ignored) {
        }
        if (target == null) {
            toast("No server selected");
            return;
        }
        final String tid = target.optString("id", "");
        TunnelPing.ping(requireContext(), target, (ms, via) -> {
            if (ms >= 0) {
                if (!tid.isEmpty()) {
                    VPNApplication.getInstance().setTunnelPing(tid, ms);
                }
                toast(ms + " ms");
            } else if (ms == -2) {
                toast("UDP server: TCP closed (normal). Connect, then PING measures real latency.");
            } else {
                toast("Ping failed");
            }
            reload();
        });
    }

    /** Tap a card: toggle its selection (green frame = will connect). */
    private void toggleSelect(JSONObject tunnel) {
        String id = tunnel.optString("id", "");
        if (id.isEmpty()) {
            return;
        }
        java.util.LinkedHashSet<String> set =
                VPNApplication.getInstance().toggleSelected(id);
        String first = set.isEmpty() ? "" : set.iterator().next();
        VPNApplication.getInstance().setActiveTunnelId(first);
        if (set.isEmpty()) {
            toast("Deselected - no profile will connect");
        } else if (set.size() == 1) {
            toast("Selected: " + tunnel.optString("name", "Server"));
        } else {
            toast("Selected " + set.size() + " profiles (round-robin)");
        }
        reload();
    }

    /** Long-press a card: Ping / Share / Edit / Delete (no connect here). */
    private void showActions(JSONObject tunnel) {
        String id = tunnel.optString("id", "");
        String name = tunnel.optString("name", "Server");
        String[] options = {"Ping", "Share", "Edit", "Delete"};
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle(name)
                .setItems(options, (d, which) -> {
                    switch (options[which]) {
                        case "Ping":
                            pingOne(tunnel);
                            break;
                        case "Share":
                            shareTunnel(tunnel);
                            break;
                        case "Edit": {
                            Intent i = new Intent(getContext(), TunnelEditorActivity.class);
                            i.putExtra(TunnelEditorActivity.EXTRA_TUNNEL_ID, id);
                            startActivity(i);
                            break;
                        }
                        case "Delete":
                            confirmDelete(id, name);
                            break;
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

    private void pingOne(JSONObject tunnel) {
        final String id = tunnel.optString("id", "");
        TunnelPing.ping(requireContext(), tunnel, (ms, via) -> {
            if (ms >= 0) {
                if (!id.isEmpty()) {
                    VPNApplication.getInstance().setTunnelPing(id, ms);
                }
                toast(ms + " ms");
            } else if (ms == -2) {
                toast("UDP server: TCP closed (normal). Connect, then PING measures real latency.");
            } else {
                toast("Ping failed");
            }
            reload();
        });
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
                        java.util.LinkedHashSet<String> sel =
                                VPNApplication.getInstance().getSelectedIds();
                        if (sel.remove(id)) {
                            VPNApplication.getInstance().setSelectedIds(sel);
                        }
                        if (id.equals(VPNApplication.getInstance().getActiveTunnelId())) {
                            String first = sel.isEmpty() ? "" : sel.iterator().next();
                            VPNApplication.getInstance().setActiveTunnelId(first);
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
