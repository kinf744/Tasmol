package com.ephang.vpn;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
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

import java.util.HashMap;
import java.util.Map;

/** Servers tab: list, select active, edit, delete, add. */
public class ServersFragment extends Fragment {
    private RecyclerView list;
    private TextView empty;
    private TunnelAdapter adapter;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_servers, container, false);
        list = v.findViewById(R.id.servers_list);
        empty = v.findViewById(R.id.servers_empty);
        list.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new TunnelAdapter(new TunnelAdapter.Listener() {
            @Override
            public void onTap(JSONObject tunnel) {
                showActions(tunnel);
            }

            @Override
            public void onLongPress(JSONObject tunnel) {
                showActions(tunnel);
            }
        });
        list.setAdapter(adapter);

        v.findViewById(R.id.servers_add).setOnClickListener(view -> {
            Intent i = new Intent(getContext(), TunnelEditorActivity.class);
            startActivity(i);
        });
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        reload();
    }

    private void reload() {
        if (getContext() == null) {
            return;
        }
        try {
            String cfgPath = BinaryManager.configPath(getContext()).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath));
            empty.setVisibility(arr.length() == 0 ? View.VISIBLE : View.GONE);

            String active = VPNApplication.getInstance().getActiveTunnelId();
            Map<String, String> live = new HashMap<>();
            if (TasVpnService.isRunning()) {
                try {
                    JSONObject st = new JSONObject(TasVpnService.controllerStatus());
                    JSONArray running = st.optJSONArray("tunnels");
                    if (running != null) {
                        for (int i = 0; i < running.length(); i++) {
                            JSONObject t = running.getJSONObject(i);
                            live.put(t.optString("id", ""), t.optString("status", ""));
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            adapter.setItems(arr, active, live);
        } catch (Exception e) {
            Toast.makeText(getContext(), "Load failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void showActions(JSONObject tunnel) {
        String id = tunnel.optString("id", "");
        String name = tunnel.optString("name", "Server");
        boolean isActive = id.equals(VPNApplication.getInstance().getActiveTunnelId());
        String[] options = isActive
                ? new String[]{"Connect", "Edit", "Delete"}
                : new String[]{"Set active", "Connect", "Edit", "Delete"};
        new AlertDialog.Builder(requireContext())
                .setTitle(name)
                .setItems(options, (d, which) -> {
                    String action = options[which];
                    switch (action) {
                        case "Set active":
                            VPNApplication.getInstance().setActiveTunnelId(id);
                            if (TasVpnService.isRunning()) {
                                String err = TasVpnService.setActiveTunnel(id);
                                toastResult(err, "Switched");
                            } else {
                                toast("Active server set");
                            }
                            reload();
                            break;
                        case "Connect":
                            VPNApplication.getInstance().setActiveTunnelId(id);
                            if (getActivity() instanceof MainActivity) {
                                ((MainActivity) getActivity()).connectTunnel(id);
                            }
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

    private void confirmDelete(String id, String name) {
        new AlertDialog.Builder(requireContext())
                .setTitle("Delete server?")
                .setMessage("Delete \"" + name + "\"?")
                .setPositiveButton("Delete", (d, w) -> {
                    try {
                        String cfgPath = BinaryManager.configPath(requireContext()).getAbsolutePath();
                        String err = VpnlibHelper.configDelete(cfgPath, id);
                        if (err != null && !err.isEmpty()) {
                            toast("Delete failed: " + err);
                        } else {
                            if (id.equals(VPNApplication.getInstance().getActiveTunnelId())) {
                                VPNApplication.getInstance().setActiveTunnelId("");
                            }
                            toast("Deleted");
                            reload();
                        }
                    } catch (Exception e) {
                        toast("Delete failed: " + e.getMessage());
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }

    private void toastResult(String errJson, String okMsg) {
        if (errJson == null || errJson.isEmpty()) {
            toast(okMsg);
            return;
        }
        try {
            JSONObject o = new JSONObject(errJson);
            if (o.has("error")) {
                toast("Failed: " + o.optString("error"));
                return;
            }
        } catch (Exception ignored) {
        }
        toast(okMsg);
    }
}
