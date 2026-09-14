package com.ephang.vpn;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** RecyclerView adapter for NPV-style config cards. */
public class TunnelAdapter extends RecyclerView.Adapter<TunnelAdapter.Holder> {

    public interface Listener {
        void onTap(JSONObject tunnel);

        void onShare(JSONObject tunnel);

        void onEdit(JSONObject tunnel);

        void onDelete(JSONObject tunnel);
    }

    private final List<JSONObject> items = new ArrayList<>();
    private final Listener listener;
    private String activeId = "";
    private final java.util.Map<String, String> liveStatus = new java.util.HashMap<>();
    private final java.util.Map<String, Long> pingMs = new java.util.HashMap<>();

    public TunnelAdapter(Listener listener) {
        this.listener = listener;
    }

    public void setItems(JSONArray arr, String activeId, java.util.Map<String, String> liveStatus) {
        items.clear();
        this.activeId = activeId == null ? "" : activeId;
        this.liveStatus.clear();
        if (liveStatus != null) {
            this.liveStatus.putAll(liveStatus);
        }
        if (arr != null) {
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o != null) {
                    items.add(o);
                }
            }
        }
        pingMs.clear();
        for (JSONObject o : items) {
            long ms = VPNApplication.getInstance().getTunnelPing(o.optString("id", ""));
            if (ms >= 0) {
                pingMs.put(o.optString("id", ""), ms);
            }
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_tunnel, parent, false);
        return new Holder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull Holder h, int position) {
        JSONObject t = items.get(position);
        String id = t.optString("id", "");
        String name = t.optString("name", "Server");
        String type = t.optString("type", "");
        JSONObject server = t.optJSONObject("server");
        String host = server != null ? server.optString("host", "") : "";
        int port = server != null ? PingUtil.dialPort(server) : 0;

        h.name.setText(name);
        h.detail.setText(host.isEmpty() ? "" : host + (port > 0 ? ":" + port : ""));
        h.type.setText(prettyType(type));

        Long ms = pingMs.get(id);
        h.ping.setText(ms != null ? ms + " ms" : "");

        boolean isActive = id.equals(activeId);
        h.card.setBackgroundResource(isActive ? R.drawable.card_bg_active : R.drawable.card_bg);

        h.card.setOnClickListener(v -> listener.onTap(t));
        h.share.setOnClickListener(v -> listener.onShare(t));
        h.edit.setOnClickListener(v -> listener.onEdit(t));
        h.delete.setOnClickListener(v -> listener.onDelete(t));
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class Holder extends RecyclerView.ViewHolder {
        final View card;
        final TextView name;
        final TextView detail;
        final TextView type;
        final TextView ping;
        final View share;
        final View edit;
        final View delete;

        Holder(View v) {
            super(v);
            card = v;
            name = v.findViewById(R.id.item_name);
            detail = v.findViewById(R.id.item_detail);
            type = v.findViewById(R.id.item_type);
            ping = v.findViewById(R.id.item_ping);
            share = v.findViewById(R.id.item_share);
            edit = v.findViewById(R.id.item_edit);
            delete = v.findViewById(R.id.item_delete);
        }
    }

    public static String prettyType(String type) {
        switch (type) {
            case "ssh":
                return "ssh";
            case "ssh_slowdns":
                return "ssh_slowdns";
            case "xray":
                return "xray";
            case "xray_slowdns":
                return "xray_slowdns";
            case "zivpn":
                return "zivpn";
            default:
                return type;
        }
    }
}
