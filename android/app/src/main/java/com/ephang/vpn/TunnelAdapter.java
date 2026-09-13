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

/** RecyclerView adapter for the server list. */
public class TunnelAdapter extends RecyclerView.Adapter<TunnelAdapter.Holder> {

    public interface Listener {
        void onTap(JSONObject tunnel);
        void onLongPress(JSONObject tunnel);
    }

    private final List<JSONObject> items = new ArrayList<>();
    private final Listener listener;
    private String activeId = "";
    private final java.util.Map<String, String> liveStatus = new java.util.HashMap<>();

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
        int port = server != null ? server.optInt("port", 0) : 0;
        String range = server != null ? server.optString("port_range", "") : "";

        h.name.setText(name);
        String addr = host;
        if (!range.isEmpty()) {
            addr += ":" + range;
        } else if (port != 0) {
            addr += ":" + port;
        }
        h.detail.setText(addr);
        h.type.setText(prettyType(type));

        boolean isActive = id.equals(activeId);
        h.active.setVisibility(isActive ? View.VISIBLE : View.GONE);

        String live = liveStatus.get(id);
        int dot;
        if ("running".equals(live)) {
            dot = R.drawable.circle_connect;
        } else if ("error".equals(live)) {
            dot = R.drawable.circle_disconnect;
        } else {
            dot = R.drawable.circle_idle;
        }
        h.dot.setBackgroundResource(dot);

        h.itemView.setOnClickListener(v -> listener.onTap(t));
        h.itemView.setOnLongClickListener(v -> {
            listener.onLongPress(t);
            return true;
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class Holder extends RecyclerView.ViewHolder {
        final View dot;
        final TextView name;
        final TextView detail;
        final TextView type;
        final TextView active;

        Holder(View v) {
            super(v);
            dot = v.findViewById(R.id.item_dot);
            name = v.findViewById(R.id.item_name);
            detail = v.findViewById(R.id.item_detail);
            type = v.findViewById(R.id.item_type);
            active = v.findViewById(R.id.item_active);
        }
    }

    public static String prettyType(String type) {
        switch (type) {
            case "ssh": return "SSH";
            case "ssh_slowdns": return "SSH + SlowDNS";
            case "xray": return "Xray";
            case "xray_slowdns": return "Xray + SlowDNS";
            case "zivpn": return "Zivpn UDP";
            default: return type;
        }
    }
}
