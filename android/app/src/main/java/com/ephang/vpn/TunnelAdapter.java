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

        void onActions(JSONObject tunnel);

        void onEdit(JSONObject tunnel);

        void onClone(JSONObject tunnel);

        void onDelete(JSONObject tunnel);
    }

    private final List<JSONObject> items = new ArrayList<>();
    private final Listener listener;
    private final java.util.Set<String> selectedIds = new java.util.HashSet<>();
    private final java.util.Map<String, String> liveStatus = new java.util.HashMap<>();
    private final java.util.Map<String, Long> pingMs = new java.util.HashMap<>();

    public TunnelAdapter(Listener listener) {
        this.listener = listener;
    }

    public void setItems(JSONArray arr, java.util.Set<String> selectedIds,
                         java.util.Map<String, String> liveStatus) {
        items.clear();
        this.selectedIds.clear();
        if (selectedIds != null) {
            this.selectedIds.addAll(selectedIds);
        }
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

    /** Cards occupy 70% of the list width (centered): -30% vs full width. */
    private static final float CARD_WIDTH_RATIO = 0.70f;

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_tunnel, parent, false);
        v.post(() -> {
            ViewGroup.LayoutParams lp = v.getLayoutParams();
            int pw = parent.getWidth();
            if (lp != null && pw > 0 && pw - parent.getPaddingLeft() - parent.getPaddingRight() > 0) {
                pw -= parent.getPaddingLeft() + parent.getPaddingRight();
                lp.width = (int) (pw * CARD_WIDTH_RATIO);
                if (lp instanceof ViewGroup.MarginLayoutParams) {
                    ((ViewGroup.MarginLayoutParams) lp).leftMargin =
                            (int) (pw * (1f - CARD_WIDTH_RATIO) / 2f);
                }
                v.setLayoutParams(lp);
            }
        });
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
        if (ProfileTransfer.isHideServer(t)) {
            h.detail.setText("serveur masqué");
        } else {
            h.detail.setText(host.isEmpty() ? "" : host + (port > 0 ? ":" + port : ""));
        }
        h.type.setText(prettyType(type));

        Long ms = pingMs.get(id);
        h.ping.setText(ms != null ? ms + " ms" : "");

        boolean isSelected = selectedIds.contains(id);
        h.card.setBackgroundResource(isSelected ? R.drawable.card_bg_active : R.drawable.card_bg);
        // Selection frame says it all: no separate round-robin badge.
        h.rr.setVisibility(View.GONE);

        // Locked (imported) profiles: no edit, no clone. Ever.
        boolean locked = ProfileTransfer.isLocked(t);
        h.edit.setVisibility(locked ? View.GONE : View.VISIBLE);
        h.clone.setVisibility(locked ? View.GONE : View.VISIBLE);
        if (locked) {
            h.rr.setVisibility(View.VISIBLE);
            h.rr.setText("LOCK");
            h.rr.setTextColor(0xFFFF5252);
        } else {
            h.rr.setVisibility(View.GONE);
        }

        h.card.setOnClickListener(v -> listener.onTap(t));
        h.card.setOnLongClickListener(v -> {
            listener.onActions(t);
            return true;
        });
        h.edit.setOnClickListener(v -> listener.onEdit(t));
        h.clone.setOnClickListener(v -> listener.onClone(t));
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
        final TextView rr;
        final View edit;
        final View clone;
        final View delete;

        Holder(View v) {
            super(v);
            card = v;
            name = v.findViewById(R.id.item_name);
            detail = v.findViewById(R.id.item_detail);
            type = v.findViewById(R.id.item_type);
            ping = v.findViewById(R.id.item_ping);
            rr = v.findViewById(R.id.item_rr);
            edit = v.findViewById(R.id.item_edit);
            clone = v.findViewById(R.id.item_clone);
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
