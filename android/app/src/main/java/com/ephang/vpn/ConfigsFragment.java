package com.ephang.vpn;

import android.app.Activity;
import android.content.Context;
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
    private static final int REQ_IMPORT_SHARE = 3001;
    private static final int REQ_EXPORT_SHARE = 3002;
    private String pendingExport = null;
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
            public void onEdit(JSONObject tunnel) {
                if (ProfileTransfer.isLocked(tunnel)) {
                    toast("Profil verrouillé : modification impossible");
                    return;
                }
                Intent i = new Intent(getContext(), TunnelEditorActivity.class);
                i.putExtra(TunnelEditorActivity.EXTRA_TUNNEL_ID, tunnel.optString("id", ""));
                startActivity(i);
            }

            @Override
            public void onClone(JSONObject tunnel) {
                if (ProfileTransfer.isLocked(tunnel)) {
                    toast("Profil verrouillé : clonage impossible");
                    return;
                }
                cloneTunnel(tunnel.optString("id", ""), tunnel.optString("name", "Server"));
            }

            @Override
            public void onDelete(JSONObject tunnel) {
                confirmDelete(tunnel.optString("id", ""), tunnel.optString("name", "Server"));
            }
        });
        list.setAdapter(adapter);

        v.findViewById(R.id.configs_active_menu).setOnClickListener(view -> showShareMenu());

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
                    boolean hidden = ProfileTransfer.isHideServer(pick);
                    activeDetail.setText(hidden ? "serveur masqué"
                            : (host.isEmpty() ? "" : host + (port > 0 ? ":" + port : "")));
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
        // Conflict rule: an API config currently owns the selection and the
        // user picked a manual profile. Warn; on confirm the API config is
        // withdrawn (API mode back to standby) and manual selection resumes.
        boolean isApiTunnel = id.equals(ApiSession.activeTunnelId(requireContext()));
        if (ApiSession.isApiActive(requireContext()) && !isApiTunnel) {
            new AlertDialog.Builder(requireContext())
                    .setTitle("Mode API actif")
                    .setMessage("Une config API est active. Les profils manuels sont "
                            + "bloqués tant qu'elle est sélectionnée.\n\n"
                            + "Retirer la config API et utiliser ce profil ?")
                    .setPositiveButton("Retirer l'API", (d, w) -> {
                        ApiSession.onManualSelection(requireContext());
                        applyToggle(id, tunnel);
                    })
                    .setNegativeButton("Annuler", null)
                    .show();
            return;
        }
        applyToggle(id, tunnel);
        // Manual selection while an API tunnel merely existed (not active)
        // also puts API mode in standby.
        ApiSession.onManualSelection(requireContext());
    }

    private void applyToggle(String id, JSONObject tunnel) {
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

    /** Long-press a card: Ping / Clone / Edit / Delete (no connect here).
     *  Locked profiles expose Ping + Delete only. */
    private void showActions(JSONObject tunnel) {
        String id = tunnel.optString("id", "");
        String name = tunnel.optString("name", "Server");
        boolean locked = ProfileTransfer.isLocked(tunnel);
        java.util.List<String> opts = new java.util.ArrayList<>();
        opts.add("Ping");
        if (!locked) {
            opts.add("Clone");
            opts.add("Edit");
        }
        opts.add("Delete");
        String[] options = opts.toArray(new String[0]);
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle(name + (locked ? " (verrouillé)" : ""))
                .setItems(options, (d, which) -> {
                    switch (options[which]) {
                        case "Ping":
                            pingOne(tunnel);
                            break;
                        case "Clone":
                            if (ProfileTransfer.isLocked(tunnel)) {
                                toast("Profil verrouillé : clonage impossible");
                            } else {
                                cloneTunnel(id, name);
                            }
                            break;
                        case "Edit": {
                            if (ProfileTransfer.isLocked(tunnel)) {
                                toast("Profil verrouillé : modification impossible");
                                break;
                            }
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

    /** Duplicate a profile (fresh id, "name copy"). */
    private void cloneTunnel(String id, String name) {
        if (id == null || id.isEmpty()) {
            return;
        }
        try {
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath()));
            JSONObject src = null;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (id.equals(t.optString("id", ""))) {
                    src = t;
                    break;
                }
            }
            if (src == null) {
                toast("Profile not found");
                return;
            }
            src.remove("id");
            src.put("name", name + " copy");
            String res = VpnlibHelper.configAdd(cfgPath(), src.toString());
            if (res != null && res.startsWith("{")) {
                JSONObject o = new JSONObject(res);
                if (o.has("error")) {
                    toast("Clone failed: " + o.optString("error"));
                    return;
                }
            }
            toast("Cloned: " + name + " copy");
            reload();
        } catch (Exception e) {
            toast("Clone failed: " + e.getMessage());
        }
    }

    /** Share menu for the SELECTED profiles (header card). Works only with
     *  1+ selected. Options: lock, expiry, hardware ids, then two buttons:
     *  export to .epha file, or export to clipboard (ephang://). */
    /** Partager + Importer via the card's ⋮ menu (same line as server name). */
    private void showShareMenu() {
        java.util.LinkedHashSet<String> selected =
                VPNApplication.getInstance().getSelectedIds();
        String[] options = {"Partager la sélection", "Importer"};
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Export Config")
                .setItems(options, (d, which) -> {
                    if (which == 0) {
                        showExportMenu();
                    } else {
                        showImportChoice();
                    }
                })
                .setNegativeButton("Annuler", null)
                .show();
    }

    /** Show the Backup form for the currently selected profiles. */
    private void showExportMenu() {
        java.util.LinkedHashSet<String> selected =
                VPNApplication.getInstance().getSelectedIds();
        if (selected.isEmpty()) {
            toast("Sélectionnez d'abord 1+ profils (cadre vert)");
            return;
        }
        final List<JSONObject> tunnels =
                ProfileTransfer.selectedTunnels(requireContext(), selected);
        if (tunnels.isEmpty()) {
            toast("Sélection vide");
            return;
        }

        final float density = getResources().getDisplayMetrics().density;
        int pad = (int) (16 * density);

        android.widget.LinearLayout layout = new android.widget.LinearLayout(requireContext());
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(pad, pad, pad, pad);

        final android.widget.EditText filenameInput = new android.widget.EditText(requireContext());
        filenameInput.setHint("Filename");
        filenameInput.setText("ephang-" + tunnels.size() + "-profils.epha");
        filenameInput.setTextColor(0xFFFFFFFF);
        filenameInput.setHintTextColor(0xFF616161);
        layout.addView(filenameInput);

        android.widget.GridLayout grid = new android.widget.GridLayout(requireContext());
        grid.setColumnCount(2);
        grid.setPadding(0, pad / 2, 0, 0);
        final java.util.Map<String, android.widget.CheckBox> boxes = new java.util.LinkedHashMap<>();
        String[][] opts = {
                {"lock", "Lock Backup"}, {"external", "External"},
                {"hideserver", "Hide Server"}, {"hideupass", "Hide UPass"},
                {"blockroot", "Block Root"}, {"hwid", "HWID"},
                {"note", "Note"}, {"expired", "Expired"},
        };
        boolean[] defaults = {false, true, false, false, false, false, false, false};
        for (int i = 0; i < opts.length; i++) {
            android.widget.CheckBox cb = new android.widget.CheckBox(requireContext());
            cb.setText(opts[i][1]);
            cb.setTextColor(0xFFFFFFFF);
            cb.setChecked(defaults[i]);
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                cb.setButtonTintList(android.content.res.ColorStateList.valueOf(0xFF00E676));
            }
            android.widget.GridLayout.LayoutParams lp = new android.widget.GridLayout.LayoutParams();
            lp.width = 0;
            lp.columnSpec = android.widget.GridLayout.spec(i % 2, 1f);
            lp.setMargins(0, (int) (4 * density), 0, (int) (4 * density));
            cb.setLayoutParams(lp);
            grid.addView(cb);
            boxes.put(opts[i][0], cb);
        }
        layout.addView(grid);

        final android.widget.EditText hwidInput = new android.widget.EditText(requireContext());
        hwidInput.setHint("HWID");
        hwidInput.setTextColor(0xFFFFFFFF);
        hwidInput.setHintTextColor(0xFF616161);
        hwidInput.setEnabled(false);
        hwidInput.setAlpha(0.4f);
        layout.addView(hwidInput);

        final android.widget.EditText noteInput = new android.widget.EditText(requireContext());
        noteInput.setHint("Note (ex. 2026 © Ephang Team)");
        noteInput.setTextColor(0xFFFFFFFF);
        noteInput.setHintTextColor(0xFF616161);
        noteInput.setEnabled(false);
        noteInput.setAlpha(0.4f);
        layout.addView(noteInput);

        final android.widget.TextView expiryText = new android.widget.TextView(requireContext());
        expiryText.setText("Expiration : —");
        expiryText.setTextColor(0xFF9E9E9E);
        expiryText.setPadding(0, pad / 2, 0, 0);
        layout.addView(expiryText);

        final String[] expiry = {""};
        boxes.get("hwid").setOnCheckedChangeListener((b, c) -> {
            hwidInput.setEnabled(c);
            hwidInput.setAlpha(c ? 1f : 0.4f);
        });
        boxes.get("note").setOnCheckedChangeListener((b, c) -> {
            noteInput.setEnabled(c);
            noteInput.setAlpha(c ? 1f : 0.4f);
        });
        boxes.get("expired").setOnCheckedChangeListener((b, c) -> {
            if (c) {
                showExpiryPicker(expiry, expiryText);
            } else {
                expiry[0] = "";
                expiryText.setText("Expiration : —");
            }
        });

        android.widget.TextView summary = new android.widget.TextView(requireContext());
        summary.setText(tunnels.size() + " profil(s) sélectionné(s)");
        summary.setTextColor(0xFF9E9E9E);
        summary.setPadding(0, pad / 2, 0, 0);
        layout.addView(summary);

        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Export Config")
                .setView(layout)
                .setPositiveButton("Fichier .epha", (d, w) -> {
                    ProfileTransfer.Restrictions r = readBackupOptions(
                            boxes, hwidInput.getText().toString(),
                            noteInput.getText().toString(), expiry[0]);
                    if (r == null) {
                        return;
                    }
                    exportToFile(tunnels, r, filenameInput.getText().toString());
                })
                .setNeutralButton("Clipboard", (d, w) -> {
                    ProfileTransfer.Restrictions r = readBackupOptions(
                            boxes, hwidInput.getText().toString(),
                            noteInput.getText().toString(), expiry[0]);
                    if (r == null) {
                        return;
                    }
                    exportToClipboard(tunnels, r);
                })
                .setNegativeButton("Annuler", null)
                .show();
    }

    /** Green date picker for the Expired option (AAAA-MM-JJ). Material style
     *  with explicit green buttons (the default can be unreadable). */
    private void showExpiryPicker(final String[] expiry, final android.widget.TextView label) {
        java.util.Calendar cal = java.util.Calendar.getInstance();
        android.app.DatePickerDialog dlg = new android.app.DatePickerDialog(requireContext(),
                android.R.style.Theme_Material_Dialog,
                (view, y, m, day) -> {
                    expiry[0] = String.format(java.util.Locale.US, "%04d-%02d-%02d", y, m + 1, day);
                    label.setText("Expiration : " + expiry[0]);
                },
                cal.get(java.util.Calendar.YEAR), cal.get(java.util.Calendar.MONTH),
                cal.get(java.util.Calendar.DAY_OF_MONTH));
        dlg.getDatePicker().setMinDate(System.currentTimeMillis() - 1000);
        dlg.show();
        // Force readable green buttons: the Material theme otherwise can
        // render light-on-light text.
        try {
            android.widget.Button ok = dlg.getButton(android.content.DialogInterface.BUTTON_POSITIVE);
            android.widget.Button cancel = dlg.getButton(android.content.DialogInterface.BUTTON_NEGATIVE);
            if (ok != null) {
                ok.setTextColor(0xFF00BF9A);
                ok.setTypeface(null, android.graphics.Typeface.BOLD);
            }
            if (cancel != null) {
                cancel.setTextColor(0xFF00BF9A);
                cancel.setTypeface(null, android.graphics.Typeface.BOLD);
            }
        } catch (Exception ignored) {
        }
    }

    /** Validate Backup options; null = invalid (toast shown). */
    private ProfileTransfer.Restrictions readBackupOptions(
            java.util.Map<String, android.widget.CheckBox> boxes,
            String hwids, String note, String expiry) {
        ProfileTransfer.Restrictions r = new ProfileTransfer.Restrictions();
        r.lockConfiguration = boxes.get("lock").isChecked();
        r.external = boxes.get("external").isChecked();
        r.hideServer = boxes.get("hideserver").isChecked();
        r.hideUpass = boxes.get("hideupass").isChecked();
        r.blockRoot = boxes.get("blockroot").isChecked();
        r.removeBanner = boxes.get("rmbanner").isChecked();
        r.customBanner = boxes.get("custombanner").isChecked();
        if (boxes.get("expired").isChecked()) {
            if (expiry == null || !expiry.matches("\\d{4}-\\d{2}-\\d{2}")) {
                toast("Choisissez une date d'expiration");
                return null;
            }
            r.expiresAt = expiry;
        }
        if (boxes.get("hwid").isChecked()) {
            if (hwids != null) {
                for (String part : hwids.split("[,;\\n]+")) {
                    String id = part.trim().replaceAll("\\s+", "").toUpperCase(java.util.Locale.US);
                    if (!id.isEmpty() && !id.matches("[A-F0-9]{32}")) {
                        toast("Hardware ID invalide : " + part.trim());
                        return null;
                    }
                    if (!id.isEmpty() && !r.allowedHardwareIds.contains(id)) {
                        r.allowedHardwareIds.add(id);
                    }
                }
            }
            if (r.allowedHardwareIds.isEmpty()) {
                toast("HWID coché : saisissez au moins un ID");
                return null;
            }
        }
        if (boxes.get("note").isChecked()) {
            r.userNote = note == null ? "" : note.trim();
        }
        return r;
    }

    private void exportToFile(List<JSONObject> tunnels, ProfileTransfer.Restrictions r,
                              String filename) {
        for (JSONObject t : tunnels) {
            if (ProfileTransfer.isLocked(t) && !ProfileTransfer.isExternalAllowed(t)) {
                toast("Partage externe interdit pour : " + t.optString("name", "Server"));
                return;
            }
        }
        try {
            String json = ProfileTransfer.buildExport(tunnels, r, filename);
            pendingExport = json;
            String name = filename == null ? "" : filename.trim();
            if (name.isEmpty()) {
                name = "ephang-" + tunnels.size() + "-profils.epha";
            } else if (!name.toLowerCase(java.util.Locale.US).endsWith(".epha")) {
                name = name + ".epha";
            }
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, name);
            startActivityForResult(i, REQ_EXPORT_SHARE);
        } catch (Exception e) {
            toast("Export impossible : " + e.getMessage());
        }
    }

    private void exportToClipboard(List<JSONObject> tunnels, ProfileTransfer.Restrictions r) {
        for (JSONObject t : tunnels) {
            if (ProfileTransfer.isLocked(t) && !ProfileTransfer.isExternalAllowed(t)) {
                toast("Partage externe interdit pour : " + t.optString("name", "Server"));
                return;
            }
        }
        try {
            String json = ProfileTransfer.buildExport(tunnels, r, null);
            String link = ProfileTransfer.toClipboard(json);
            android.content.ClipboardManager cm = (android.content.ClipboardManager) requireContext()
                    .getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(android.content.ClipData.newPlainText("ephang", link));
            TasVpnService.logEvent("exported " + tunnels.size() + " profile(s) to clipboard"
                    + (r.lockConfiguration ? " (locked)" : ""));
            toast("Lien copié (" + tunnels.size() + " profil(s))");
        } catch (Exception e) {
            toast("Export impossible : " + e.getMessage());
        }
    }

    /** Import entry: file (.epha) or clipboard (ephang://). */
    private void showImportChoice() {
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Importer des profils")
                .setItems(new String[]{"Fichier .epha", "Clipboard (ephang://...)"}, (d, which) -> {
                    if (which == 0) {
                        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType("*/*");
                        startActivityForResult(i, REQ_IMPORT_SHARE);
                    } else {
                        showClipboardImport();
                    }
                })
                .setNegativeButton("Annuler", null)
                .show();
    }

    private void showClipboardImport() {
        final android.widget.EditText input = new android.widget.EditText(requireContext());
        input.setHint("ephang://...");
        input.setTextColor(0xFFFFFFFF);
        input.setHintTextColor(0xFF616161);
        input.setMinLines(3);
        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle("Coller le lien")
                .setView(input)
                .setPositiveButton("Importer", (d, w) -> doImport(input.getText().toString()))
                .setNegativeButton("Annuler", null)
                .show();
    }

    private void doImport(String raw) {
        ProfileTransfer.ImportResult res;
        try {
            res = ProfileTransfer.parseImport(raw);
        } catch (Exception e) {
            toast("Import impossible : " + e.getMessage());
            return;
        }
        int added = 0;
        try {
            String cfgPath = cfgPath();
            for (JSONObject t : res.tunnels) {
                String r = VpnlibHelper.configAdd(cfgPath, t.toString());
                if (r != null && r.startsWith("{") && new JSONObject(r).has("error")) {
                    res.skipped++;
                    continue;
                }
                added++;
            }
        } catch (Exception e) {
            toast("Import impossible : " + e.getMessage());
            return;
        }
        TasVpnService.logEvent("imported " + added + " profile(s)"
                + (res.locked ? " (locked)" : "")
                + (res.skipped > 0 ? ", " + res.skipped + " skipped" : ""));
        toast("Importés : " + added + (res.locked ? " (verrouillés)" : "")
                + (res.skipped > 0 ? " - ignorés : " + res.skipped : ""));
        reload();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_IMPORT_SHARE) {
            if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null) {
                return;
            }
            try (java.io.InputStream in =
                         requireContext().getContentResolver().openInputStream(data.getData())) {
                byte[] content = readAllBytes(in);
                doImport(new String(content, java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception e) {
                toast("Import impossible : " + e.getMessage());
            }
            return;
        }
        if (requestCode == REQ_EXPORT_SHARE) {
            if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null
                    || pendingExport == null) {
                pendingExport = null;
                return;
            }
            try (java.io.OutputStream out = requireContext().getContentResolver()
                    .openOutputStream(data.getData())) {
                out.write(pendingExport.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                TasVpnService.logEvent("exported profiles to .epha file");
                toast("Fichier .epha enregistré");
            } catch (Exception e) {
                toast("Export impossible : " + e.getMessage());
            } finally {
                pendingExport = null;
            }
        }
    }

    private static byte[] readAllBytes(java.io.InputStream in) throws Exception {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = in.read(tmp)) > 0) {
            buf.write(tmp, 0, n);
        }
        return buf.toByteArray();
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
