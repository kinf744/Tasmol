package com.ephang.vpn;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.fragment.app.Fragment;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/** MORE tab: config import/export + settings + about. Fully offline. */
public class MoreFragment extends Fragment {
    private static final int REQ_IMPORT = 2001;
    private static final int REQ_EXPORT = 2002;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_more, container, false);
        VPNApplication app = VPNApplication.getInstance();

        v.findViewById(R.id.more_import).setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_IMPORT);
        });
        v.findViewById(R.id.more_export).setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, "ephang-vpn-config.yaml");
            startActivityForResult(i, REQ_EXPORT);
        });

        Switch dark = v.findViewById(R.id.more_dark_mode);
        dark.setChecked(app.isDarkModeEnabled());
        dark.setOnCheckedChangeListener((btn, checked) -> {
            app.setDarkModeEnabled(checked);
            AppCompatDelegate.setDefaultNightMode(checked
                    ? AppCompatDelegate.MODE_NIGHT_YES
                    : AppCompatDelegate.MODE_NIGHT_NO);
            if (getActivity() != null) {
                getActivity().recreate();
            }
        });

        Switch boot = v.findViewById(R.id.more_autostart);
        boot.setChecked(app.isAutoStartEnabled());
        boot.setOnCheckedChangeListener((btn, checked) -> app.setAutoStartEnabled(checked));

        EditText port = v.findViewById(R.id.more_port);
        port.setText(String.valueOf(app.getManagePort()));
        Button savePort = v.findViewById(R.id.more_save_port);
        savePort.setOnClickListener(view -> {
            try {
                int p = Integer.parseInt(port.getText().toString().trim());
                if (p < 0 || p > 65535) {
                    throw new NumberFormatException();
                }
                app.setManagePort(p);
                toast("Saved - applies on next connect");
            } catch (NumberFormatException e) {
                toast("Invalid port");
            }
        });

        TextView active = v.findViewById(R.id.more_active);
        String activeId = app.getActiveTunnelId();
        active.setText("Active server: " + (activeId == null || activeId.isEmpty() ? "none" : activeId));

        TextView rrStatus = new TextView(getContext());
        rrStatus.setTextColor(0xFF9E9E9E);
        rrStatus.setTypeface(android.graphics.Typeface.MONOSPACE);
        ((ViewGroup) active.getParent()).addView(rrStatus,
                new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        Runnable refreshRR = () -> {
            String csv = app.getRoundRobinIds();
            int n = csv.isEmpty() ? 0 : csv.split(",").length;
            rrStatus.setText(n >= 2 ? "Round-robin: " + n + " profiles" : "Round-robin: off (single mode)");
        };
        refreshRR.run();
        Button clearRR = new Button(getContext());
        clearRR.setText("Clear round-robin");
        clearRR.setOnClickListener(view -> {
            app.setRoundRobinIds("");
            refreshRR.run();
            toast("Round-robin cleared");
        });
        ((ViewGroup) active.getParent()).addView(clearRR);

        TextView version = v.findViewById(R.id.more_version);
        String gov = "";
        try {
            gov = VpnlibHelper.version();
        } catch (Exception ignored) {
        }
        version.setText("Ephang VPN 1.0.0  •  core " + gov);

        v.findViewById(R.id.more_reset).setOnClickListener(view ->
                new AlertDialog.Builder(requireContext())
                        .setTitle("Reset configuration?")
                        .setMessage("All servers will be deleted.")
                        .setPositiveButton("Reset", (d, w) -> {
                            try {
                                File cfg = BinaryManager.configPath(requireContext());
                                if (cfg.exists() && !cfg.delete()) {
                                    toast("Reset failed");
                                    return;
                                }
                                app.setActiveTunnelId("");
                                toast("Configuration reset");
                            } catch (Exception e) {
                                toast("Reset failed: " + e.getMessage());
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show());
        return v;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        try {
            File cfg = BinaryManager.configPath(requireContext());
            if (requestCode == REQ_IMPORT) {
                try (InputStream in = requireContext().getContentResolver().openInputStream(uri)) {
                    byte[] content = readAll(in);
                    if (content.length == 0) {
                        throw new IllegalStateException("empty file");
                    }
                    Files.write(cfg.toPath(), content);
                    TasVpnService.logEvent("config imported (" + content.length + " bytes)");
                    toast("Config imported - restart VPN to apply");
                }
            } else if (requestCode == REQ_EXPORT) {
                if (!cfg.exists()) {
                    toast("Nothing to export yet");
                    return;
                }
                try (OutputStream out = requireContext().getContentResolver().openOutputStream(uri)) {
                    Files.copy(cfg.toPath(), out);
                    toast("Config exported");
                }
            }
        } catch (Exception e) {
            toast("Failed: " + e.getMessage());
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = in.read(tmp)) > 0) {
            buf.write(tmp, 0, n);
        }
        return buf.toByteArray();
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
