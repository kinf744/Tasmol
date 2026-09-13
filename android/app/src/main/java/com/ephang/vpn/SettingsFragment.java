package com.ephang.vpn;

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

/** Settings tab: theme, autostart, port, active server, reset, about. */
public class SettingsFragment extends Fragment {
    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_settings, container, false);
        VPNApplication app = VPNApplication.getInstance();

        Switch dark = v.findViewById(R.id.settings_dark_mode);
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

        Switch boot = v.findViewById(R.id.settings_autostart);
        boot.setChecked(app.isAutoStartEnabled());
        boot.setOnCheckedChangeListener((btn, checked) -> app.setAutoStartEnabled(checked));

        EditText port = v.findViewById(R.id.settings_port);
        port.setText(String.valueOf(app.getManagePort()));
        Button savePort = v.findViewById(R.id.settings_save_port);
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

        TextView active = v.findViewById(R.id.settings_active);
        String activeId = app.getActiveTunnelId();
        active.setText("Active server: " + (activeId == null || activeId.isEmpty() ? "none" : activeId));

        TextView version = v.findViewById(R.id.settings_version);
        String gov = "";
        try {
            gov = VpnlibHelper.version();
        } catch (Exception ignored) {
        }
        version.setText("Ephang VPN 1.0.0  •  core " + gov);

        v.findViewById(R.id.settings_reset).setOnClickListener(view ->
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

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
