package com.ephang.vpn;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
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

/** Settings menu (Picko-style, adapted): network, reconnect, UI, device. */
public class SettingsFragment extends Fragment {
    private static final int REQ_IMPORT = 2001;
    private static final int REQ_EXPORT = 2002;

    private TextView delayText;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_settings, container, false);
        VPNApplication app = VPNApplication.getInstance();

        // Device identity (no permission needed).
        String androidId = "";
        try {
            androidId = Settings.Secure.getString(
                    requireContext().getContentResolver(), Settings.Secure.ANDROID_ID);
        } catch (Exception ignored) {
        }
        if (androidId == null) {
            androidId = "";
        }
        final String aid = androidId;
        ((TextView) v.findViewById(R.id.settings_android_id))
                .setText(aid.isEmpty() ? "—" : aid);
        ((TextView) v.findViewById(R.id.settings_root)).setText(
                "Intégrité : " + (isRooted() ? "root détecté" : "aucun root détecté"));
        v.findViewById(R.id.settings_copy_id).setOnClickListener(view -> {
            if (aid.isEmpty()) {
                toast("ID indisponible");
                return;
            }
            try {
                ClipboardManager cm = (ClipboardManager) requireContext()
                        .getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("Android ID", aid));
                toast("ID copié");
            } catch (Exception e) {
                toast("Copie impossible");
            }
        });

        bindSwitch(v, R.id.settings_dns, app.isDnsProtectionEnabled(),
                app::setDnsProtectionEnabled);
        bindSwitch(v, R.id.settings_stop_loss, app.isStopOnNetworkLossEnabled(),
                app::setStopOnNetworkLossEnabled);
        bindSwitch(v, R.id.settings_reconnect, app.isAutoReconnectEnabled(),
                app::setAutoReconnectEnabled);
        bindSwitch(v, R.id.settings_boot, app.isLaunchOnBootEnabled(),
                app::setLaunchOnBootEnabled);
        bindSwitch(v, R.id.settings_verbose, app.isVerboseDiagnosticsEnabled(),
                app::setVerboseDiagnosticsEnabled);
        bindSwitch(v, R.id.settings_confirm, app.isConfirmDisconnectEnabled(),
                app::setConfirmDisconnectEnabled);

        Switch dark = v.findViewById(R.id.settings_dark);
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

        delayText = v.findViewById(R.id.settings_delay);
        delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
        v.findViewById(R.id.settings_delay_minus).setOnClickListener(view -> {
            app.setReconnectDelaySeconds(app.getReconnectDelaySeconds() - 1);
            delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
        });
        v.findViewById(R.id.settings_delay_plus).setOnClickListener(view -> {
            app.setReconnectDelaySeconds(app.getReconnectDelaySeconds() + 1);
            delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
        });

        EditText port = v.findViewById(R.id.settings_port);
        port.setText(String.valueOf(app.getManagePort()));
        v.findViewById(R.id.settings_save_port).setOnClickListener(view -> {
            try {
                int p = Integer.parseInt(port.getText().toString().trim());
                if (p < 0 || p > 65535) {
                    throw new NumberFormatException();
                }
                app.setManagePort(p);
                toast("Enregistré - appliqué à la prochaine connexion");
            } catch (NumberFormatException e) {
                toast("Port invalide");
            }
        });

        v.findViewById(R.id.settings_import).setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_IMPORT);
        });
        v.findViewById(R.id.settings_export).setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, "ephang-vpn-config.yaml");
            startActivityForResult(i, REQ_EXPORT);
        });

        v.findViewById(R.id.settings_reset).setOnClickListener(view ->
                new AlertDialog.Builder(requireContext())
                        .setTitle("Réinitialiser les réglages ?")
                        .setMessage("Les profils et serveurs restent intacts.")
                        .setPositiveButton("Réinitialiser", (d, w) -> {
                            app.resetSettings();
                            toast("Réglages réinitialisés");
                            refreshSwitches(v);
                        })
                        .setNegativeButton("Annuler", null)
                        .show());

        v.findViewById(R.id.settings_reset_config).setOnClickListener(view ->
                new AlertDialog.Builder(requireContext())
                        .setTitle("Supprimer tous les serveurs ?")
                        .setPositiveButton("Supprimer", (d, w) -> {
                            try {
                                File cfg = BinaryManager.configPath(requireContext());
                                if (cfg.exists() && !cfg.delete()) {
                                    toast("Échec");
                                    return;
                                }
                                app.setActiveTunnelId("");
                                app.setSelectedIds(null);
                                toast("Serveurs supprimés");
                            } catch (Exception e) {
                                toast("Échec : " + e.getMessage());
                            }
                        })
                        .setNegativeButton("Annuler", null)
                        .show());

        TextView version = v.findViewById(R.id.settings_version);
        String gov = "";
        try {
            gov = VpnlibHelper.version();
        } catch (Exception ignored) {
        }
        version.setText("Ephang VPN 1.0.0  •  core " + gov);
        return v;
    }

    private interface BoolSetter {
        void set(boolean v);
    }

    private void bindSwitch(View root, int id, boolean initial, BoolSetter setter) {
        Switch sw = root.findViewById(id);
        sw.setChecked(initial);
        sw.setOnCheckedChangeListener((btn, checked) -> setter.set(checked));
    }

    private void refreshSwitches(View v) {
        VPNApplication app = VPNApplication.getInstance();
        ((Switch) v.findViewById(R.id.settings_dns)).setChecked(app.isDnsProtectionEnabled());
        ((Switch) v.findViewById(R.id.settings_stop_loss)).setChecked(app.isStopOnNetworkLossEnabled());
        ((Switch) v.findViewById(R.id.settings_reconnect)).setChecked(app.isAutoReconnectEnabled());
        ((Switch) v.findViewById(R.id.settings_boot)).setChecked(app.isLaunchOnBootEnabled());
        ((Switch) v.findViewById(R.id.settings_verbose)).setChecked(app.isVerboseDiagnosticsEnabled());
        ((Switch) v.findViewById(R.id.settings_confirm)).setChecked(app.isConfirmDisconnectEnabled());
        delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
    }

    private static boolean isRooted() {
        for (String p : new String[]{"/system/xbin/su", "/system/bin/su", "/sbin/su",
                "/system/sd/xbin/su", "/data/local/xbin/su"}) {
            try {
                if (new File(p).exists()) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
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
                        throw new IllegalStateException("fichier vide");
                    }
                    Files.write(cfg.toPath(), content);
                    TasVpnService.logEvent("config imported (" + content.length + " bytes)");
                    toast("Config importée - reconnectez pour appliquer");
                }
            } else if (requestCode == REQ_EXPORT) {
                if (!cfg.exists()) {
                    toast("Rien à exporter");
                    return;
                }
                try (OutputStream out = requireContext().getContentResolver().openOutputStream(uri)) {
                    Files.copy(cfg.toPath(), out);
                    toast("Config exportée");
                }
            }
        } catch (Exception e) {
            toast("Échec : " + e.getMessage());
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
