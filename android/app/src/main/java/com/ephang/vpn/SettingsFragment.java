package com.ephang.vpn;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
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


/** Settings menu (Picko-style, adapted): network, reconnect, UI, device. */
public class SettingsFragment extends Fragment {

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
                "Intégrité : " + (ProfileTransfer.isRooted() ? "root détecté" : "aucun root détecté"));
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
        bindSwitch(v, R.id.settings_wakelock, app.isWakeLockEnabled(),
                app::setWakeLockEnabled);
        bindSwitch(v, R.id.settings_boost, app.isSlowDnsBoostEnabled(),
                app::setSlowDnsBoostEnabled);
        bindSwitch(v, R.id.settings_tcpnodelay, app.isTcpNoDelayEnabled(),
                app::setTcpNoDelayEnabled);

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

        final TextView mtuText = v.findViewById(R.id.settings_mtu);
        mtuText.setText(String.valueOf(app.getCustomMtu()));
        v.findViewById(R.id.settings_mtu_minus).setOnClickListener(view -> {
            int m = app.getCustomMtu() - 100;
            app.setCustomMtu(m);
            mtuText.setText(String.valueOf(app.getCustomMtu()));
            toast("MTU " + app.getCustomMtu() + " - prochaine connexion");
        });
        v.findViewById(R.id.settings_mtu_plus).setOnClickListener(view -> {
            int m = app.getCustomMtu() + 100;
            app.setCustomMtu(m);
            mtuText.setText(String.valueOf(app.getCustomMtu()));
            toast("MTU " + app.getCustomMtu() + " - prochaine connexion");
        });

        final EditText dns1 = v.findViewById(R.id.settings_dns_primary);
        final EditText dns2 = v.findViewById(R.id.settings_dns_secondary);
        dns1.setText(app.getCustomDnsPrimary());
        dns2.setText(app.getCustomDnsSecondary());
        android.view.View.OnFocusChangeListener saveDns = (view, hasFocus) -> {
            if (!hasFocus) {
                saveDnsFields(dns1, dns2);
            }
        };
        dns1.setOnFocusChangeListener(saveDns);
        dns2.setOnFocusChangeListener(saveDns);

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

        TextView version = v.findViewById(R.id.settings_version);
        String gov = "";
        try {
            gov = VpnlibHelper.version();
        } catch (Throwable ignored) {
            // Native Go call can throw Error (not Exception) when the Go
            // runtime isn't loaded yet: never crash the fragment for it.
        }
        // VpnlibHelper.version() can crash at native level (gomobile call
        // failure → JNI throw caught here) or at parse level. Shield both.
        if (gov == null) {
            gov = "";
        }
        version.setText("Ephang VPN 1.0.0" + (gov.isEmpty() ? "" : "  •  core " + gov));
        return v;
    }

    private void saveDnsFields(EditText dns1, EditText dns2) {
        VPNApplication app = VPNApplication.getInstance();
        String p = dns1.getText().toString().trim();
        String s = dns2.getText().toString().trim();
        if (!p.isEmpty() && !isIpLiteral(p)) {
            toast("DNS primaire invalide");
            dns1.setText(app.getCustomDnsPrimary());
            return;
        }
        if (!s.isEmpty() && !isIpLiteral(s)) {
            toast("DNS secondaire invalide");
            dns2.setText(app.getCustomDnsSecondary());
            return;
        }
        if (!p.isEmpty()) {
            app.setCustomDnsPrimary(p);
        }
        if (!s.isEmpty()) {
            app.setCustomDnsSecondary(s);
        }
        toast("DNS enregistré - prochaine connexion");
    }

    private static boolean isIpLiteral(String ip) {
        if (ip == null) {
            return false;
        }
        String[] parts = ip.split("\\.", -1);
        if (parts.length == 4) {
            try {
                for (String q : parts) {
                    int n = Integer.parseInt(q);
                    if (n < 0 || n > 255) {
                        return false;
                    }
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return ip.contains(":") && ip.length() >= 3;
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
        ((Switch) v.findViewById(R.id.settings_wakelock)).setChecked(app.isWakeLockEnabled());
        ((Switch) v.findViewById(R.id.settings_boost)).setChecked(app.isSlowDnsBoostEnabled());
        ((Switch) v.findViewById(R.id.settings_tcpnodelay)).setChecked(app.isTcpNoDelayEnabled());
        delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
        ((TextView) v.findViewById(R.id.settings_mtu)).setText(String.valueOf(app.getCustomMtu()));
        ((EditText) v.findViewById(R.id.settings_dns_primary)).setText(app.getCustomDnsPrimary());
        ((EditText) v.findViewById(R.id.settings_dns_secondary)).setText(app.getCustomDnsSecondary());
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
