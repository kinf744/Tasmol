package com.borum.vpn;

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

public class SettingsFragment extends Fragment {

    private TextView delayText;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v;
        try {
            v = inflater.inflate(R.layout.fragment_settings, container, false);
        } catch (Exception e) {

            TextView fallback = new TextView(container.getContext());
            fallback.setText("Settings error: " + e.getMessage());
            fallback.setTextColor(0xFFFFFFFF);
            return fallback;
        }
        try {
            initSettingsView(v);
        } catch (Exception | Error e) {

            TasVpnService.logEvent("error", "settings", "init failed: " + e);
            TextView fallback = new TextView(container.getContext());
            fallback.setText("Settings unavailable: " + e.getMessage());
            fallback.setTextColor(0xFFFFFFFF);
            return fallback;
        }
        return v;
    }

    private void initSettingsView(View v) {
        VPNApplication app = VPNApplication.getInstance();
        View portInput = v.findViewById(R.id.settings_port);
        if (portInput != null) {

        }

        String integrity = getString(R.string.settings_integrity,
                ProfileTransfer.isRooted()
                        ? getString(R.string.settings_root_detected)
                        : getString(R.string.settings_no_root));
        TextView rootView = v.findViewById(R.id.settings_root);
        if (rootView != null) {
            rootView.setText(integrity);
        }

        String theme = UiPrefs.getTheme(requireContext());
        bindPill(v, R.id.settings_theme_system, "system".equals(theme));
        bindPill(v, R.id.settings_theme_light, "light".equals(theme));
        bindPill(v, R.id.settings_theme_dark, "dark".equals(theme));
        android.view.View.OnClickListener themePick = view -> {
            String mode = view.getId() == R.id.settings_theme_light ? "light"
                    : view.getId() == R.id.settings_theme_dark ? "dark" : "system";
            UiPrefs.setTheme(requireContext(), mode);
            if (getActivity() != null) {
                getActivity().recreate();
            }
        };
        View ts = v.findViewById(R.id.settings_theme_system);
        View tl = v.findViewById(R.id.settings_theme_light);
        View td = v.findViewById(R.id.settings_theme_dark);
        if (ts != null) ts.setOnClickListener(themePick);
        if (tl != null) tl.setOnClickListener(themePick);
        if (td != null) td.setOnClickListener(themePick);

        String lang = UiPrefs.getLang(requireContext());
        bindPill(v, R.id.settings_lang_system, "system".equals(lang));
        bindPill(v, R.id.settings_lang_fr, "fr".equals(lang));
        bindPill(v, R.id.settings_lang_en, "en".equals(lang));
        android.view.View.OnClickListener langPick = view -> {
            String mode = view.getId() == R.id.settings_lang_fr ? "fr"
                    : view.getId() == R.id.settings_lang_en ? "en" : "system";
            UiPrefs.setLang(requireContext(), mode);
            if (getActivity() != null) {
                getActivity().recreate();
            }
        };
        View ls = v.findViewById(R.id.settings_lang_system);
        View lf = v.findViewById(R.id.settings_lang_fr);
        View le = v.findViewById(R.id.settings_lang_en);
        if (ls != null) ls.setOnClickListener(langPick);
        if (lf != null) lf.setOnClickListener(langPick);
        if (le != null) le.setOnClickListener(langPick);

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

        delayText = v.findViewById(R.id.settings_delay);
        if (delayText != null) {
            delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
        }
        View delayMinus = v.findViewById(R.id.settings_delay_minus);
        View delayPlus = v.findViewById(R.id.settings_delay_plus);
        if (delayMinus != null && delayPlus != null && delayText != null) {
            delayMinus.setOnClickListener(view -> {
                app.setReconnectDelaySeconds(app.getReconnectDelaySeconds() - 1);
                delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
            });
            delayPlus.setOnClickListener(view -> {
                app.setReconnectDelaySeconds(app.getReconnectDelaySeconds() + 1);
                delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
            });
        }

        final TextView mtuText = v.findViewById(R.id.settings_mtu);
        if (mtuText != null) {
            mtuText.setText(String.valueOf(app.getCustomMtu()));
        }
        View mtuMinus = v.findViewById(R.id.settings_mtu_minus);
        View mtuPlus = v.findViewById(R.id.settings_mtu_plus);
        if (mtuMinus != null && mtuPlus != null && mtuText != null) {
            mtuMinus.setOnClickListener(view -> {
                int m = app.getCustomMtu() - 100;
                app.setCustomMtu(m);
                mtuText.setText(String.valueOf(app.getCustomMtu()));
                toast("MTU " + app.getCustomMtu() + " - prochaine connexion");
            });
            mtuPlus.setOnClickListener(view -> {
                int m = app.getCustomMtu() + 100;
                app.setCustomMtu(m);
                mtuText.setText(String.valueOf(app.getCustomMtu()));
                toast("MTU " + app.getCustomMtu() + " - prochaine connexion");
            });
        }

        final         EditText dns1 = v.findViewById(R.id.settings_dns_primary);
        EditText dns2 = v.findViewById(R.id.settings_dns_secondary);
        if (dns1 != null && dns2 != null) {
            dns1.setText(app.getCustomDnsPrimary());
            dns2.setText(app.getCustomDnsSecondary());
            android.view.View.OnFocusChangeListener saveDns = (view, hasFocus) -> {
                if (!hasFocus) {
                    saveDnsFields(dns1, dns2);
                }
            };
            dns1.setOnFocusChangeListener(saveDns);
            dns2.setOnFocusChangeListener(saveDns);
        }

        EditText port = v.findViewById(R.id.settings_port);
        if (port != null) {
            port.setText(String.valueOf(app.getManagePort()));
        }
        View savePort = v.findViewById(R.id.settings_save_port);
        if (savePort != null && port != null) {
            savePort.setOnClickListener(view -> {
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
        }

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

        }

        if (gov == null) {
            gov = "";
        }
        if (version != null) {
            version.setText("borum VPN 1.0.0" + (gov.isEmpty() ? "" : "  •  core " + gov));
        }

        final EditText orangeHost = v.findViewById(R.id.settings_orange_host);
        final View orangeSave = v.findViewById(R.id.settings_orange_save);
        if (orangeHost != null) {
            orangeHost.setText(app.getOrangeFastHost());
        }
        if (orangeSave != null && orangeHost != null) {
            orangeSave.setOnClickListener(view -> {
                String h = orangeHost.getText().toString().trim();
                if (h.isEmpty()) {
                    toast("Host invalide");
                    return;
                }
                app.setOrangeFastHost(h);

                app.resetConfigFile(requireContext());
                toast("Orange Fast host enregistré - recréation config");
            });
        }

        final EditText mtnHost = v.findViewById(R.id.settings_mtn_host);
        final View mtnSave = v.findViewById(R.id.settings_mtn_save);
        if (mtnHost != null) {
            mtnHost.setText(app.getMtnUnlimitedHost());
        }
        if (mtnSave != null && mtnHost != null) {
            mtnSave.setOnClickListener(view -> {
                String h = mtnHost.getText().toString().trim();
                if (h.isEmpty()) {
                    toast("Host invalide");
                    return;
                }
                app.setMtnUnlimitedHost(h);

                app.resetConfigFile(requireContext());
                toast("MTN Illimité host enregistré - recréation config");
            });
        }
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
        if (sw == null) {
            return;
        }
        sw.setChecked(initial);
        sw.setOnCheckedChangeListener((btn, checked) -> setter.set(checked));
    }

    private void refreshSwitches(View v) {
        VPNApplication app = VPNApplication.getInstance();
        setSwitchChecked(v, R.id.settings_dns, app.isDnsProtectionEnabled());
        setSwitchChecked(v, R.id.settings_stop_loss, app.isStopOnNetworkLossEnabled());
        setSwitchChecked(v, R.id.settings_reconnect, app.isAutoReconnectEnabled());
        setSwitchChecked(v, R.id.settings_boot, app.isLaunchOnBootEnabled());
        setSwitchChecked(v, R.id.settings_verbose, app.isVerboseDiagnosticsEnabled());
        setSwitchChecked(v, R.id.settings_confirm, app.isConfirmDisconnectEnabled());
        setSwitchChecked(v, R.id.settings_wakelock, app.isWakeLockEnabled());
        setSwitchChecked(v, R.id.settings_boost, app.isSlowDnsBoostEnabled());
        setSwitchChecked(v, R.id.settings_tcpnodelay, app.isTcpNoDelayEnabled());
        if (delayText != null) {
            delayText.setText(String.valueOf(app.getReconnectDelaySeconds()));
        }
        TextView mtv = v.findViewById(R.id.settings_mtu);
        if (mtv != null) {
            mtv.setText(String.valueOf(app.getCustomMtu()));
        }
        EditText dns1v = v.findViewById(R.id.settings_dns_primary);
        if (dns1v != null) {
            dns1v.setText(app.getCustomDnsPrimary());
        }
        EditText dns2v = v.findViewById(R.id.settings_dns_secondary);
        if (dns2v != null) {
            dns2v.setText(app.getCustomDnsSecondary());
        }
    }

    private void setSwitchChecked(View root, int id, boolean checked) {
        View sw = root.findViewById(id);
        if (sw instanceof Switch) {
            ((Switch) sw).setChecked(checked);
        }
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }

    private void bindPill(View v, int id, boolean selected) {
        TextView t = v.findViewById(id);
        if (t == null) {
            return;
        }
        int color = selected ? R.color.npv_green : R.color.npv_grey;
        t.setTextColor(androidx.core.content.ContextCompat.getColor(requireContext(), color));
        t.setTypeface(null, selected ? android.graphics.Typeface.BOLD
                : android.graphics.Typeface.NORMAL);
    }
}
