package com.borum.vpn;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/** MORE tab: Settings, Hotspot sharing, Telegram support links. */
public class MoreFragment extends Fragment {
    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_more, container, false);
        v.findViewById(R.id.more_menu_settings).setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).showFragment(new SettingsFragment(), "settings");
            }
        });
        v.findViewById(R.id.more_menu_hotspot).setOnClickListener(view -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).showFragment(new HotspotFragment(), "hotspot");
            }
        });
        v.findViewById(R.id.more_menu_tg_channel).setOnClickListener(view ->
                openTelegram("https://t.me/lkgcddtoogv"));
        v.findViewById(R.id.more_menu_tg_inbox).setOnClickListener(view ->
                openTelegram("https://t.me/kighmu"));
        return v;
    }

    private void openTelegram(String url) {
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(intent);
        } catch (Exception e) {
            intent.setData(Uri.parse(url));
            try {
                startActivity(intent);
            } catch (Exception ignored) {
            }
        }
    }
}
