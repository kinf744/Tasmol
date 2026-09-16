package com.ephang.vpn;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/** MORE tab: two menus - Settings and Hotspot sharing. */
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
        return v;
    }
}
