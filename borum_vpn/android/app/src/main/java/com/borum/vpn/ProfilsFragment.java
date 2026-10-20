package com.borum.vpn;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.fragment.app.Fragment;

import org.json.JSONObject;

public class ProfilsFragment extends Fragment {
    private TextView info;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        LinearLayout ll = new LinearLayout(getContext());
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);
        info = new TextView(getContext());
        info.setTextSize(16);
        ll.addView(info);
        refresh();
        return ll;
    }

    private void refresh() {
        String uuid = ApiSession.deviceUuid(getContext());
        String code = ApiSession.code(getContext());
        PhoHelper.check(uuid, (resp, err) -> {
            if (getActivity() == null) return;
            getActivity().runOnUiThread(() -> {
                if (err != null || resp == null) {
                    info.setText("Erreur: " + (err != null ? err.getMessage() : "pas de reponse"));
                    return;
                }
                JSONObject acc = resp.optJSONObject("account");
                StringBuilder sb = new StringBuilder();
                sb.append("Telephone: ").append(ApiSession.phone(getContext())).append("\n");
                sb.append("Expire: ").append(ApiSession.expiresAt(getContext())).append("\n");
                if (acc != null) {
                    sb.append("Actif: ").append(acc.optInt("active", 0) == 1 ? "oui" : "non").append("\n");
                    sb.append("Restant: ").append(acc.optString("remaining", "-")).append("\n");
                    sb.append("Limite: ").append(acc.optString("limit", "-")).append("\n");
                }
                info.setText(sb.toString());
            });
        });
    }
}
