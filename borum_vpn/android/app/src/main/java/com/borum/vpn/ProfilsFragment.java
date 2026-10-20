package com.borum.vpn;

import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import org.json.JSONObject;

public class ProfilsFragment extends Fragment {
    private TextView tPhone, tExpires, tActive, tRemaining, tLimit;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        LinearLayout root = new LinearLayout(getContext());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(24, 24, 24, 24);
        root.setBackgroundColor(Color.parseColor("#F2F2F2"));

        CardView card = new CardView(getContext());
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cp.setMargins(16, 16, 16, 16);
        card.setLayoutParams(cp);
        card.setRadius(24);
        card.setCardElevation(8);
        card.setUseCompatPadding(true);

        LinearLayout inner = new LinearLayout(getContext());
        inner.setOrientation(LinearLayout.VERTICAL);
        inner.setPadding(32, 32, 32, 32);

        TextView title = new TextView(getContext());
        title.setText("PROFIL");
        title.setTextSize(20);
        title.setTypeface(null, Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        inner.addView(title);

        tPhone = makeRow("Telephone", "-");
        tExpires = makeRow("Expiration", "-");
        tActive = makeRow("Statut", "-");
        tRemaining = makeRow("Restant", "-");
        tLimit = makeRow("Limite", "-");
        inner.addView(tPhone);
        inner.addView(tExpires);
        inner.addView(tActive);
        inner.addView(tRemaining);
        inner.addView(tLimit);

        card.addView(inner);
        root.addView(card);
        refresh();
        return root;
    }

    private TextView makeRow(String label, String value) {
        TextView tv = new TextView(getContext());
        tv.setText(label + ": " + value);
        tv.setTextSize(16);
        tv.setPadding(0, 12, 0, 12);
        return tv;
    }

    private void refresh() {
        String uuid = ApiSession.deviceUuid(getContext());
        PhoHelper.check(uuid, (resp, err) -> {
            if (getActivity() == null) return;
            getActivity().runOnUiThread(() -> {
                if (err != null || resp == null) {
                    tPhone.setText("Erreur: " + (err != null ? err.getMessage() : "pas de reponse"));
                    return;
                }
                JSONObject acc = resp.optJSONObject("account");
                tPhone.setText("Telephone: " + ApiSession.phone(getContext()));
                tExpires.setText("Expiration: " + ApiSession.expiresAt(getContext()));
                if (acc != null) {
                    tActive.setText("Statut: " + (acc.optInt("active", 0) == 1 ? "Actif" : "Inactif"));
                    tRemaining.setText("Restant: " + acc.optString("remaining", "-"));
                    tLimit.setText("Limite: " + acc.optString("limit", "-"));
                }
            });
        });
    }
}
