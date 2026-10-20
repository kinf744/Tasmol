package com.borum.vpn;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * PROFILS : aperçu "CONNEXIONS VPN" (design de l'ancien écran d'activation).
 * Une carte par profil API : pastille Actif, quota utilisé (% + barre),
 * Restant / Utilisé / Total, date d'expiration.
 */
public class ProfilsFragment extends Fragment {
    private static final int BG = Color.parseColor("#0A1220");
    private static final int CARD_BG = Color.parseColor("#111B2A");
    private static final int CARD_STROKE = Color.parseColor("#1E2A3D");
    private static final int TXT = Color.parseColor("#E6EDF5");
    private static final int TXT_DIM = Color.parseColor("#8CA0B8");
    private static final int GREEN = Color.parseColor("#34D399");
    private static final int CYAN = Color.parseColor("#38BDF8");
    private static final int RED = Color.parseColor("#F87171");

    private LinearLayout list;
    private TextView header;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle s) {
        ScrollView root = new ScrollView(getContext());
        root.setBackgroundColor(BG);
        root.setFillViewport(true);
        root.setVerticalScrollBarEnabled(false);

        LinearLayout page = new LinearLayout(getContext());
        page.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        page.setPadding(pad, pad, pad, dp(24));
        root.addView(page);

        // --- En-tête : "CONNEXIONS VPN" + bouton rafraîchir ---
        LinearLayout head = new LinearLayout(getContext());
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.setPadding(dp(8), dp(4), dp(8), dp(12));
        header = new TextView(getContext());
        header.setText("CONNEXIONS VPN");
        header.setTextColor(Color.parseColor("#B7C4D6"));
        header.setTextSize(17);
        header.setTypeface(null, Typeface.BOLD);
        header.setLetterSpacing(0.12f);
        head.addView(header, new LinearLayout.LayoutParams(0, -2, 1));
        TextView refresh = new TextView(getContext());
        refresh.setText("\u27F3");
        refresh.setTextColor(CYAN);
        refresh.setTextSize(24);
        refresh.setPadding(dp(12), dp(4), dp(4), dp(4));
        refresh.setOnClickListener(v -> refresh());
        head.addView(refresh);
        page.addView(head);

        list = new LinearLayout(getContext());
        list.setOrientation(LinearLayout.VERTICAL);
        page.addView(list);

        refresh();
        return root;
    }

    private void refresh() {
        if (getActivity() == null) return;
        render(ApiSession.accountCard(getContext()), ApiSession.configs(getContext()));
        String uuid = ApiSession.deviceUuid(getContext());
        PhoHelper.check(uuid, (resp, err) -> {
            if (getActivity() == null) return;
            JSONObject acc = (resp != null) ? resp.optJSONObject("account") : null;
            if (acc != null) ApiSession.saveAccountCard(getContext(), acc);
            getActivity().runOnUiThread(() -> render(acc, ApiSession.configs(getContext())));
        });
        PhoHelper.configs(uuid, ApiSession.code(getContext()), (r2, e2) -> {
            if (r2 != null && r2.optBoolean("success", false)) {
                ApiSession.saveConfigs(getContext(), r2.optJSONArray("configs"));
                if (getActivity() != null) {
                    getActivity().runOnUiThread(() ->
                            render(ApiSession.accountCard(getContext()),
                                    ApiSession.configs(getContext())));
                }
            }
        });
    }

    private void render(JSONObject acc, JSONArray configs) {
        if (list == null || getActivity() == null) return;
        list.removeAllViews();
        JSONArray labels = (configs != null) ? configs : new JSONArray();
        if (labels.length() == 0) {
            TextView empty = new TextView(getContext());
            empty.setText("Aucun profil. Ouvrez l'onglet ACCUEIL pour actualiser.");
            empty.setTextColor(TXT_DIM);
            empty.setTextSize(14);
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(0, dp(40), 0, 0);
            list.addView(empty);
            return;
        }
        for (int i = 0; i < labels.length(); i++) {
            JSONObject c = labels.optJSONObject(i);
            if (c != null) list.addView(profileCard(c.optString("label", "Profil"), acc));
        }
    }

    private View profileCard(String label, JSONObject acc) {
        CardView card = new CardView(getContext());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(6);
        lp.bottomMargin = dp(12);
        card.setLayoutParams(lp);
        card.setRadius(dp(22));
        card.setCardBackgroundColor(CARD_BG);
        card.setCardElevation(0);
        GradientDrawable st = new GradientDrawable();
        st.setColor(CARD_BG);
        st.setCornerRadius(dp(22));
        st.setStroke(dp(1), CARD_STROKE);
        card.setForeground(st);

        LinearLayout in = new LinearLayout(getContext());
        in.setOrientation(LinearLayout.VERTICAL);
        in.setPadding(dp(18), dp(16), dp(18), dp(16));
        card.addView(in);

        // --- Ligne 1 : titre + pastille Actif ---
        LinearLayout row1 = new LinearLayout(getContext());
        row1.setOrientation(LinearLayout.HORIZONTAL);
        row1.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(getContext());
        title.setText(label);
        title.setTextColor(TXT);
        title.setTextSize(19);
        title.setTypeface(null, Typeface.BOLD);
        title.setMaxLines(1);
        title.setEllipsize(TextUtils.TruncateAt.END);
        row1.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        boolean active = acc == null || acc.optInt("active", 1) == 1;
        row1.addView(pill("Actif", active ? GREEN : RED));
        in.addView(row1);

        if (acc == null) {
            TextView wait = new TextView(getContext());
            wait.setText("Chargement du compte…");
            wait.setTextColor(TXT_DIM);
            wait.setTextSize(14);
            wait.setPadding(0, dp(14), 0, dp(4));
            in.addView(wait);
            return card;
        }

        boolean unlimited = acc.optBoolean("unlimited", false);
        long limit = acc.optLong("data_limit_bytes", 0);
        long remaining = acc.optLong("data_remaining_bytes", 0);
        long used = Math.max(0, limit - remaining);
        int pct = (limit > 0 && !unlimited) ? (int) Math.min(100, used * 100 / limit) : 0;
        int barColor = (pct >= 100) ? RED : CYAN;

        // --- Ligne 2 : "Quota utilisé" + % ---
        LinearLayout row2 = new LinearLayout(getContext());
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setPadding(0, dp(16), 0, dp(8));
        TextView qLabel = new TextView(getContext());
        qLabel.setText("Quota utilisé");
        qLabel.setTextColor(TXT_DIM);
        qLabel.setTextSize(15);
        row2.addView(qLabel, new LinearLayout.LayoutParams(0, -2, 1));
        TextView qVal = new TextView(getContext());
        qVal.setText(unlimited ? "∞" : pct + " %");
        qVal.setTextColor(barColor);
        qVal.setTextSize(16);
        qVal.setTypeface(null, Typeface.BOLD);
        row2.addView(qVal);
        in.addView(row2);

        // --- Barre de progression ---
        if (!unlimited) {
            ProgressBar bar = new ProgressBar(getContext(), null,
                    android.R.attr.progressBarStyleHorizontal);
            bar.setMax(100);
            bar.setProgress(pct);
            bar.setProgressTintList(ColorStateList.valueOf(barColor));
            bar.setProgressBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1A2536")));
            bar.setMinimumHeight(dp(10));
            LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1, dp(10));
            bp.setMargins(0, 0, 0, dp(14));
            in.addView(bar, bp);
        }

        // --- Lignes données : Restant / Utilisé / Total ---
        in.addView(dataRow("Restant", unlimited ? "Illimité" : fmtData(remaining), GREEN));
        in.addView(dataRow("Utilisé", unlimited ? "—" : fmtData(used), TXT));
        in.addView(dataRow("Total", unlimited ? "Illimité" : fmtData(limit), TXT));

        // --- Pied : expiration ---
        String exp = acc.optString("expires_at", "");
        TextView foot = new TextView(getContext());
        foot.setText(exp.isEmpty() ? "Sans expiration" : "Expire le " + fmtDate(exp));
        foot.setTextColor(TXT_DIM);
        foot.setTextSize(14);
        foot.setPadding(0, dp(12), 0, 0);
        in.addView(foot);
        return card;
    }

    private TextView dataRow(String label, String value, int valueColor) {
        LinearLayout row = new LinearLayout(getContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(9), 0, dp(9));
        TextView l = new TextView(getContext());
        l.setText(label);
        l.setTextColor(TXT_DIM);
        l.setTextSize(15);
        row.addView(l, new LinearLayout.LayoutParams(0, -2, 1));
        TextView v = new TextView(getContext());
        v.setText(value);
        v.setTextColor(valueColor);
        v.setTextSize(16);
        v.setTypeface(null, Typeface.BOLD);
        row.addView(v);
        LinearLayout w = new LinearLayout(getContext());
        w.setOrientation(LinearLayout.VERTICAL);
        w.addView(row);
        View sep = new View(getContext());
        sep.setBackgroundColor(Color.parseColor("#182338"));
        w.addView(sep, new LinearLayout.LayoutParams(-1, dp(1)));
        return w;
    }

    private TextView pill(String text, int color) {
        TextView tv = new TextView(getContext());
        tv.setText("\u25CF " + text);
        tv.setTextColor(color);
        tv.setTextSize(14);
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(dp(14), dp(5), dp(14), dp(5));
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(40));
        bg.setColor(Color.argb(40, Color.red(color), Color.green(color), Color.blue(color)));
        bg.setStroke(dp(1), color);
        tv.setBackground(bg);
        return tv;
    }

    private static String fmtData(long bytes) {
        if (bytes <= 0) return "0 B";
        double gb = bytes / 1073741824.0;
        if (gb >= 1) {
            String s = String.format(Locale.US, "%.1f", gb);
            if (s.endsWith(".0")) s = s.substring(0, s.length() - 2);
            return s + " GB";
        }
        double mb = bytes / 1048576.0;
        if (mb >= 1) {
            String s = String.format(Locale.US, "%.1f", mb);
            if (s.endsWith(".0")) s = s.substring(0, s.length() - 2);
            return s + " MB";
        }
        return bytes + " B";
    }

    private static String fmtDate(String iso) {
        for (String pattern : new String[]{"yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"}) {
            try {
                Date d = new SimpleDateFormat(pattern, Locale.US).parse(iso);
                if (d != null) {
                    return new SimpleDateFormat("d MMM. yyyy", Locale.FRENCH).format(d);
                }
            } catch (Exception ignored) {
            }
        }
        return iso;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
