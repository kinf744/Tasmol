package com.borum.vpn;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class LogsFragment extends Fragment implements VpnEventBus.Observer {
    private static final int MAX_DISPLAYED = 260;

    private VpnEventBus bus;
    private String filter = "tout";
    private boolean frozen = false;
    private int lastDisplayedSize = -1;

    private ScrollView scroller;
    private LinearLayout timeline;
    private TextView emptyView;
    private LinearLayout chipsContainer;
    private TextView freezeLabel;
    private Button freezeButton;
    private Button clearButton;
    private ImageButton shareButton;
    private ImageButton backButton;

    private boolean attached = false;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_logs, container, false);

        bus = VpnEventBus.get();

        backButton = v.findViewById(R.id.logs_back);
        shareButton = v.findViewById(R.id.logs_share);
        scroller = v.findViewById(R.id.logs_scroll);
        timeline = v.findViewById(R.id.logs_timeline);
        emptyView = v.findViewById(R.id.logs_empty);
        chipsContainer = v.findViewById(R.id.logs_chips);
        freezeLabel = v.findViewById(R.id.logs_freeze_label);
        freezeButton = v.findViewById(R.id.logs_freeze);
        clearButton = v.findViewById(R.id.logs_clear);

        // Seed depuis l'historique existant si le bus est encore vide.
        if (bus.total() == 0) {
            Context ctx = requireContext();
            String raw = BinaryManager.readLogTail(200_000);
            if (!TextUtils.isEmpty(raw)) {
                List<String> lines = new ArrayList<>();
                for (String line : raw.split("\n")) {
                    lines.add(line);
                }
                bus.seedFromLines(lines);
            }
        }

        backButton.setOnClickListener(iv -> {
            if (getActivity() instanceof MainActivity) {
                ((MainActivity) getActivity()).returnToHome();
            }
        });

        shareButton.setOnClickListener(iv -> shareJournal());

        freezeButton.setOnClickListener(iv -> {
            frozen = !frozen;
            bus.setFrozen(frozen);
            applyFreezeUI();
        });

        clearButton.setOnClickListener(iv -> confirmClear());

        buildChips();
        refreshUI(bus.getEventsFiltered());

        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        attached = true;
        bus.register(this, this);
        applyFreezeUI();
        scrollToBottom();
    }

    @Override
    public void onPause() {
        super.onPause();
        attached = false;
        bus.unregister(this);
    }

    @Override
    public void onDestroyView() {
        bus.unregister(this);
        super.onDestroyView();
    }

    @Override
    public void onEventsChanged(List<VpnEvent> events) {
        if (!attached || getContext() == null || timeline == null) {
            return;
        }
        refreshUI(events == null ? bus.getEventsFiltered() : events);
    }

    /* ---------- construction de la timeline ---------- */

    private void refreshUI(List<VpnEvent> events) {
        if (timeline == null) {
            return;
        }
        List<VpnEvent> list = (events == null) ? bus.getEventsFiltered() : events;
        int size = list.size();
        if (size == lastDisplayedSize && filter.equals(bus.getFilter())) {
            return; // aucun changement
        }
        lastDisplayedSize = size;
        timeline.removeAllViews();

        int shown = 0;
        for (int i = 0; i < list.size() && shown < MAX_DISPLAYED; i++) {
            VpnEvent ev = list.get(i);
            if (!ev.matchesFilter(filter)) {
                continue;
            }
            addEventCard(ev, shown == 0);
            shown++;
        }

        boolean empty = shown == 0;
        if (emptyView != null) {
            emptyView.setVisibility(empty ? View.VISIBLE : View.GONE);
        }
        if (timeline != null) {
            timeline.setVisibility(empty ? View.GONE : View.VISIBLE);
        }

        if (!empty && !frozen) {
            scrollToBottom();
        }
        buildChips();
    }

    private void addEventCard(VpnEvent ev, boolean highlight) {
        Context ctx = getContext();
        if (ctx == null) {
            return;
        }

        int color = ev.color();

        // Ligne de la chronologie (connecteur + point)
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        row.setPadding(0, 6, 0, 6);

        LinearLayout connector = new LinearLayout(ctx);
        connector.setOrientation(LinearLayout.VERTICAL);
        connector.setLayoutParams(new LinearLayout.LayoutParams(
                dpToPx(26), LinearLayout.LayoutParams.MATCH_PARENT));
        connector.setGravity(android.view.Gravity.CENTER_HORIZONTAL);

        View line = new View(ctx);
        line.setLayoutParams(new LinearLayout.LayoutParams(
                dpToPx(3), LinearLayout.LayoutParams.MATCH_PARENT));
        line.setBackgroundColor(0xFF1E293B);

        android.widget.ImageView dot = new android.widget.ImageView(ctx);
        int dotSize = dpToPx(12);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dotSize, dotSize);
        dotParams.topMargin = dpToPx(2);
        dot.setLayoutParams(dotParams);
        dot.setImageDrawable(makeDot(color));

        connector.addView(line);
        connector.addView(dot);

        // Carte événement
        LinearLayout card = new LinearLayout(ctx);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        card.setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12));
        card.setBackgroundResource(R.drawable.log_card_bg);
        card.setElevation(0f);

        // En-tête carte : heure (gauche) + puce niveau (droite)
        LinearLayout header = new LinearLayout(ctx);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        TextView timeView = new TextView(ctx);
        timeView.setText(formatTime(ev.timestamp));
        timeView.setTextColor(ContextCompat.getColor(ctx, R.color.log_text_dim));
        timeView.setTextSize(11f);
        timeView.setLayoutParams(new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        TextView chip = new TextView(ctx);
        chip.setText(levelLabel(ev.level));
        chip.setTextSize(10f);
        chip.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        chip.setTextColor(0xFFFFFFFF);
        chip.setPadding(dpToPx(8), dpToPx(2), dpToPx(8), dpToPx(2));
        chip.setBackground(makeChip(color));
        LinearLayout.LayoutParams chipParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        chipParams.leftMargin = dpToPx(8);
        chip.setLayoutParams(chipParams);

        header.addView(timeView);
        header.addView(chip);

        TextView titleView = new TextView(ctx);
        titleView.setText(TextUtils.isEmpty(ev.title) ? "Événement" : ev.title);
        titleView.setTextColor(ContextCompat.getColor(ctx, R.color.log_text));
        titleView.setTextSize(14.5f);
        titleView.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        titleView.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        card.addView(header);
        card.addView(titleView);

        if (!TextUtils.isEmpty(ev.description) && !ev.description.equals(ev.title)) {
            TextView descView = new TextView(ctx);
            descView.setText(ev.description);
            descView.setTextColor(ContextCompat.getColor(ctx, R.color.log_text_dim));
            descView.setTextSize(12.5f);
            LinearLayout.LayoutParams descParams = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            descParams.topMargin = dpToPx(4);
            descView.setLayoutParams(descParams);
            card.addView(descView);
        }

        row.addView(connector);
        row.addView(card);

        if (highlight) {
            card.setBackgroundColor(ContextCompat.getColor(ctx, R.color.log_card_hover));
            Animation fade = new AlphaAnimation(0f, 1f);
            fade.setDuration(400);
            row.startAnimation(fade);
        }

        timeline.addView(row);
    }

    /* ---------- filtres ---------- */

    private void buildChips() {
        if (chipsContainer == null || getContext() == null) {
            return;
        }
        chipsContainer.removeAllViews();

        String[] filters = {
                "tout", "problemes", "connexion", "application"
        };
        int[] labels = {
                R.string.logs_filter_all, R.string.logs_filter_problems,
                R.string.logs_filter_connection, R.string.logs_filter_application
        };

        for (int i = 0; i < filters.length; i++) {
            String f = filters[i];
            int count = bus.count(f);
            ChipView chip = new ChipView(getContext());
            chip.setText(getString(labels[i]) + "  " + count);
            chip.setTextSize(13f);
            chip.setSelected(f.equals(filter));
            chip.applyState();
            chip.setOnClickListener(v -> {
                filter = f;
                bus.setFilter(f);
                buildChips();
                refreshUI(null);
            });
            chipsContainer.addView(chip);

            if (i < filters.length - 1) {
                TextView sep = new TextView(getContext());
                sep.setText("  ");
                sep.setTextSize(13f);
                chipsContainer.addView(sep);
            }
        }
    }

    /* ---------- actions ---------- */

    private void applyFreezeUI() {
        if (freezeLabel == null || freezeButton == null) {
            return;
        }
        View indicator = getView() != null ? getView().findViewById(R.id.logs_freeze_indicator) : null;
        Context ctx = requireContext();
        if (frozen) {
            freezeLabel.setVisibility(View.VISIBLE);
            freezeLabel.setText(R.string.logs_freeze_label);
            freezeButton.setText(R.string.logs_unfreeze);
            freezeButton.setBackgroundColor(ContextCompat.getColor(ctx, R.color.log_green));
            if (indicator != null) {
                indicator.setVisibility(View.VISIBLE);
                indicator.setBackgroundColor(ContextCompat.getColor(ctx, R.color.log_orange));
            }
        } else {
            freezeLabel.setVisibility(View.GONE);
            freezeButton.setText(R.string.logs_freeze);
            freezeButton.setBackgroundResource(R.drawable.log_card_bg);
            if (indicator != null) {
                indicator.setVisibility(View.GONE);
            }
        }
    }

    private void confirmClear() {
        new AlertDialog.Builder(requireContext())
                .setTitle(R.string.logs_clear_title)
                .setMessage(R.string.logs_clear_msg)
                .setPositiveButton(R.string.logs_clear_confirm, (d, which) -> {
                    bus.clear();
                    if (timeline != null) {
                        timeline.removeAllViews();
                    }
                    if (emptyView != null) {
                        emptyView.setVisibility(View.VISIBLE);
                    }
                    buildChips();
                    Toast.makeText(requireContext(), "Journal vidé", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void shareJournal() {
        String text = bus.shareText();
        if (TextUtils.isEmpty(text) || text.trim().lines().count() <= 4) {
            Toast.makeText(requireContext(), "Rien à partager pour l'instant", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TEXT, text);
        i.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.logs_share_subject));
        startActivity(Intent.createChooser(i, getString(R.string.logs_share_chooser)));
    }

    private void scrollToBottom() {
        if (scroller != null) {
            scroller.post(() -> scroller.fullScroll(View.FOCUS_DOWN));
        }
    }

    /* ---------- utilitaires ---------- */

    private String formatTime(long millis) {
        return java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT,
                Locale.getDefault()).format(millis);
    }

    private String levelLabel(String level) {
        if (level == null) return "Info";
        switch (level.toLowerCase()) {
            case "success": return "Succès";
            case "udp-ok": return "Succès";
            case "ready": return "Prêt";
            case "connection": return "Connexion";
            case "error": return "Erreur";
            case "warning": return "Avertissement";
            case "stop": return "Arrêt";
            case "info": return "Info";
            default: return level;
        }
    }

    private int dpToPx(int dp) {
        return (int) (dp * getResources().getDisplayMetrics().density);
    }

    private android.graphics.drawable.GradientDrawable makeDot(int color) {
        android.graphics.drawable.GradientDrawable d =
                new android.graphics.drawable.GradientDrawable();
        d.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        d.setColor(color);
        d.setSize(dpToPx(12), dpToPx(12));
        return d;
    }

    private android.graphics.drawable.GradientDrawable makeChip(int color) {
        android.graphics.drawable.GradientDrawable d =
                new android.graphics.drawable.GradientDrawable();
        d.setShape(android.graphics.drawable.GradientDrawable.RECTANGLE);
        d.setColor(color);
        d.setCornerRadius(dpToPx(10));
        return d;
    }

    /** Bouton puce de filtre avec état sélectionné. */
    private static class ChipView extends androidx.appcompat.widget.AppCompatTextView {
        public ChipView(Context c) {
            super(c);
            setPadding(dpToPx(c, 12), dpToPx(c, 6), dpToPx(c, 12), dpToPx(c, 6));
        }

        @Override
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            applyState();
        }

        void applyState() {
            Context c = getContext();
            if (c == null) return;
            if (isSelected()) {
                setBackgroundColor(ContextCompat.getColor(c, R.color.log_chip_selected));
                setTextColor(ContextCompat.getColor(c, R.color.log_chip_selected_text));
            } else {
                setBackgroundColor(ContextCompat.getColor(c, R.color.log_chip_bg));
                setTextColor(ContextCompat.getColor(c, R.color.log_text_dim));
            }
            setClipToOutline(false);
        }

        private static int dpToPx(Context c, int dp) {
            return (int) (dp * c.getResources().getDisplayMetrics().density);
        }
    }
}
