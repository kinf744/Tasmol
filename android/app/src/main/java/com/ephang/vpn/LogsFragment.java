package com.ephang.vpn;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LOGS tab: unified connection journal (Download/kighmu.txt, written by the
 * Go data plane and mirrored Java events). Lines carry [level] [component]:
 * error red, warning amber, connection cyan tag, info grey tag.
 */
public class LogsFragment extends Fragment {
    private static final int TAIL_CHARS = 120_000;
    private static final Pattern LINE_RE =
            Pattern.compile("^(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?)\\s+(.*)$", Pattern.DOTALL);
    private static final Pattern TAGGED_RE =
            Pattern.compile("^\\[(info|journal|connection|warning|error)\\] \\[([^\\]]*)\\] ?(.*)$",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private TextView logText;
    private ScrollView scroller;
    private android.widget.Button modeBtn;
    private boolean verbose = false;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 2000);
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_logs, container, false);
        logText = v.findViewById(R.id.logs_text);
        scroller = v.findViewById(R.id.logs_scroll);
        v.findViewById(R.id.logs_clear).setOnClickListener(view -> {
            TasVpnService.clearLog();
            BinaryManager.clearKighmu();
            refresh();
        });
        v.findViewById(R.id.logs_share).setOnClickListener(view -> shareJournal());
        modeBtn = v.findViewById(R.id.logs_mode);
        verbose = VPNApplication.getInstance().isVerboseDiagnosticsEnabled();
        modeBtn.setText(verbose ? "Verbose" : "Journal");
        modeBtn.setOnClickListener(view -> {
            verbose = !verbose;
            modeBtn.setText(verbose ? "Verbose" : "Journal");
            refresh();
        });
        refresh();
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    public void onPause() {
        super.onPause();
        handler.removeCallbacks(tick);
    }

    private void refresh() {
        if (logText == null || getContext() == null) {
            return;
        }
        String raw = BinaryManager.readKighmuTail(TAIL_CHARS);
        if (raw == null || raw.trim().isEmpty()) {
            logText.setText("No events yet.\nConnect to start the journal.");
            return;
        }
        logText.setText(renderJournal(raw));
        if (scroller != null) {
            scroller.post(() -> scroller.fullScroll(View.FOCUS_DOWN));
        }
    }

    private void shareJournal() {
        try {
            String raw = BinaryManager.readKighmuTail(300_000);
            if (raw == null || raw.trim().isEmpty()) {
                Toast.makeText(getContext(), "Nothing to share yet", Toast.LENGTH_SHORT).show();
                return;
            }
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_TEXT, raw);
            i.putExtra(Intent.EXTRA_SUBJECT, "kighmu.txt");
            startActivity(Intent.createChooser(i, "Share journal via"));
        } catch (Exception e) {
            Toast.makeText(getContext(), "Share failed", Toast.LENGTH_SHORT).show();
        }
    }

    /** Parse "[time] [level] [component] message" rows into colored spans.
     *  Journal mode (default) shows journal+connection+warning+error only
     *  (capped to the last 300); Verbose shows the full firehose. */
    private CharSequence renderJournal(String raw) {
        int grey = ContextCompat.getColor(requireContext(), R.color.npv_grey);
        int dim = ContextCompat.getColor(requireContext(), R.color.npv_dim);
        int text = ContextCompat.getColor(requireContext(), R.color.npv_text);
        int red = ContextCompat.getColor(requireContext(), R.color.npv_red);
        int yellow = ContextCompat.getColor(requireContext(), R.color.npv_yellow);
        int cyan = ContextCompat.getColor(requireContext(), R.color.npv_green);
        java.util.ArrayList<String[]> rows = new java.util.ArrayList<>();
        for (String line : raw.split("\n")) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            String time = "";
            String rest = line;
            Matcher lm = LINE_RE.matcher(line);
            if (lm.matches()) {
                time = lm.group(1);
                // Display as [HH:MM:SS] — drop the millisecond part.
                if (time.length() > 8) {
                    time = time.substring(0, 8);
                }
                rest = lm.group(2).trim();
            }
            String level = "info";
            String comp = "";
            String msg = rest;
            Matcher tm = TAGGED_RE.matcher(rest);
            if (tm.matches()) {
                level = tm.group(1).toLowerCase();
                comp = tm.group(2);
                msg = tm.group(3).trim();
            }
            if (!verbose && level.equals("info")) {
                continue;
            }
            rows.add(new String[]{time, level, comp, msg});
        }
        // Cap journal volume (Picko-style): last 300 relevant rows.
        if (!verbose && rows.size() > 300) {
            rows = new java.util.ArrayList<>(rows.subList(rows.size() - 300, rows.size()));
        }
        SpannableStringBuilder sb = new SpannableStringBuilder();
        for (String[] r : rows) {
            String time = r[0];
            String level = r[1];
            String comp = r[2];
            String msg = r[3];
            int tagColor = dim;
            int msgColor = text;
            switch (level) {
                case "error":
                    tagColor = red;
                    msgColor = red;
                    break;
                case "warning":
                    tagColor = yellow;
                    msgColor = yellow;
                    break;
                case "connection":
                    tagColor = cyan;
                    msgColor = text;
                    break;
                case "journal":
                    tagColor = cyan;
                    msgColor = text;
                    break;
                default:
                    tagColor = dim;
                    msgColor = text;
                    break;
            }
            appendSpan(sb, "[" + time + "] ", grey);
            if (!comp.isEmpty()) {
                appendSpan(sb, "[" + comp + "] ", tagColor);
            } else if (!level.equals("info")) {
                appendSpan(sb, "[" + level + "] ", tagColor);
            }
            appendSpan(sb, msg + "\n", msgColor);
        }
        if (sb.length() == 0) {
            return "Journal is empty for this filter.\nConnect to start logging.";
        }
        return sb;
    }

    private static void appendSpan(SpannableStringBuilder sb, String text, int color) {
        int start = sb.length();
        sb.append(text);
        sb.setSpan(new ForegroundColorSpan(color), start, sb.length(),
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }
}
