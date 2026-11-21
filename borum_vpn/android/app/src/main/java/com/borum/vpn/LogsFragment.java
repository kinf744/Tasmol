package com.borum.vpn;

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

public class LogsFragment extends Fragment {
    private static final int TAIL_CHARS = 120_000;
    private static final int REQ_SAVE_JOURNAL = 3101;
    private static final Pattern LINE_RE =
            Pattern.compile("^(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?)\\s+(.*)$", Pattern.DOTALL);
    private static final Pattern TAGGED_RE =
            Pattern.compile("^\\[(info|journal|connection|warning|error)\\] \\[([^\\]]*)\\] ?(.*)$",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern BARE_RE =
            Pattern.compile("^\\[(udp-ok|udp|ready)\\] ?(.*)$", Pattern.DOTALL);

    private static final String BLOCK_START = "Connecting udp server";

    private static final String SEPARATOR = "───────────────────────────────────────";

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

        logText.setLineSpacing(0f, 1.45f);
        logText.setIncludeFontPadding(true);
        scroller = v.findViewById(R.id.logs_scroll);
        v.findViewById(R.id.logs_clear).setOnClickListener(view -> {
            TasVpnService.clearLog();
            BinaryManager.clearLog();
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

    private long lastSeenStamp = -2;
    private boolean lastSeenVerbose = false;

    private void refresh() {
        if (logText == null || getContext() == null) {
            return;
        }

        long stamp = BinaryManager.logStamp();
        if (stamp == 0) {
            lastSeenStamp = -1;
        } else if (stamp == lastSeenStamp && verbose == lastSeenVerbose) {
            return;
        }
        lastSeenStamp = stamp;
        lastSeenVerbose = verbose;
        String raw = BinaryManager.readLogTail(TAIL_CHARS);
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
            String raw = BinaryManager.readLogTail(300_000);
            if (raw == null || raw.trim().isEmpty()) {
                Toast.makeText(getContext(), "Nothing to share yet", Toast.LENGTH_SHORT).show();
                return;
            }
            new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                    .setTitle("Journal")
                    .setItems(new String[]{"Partager le texte", "Enregistrer en fichier"}, (d, which) -> {
                        if (which == 0) {
                            Intent i = new Intent(Intent.ACTION_SEND);
                            i.setType("text/plain");
                            i.putExtra(Intent.EXTRA_TEXT, raw);
                            i.putExtra(Intent.EXTRA_SUBJECT, "vpn.log");
                            startActivity(Intent.createChooser(i, "Share journal via"));
                        } else {
                            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                            i.addCategory(Intent.CATEGORY_OPENABLE);
                            i.setType("text/plain");
                            i.putExtra(Intent.EXTRA_TITLE, "vpn.log");
                            startActivityForResult(i, REQ_SAVE_JOURNAL);
                        }
                    })
                    .setNegativeButton("Annuler", null)
                    .show();
        } catch (Exception e) {
            Toast.makeText(getContext(), "Share failed: " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_SAVE_JOURNAL) {
            return;
        }
        if (resultCode != android.app.Activity.RESULT_OK || data == null
                || data.getData() == null) {
            return;
        }
        try (java.io.OutputStream out = requireContext().getContentResolver()
                .openOutputStream(data.getData())) {
            if (out == null) {
                throw new IllegalStateException("openOutputStream returned null");
            }
            out.write(BinaryManager.readLogTail(2_000_000)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Toast.makeText(getContext(), "Journal enregistré", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(getContext(), "Enregistrement impossible : " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }

    private static boolean isJournalLine(String level) {

        return level.equals("connection") || level.equals("error");
    }

    private CharSequence renderJournal(String raw) {
        final int white = 0xFFFFFFFF;
        final int red = 0xFFFF5252;
        final int greenVif = 0xFF00E676;
        final int orangeVif = 0xFFFF9500;
        final int greyLight = 0xFFB0BEC5;
        final boolean up = TasVpnService.isRunning() && !TasVpnService.isStarting();

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

                if (time.length() > 8) {
                    time = time.substring(0, 8);
                }
                rest = lm.group(2).trim();
            }
            String level = "info";
            String comp = "";
            String msg = rest;
            Matcher bm = BARE_RE.matcher(rest);
            Matcher tm = TAGGED_RE.matcher(rest);
            if (bm.matches()) {
                level = bm.group(1).toLowerCase();
                msg = bm.group(2).trim();
            } else if (tm.matches()) {
                level = tm.group(1).toLowerCase();
                comp = tm.group(2);
                msg = tm.group(3).trim();
            }

            if (!verbose) {
                if (!isJournalLine(level)) {
                    continue;
                }
                if (level.equals("connection") && !msg.toLowerCase(java.util.Locale.US).contains("connect")) {
                    continue;
                }
                if (level.equals("error")) {
                    msg = TasVpnService.shortReason(msg);
                }
            }
            rows.add(new String[]{time, level, comp, msg});
        }

        if (!verbose && rows.size() > 15) {
            rows = new java.util.ArrayList<>(rows.subList(rows.size() - 15, rows.size()));
        }
        SpannableStringBuilder sb = new SpannableStringBuilder();
        boolean firstBlockLine = true;
        for (String[] r : rows) {
            String time = r[0];
            String level = r[1];
            String comp = r[2];
            String msg = r[3];
            int tagColor;
            int msgColor = white;

            boolean bare = level.equals("udp") || level.equals("udp-ok")
                    || level.equals("ready");

            if (bare && level.equals("udp") && msg.startsWith(BLOCK_START)
                    && !firstBlockLine) {
                sb.append('\n');
                appendSpan(sb, SEPARATOR, 0xFF37474F);
                sb.append('\n');
            }
            if (bare) {
                firstBlockLine = false;
            }
            switch (level) {
                case "error":
                    tagColor = red;
                    msgColor = red;
                    break;
                case "warning":
                    tagColor = up ? orangeVif : greyLight;
                    msgColor = tagColor;
                    break;
                case "ready":

                    tagColor = orangeVif;
                    msgColor = orangeVif;
                    break;
                case "udp-ok":
                    tagColor = greenVif;
                    msgColor = greenVif;
                    break;
                case "udp":
                    tagColor = greenVif;
                    msgColor = greenVif;
                    break;
                case "connection":
                case "journal":
                    tagColor = up ? greenVif : greyLight;
                    break;
                default:
                    tagColor = greyLight;
                    break;
            }
            appendSpan(sb, "[" + time + "] ", bare ? white : (up ? white : greyLight));
            if (bare) {
                appendSpan(sb, msg + "\n", msgColor);
                continue;
            }
            if (!comp.isEmpty()) {
                appendSpan(sb, "[" + comp + "] ", tagColor);
            } else if (!level.equals("info")) {
                appendSpan(sb, "[" + level + "] ", tagColor);
            }
            appendSpan(sb, msg + "\n", msgColor);
        }
        if (sb.length() == 0) {

            SpannableStringBuilder empty = new SpannableStringBuilder();
            if (verbose) {
                String[] rawLines = raw.split("\n");
                int from = Math.max(0, rawLines.length - 40);
                appendSpan(empty, "(fin du journal brut)\n", greyLight);
                for (int i = from; i < rawLines.length; i++) {
                    appendSpan(empty, rawLines[i].trim() + "\n", white);
                }
            } else {
                appendSpan(empty, "Aucune session affichable.\n\n", greyLight);
                appendSpan(empty, "Le journal ne montre que les connexions "
                        + "(zivpn, Hysteria, Xray, SSH) et les erreurs.\n",
                        greyLight);
                appendSpan(empty, "Basculer sur Verbose pour le flux technique "
                        + "complet.\n", greyLight);
            }
            return empty;
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
