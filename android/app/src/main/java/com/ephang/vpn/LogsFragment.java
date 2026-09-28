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
    private static final int REQ_SAVE_JOURNAL = 3101;
    private static final Pattern LINE_RE =
            Pattern.compile("^(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?)\\s+(.*)$", Pattern.DOTALL);
    private static final Pattern TAGGED_RE =
            Pattern.compile("^\\[(info|journal|connection|warning|error)\\] \\[([^\\]]*)\\] ?(.*)$",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    /** Lignes "barres" du journal de session UDP: [level] message, sans
     *  composant. La couleur porte sur le texte entier. */
    private static final Pattern BARE_RE =
            Pattern.compile("^\\[(udp-ok|udp|ready)\\] ?(.*)$", Pattern.DOTALL);

    /** First line of a session block — marks a block boundary. */
    private static final String BLOCK_START = "Connecting udp server";
    /** Dim rule drawn between two session blocks. */
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
        // Interlignage : 1.45x sur une police 13sp donne ~5px de respiration
        // entre deux lignes, sans casser la lecture en police fixe.
        logText.setLineSpacing(0f, 1.45f);
        logText.setIncludeFontPadding(true);
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

    private long lastSeenStamp = -2;
    private boolean lastSeenVerbose = false;

    private void refresh() {
        if (logText == null || getContext() == null) {
            return;
        }
        // Skip total: ni lecture ni re-render si le journal n'a pas bougé
        // (2s tick). Le cache est invalidé dès que le fichier est tronqué
        // (clear) pour ne pas garder un écran figé.
        long stamp = BinaryManager.kighmuStamp();
        if (stamp == 0) {
            lastSeenStamp = -1;
        } else if (stamp == lastSeenStamp && verbose == lastSeenVerbose) {
            return;
        }
        lastSeenStamp = stamp;
        lastSeenVerbose = verbose;
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

    /** Share the journal. The app can no longer write to Download/ on
     *  Android 10+, so saving the file goes through the system document
     *  picker (ACTION_CREATE_DOCUMENT) instead of a direct write. */
    private void shareJournal() {
        try {
            String raw = BinaryManager.readKighmuTail(300_000);
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
                            i.putExtra(Intent.EXTRA_SUBJECT, "kighmu.txt");
                            startActivity(Intent.createChooser(i, "Share journal via"));
                        } else {
                            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                            i.addCategory(Intent.CATEGORY_OPENABLE);
                            i.setType("text/plain");
                            i.putExtra(Intent.EXTRA_TITLE, "kighmu.txt");
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
            out.write(BinaryManager.readKighmuTail(2_000_000)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Toast.makeText(getContext(), "Journal enregistré", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(getContext(), "Enregistrement impossible : " + e.getMessage(),
                    Toast.LENGTH_SHORT).show();
        }
    }

    /** Parse "[time] [level] [component] message" rows into colored spans.
     *  Journal mode (default) shows journal+connection+warning+error only
     *  (capped to the last 300); Verbose shows the full firehose.
     *  Palette exacte demandée :
     *   - connecté   : blanc (texte/horodatage) + vert vif (connexion/journal)
     *                  + orange vif (warnings) + rouge (erreurs)
     *   - déconnecté/échec : blanc + rouge + gris clair (le reste). */
    /** Levels kept in the filtered "Journal" view: the session block plus
     *  anything the user must not miss (failures, warnings). */
    private static boolean isJournalLine(String level) {
        return level.equals("udp") || level.equals("udp-ok") || level.equals("ready")
                || level.equals("error") || level.equals("warning");
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
                // Display as [HH:MM:SS] — drop the millisecond part.
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
            // Mode Journal : on ne montre que le bloc de session et les
            // incidents. Tout le reste — "[session] starting session",
            // "[session] mode=single", "[zivvn] udp <ip> (8 range(s))",
            // "[session] starting helper ...", "[app] connected (id)" — est
            // du bruit technique demande par personne : il reste accessible
            // en mode Verbose, qui affiche le flux complet.
            if (!verbose && !isJournalLine(level)) {
                continue;
            }
            rows.add(new String[]{time, level, comp, msg});
        }
        // Cap journal volume (Picko-style): last 300 relevant rows.
        if (!verbose && rows.size() > 300) {
            rows = new java.util.ArrayList<>(rows.subList(rows.size() - 300, rows.size()));
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
            // Journal de session (zivvn / Hysteria / Xray / SSH) : la couleur
            // porte sur le texte, pas sur un tag — [HH:mm:ss] seul, message
            // entierement vert ou orange.
            boolean bare = level.equals("udp") || level.equals("udp-ok")
                    || level.equals("ready");
            // Professional rhythm: each connect block is separated from the
            // previous one by a blank line and a dim rule, so several
            // consecutive sessions read as distinct units instead of a wall
            // of undifferentiated lines.
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
                    // The block keeps its own palette whatever the current
                    // session state: these lines described one specific
                    // moment, greying them out on a later disconnect made the
                    // requested colours look like they had not been applied.
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
            // Mode Journal filtre tout sauf le bloc de session et les
            // incidents. Afficher le brut ici rejouerait exactement le bruit
            // que le filtre vient de retirer, donc on explique l'etat vide et
            // on renvoie vers le mode Verbose qui, lui, montre le flux brut.
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
