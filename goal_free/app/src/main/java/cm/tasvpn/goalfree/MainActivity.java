package cm.tasvpn.goalfree;

import android.app.Activity;
import android.content.ClipData;
import android.graphics.Color;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.method.ScrollingMovementMethod;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Goal Free — sonne les hôtes Free Basics / Meta via le proxy
 * 157.240.9.39:8080 (le proxy Free Basics de Meta, zero-rated sur MTN CM).
 *
 * Principe de la sonde (le mode proxy) : requête HTTP en forme proxy
 * (URI absolue) envoyée AU proxy Meta —
 *
 *     GET http://<hôte-candidat>/ HTTP/1.1\r\nHost: <hôte>\r\n...
 *
 * Le code de statut rendu par le proxy classe l'hôte :
 *   200 OK       → l'hôte est servi par Free Basics (zero-rated ✓)
 *   403          → l'hôte n'est PAS dans le catalogue Free Basics
 *   429          → rate-limit du proxy (l'hôte existe, trop de requêtes)
 *   502/504      → l'origine ne répond pas au proxy
 *   301/302      → redirection (souvent vers login/consentement)
 *   ERR/timeout  → injoignable depuis ce réseau
 *
 * Robustesse ("quasi parfait") : 2 tentatives par hôte, 2 formes de
 * requête (URI absolue + forme Host), timeout 6 s, latence mesurée,
 * tri 200-d'abord, copie des résultats et des hôtes valides.
 */
public class MainActivity extends Activity {

    private static final String PROXY_HOST = "157.240.9.39";
    private static final int PROXY_PORT = 8080;
    private static final int TIMEOUT_MS = 6000;
    private static final int THREADS = 10;
    private static final int ATTEMPTS = 2;

    private static final String UA =
            "Mozilla/5.0 (Linux; Android 10; SM-A105F Build/QP1A.190711.020) " +
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.120 Mobile Safari/537.36 " +
            "[FBAN/FB4A;FBAV/400.0.0.32.61;FBBV/335331542;]";

    private static final String DEFAULT_HOSTS =
            "free.facebook.com\n" +
            "m.facebook.com\n" +
            "d.facebook.com\n" +
            "z-m.facebook.com\n" +
            "mtouch.facebook.com\n" +
            "edge.facebook.com\n" +
            "portal.facebook.com\n" +
            "b-m.facebook.com\n" +
            "web.facebook.com\n" +
            "connect.facebook.net\n" +
            "graph.facebook.com\n" +
            "api.facebook.com\n" +
            "rupload.facebook.com\n" +
            "detect.freebasics.com\n" +
            "about.freebasics.com\n" +
            "help.freebasics.com\n" +
            "explore.freebasics.com\n" +
            "free.freebasics.com\n" +
            "static.xx.fbcdn.net\n" +
            "scontent.xx.fbcdn.net";

    private EditText hostsEdit;
    private Spinner modeSpin;
    private TextView resultsView;
    private TextView progressView;
    private Button scanBtn;
    private volatile String lastResults = "";
    private volatile String lastValid = "";
    private volatile boolean running = false;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        hostsEdit = findViewById(R.id.hosts);
        modeSpin = findViewById(R.id.mode);
        resultsView = findViewById(R.id.results);
        progressView = findViewById(R.id.progress);
        scanBtn = findViewById(R.id.scan);
        Button copyAll = findViewById(R.id.copyAll);
        Button copyOk = findViewById(R.id.copyOk);

        hostsEdit.setText(DEFAULT_HOSTS);
        resultsView.setMovementMethod(new ScrollingMovementMethod());
        modeSpin.setAdapter(new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item,
                new String[]{"Proxy 157.240.9.39:8080", "Direct hôte:80"}));

        copyAll.setOnClickListener(v -> copy("Résultats copiés", lastResults));
        copyOk.setOnClickListener(v -> copy("Hôtes valides (200) copiés", lastValid));
        scanBtn.setOnClickListener(v -> {
            if (!running) startScan();
        });
    }

    private void copy(String msg, String data) {
        if (data == null || data.trim().isEmpty()) {
            Toast.makeText(this, "Rien à copier", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("goal_free", data));
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    // ══ LA CHASSE ══════════════════════════════════════════════════════

    private void startScan() {
        running = true;
        scanBtn.setEnabled(false);
        lastResults = "";
        lastValid = "";

        List<String> list = new ArrayList<>();
        for (String h : hostsEdit.getText().toString().split("\\s+")) {
            h = h.trim().toLowerCase();
            if (!h.isEmpty() && !list.contains(h)) list.add(h);
        }
        final int total = list.size();
        if (total == 0) {
            running = false;
            scanBtn.setEnabled(true);
            Toast.makeText(this, "Aucun hôte dans la liste", Toast.LENGTH_SHORT).show();
            return;
        }
        final int mode = modeSpin.getSelectedItemPosition();
        progressView.setText("Sonde 0/" + total + " …");
        resultsView.setText("");

        final long t0 = System.currentTimeMillis();
        final ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        final CountDownLatch done = new CountDownLatch(total);
        final AtomicInteger finished = new AtomicInteger();
        final List<String[]> results = Collections.synchronizedList(new ArrayList<String[]>());
        // String[] = {code, reason, host, latency}

        for (final String host : list) {
            pool.execute(() -> {
                String[] r = probeBest(host, mode);
                results.add(r);
                int f = finished.incrementAndGet();
                ui.post(() -> progressView.setText("Sonde " + f + "/" + total + " …"));
                done.countDown();
            });
        }

        new Thread(() -> {
            try {
                done.await(5, TimeUnit.MINUTES);
            } catch (InterruptedException ignored) {
            }
            pool.shutdownNow();

            // Tri : 200 d'abord, puis par code croissant, puis par hôte
            Collections.sort(results, (a, b) -> {
                int ca = parseCode(a[0]), cb = parseCode(b[0]);
                if (ca != cb) return ca - cb;
                return a[2].compareTo(b[2]);
            });

            StringBuilder sb = new StringBuilder();
            StringBuilder okList = new StringBuilder();
            int ok = 0;
            SpannableStringBuilder colored = new SpannableStringBuilder();
            int hStart = colored.length();
            colored.append("== SONDE FREE BASICS (MTN CM) ==\n");
            colored.setSpan(new ForegroundColorSpan(0xFF4CAF50), hStart, colored.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            for (String[] r : results) {
                String line = r[0] + " " + r[1] + "  " + r[2] + "  (" + r[3] + " ms)";
                sb.append(line).append("\n");
                int start = colored.length();
                colored.append(line).append("\n");
                colored.setSpan(new ForegroundColorSpan(colorFor(r[0])), start, colored.length(),
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                if ("200".equals(r[0])) {
                    ok++;
                    okList.append(r[2]).append("\n");
                }
            }
            long dt = (System.currentTimeMillis() - t0) / 1000;
            final String header = "== SONDE FREE BASICS (MTN CM) — " + ok + "/" + total
                    + " hôtes OK — " + dt + " s ==\n\n";
            final String body = sb.toString();
            final String valid = okList.toString();
            final int okCount = ok;
            final SpannableStringBuilder coloredFinal = colored;
            lastResults = header + body;
            lastValid = valid;
            ui.post(() -> {
                resultsView.setText(coloredFinal);
                progressView.setText("Terminé : " + okCount + "/" + total
                        + " hôtes OK en " + dt + " s");
                scanBtn.setEnabled(true);
                running = false;
            });
        }).start();
    }

    /** 2 tentatives, la meilleure (200 prioritaire, sinon le code le plus bas). */
    private String[] probeBest(String host, int mode) {
        String[] best = null;
        for (int i = 0; i < ATTEMPTS; i++) {
            String[] r;
            if (mode == 0) {
                // Les 2 formes : URI absolue puis forme Host (les proxies
                // Free Basics n'acceptent pas toujours l'URI absolue).
                r = (i == 0) ? probeProxy(host, true) : probeProxy(host, false);
            } else {
                r = probeDirect(host);
            }
            if (r != null && "200".equals(r[0])) return r;
            if (r != null && (best == null || parseCode(r[0]) < parseCode(best[0]))) best = r;
        }
        if (best == null) {
            best = new String[]{"ERR", "injoignable", host, "0"};
        }
        return best;
    }

    /** La sonde via le proxy Free Basics 157.240.9.39:8080. */
    private String[] probeProxy(String host, boolean absoluteUri) {
        long t0 = System.currentTimeMillis();
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(PROXY_HOST, PROXY_PORT), TIMEOUT_MS);
            s.setSoTimeout(TIMEOUT_MS);
            String target = absoluteUri ? ("http://" + host + "/") : "/";
            String req = "GET " + target + " HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: " + UA + "\r\n"
                    + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    + "Accept-Language: fr-FR,fr;q=0.9,en;q=0.8\r\n"
                    + "Accept-Encoding: identity\r\n"
                    + "Proxy-Connection: close\r\n"
                    + "Connection: close\r\n\r\n";
            OutputStream os = s.getOutputStream();
            os.write(req.getBytes(StandardCharsets.ISO_8859_1));
            os.flush();
            StringBuilder full = new StringBuilder();
            StringBuilder body = new StringBuilder();
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.ISO_8859_1));
            String line = br.readLine();
            boolean inBody = false;
            while (line != null) {
                full.append(line).append("\n");
                if (inBody && body.length() < 300) {
                    body.append(line.trim()).append(" ");
                }
                if (line.trim().isEmpty()) {
                    inBody = true;
                }
                line = br.readLine();
            }
            long ms = System.currentTimeMillis() - t0;
            if (full.length() == 0) {
                return new String[]{"000", "réponse vide", host, String.valueOf(ms)};
            }
            String[] lines = full.toString().trim().split("\n");
            String[] parts = lines[0].trim().split("\\s+", 3);
            String code = parts.length > 1 ? parts[1] : "000";
            String reason = parts.length > 2 ? parts[2] : "";
            if (!"200".equals(code)) {
                String snippet = body.toString().replaceAll("<[^>]*>", " ").replaceAll("\\s+", " ").trim();
                if (snippet.length() > 2) {
                    if (snippet.length() > 80) snippet = snippet.substring(0, 80) + "…";
                    return new String[]{code, reason + " — " + snippet, host, String.valueOf(ms)};
                }
            }
            return new String[]{code, reason, host, String.valueOf(ms)};
        } catch (Exception e) {
            long ms = System.currentTimeMillis() - t0;
            return new String[]{"ERR", e.getClass().getSimpleName(), host, String.valueOf(ms)};
        } finally {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    /** La sonde directe : host:80 (la vérification zero-rating sans proxy). */
    private String[] probeDirect(String host) {
        long t0 = System.currentTimeMillis();
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, 80), TIMEOUT_MS);
            s.setSoTimeout(TIMEOUT_MS);
            String req = "GET / HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: " + UA + "\r\n"
                    + "Accept: text/html,*/*;q=0.8\r\n"
                    + "Accept-Encoding: identity\r\n"
                    + "Connection: close\r\n\r\n";
            OutputStream os = s.getOutputStream();
            os.write(req.getBytes(StandardCharsets.ISO_8859_1));
            os.flush();
            StringBuilder full = new StringBuilder();
            StringBuilder body = new StringBuilder();
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.ISO_8859_1));
            String line = br.readLine();
            boolean inBody = false;
            while (line != null) {
                full.append(line).append("\n");
                if (inBody && body.length() < 300) {
                    body.append(line.trim()).append(" ");
                }
                if (line.trim().isEmpty()) {
                    inBody = true;
                }
                line = br.readLine();
            }
            long ms = System.currentTimeMillis() - t0;
            if (full.length() == 0) {
                return new String[]{"000", "réponse vide", host, String.valueOf(ms)};
            }
            String[] lines = full.toString().trim().split("\n");
            String[] parts = lines[0].trim().split("\\s+", 3);
            String code = parts.length > 1 ? parts[1] : "000";
            String reason = parts.length > 2 ? parts[2] : "";
            if (!"200".equals(code)) {
                String snippet = body.toString().replaceAll("<[^>]*>", " ").replaceAll("\\s+", " ").trim();
                if (snippet.length() > 2) {
                    if (snippet.length() > 80) snippet = snippet.substring(0, 80) + "…";
                    return new String[]{code, reason + " — " + snippet, host, String.valueOf(ms)};
                }
            }
            return new String[]{code, reason, host, String.valueOf(ms)};
        } catch (Exception e) {
            long ms = System.currentTimeMillis() - t0;
            return new String[]{"ERR", e.getClass().getSimpleName(), host, String.valueOf(ms)};
        } finally {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    /** La palette 4 couleurs : vert 200, jaune 502, rouge 403, gris 429. */
    private static int colorFor(String code) {
        if ("200".equals(code)) return 0xFF4CAF50;
        if ("502".equals(code) || "504".equals(code)) return 0xFFFFEB3B;
        if ("403".equals(code)) return 0xFFF44336;
        if ("429".equals(code)) return 0xFF90A4AE;
        if ("ERR".equals(code) || "000".equals(code)) return 0xFFFF8A65;
        return 0xFFE0E0E0;
    }

    private static int parseCode(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return 999;
        }
    }
}
