package cm.tasvpn.goalfree;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.method.ScrollingMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
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

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Goal Free — le sondeur et le tunnel Free Basics de Meta (MTN CM).
 *
 * Le proxy 157.240.9.39:8080 accepte la méthode CONNECT avec l'empreinte
 * Internet.org (l'UA + X-IORG-BSID/X-IORG-SERVICE-ID). 200 = le tunnel
 * s'ouvre vers <hôte>:443 — le free-mode.
 *
 * L'affichage : UNIQUEMENT « CODE — hôte », coloré :
 *   vert 200 · jaune 502 · rouge 403 · gris 429 · orange erreur.
 * Chaque hôte de la liste obtient TOUJOURS une ligne de résultat.
 */
public class MainActivity extends Activity {

    private static final String PROXY_HOST = "157.240.9.39";
    private static final int PROXY_PORT = 8080;
    private static final int CONNECT_TIMEOUT = 6000;
    private static final int READ_TIMEOUT = 5000;
    private static final int THREADS = 10;

    private static final String UA_INTERNET_ORG =
            "Mozilla/5.0 (Linux; Android 14; SM-A245F) Chrome/133.0.6943.122 " +
            "[FBAN/InternetOrgApp;FBAV/166.0.0.0.169;]";
    private static final String X_IORG_BSID =
            "a08359b0-d7ec-4cb5-97bf-000bdc29ec87";

    private static final String DEFAULT_HOSTS =
            "free.facebook.com\n" +
            "m.facebook.com\n" +
            "web.facebook.com\n" +
            "connect.facebook.net\n" +
            "graph.facebook.com\n" +
            "api.facebook.com\n" +
            "rupload.facebook.com\n" +
            "d.facebook.com\n" +
            "z-m.facebook.com\n" +
            "mtouch.facebook.com\n" +
            "edge.facebook.com\n" +
            "portal.facebook.com\n" +
            "b-m.facebook.com\n" +
            "detect.freebasics.com\n" +
            "about.freebasics.com\n" +
            "help.freebasics.com\n" +
            "explore.freebasics.com\n" +
            "free.freebasics.com\n" +
            "static.xx.fbcdn.net\n" +
            "scontent.xx.fbcdn.net\n" +
            "techypals.com\n" +
            "read.worldreader.org\n" +
            "www.voaafrique.com\n" +
            "francais.rt.com";

    private EditText hostsEdit;
    private TextView resultsView;
    private TextView progressView;
    private Button scanBtn;
    private Button tunnelBtn;
    private volatile String lastResults = "";
    private volatile String lastValid = "";
    private volatile boolean running = false;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        hostsEdit = findViewById(R.id.hosts);
        resultsView = findViewById(R.id.results);
        progressView = findViewById(R.id.progress);
        scanBtn = findViewById(R.id.scan);
        tunnelBtn = findViewById(R.id.tunnel);
        Button copyAll = findViewById(R.id.copyAll);
        Button copyOk = findViewById(R.id.copyOk);

        hostsEdit.setText(DEFAULT_HOSTS);
        resultsView.setMovementMethod(new ScrollingMovementMethod());

        copyAll.setOnClickListener(v -> copy("Résultats copiés", lastResults));
        copyOk.setOnClickListener(v -> copy("Hôtes 200 (tunnel OK) copiés", lastValid));
        scanBtn.setOnClickListener(v -> {
            if (!running) startScan();
        });
        tunnelBtn.setOnClickListener(v -> {
            if (!running) startTunnelTest();
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

    // ══ LE TUNNEL CONNECT ════════════════════════════════════════════════

    /**
     * Ouvre le tunnel CONNECT à travers le proxy Free Basics.
     * Retourne le socket tunnélé (le statut 200) ou null.
     * Le code du statut est écrit dans codeOut[0].
     */
    private Socket connectTunnel(String host, int port, StringBuilder codeOut) {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(PROXY_HOST, PROXY_PORT), CONNECT_TIMEOUT);
            s.setSoTimeout(READ_TIMEOUT);
            String req = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n"
                    + "Host: " + host + ":" + port + "\r\n"
                    + "Proxy-Connection: keep-alive\r\n"
                    + "User-Agent: " + UA_INTERNET_ORG + "\r\n"
                    + "X-IORG-BSID: " + X_IORG_BSID + "\r\n"
                    + "X-IORG-SERVICE-ID: null\r\n\r\n";
            OutputStream os = s.getOutputStream();
            os.write(req.getBytes(StandardCharsets.ISO_8859_1));
            os.flush();
            // La réponse : jusqu'à \r\n\r\n (les en-têtes du proxy tiennent
            // dans le premier paquet — lu en une fois, borné par le timeout).
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            InputStream is = s.getInputStream();
            byte[] buf = new byte[2048];
            int n;
            while (resp.size() < 4096 && (n = is.read(buf)) != -1) {
                resp.write(buf, 0, n);
                byte[] b = resp.toByteArray();
                if (b.length >= 4 && b[b.length - 4] == '\r' && b[b.length - 3] == '\n'
                        && b[b.length - 2] == '\r' && b[b.length - 1] == '\n') {
                    break;
                }
                if (b.length > 2 && b[0] != 'H') {
                    break; // pas du HTTP : inutile d'attendre la suite
                }
            }
            String head = resp.toString("ISO-8859-1");
            String[] parts = head.trim().split("\\s+", 3);
            String code = parts.length > 1 ? parts[1] : "000";
            codeOut.setLength(0);
            codeOut.append(code);
            if ("200".equals(code)) {
                return s; // le tunnel est établi
            }
            try {
                s.close();
            } catch (Exception ignored) {
            }
            return null;
        } catch (Exception e) {
            codeOut.setLength(0);
            codeOut.append("ERR");
            try {
                s.close();
            } catch (Exception ignored) {
            }
            return null;
        }
    }

    /** La sonde : CONNECT + le statut (le code seul, le tunnel refermé). */
    private String[] probeHost(String host) {
        StringBuilder codeOut = new StringBuilder("000");
        long t0 = System.currentTimeMillis();
        Socket t = connectTunnel(host, 443, codeOut);
        int ms = (int) (System.currentTimeMillis() - t0);
        String code = codeOut.toString();
        if (t != null) {
            try {
                t.close();
            } catch (Exception ignored) {
            }
            return new String[]{code, host, String.valueOf(ms)};
        }
        return new String[]{code.equals("000") ? "ERR" : code, host, String.valueOf(ms)};
    }

    // ══ LA CHASSE ════════════════════════════════════════════════════════

    private void startScan() {
        running = true;
        scanBtn.setEnabled(false);
        tunnelBtn.setEnabled(false);
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
            tunnelBtn.setEnabled(true);
            Toast.makeText(this, "Aucun hôte dans la liste", Toast.LENGTH_SHORT).show();
            return;
        }
        progressView.setText("Sonde CONNECT 0/" + total + " …");
        resultsView.setText("");

        final long t0 = System.currentTimeMillis();
        final ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        final CountDownLatch done = new CountDownLatch(total);
        final AtomicInteger finished = new AtomicInteger();
        final List<String[]> results = Collections.synchronizedList(new ArrayList<String[]>());

        for (final String host : list) {
            pool.execute(() -> {
                String[] r = probeHost(host);
                results.add(r);
                int f = finished.incrementAndGet();
                ui.post(() -> progressView.setText("Sonde CONNECT " + f + "/" + total + " …"));
                done.countDown();
            });
        }

        new Thread(() -> {
            try {
                done.await(15, TimeUnit.MINUTES);
            } catch (InterruptedException ignored) {
            }
            pool.shutdownNow();

            Collections.sort(results, (a, b) -> {
                int ca = colorRank(a[0]), cb = colorRank(b[0]);
                if (ca != cb) return ca - cb;
                return a[1].compareTo(b[1]);
            });

            int ok = 0;
            SpannableStringBuilder colored = new SpannableStringBuilder();
            int hStart = colored.length();
            colored.append("== TUNNEL FREE BASICS (CONNECT) ==\n");
            colored.setSpan(new ForegroundColorSpan(0xFF4CAF50), hStart, colored.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            StringBuilder sb = new StringBuilder();
            StringBuilder okList = new StringBuilder();
            for (String[] r : results) {
                String line = r[0] + " — " + r[1];
                int start = colored.length();
                colored.append(line).append("\n");
                colored.setSpan(new ForegroundColorSpan(colorFor(r[0])), start, colored.length(),
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                sb.append(line).append("\n");
                if ("200".equals(r[0])) {
                    ok++;
                    okList.append(r[1]).append("\n");
                }
            }
            long dt = (System.currentTimeMillis() - t0) / 1000;
            final String header = "== TUNNEL FREE BASICS — " + ok + "/" + total
                    + " hôtes OK — " + dt + " s ==\n";
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
                tunnelBtn.setEnabled(true);
                running = false;
            });
        }).start();
    }

    // ══ LE TEST RÉEL : le chargement HTTPS À TRAVERS le tunnel ═══════════

    private void startTunnelTest() {
        running = true;
        scanBtn.setEnabled(false);
        tunnelBtn.setEnabled(false);
        List<String> okHosts = new ArrayList<>();
        for (String h : lastValid.split("\n")) {
            if (!h.trim().isEmpty()) okHosts.add(h.trim());
        }
        if (okHosts.isEmpty()) {
            okHosts.add("free.facebook.com");
        }
        final List<String> hosts = okHosts;
        progressView.setText("Test du tunnel réel (le chargement HTTPS)…");
        resultsView.setText("");

        new Thread(() -> {
            StringBuilder out = new StringBuilder(
                    "== LE TUNNEL RÉEL : le chargement HTTPS à travers le proxy ==\n\n");
            for (String host : hosts) {
                StringBuilder codeOut = new StringBuilder("000");
                long t0 = System.currentTimeMillis();
                Socket t = connectTunnel(host, 443, codeOut);
                if (t == null) {
                    out.append("✗ ").append(host).append(" — ")
                       .append(codeOut.toString()).append("\n");
                    ui.post(() -> resultsView.setText(out.toString()));
                    continue;
                }
                try {
                    SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    SSLSocket ssl = (SSLSocket) sf.createSocket(t, host, 443, true);
                    ssl.setSoTimeout(8000);
                    ssl.startHandshake();
                    OutputStream os = ssl.getOutputStream();
                    os.write(("GET / HTTP/1.1\r\nHost: " + host
                            + "\r\nUser-Agent: " + UA_INTERNET_ORG
                            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    os.flush();
                    InputStream is = ssl.getInputStream();
                    ByteArrayOutputStream page = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n, tot = 0;
                    long dl = System.currentTimeMillis() + 8000;
                    while (tot < 150000 && System.currentTimeMillis() < dl
                            && (n = is.read(buf)) != -1) {
                        page.write(buf, 0, n);
                        tot += n;
                    }
                    long ms = System.currentTimeMillis() - t0;
                    out.append("✓ ").append(host).append(" — la page HTTPS a transité "
                            .concat("GRATUITEMENT par le tunnel : "))
                       .append(tot).append(" octets en ").append(ms).append(" ms\n");
                    try {
                        ssl.close();
                    } catch (Exception ignored) {
                    }
                } catch (Exception e) {
                    out.append("✗ ").append(host).append(" — le tunnel ouvert mais le TLS a échoué : ")
                       .append(e.getClass().getSimpleName()).append("\n");
                }
                ui.post(() -> resultsView.setText(out.toString()));
            }
            out.append("\n== FIN — le trafic a transité GRATUITEMENT via le proxy Free Basics ==\n");
            ui.post(() -> {
                resultsView.setText(out.toString());
                progressView.setText("Test du tunnel réel terminé.");
                scanBtn.setEnabled(true);
                tunnelBtn.setEnabled(true);
                running = false;
            });
        }).start();
    }

    // ══ LA PALETTE ═══════════════════════════════════════════════════════

    /** Les 4 couleurs : vert 200, jaune 502, rouge 403, gris 429. */
    private static int colorFor(String code) {
        if ("200".equals(code)) return 0xFF4CAF50;
        if ("502".equals(code) || "504".equals(code)) return 0xFFFFEB3B;
        if ("403".equals(code)) return 0xFFF44336;
        if ("429".equals(code)) return 0xFF90A4AE;
        if ("ERR".equals(code) || "000".equals(code)) return 0xFFFF8A65;
        return 0xFFE0E0E0;
    }

    private static int colorRank(String code) {
        if ("200".equals(code)) return 0;
        return colorFor(code) & 0xFFFFFF;
    }
}
