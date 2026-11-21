package com.borum.vpn;

import android.content.Context;
import android.net.TrafficStats;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * UsageTracker suit la consommation de données du tunnel VPN et l'envoie
 * périodiquement à l'API stivaros (/api/v1/usage/report) afin que le
 * panel admin et l'onglet Profils affichent la consommation exacte de
 * chaque compte (y compris en illimité).
 *
 * Utilise TrafficStats pour l'UID de l'application : comme BORUM VPN est
 * une appli VPN dédiée, la quasi-totalité du trafic passe par le tunnel.
 */
public final class UsageTracker {
    private static final String TAG = "UsageTracker";
    private static final String ENDPOINT = "/api/v1/usage/report";
    private static final long INTERVAL_MS = 30_000; // envoi toutes les 30s

    private final Context ctx;
    private final String apiBaseUrl;
    private final String uuid;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable runner = new Runnable() {
        @Override
        public void run() {
            sendUsage();
            handler.postDelayed(this, INTERVAL_MS);
        }
    };

    private long lastRx = -1;
    private long lastTx = -1;
    private boolean running = false;

    public UsageTracker(Context ctx, String apiBaseUrl, String uuid) {
        this.ctx = ctx.getApplicationContext();
        this.apiBaseUrl = (apiBaseUrl == null || apiBaseUrl.isEmpty()) ? "" : apiBaseUrl;
        this.uuid = (uuid == null) ? "" : uuid.trim();
    }

    /** Retourne true si le tracker peut envoyer (URL + UUID valides). */
    public boolean isReady() {
        return !apiBaseUrl.isEmpty() && !uuid.isEmpty();
    }

    public void start() {
        if (running) {
            return;
        }
        if (!isReady()) {
            Log.w(TAG, "UsageTracker non prêt: apiBaseUrl='" + apiBaseUrl + "' uuid='" + uuid + "'");
            return;
        }
        running = true;
        // Initialiser les références pour ne pas envoyer un pic d'emblée
        lastRx = TrafficStats.getUidRxBytes(ctx.getApplicationInfo().uid);
        lastTx = TrafficStats.getUidTxBytes(ctx.getApplicationInfo().uid);
        // Envoi immédiat pour ne pas perdre les premiers octets
        handler.post(runner);
        Log.d(TAG, "UsageTracker démarré (envoi immédiat)");
    }

    public void stop() {
        if (!running) {
            return;
        }
        running = false;
        handler.removeCallbacks(runner);
        // Envoi final des données restantes
        sendUsage();
        lastRx = -1;
        lastTx = -1;
        Log.d(TAG, "UsageTracker arrêté");
    }

    private void sendUsage() {
        if (!running || !isReady()) {
            return;
        }
        long rx = TrafficStats.getUidRxBytes(ctx.getApplicationInfo().uid);
        long tx = TrafficStats.getUidTxBytes(ctx.getApplicationInfo().uid);
        if (lastRx < 0 || lastTx < 0) {
            lastRx = rx;
            lastTx = tx;
            return;
        }
        long up = Math.max(0, tx - lastTx);
        long down = Math.max(0, rx - lastRx);
        lastRx = rx;
        lastTx = tx;
        if (up == 0 && down == 0) {
            return;
        }
        new Thread(() -> postToApi(up, down, 0)).start();
    }

    private void postToApi(final long bytesUp, final long bytesDown, final int attempt) {
        if (attempt >= 2) {
            Log.w(TAG, "Usage report échoué après 2 tentatives");
            return;
        }
        try {
            String base = apiBaseUrl.endsWith("/") ? apiBaseUrl : apiBaseUrl + "/";
            URL url = new URL(base + "api/v1/usage/report");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);
            JSONObject body = new JSONObject();
            body.put("uuid", uuid);
            body.put("bytes_up", bytesUp);
            body.put("bytes_down", bytesDown);
            body.put("timestamp", System.currentTimeMillis());
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.toString().getBytes("UTF-8"));
            }
            int code = conn.getResponseCode();
            String resp = "";
            try {
                java.io.InputStream is = conn.getInputStream();
                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(is));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                resp = sb.toString();
                br.close();
            } catch (Exception ignored) {
            }
            Log.d(TAG, "Usage report sent: up=" + bytesUp + " down=" + bytesDown + " code=" + code + " resp=" + resp);
            conn.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "Usage report tentative " + (attempt + 1) + " échouée: " + e.getMessage());
            // Retry immédiat une fois
            new Thread(() -> postToApi(bytesUp, bytesDown, attempt + 1)).start();
        }
    }
}
