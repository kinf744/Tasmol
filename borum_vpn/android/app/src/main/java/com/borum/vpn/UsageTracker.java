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
        this.apiBaseUrl = apiBaseUrl == null ? "" : apiBaseUrl;
        this.uuid = uuid == null ? "" : uuid;
    }

    public void start() {
        if (running) {
            return;
        }
        running = true;
        // Initialiser les références pour ne pas envoyer un pic d'emblée
        lastRx = TrafficStats.getUidRxBytes(ctx.getApplicationInfo().uid);
        lastTx = TrafficStats.getUidTxBytes(ctx.getApplicationInfo().uid);
        handler.postDelayed(runner, INTERVAL_MS);
        Log.d(TAG, "UsageTracker démarré");
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
        if (!running || apiBaseUrl.isEmpty() || uuid.isEmpty()) {
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
        new Thread(() -> postToApi(up, down)).start();
    }

    private void postToApi(long bytesUp, long bytesDown) {
        try {
            URL url = new URL(apiBaseUrl.endsWith("/") ? apiBaseUrl + "api/v1/usage/report"
                    : apiBaseUrl + "/api/v1/usage/report");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
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
            Log.d(TAG, "Usage report sent: up=" + bytesUp + " down=" + bytesDown + " code=" + code);
            conn.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "Usage report failed: " + e.getMessage());
        }
    }
}
