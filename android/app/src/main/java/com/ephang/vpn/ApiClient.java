package com.ephang.vpn;

import android.os.Handler;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Thin client for the remote-config API (api-v1.kingom.ggff.net),
 * mirroring the Stivaros panel protocol:
 *   POST /api/v1/devices/register {uuid/device_install_id, phone_number, activation_code}
 *   GET  /api/v1/user/configs?uuid=..&code=..
 */
public final class ApiClient {
    // Endpoints essayés dans l'ordre jusqu'au premier qui répond.
    // NB: Cloudflare ne proxifie que certains ports HTTPS (443, 2053,
    // 2083, 2087, 2096, 8443) — 5443 y est refusé (connection reset).
    public static final String[] BASE_URLS = {
            // Fonctionne via HAProxy (SNI api-v1 -> API :9443): port 443,
            // le seul systématiquement ouvert sur les réseaux "gratuits".
            "https://api-v1.kingom.ggff.net",
            "https://api-v1.kingom.ggff.net:8443",
            "https://api-v1.kingom.ggff.net:5443",
            "http://api-v1.kingom.ggff.net:9090",
    };
    private static final int TIMEOUT_MS = 15000;

    // L'API d'activation tourne typiquement derrière un vhost auto-signé
    // sur le VPS (cert CN = domaine du tunnel, pas api-v1). Hors système
    // CA + SNI mismatch, HttpsURLConnection rejette systématiquement. On
    // assouplit TLS pour CES endpoints uniquement (payload limité à
    // phone/code/uuid ; le code est l'authentifiant, pas le canal).
    private static javax.net.ssl.SSLSocketFactory permissiveFactory;
    private static final javax.net.ssl.HostnameVerifier PERMISSIVE_HOSTNAME =
            (hostname, session) -> true;

    private static synchronized javax.net.ssl.SSLSocketFactory permissiveTLS() {
        if (permissiveFactory == null) {
            try {
                javax.net.ssl.TrustManager[] tm = {new javax.net.ssl.X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {
                        if (c != null && c.length > 0) {
                            try {
                                java.security.MessageDigest md =
                                        java.security.MessageDigest.getInstance("SHA-256");
                                byte[] h = md.digest(c[0].getEncoded());
                                StringBuilder sb = new StringBuilder();
                                for (byte b : h) {
                                    sb.append(String.format("%02x", b));
                                }
                                logApi("tls", "cert serveur accepté sha256=" + sb
                                        + " CN=" + c[0].getSubjectX500Principal());
                            } catch (Exception ignored) {
                            }
                        }
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                }};
                javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
                ctx.init(null, tm, new java.security.SecureRandom());
                permissiveFactory = ctx.getSocketFactory();
            } catch (Exception ignored) {
            }
        }
        return permissiveFactory;
    }

    private static final ExecutorService IO = Executors.newCachedThreadPool();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    public interface Callback {
        void onResult(JSONObject response, Exception error);
    }

    private ApiClient() {
    }

    /** POST /api/v1/devices/register — activates this device (phone+code+uuid). */
    public static void register(String phone, String code, String uuid, Callback cb) {
        IO.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("uuid", uuid);
                body.put("device_install_id", uuid);
                body.put("phone_number", phone);
                body.put("activation_code", code);
                JSONObject resp = request("POST", "/api/v1/devices/register", body);
                deliver(cb, resp, null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    /** GET /api/v1/user/configs — list the subscriber's server configs. */
    public static void fetchConfigs(String uuid, String code, Callback cb) {
        IO.execute(() -> {
            try {
                String q = "/api/v1/user/configs?uuid=" + enc(uuid) + "&code=" + enc(code);
                JSONObject resp = request("GET", q, null);
                deliver(cb, resp, null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    /** GET /api/v1/devices/check — is the device still activated? */
    public static void checkDevice(String uuid, Callback cb) {
        IO.execute(() -> {
            try {
                JSONObject resp = request("GET", "/api/v1/devices/check?device_id=" + enc(uuid), null);
                deliver(cb, resp, null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    private static void deliver(Callback cb, JSONObject resp, Exception err) {
        MAIN.post(() -> cb.onResult(resp, err));
    }

    private static String enc(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static JSONObject request(String method, String path, JSONObject body) throws Exception {
        Exception last = null;
        JSONObject stray = null; // réponse HTTP non-API (ex: rejet Xray vide)
        for (String base : BASE_URLS) {
            logApi(method + " " + path, "-> " + base + path);
            try {
                JSONObject r = requestOn(base, method, path, body);
                // Une vraie réponse API porte success/activated/message.
                if (r.has("success") || r.has("activated") || r.has("message")) {
                    logApi(method + " " + path, "<- " + base + " OK");
                    return r;
                }
                stray = r; // bruit d'un autre service (Xray/haproxy): on continue
                logApi(method + " " + path, "<- " + base + " non-API, endpoint suivant");
            } catch (Exception e) {
                last = e;
                logApi(method + " " + path, "<- " + base + " FAIL " + describe(e));
            }
        }
        if (stray != null) {
            return stray;
        }
        throw last != null ? last : new Exception("no API endpoint");
    }

    /** Chaîne cause complète (SocketException -> cause, etc.). */
    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            if (sb.length() > 0) {
                sb.append(" <- ");
            }
            sb.append(t.getClass().getSimpleName())
              .append(": ").append(String.valueOf(t.getMessage()));
            t = t.getCause();
        }
        return sb.toString();
    }

    /** Journal d'activation: visible dans l'onglet Logs ET dans
     *  Download/kighmu.txt (secrets masqués). */
    private static void logApi(String op, String msg) {
        // Ne jamais écrire le code d'activation: seuls 2 derniers chiffres.
        String safe = msg.replaceAll("(code=|activation_code[\"=:\\s]*)([0-9]{4})([0-9]{2})",
                "$1****$3");
        TasVpnService.logEvent("info", "api", op + " " + safe);
    }

    private static JSONObject requestOn(String base, String method, String path,
                                        JSONObject body) throws Exception {
        HttpURLConnection c = null;
        try {
            URL url = new URL(base + path);
            c = (HttpURLConnection) url.openConnection();
            if (c instanceof javax.net.ssl.HttpsURLConnection) {
                javax.net.ssl.SSLSocketFactory f = permissiveTLS();
                if (f != null) {
                    javax.net.ssl.HttpsURLConnection hs =
                            (javax.net.ssl.HttpsURLConnection) c;
                    hs.setSSLSocketFactory(f);
                    hs.setHostnameVerifier(PERMISSIVE_HOSTNAME);
                }
            }
            c.setConnectTimeout(TIMEOUT_MS);
            c.setReadTimeout(TIMEOUT_MS);
            c.setRequestMethod(method);
            c.setRequestProperty("Accept", "application/json");
            if (body != null) {
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");
                byte[] out = body.toString().getBytes(StandardCharsets.UTF_8);
                OutputStream os = c.getOutputStream();
                os.write(out);
                os.flush();
                os.close();
            }
            int code = c.getResponseCode();
            InputStream is = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
            String text = readAll(is);
            logApi(method + " " + path, "HTTP " + code + " (" + text.length()
                    + " o): " + (text.length() > 300 ? text.substring(0, 300) + "…" : text));
            JSONObject resp = text.isEmpty() ? new JSONObject() : new JSONObject(text);
            // Surface HTTP-level failures in a uniform field.
            if (code >= 400 && !resp.has("success")) {
                resp.put("success", false);
            }
            return resp;
        } finally {
            if (c != null) {
                c.disconnect();
            }
        }
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) {
            return "";
        }
        BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line);
        }
        r.close();
        return sb.toString();
    }

    /** Extract the configs array from a /user/configs response (never null). */
    public static JSONArray configsOf(JSONObject resp) {
        if (resp == null) {
            return new JSONArray();
        }
        JSONArray a = resp.optJSONArray("configs");
        return a != null ? a : new JSONArray();
    }
}
