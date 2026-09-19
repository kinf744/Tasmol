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
    public static final String BASE_URL = "https://api-v1.kingom.ggff.net:5443";
    private static final int TIMEOUT_MS = 15000;

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
        HttpURLConnection c = null;
        try {
            URL url = new URL(BASE_URL + path);
            c = (HttpURLConnection) url.openConnection();
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
