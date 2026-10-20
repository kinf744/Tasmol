package com.ephang.vpn;

import android.os.Handler;
import android.os.Looper;

import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import vpnlib.Vpnlib;

/**
 * Java ⇒ Pont Go durci (libpho): activation API pinnée TLS, coffre
 * chiffré au repos, self-check anti-debug. Tout blocage réseau passe ici;
 * aucun endpoint ni secret n'apparaît dans le bytecode Java.
 */
public final class PhoHelper {
    private static final ExecutorService IO = Executors.newCachedThreadPool();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static boolean ready = false;
    private static android.content.Context appCtx;

    public interface Callback {
        void onResult(JSONObject response, Exception error);
    }

    private PhoHelper() {
    }

    public static synchronized void init(android.content.Context ctx) {
        if (ready) {
            return;
        }
        ready = true;
        appCtx = ctx.getApplicationContext();
        Vpnlib.phoInit(ctx.getFilesDir().getAbsolutePath() + "/pho");
    }

    /**
     * Preuve d'appareil anti-clonage : HMAC-SHA256(SHA-256(ANDROID_ID),
     * uuid), hex — identique au calcul natif de Borum VPN (libpho). Le
     * serveur l'épingle au premier register et refuse tout uuid présenté
     * depuis un autre matériel.
     */
    private static String deviceProof(String uuid) {
        try {
            String aid = android.provider.Settings.Secure.getString(
                    appCtx.getContentResolver(),
                    android.provider.Settings.Secure.ANDROID_ID);
            if (aid == null) {
                aid = "";
            }
            java.security.MessageDigest sha =
                    java.security.MessageDigest.getInstance("SHA-256");
            byte[] key = sha.digest(aid.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            byte[] out = mac.doFinal(uuid.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    public static void selfCheck(Callback cb) {
        IO.execute(() -> {
            try {
                deliver(cb, new JSONObject(Vpnlib.phoSelfCheck()), null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    public static void activate(String phone, String code, String uuid, Callback cb) {
        IO.execute(() -> {
            try {
                JSONObject r = new JSONObject(Vpnlib.phoActivate(phone, code, uuid, deviceProof(uuid)));
                if (r.has("error")) {
                    deliver(cb, null, new Exception(r.optString("error")));
                    return;
                }
                deliver(cb, r, null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    public static void configs(String uuid, String code, Callback cb) {
        IO.execute(() -> {
            try {
                JSONObject r = new JSONObject(Vpnlib.phoFetchConfigs(uuid, code));
                if (r.has("error")) {
                    deliver(cb, null, new Exception(r.optString("error")));
                    return;
                }
                deliver(cb, r, null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    /** GET /api/v1/devices/check — statut du compte lié à cet appareil. */
    public static void check(String uuid, Callback cb) {
        IO.execute(() -> {
            try {
                JSONObject r = new JSONObject(Vpnlib.phoCheck(uuid, deviceProof(uuid)));
                if (r.has("error")) {
                    deliver(cb, null, new Exception(r.optString("error")));
                    return;
                }
                deliver(cb, r, null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    // -- coffre chiffré (jamais de valeur lisible dans SharedPreferences) --

    public static void vaultPut(android.content.Context ctx, String uuid, String k, String v) {
        Vpnlib.phoVaultPut(uuid, k, v);
    }

    public static String vaultGet(String uuid, String k) {
        String v = Vpnlib.phoVaultGet(uuid, k);
        return v == null ? "" : v;
    }

    public static void vaultClear(String uuid) {
        Vpnlib.phoVaultClear(uuid);
    }

    private static void deliver(Callback cb, JSONObject resp, Exception err) {
        MAIN.post(() -> cb.onResult(resp, err));
    }
}
