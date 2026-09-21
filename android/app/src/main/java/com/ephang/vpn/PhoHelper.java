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
        Vpnlib.PhoInit(ctx.getFilesDir().getAbsolutePath() + "/pho");
    }

    public static void selfCheck(Callback cb) {
        IO.execute(() -> {
            try {
                deliver(cb, new JSONObject(Vpnlib.PhoSelfCheck()), null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    public static void activate(String phone, String code, String uuid, Callback cb) {
        IO.execute(() -> {
            try {
                JSONObject r = new JSONObject(Vpnlib.PhoActivate(phone, code, uuid));
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
                JSONObject r = new JSONObject(Vpnlib.PhoFetchConfigs(uuid, code));
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
        Vpnlib.PhoVaultPut(uuid, k, v);
    }

    public static String vaultGet(String uuid, String k) {
        String v = Vpnlib.PhoVaultGet(uuid, k);
        return v == null ? "" : v;
    }

    public static void vaultClear(String uuid) {
        Vpnlib.PhoVaultClear(uuid);
    }

    private static void deliver(Callback cb, JSONObject resp, Exception err) {
        MAIN.post(() -> cb.onResult(resp, err));
    }
}
