package com.borum.vpn;

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

    /** Message générique (sans révéler la sonde) si l'environnement est
     *  compromis : l'API d'activation/configs est la cible — on refuse. */
    private static final String SEC_BLOCKED = "Environnement non autorisé";

    public interface Callback {
        void onResult(JSONObject response, Exception error);
    }

    private PhoHelper() {
    }

    private static boolean blocked(Callback cb) {
        if (IntegrityGuard.hardBlocked()) {
            deliver(cb, null, new Exception(SEC_BLOCKED));
            return true;
        }
        return false;
    }

    public static synchronized void init(android.content.Context ctx) {
        if (ready) {
            return;
        }
        ready = true;
        Vpnlib.phoInit(ctx.getFilesDir().getAbsolutePath() + "/pho");
    }

    public static void selfCheck(Callback cb) {
        if (blocked(cb)) {
            return;
        }
        IO.execute(() -> {
            try {
                deliver(cb, new JSONObject(Vpnlib.phoSelfCheck()), null);
            } catch (Exception e) {
                deliver(cb, null, e);
            }
        });
    }

    public static void activate(String phone, String code, String uuid, Callback cb) {
        if (blocked(cb)) {
            return;
        }
        IO.execute(() -> {
            try {
                JSONObject r = new JSONObject(Vpnlib.phoActivate(phone, code, uuid));
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
        if (blocked(cb)) {
            return;
        }
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
        if (blocked(cb)) {
            return;
        }
        IO.execute(() -> {
            try {
                JSONObject r = new JSONObject(Vpnlib.phoCheck(uuid));
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
