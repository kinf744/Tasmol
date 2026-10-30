package com.borum.vpn;

import android.content.Context;
import android.os.SystemClock;

import org.json.JSONObject;

/**
 * Garde-fous d'activation : quota data, expiration et anti-contournement
 * de l'horloge.
 *
 * Les trois vérifications s'appuient sur la réponse /api/v1/devices/check
 * (objet "account") fournie par le serveur Stivaros :
 *   - quota_mb <= 0  => illimité
 *   - data_remaining_bytes <= 0 et pas illimité => quota épuisé
 *   - expires_at dans le passé => abonnement expiré
 *
 * Décalage horaire serveur ↔ appareil :
 *   expires_at est stocké côté serveur (heure serveur). L'horloge locale
 *   de l'appareil peut avoir un décalage (ex. +1h) vs le serveur, ce qui
 *   ferait expirer prématurément un compte de courte durée (1h). On stocke
 *   donc l'heure serveur lors du dernier /api/v1/devices/check (via
 *   ApiSession.saveServerTime) et on l'extrapole pour estimer l'heure
 *   serveur courante, utilisée pour toutes les comparaisons d'expiration.
 *
 * Anti-contournement d'horloge :
 *   SystemClock.elapsedRealtime() est monotonique SAUF après un redémarrage
 *   de l'appareil, auquel cas il repart de 0. On croise avec l'heure murale
 *   pour distinguer redémarrage normal et vrai recul d'horloge.
 */
public final class SecurityGuard {
    private static final String PREFS = "borum_security";
    private static final String K_LAST_MONO = "last_mono_realtime";
    private static final String K_LAST_WALL = "last_wall_millis";
    private static final long CLOCK_TOLERANCE_MS = 30_000; // 30s de tolérance

    private SecurityGuard() {
    }

    private static android.content.SharedPreferences p(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /**
     * Vérifie que la connexion est autorisée (quota non épuisé, abonnement
     * non expiré, pas de contournement d'horloge détecté).
     *
     * @return null si tout va bien, sinon un message d'erreur lisible à
     *         afficher à l'utilisateur.
     */
    public static String checkConnectionAllowed(Context ctx) {
        if (ctx == null) {
            return "Contexte indisponible";
        }

        // 1) Anti-contournement d'horloge
        String clockErr = checkClockTampering(ctx);
        if (clockErr != null) {
            return clockErr;
        }

        // 2) Récupérer le dernier compte connu (carte compte API)
        JSONObject acc = ApiSession.accountCard(ctx);
        if (acc == null) {
            // Pas de compte connu : laisser passer, le serveur refusera
            // de toute façon au besoin.
            return null;
        }

        // Expiration : comparer avec l'heure SERVEUR estimée (pas l'heure
        // locale de l'appareil, qui peut être décalée vs le serveur).
        String exp = acc.optString("expires_at", "");
        if (!exp.isEmpty() && isExpired(exp, ctx)) {
            return "Abonnement expiré le " + fmtDate(exp)
                    + ". Contactez l'administrateur pour le renouveler.";
        }

        // Quota
        boolean unlimited = acc.optBoolean("unlimited", false);
        long remaining = acc.optLong("data_remaining_bytes", 0);
        if (!unlimited && remaining <= 0) {
            return "Quota data épuisé (" + fmtData(0) + " restant). "
                    + "Renouvelez votre forfait.";
        }

        return null;
    }

    /**
     * Détecte un recul de l'horloge murale depuis la dernière observation.
     * Retourne un message d'erreur si contournement suspecté, null sinon.
     *
     * SystemClock.elapsedRealtime() est monotonique SAUF après un redémarrage
     * de l'appareil, auquel cas il repart de 0. Un simple recul du compteur
     * mono ne doit donc pas être interprété comme un contournement si
     * l'heure murale (System.currentTimeMillis) a, elle, avancé entre-temps.
     */
    private static String checkClockTampering(Context ctx) {
        long nowMono = SystemClock.elapsedRealtime();
        long nowWall = System.currentTimeMillis();
        long lastMono = p(ctx).getLong(K_LAST_MONO, -1);
        long lastWall = p(ctx).getLong(K_LAST_WALL, -1);

        if (lastMono >= 0 && lastWall >= 0) {
            long deltaMono = nowMono - lastMono;
            if (deltaMono < -CLOCK_TOLERANCE_MS) {
                // Le compteur mono a reculé : soit redémarrage de l'appareil,
                // soit contournement d'horloge. On tranche avec l'heure murale.
                if (nowWall < lastWall - CLOCK_TOLERANCE_MS) {
                    // L'heure murale a aussi reculé : vrai contournement.
                    return "Horloge système modifiée. "
                            + "Réglage de l'heure interdit pendant un abonnement actif.";
                }
                // Sinon : redémarrage normal (mono reset, mur avancé) — on laisse passer.
            }
        }
        p(ctx).edit().putLong(K_LAST_MONO, nowMono).putLong(K_LAST_WALL, nowWall).apply();
        return null;
    }

    /**
     * Vérifie si une date d'expiration (au format serveur, ISO) est dépassée.
     * Utilise l'heure serveur estimée (extrapolée depuis le dernier check API)
     * quand elle est disponible, sinon replie sur l'heure locale.
     */
    private static boolean isExpired(String iso, Context ctx) {
        long nowServerMs = ApiSession.estimatedServerTimeMs(ctx);
        java.util.Date now;
        if (nowServerMs >= 0) {
            now = new java.util.Date(nowServerMs);
        } else {
            now = new java.util.Date();
        }
        try {
            java.text.SimpleDateFormat[] patterns = new java.text.SimpleDateFormat[]{
                    new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.US),
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US),
                    new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
            };
            for (java.text.SimpleDateFormat p : patterns) {
                try {
                    java.util.Date d = p.parse(iso);
                    if (d != null) {
                        return d.before(now);
                    }
                } catch (Exception ignored) {
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /** Marque une vérification réussie (à appeler après une connexion
     *  établie ou un check API réussi). */
    public static void noteSuccessfulCheck(Context ctx) {
        if (ctx == null) return;
        p(ctx).edit()
                .putLong(K_LAST_MONO, SystemClock.elapsedRealtime())
                .putLong(K_LAST_WALL, System.currentTimeMillis())
                .apply();
    }

    /** Efface l'état mémoire de l'horloge (appelé lors du reset de compte). */
    public static void resetSecurity(Context ctx) {
        if (ctx == null) return;
        p(ctx).edit().remove(K_LAST_MONO).remove(K_LAST_WALL).apply();
    }

    // ---------- helpers ----------

    private static String fmtDate(String iso) {
        try {
            java.text.SimpleDateFormat[] patterns = new java.text.SimpleDateFormat[]{
                    new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.US),
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US),
                    new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
            };
            for (java.text.SimpleDateFormat p : patterns) {
                try {
                    java.util.Date d = p.parse(iso);
                    if (d != null) {
                        return new java.text.SimpleDateFormat("d MMM yyyy", java.util.Locale.FRENCH).format(d);
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return iso;
    }

    private static String fmtData(long bytes) {
        if (bytes <= 0) return "0 B";
        double gb = bytes / 1073741824.0;
        if (gb >= 1) {
            String s = String.format(java.util.Locale.US, "%.1f", gb);
            if (s.endsWith(".0")) s = s.substring(0, s.length() - 2);
            return s + " GB";
        }
        double mb = bytes / 1048576.0;
        if (mb >= 1) {
            String s = String.format(java.util.Locale.US, "%.1f", mb);
            if (s.endsWith(".0")) s = s.substring(0, s.length() - 2);
            return s + " MB";
        }
        return bytes + " B";
    }
}
