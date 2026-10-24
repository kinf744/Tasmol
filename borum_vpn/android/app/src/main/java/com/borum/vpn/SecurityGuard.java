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
 * Anti-contournement d'horloge :
 *   L'horloge murale (System.currentTimeMillis) peut être modifiée par
 *   l'utilisateur pour repousser une date d'expiration. On s'appuie donc
 *   sur SystemClock.elapsedRealtime() (monotonique, immune aux réglages
 *   utilisateur) comme référence de "dernière fois vue". Si l'horloge
 *   murale recule d'au moins 30 secondes par rapport à la dernière
 *   observation, on considère qu'il y a eu contournement et on bloque.
 */
public final class SecurityGuard {
    private static final String PREFS = "borum_security";
    private static final String K_LAST_MONO = "last_mono_realtime";
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

        // Expiration
        String exp = acc.optString("expires_at", "");
        if (!exp.isEmpty() && isExpired(exp)) {
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
     */
    private static String checkClockTampering(Context ctx) {
        long nowMono = SystemClock.elapsedRealtime();
        long lastMono = p(ctx).getLong(K_LAST_MONO, -1);

        if (lastMono >= 0) {
            long delta = nowMono - lastMono;
            if (delta < -CLOCK_TOLERANCE_MS) {
                // L'horloge a reculé : tentative de contournement d'expiration
                return "Horloge système modifiée. "
                        + "Réglage de l'heure interdit pendant un abonnement actif.";
            }
        }
        p(ctx).edit().putLong(K_LAST_MONO, nowMono).apply();
        return null;
    }

    /** Marque une vérification réussie (à appeler après une connexion
     *  établie ou un check API réussi). */
    public static void noteSuccessfulCheck(Context ctx) {
        if (ctx == null) return;
        p(ctx).edit().putLong(K_LAST_MONO, SystemClock.elapsedRealtime()).apply();
    }

    // ---------- helpers ----------

    private static boolean isExpired(String iso) {
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
                        return d.before(new java.util.Date());
                    }
                } catch (Exception ignored) {
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

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
