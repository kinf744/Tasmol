package com.borum.vpn;

import android.content.Context;
import android.os.SystemClock;

import org.json.JSONObject;

public final class SecurityGuard {
    private static final String PREFS = "borum_security";
    private static final String K_LAST_MONO = "last_mono_realtime";
    private static final String K_LAST_WALL = "last_wall_millis";
    private static final long CLOCK_TOLERANCE_MS = 30_000; 

    private SecurityGuard() {
    }

    private static android.content.SharedPreferences p(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static String checkConnectionAllowed(Context ctx) {
        if (ctx == null) {
            return "Contexte indisponible";
        }

        String clockErr = checkClockTampering(ctx);
        if (clockErr != null) {
            return clockErr;
        }

        JSONObject acc = ApiSession.accountCard(ctx);
        if (acc == null) {

            return null;
        }

        String exp = acc.optString("expires_at", "");
        if (!exp.isEmpty() && isExpired(exp, ctx)) {
            return "Abonnement expiré le " + fmtDate(exp)
                    + ". Contactez l'administrateur pour le renouveler.";
        }

        boolean unlimited = acc.optBoolean("unlimited", false);
        long remaining = acc.optLong("data_remaining_bytes", 0);
        if (!unlimited && remaining <= 0) {
            return "Quota data épuisé (" + fmtData(0) + " restant). "
                    + "Renouvelez votre forfait.";
        }

        return null;
    }

    private static String checkClockTampering(Context ctx) {
        long nowMono = SystemClock.elapsedRealtime();
        long nowWall = System.currentTimeMillis();
        long lastMono = p(ctx).getLong(K_LAST_MONO, -1);
        long lastWall = p(ctx).getLong(K_LAST_WALL, -1);

        if (lastMono >= 0 && lastWall >= 0) {
            long deltaMono = nowMono - lastMono;
            if (deltaMono < -CLOCK_TOLERANCE_MS) {

                if (nowWall < lastWall - CLOCK_TOLERANCE_MS) {

                    return "Horloge système modifiée. "
                            + "Réglage de l'heure interdit pendant un abonnement actif.";
                }

            }
        }
        p(ctx).edit().putLong(K_LAST_MONO, nowMono).putLong(K_LAST_WALL, nowWall).apply();
        return null;
    }

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

    public static void noteSuccessfulCheck(Context ctx) {
        if (ctx == null) return;
        p(ctx).edit()
                .putLong(K_LAST_MONO, SystemClock.elapsedRealtime())
                .putLong(K_LAST_WALL, System.currentTimeMillis())
                .apply();
    }

    public static void resetSecurity(Context ctx) {
        if (ctx == null) return;
        p(ctx).edit().remove(K_LAST_MONO).remove(K_LAST_WALL).apply();
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
