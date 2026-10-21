package com.borum.vpn;

import androidx.appcompat.app.AppCompatDelegate;

import androidx.core.os.LocaleListCompat;

/**
 * Thème (Système / Clair / Sombre) et langue (Système / Français / English)
 * — persistés dans les préférences de l'app et réappliqués au démarrage.
 *
 * Le thème pilote AppCompatDelegate.setDefaultNightMode : la palette
 * npv_* vit dans values/colors.xml (clair) et values-night/colors.xml
 * (sombre, palette historique) — toutes les vues qui référencent
 * @color/npv_* basculent automatiquement.
 *
 * La langue pilote AppCompatDelegate.setApplicationLocales (per-app
 * locale, backporté par appcompat 1.6). "system" remet la liste vide.
 */
public final class UiPrefs {

    public static final String PREFS = "borum_vpn_prefs";
    private static final String K_THEME = "set_theme";   // system|light|dark
    private static final String K_LANG = "set_lang";     // system|fr|en

    private UiPrefs() {
    }

    private static android.content.SharedPreferences p(android.content.Context ctx) {
        return ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE);
    }

    // ── Thème ────────────────────────────────────────────────────────────

    public static String getTheme(android.content.Context ctx) {
        return p(ctx).getString(K_THEME, "system");
    }

    public static void setTheme(android.content.Context ctx, String mode) {
        p(ctx).edit().putString(K_THEME, mode).apply();
        applyTheme(mode);
    }

    /** Applique le thème persisté (à appeler au démarrage de l'app). */
    public static void applySavedTheme(android.content.Context ctx) {
        applyTheme(getTheme(ctx));
    }

    private static void applyTheme(String mode) {
        if ("light".equals(mode)) {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);
        } else if ("dark".equals(mode)) {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
        } else {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
        }
    }

    // ── Langue ───────────────────────────────────────────────────────────

    public static String getLang(android.content.Context ctx) {
        return p(ctx).getString(K_LANG, "system");
    }

    public static void setLang(android.content.Context ctx, String mode) {
        p(ctx).edit().putString(K_LANG, mode).apply();
        applyLang(mode);
    }

    /** Applique la langue persistée (à appeler au démarrage de l'app). */
    public static void applySavedLang(android.content.Context ctx) {
        applyLang(getLang(ctx));
    }

    private static void applyLang(String mode) {
        if ("fr".equals(mode)) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("fr"));
        } else if ("en".equals(mode)) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("en"));
        } else {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList());
        }
    }
}
