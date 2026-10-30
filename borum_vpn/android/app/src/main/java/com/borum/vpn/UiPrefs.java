package com.borum.vpn;

import androidx.appcompat.app.AppCompatDelegate;

import androidx.core.os.LocaleListCompat;

public final class UiPrefs {

    public static final String PREFS = "borum_vpn_prefs";
    private static final String K_THEME = "set_theme";   
    private static final String K_LANG = "set_lang";     

    private UiPrefs() {
    }

    private static android.content.SharedPreferences p(android.content.Context ctx) {
        return ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE);
    }

    public static String getTheme(android.content.Context ctx) {
        return p(ctx).getString(K_THEME, "system");
    }

    public static void setTheme(android.content.Context ctx, String mode) {
        p(ctx).edit().putString(K_THEME, mode).apply();
        applyTheme(mode);
    }

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

    public static String getLang(android.content.Context ctx) {
        return p(ctx).getString(K_LANG, "system");
    }

    public static void setLang(android.content.Context ctx, String mode) {
        p(ctx).edit().putString(K_LANG, mode).apply();
        applyLang(mode);
    }

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
