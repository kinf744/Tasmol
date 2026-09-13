package com.vpnapp;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

public class VPNApplication extends Application {
    private static VPNApplication instance;
    private SharedPreferences prefs;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        prefs = getSharedPreferences("vpn_app_prefs", Context.MODE_PRIVATE);
    }

    public static VPNApplication getInstance() {
        return instance;
    }

    public SharedPreferences getPrefs() {
        return prefs;
    }

    public String getServerUrl() {
        return prefs.getString("server_url", "http://127.0.0.1:" + getManagePort() + "/");
    }

    public int getManagePort() {
        return prefs.getInt("manage_port", 18080);
    }

    public void setManagePort(int port) {
        prefs.edit().putInt("manage_port", port).apply();
    }

    public String getActiveTunnelId() {
        return prefs.getString("active_tunnel_id", "");
    }

    public void setActiveTunnelId(String id) {
        prefs.edit().putString("active_tunnel_id", id == null ? "" : id).apply();
    }

    public void setServerUrl(String url) {
        prefs.edit().putString("server_url", url).apply();
    }

    public boolean isAutoStartEnabled() {
        return prefs.getBoolean("auto_start", true);
    }

    public void setAutoStartEnabled(boolean enabled) {
        prefs.edit().putBoolean("auto_start", enabled).apply();
    }

    public boolean isDarkModeEnabled() {
        return prefs.getBoolean("dark_mode", false);
    }

    public void setDarkModeEnabled(boolean enabled) {
        prefs.edit().putBoolean("dark_mode", enabled).apply();
    }
}