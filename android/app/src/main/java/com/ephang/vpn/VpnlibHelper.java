package com.ephang.vpn;

import vpnlib.Vpnlib;

/**
 * Single place calling the gomobile bindings (easy to adapt if the
 * generated signatures ever change).
 */
public final class VpnlibHelper {
    private VpnlibHelper() {
    }

    public static String listTunnels(String configPath) {
        return Vpnlib.listTunnels(configPath);
    }

    public static String socksAddrFor(String configPath, String id) {
        return Vpnlib.socksAddrFor(configPath, id);
    }

    public static String parseLink(String link) {
        return Vpnlib.parseLink(link);
    }

    public static String configAdd(String configPath, String tunnelJSON) {
        return Vpnlib.configAdd(configPath, tunnelJSON);
    }

    public static String configUpdate(String configPath, String id, String tunnelJSON) {
        return Vpnlib.configUpdate(configPath, id, tunnelJSON);
    }

    public static String configDelete(String configPath, String id) {
        return Vpnlib.configDelete(configPath, id);
    }

    public static String version() {
        return Vpnlib.mobileVersion();
    }
}
