package com.ephang.vpn;

import java.net.InetSocketAddress;
import java.net.Socket;

/** TCP connect latency probe (no root needed). Runs on caller thread. */
public final class PingUtil {
    private PingUtil() {
    }

    /** Returns round-trip ms, or -1 on failure. */
    public static long ping(String host, int port, int timeoutMs) {
        if (host == null || host.isEmpty() || port <= 0) {
            return -1;
        }
        Socket s = new Socket();
        try {
            long t0 = System.currentTimeMillis();
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            long dt = System.currentTimeMillis() - t0;
            return dt;
        } catch (Exception e) {
            return -1;
        } finally {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    /** Resolve the dial port of a tunnel JSON (port_range first item wins). */
    public static int dialPort(org.json.JSONObject server) {
        if (server == null) {
            return 0;
        }
        String range = server.optString("port_range", "");
        if (!range.isEmpty()) {
            String first = range.split(",")[0].trim().split("-")[0].trim();
            try {
                return Integer.parseInt(first);
            } catch (NumberFormatException ignored) {
            }
        }
        return server.optInt("port", 0);
    }
}
