package com.ephang.vpn;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONObject;


public final class TunnelPing {
    private TunnelPing() {
    }

    public interface Callback {
        
        void onResult(long ms, String via);
    }

    public static void ping(Context ctx, JSONObject tunnel, Callback cb) {
        Handler main = new Handler(Looper.getMainLooper());
        new Thread(() -> {
            long ms = -1;
            String via = "";
            try {
                String id = tunnel.optString("id", "");
                String type = tunnel.optString("type", "");
                JSONObject server = tunnel.optJSONObject("server");
                String host = server != null ? server.optString("host", "") : "";
                int port = server != null ? PingUtil.dialPort(server) : 0;

                if (TasVpnService.isRunning() && !id.isEmpty()) {
                    try {
                        String cfgPath = BinaryManager.configPath(ctx).getAbsolutePath();
                        JSONObject o = new JSONObject(VpnlibHelper.socksAddrFor(cfgPath, id));
                        if (!o.has("error")) {
                            String socks = o.optString("socks", "");
                            String[] hp = socks.split(":");
                            if (hp.length == 2) {
                                ms = SocksUdpPing.ping(hp[0], Integer.parseInt(hp[1]), 5000);
                                via = "udp";
                                if (ms < 0) {
                                    
                                    
                                    ms = SocksTcpPing.ping(hp[0], Integer.parseInt(hp[1]), 5000);
                                    via = "tun";
                                }
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
                if (ms < 0 && !host.isEmpty() && port > 0) {
                    
                    
                    
                    ms = PingUtil.ping(host, port, 4000);
                    via = "tcp";
                }
                if (ms < 0) {
                    via = "";
                }
                final boolean isUdpOnly = type.equals("zivpn");
                final long result = ms;
                final String how = via;
                final boolean udpOnly = isUdpOnly;
                main.post(() -> {
                    if (result >= 0 || !udpOnly) {
                        cb.onResult(result, how);
                    } else {
                        cb.onResult(-2, "udp"); 
                    }
                });
            } catch (Exception e) {
                main.post(() -> cb.onResult(-1, ""));
            }
        }).start();
    }
}
