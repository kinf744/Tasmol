package com.vpnapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) ||
            "android.intent.action.QUICKBOOT_POWERON".equals(intent.getAction())) {

            VPNApplication app = (VPNApplication) context.getApplicationContext();
            if (!app.isAutoStartEnabled()) {
                return;
            }
            String tunnelId = app.getActiveTunnelId();
            if (tunnelId == null || tunnelId.isEmpty()) {
                tunnelId = BinaryManager.firstTunnelId(context);
            }
            if (tunnelId == null || tunnelId.isEmpty()) {
                Log.i("BootReceiver", "no tunnel configured, skipping autostart");
                return;
            }
            Intent serviceIntent = new Intent(context, TasVpnService.class);
            serviceIntent.setAction(TasVpnService.ACTION_CONNECT);
            serviceIntent.putExtra(TasVpnService.EXTRA_TUNNEL_ID, tunnelId);
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
            Log.i("BootReceiver", "TasVpnService started on boot");
        }
    }
}
