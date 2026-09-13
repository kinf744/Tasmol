package com.vpnapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) ||
            Intent.ACTION_QUICKBOOT_POWERON.equals(intent.getAction())) {
            
            VPNApplication app = (VPNApplication) context.getApplicationContext();
            if (app.isAutoStartEnabled()) {
                Intent serviceIntent = new Intent(context, VPNService.class);
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent);
                } else {
                    context.startService(serviceIntent);
                }
                Log.d("BootReceiver", "VPN Service started on boot");
            }
        }
    }
}