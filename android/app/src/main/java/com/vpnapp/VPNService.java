package com.vpnapp;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.core.app.NotificationCompat;

public class VPNService extends Service {
    private static final String CHANNEL_ID = "vpn_service_channel";
    private static final int NOTIFICATION_ID = 1;
    private Process vpnProcess;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, createNotification());
        startVPNProcess();
        return START_STICKY;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "VPN Service",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("VPN App background service");
            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(channel);
        }
    }

    private Notification createNotification() {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, intent, PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("VPN App Running")
                .setContentText("Tap to open Web UI")
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    private void startVPNProcess() {
        new Thread(() -> {
            try {
                String[] cmd = {
                    "/data/data/com.termux/files/usr/bin/vpn-app",
                    "-config", "/data/data/com.termux/files/home/.vpn-app/config.yaml"
                };
                
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.directory(new java.io.File("/data/data/com.termux/files/home"));
                pb.redirectErrorStream(true);
                
                vpnProcess = pb.start();
                
                // Read output
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(vpnProcess.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.d("VPNService", line);
                }
                
                int exitCode = vpnProcess.waitFor();
                Log.d("VPNService", "VPN process exited with code: " + exitCode);
                
            } catch (Exception e) {
                Log.e("VPNService", "Error starting VPN", e);
            }
        }).start();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (vpnProcess != null) {
            vpnProcess.destroy();
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}