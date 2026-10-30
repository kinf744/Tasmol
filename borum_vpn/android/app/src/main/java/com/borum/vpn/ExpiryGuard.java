package com.borum.vpn;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public final class ExpiryGuard {
    private static final String TAG = "ExpiryGuard";
    private static final long CHECK_INTERVAL_MS = 300_000L; 

    private static volatile ExpiryGuard instance;
    private final HandlerThread workerThread;
    private final Handler workerHandler;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Runnable checkTask;
    private volatile boolean running = false;

    private ExpiryGuard(Context ctx) {
        workerThread = new HandlerThread("expiry-guard");
        workerThread.start();
        workerHandler = new Handler(workerThread.getLooper());

        checkTask = new Runnable() {
            @Override
            public void run() {
                if (!running) {
                    return;
                }
                try {
                    if (isExpired(ctx)) {
                        Log.w(TAG, "Compte expire detection : reinitialisation forcee");
                        mainHandler.post(() -> forceReset(ctx));
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "Erreur verification expiration", t);
                }
                if (running) {
                    workerHandler.postDelayed(this, CHECK_INTERVAL_MS);
                }
            }
        };
    }

    public static ExpiryGuard getInstance(Context ctx) {
        if (instance == null) {
            instance = new ExpiryGuard(ctx.getApplicationContext());
        }
        return instance;
    }

    public void start() {
        if (running) {
            return;
        }
        running = true;
        workerHandler.postDelayed(checkTask, CHECK_INTERVAL_MS);
    }

    public void stop() {
        running = false;
        workerHandler.removeCallbacks(checkTask);
    }

    private boolean isExpired(Context ctx) {
        String exp = ApiSession.expiresAt(ctx);
        if (exp == null || exp.isEmpty()) {
            return false;
        }
        try {

            long nowServerMs = ApiSession.estimatedServerTimeMs(ctx);
            Date now = nowServerMs >= 0 ? new Date(nowServerMs) : new Date();

            SimpleDateFormat[] patterns = new SimpleDateFormat[]{
                    new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US),
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US),
                    new SimpleDateFormat("yyyy-MM-dd", Locale.US)
            };
            for (SimpleDateFormat fmt : patterns) {
                try {
                    Date d = fmt.parse(exp);
                    if (d != null && d.before(now)) {
                        return true;
                    }
                    break; 
                } catch (Exception ignored) {

                }
            }
            return false;
        } catch (Exception ignored) {

            return false;
        }
    }

    private void forceReset(Context ctx) {
        running = false;
        workerHandler.removeCallbacks(checkTask);

        try {
            Intent disconnect = new Intent(ctx, TasVpnService.class);
            disconnect.setAction(TasVpnService.ACTION_NUCLEAR_DISCONNECT);
            ctx.startService(disconnect);
        } catch (Exception ignored) {
            Log.w(TAG, "Impossible de deconnecter le VPN", ignored);
        }

        ApiSession.resetAll(ctx);
        VPNApplication app = VPNApplication.getInstance();
        if (app != null) {
            app.resetAll();
            app.resetConfigFile(ctx);
        }

        Intent i = new Intent(ctx, AuthActivity.class);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK |
                   Intent.FLAG_ACTIVITY_CLEAR_TOP);
        ctx.startActivity(i);
    }
}
