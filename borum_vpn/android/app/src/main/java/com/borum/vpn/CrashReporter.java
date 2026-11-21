package com.borum.vpn;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * CrashReporter handles crash reporting for the Borum VPN Android app.
 * Reports crashes, ANRs, disconnections, and other errors to the stivaros API.
 */
public class CrashReporter {
    private static final String TAG = "CrashReporter";
    private static final String API_ENDPOINT = "/api/v1/crash/report";

    private static String apiBaseUrl = "";
    private static String uuid = "";
    private static String appVersion = "";
    private static String deviceModel = "";
    private static String androidVersion = "";
    private static Context appContext = null;
    private static Thread.UncaughtExceptionHandler defaultHandler = null;

    /**
     * Initialize the crash reporter.
     * Must be called early in the application lifecycle (e.g., in Application.onCreate()).
     */
    public static void init(@NonNull Context context, @NonNull String apiBaseUrl, @NonNull String uuid) {
        CrashReporter.apiBaseUrl = apiBaseUrl;
        CrashReporter.uuid = uuid;
        CrashReporter.appContext = context.getApplicationContext();

        // Get app version
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            appVersion = pInfo.versionName;
        } catch (PackageManager.NameNotFoundException e) {
            appVersion = "unknown";
        }

        // Device info
        deviceModel = Build.MODEL;
        androidVersion = Build.VERSION.RELEASE;

        // Set up uncaught exception handler
        defaultHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(@NonNull Thread thread, @NonNull Throwable ex) {
                reportCrash("crash", ex.getMessage(), getStackTrace(ex), thread.getName());
                // Call the default handler after a short delay to allow our report to be sent
                new Thread(() -> {
                    try {
                        Thread.sleep(2000); // Give time for the report to be sent
                    } catch (InterruptedException ignored) {}
                    if (defaultHandler != null) {
                        defaultHandler.uncaughtException(thread, ex);
                    }
                }).start();
            }
        });
    }

    /**
     * Set the UUID for the current user.
     * Call this after user login/activation.
     */
    public static void setUuid(@NonNull String newUuid) {
        uuid = newUuid;
    }

    /**
     * Report a crash/exception.
     */
    public static void reportCrash(@NonNull String crashType, @Nullable String message, @Nullable String stackTrace, @NonNull String threadName) {
        if (uuid == null || uuid.isEmpty() || apiBaseUrl == null || apiBaseUrl.isEmpty()) {
            Log.w(TAG, "Cannot report crash: UUID or API URL not set");
            return;
        }

        new Thread(() -> {
            try {
                sendCrashReport(crashType, message, stackTrace, Thread.currentThread().getName());
            } catch (Exception e) {
                Log.e(TAG, "Failed to send crash report", e);
            }
        }).start();
    }

    /**
     * Report a crash with a Throwable.
     */
    public static void reportCrash(@NonNull String crashType, @NonNull Throwable throwable, @NonNull String threadName) {
        reportCrash(crashType, throwable.getMessage(), getStackTrace(throwable), threadName);
    }

    /**
     * Report a disconnection issue.
     */
    public static void reportDisconnect(@NonNull String reason, @Nullable String details) {
        String message = reason;
        if (details != null && !details.isEmpty()) {
            message += ": " + details;
        }
        reportCrash("disconnect", message, "", "tunnel");
    }

    /**
     * Report a generic error.
     */
    public static void reportError(@NonNull String message, @Nullable String context) {
        String fullMessage = message;
        if (context != null && !context.isEmpty()) {
            fullMessage = context + ": " + message;
        }
        reportCrash("error", fullMessage, "", "background");
    }

    /**
     * Report an exception with stack trace.
     */
    public static void reportException(@NonNull Throwable throwable, @NonNull String context) {
        String message = context + ": " + throwable.getMessage();
        reportCrash("exception", message, getStackTrace(throwable), "tunnel");
    }

    /**
     * Report a network disconnection.
     */
    public static void reportNetworkDisconnect(@NonNull String reason, @Nullable String details) {
        String message = "Network disconnect: " + reason;
        if (details != null && !details.isEmpty()) {
            message += " - " + details;
        }
        reportCrash("disconnect", message, "", "network");
    }

    /**
     * Send the crash report to the API.
     */
    private static void sendCrashReport(String crashType, String message, String stackTrace, String threadName) {
        if (uuid == null || uuid.isEmpty() || apiBaseUrl == null || apiBaseUrl.isEmpty()) {
            return;
        }

        try {
            URL url = new URL(apiBaseUrl + "/api/v1/crash/report");
            HttpURLConnection conn = (HttpURLConnection) new URL(apiBaseUrl + "/api/v1/crash/report").openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            JSONObject json = new JSONObject();
            json.put("uuid", uuid);
            json.put("platform", "android");
            json.put("app_version", appVersion);
            json.put("android_version", androidVersion);
            json.put("device_model", deviceModel);
            json.put("crash_type", crashType);
            json.put("crash_message", message != null ? message : "");
            json.put("stack_trace", stackTrace != null ? stackTrace : "");
            json.put("thread_name", threadName);
            json.put("timestamp", System.currentTimeMillis() / 1000);

            byte[] postData = json.toString().getBytes("UTF-8");
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setRequestProperty("Content-Length", String.valueOf(postData.length));
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.toString().getBytes("UTF-8"));
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Crash report failed with code: " + responseCode);
            }

            conn.disconnect();
        } catch (Exception e) {
            Log.e(TAG, "Failed to send crash report", e);
        }
    }

    /**
     * Get stack trace as string.
     */
    @NonNull
    private static String getStackTrace(@NonNull Throwable throwable) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : throwable.getStackTrace()) {
            sb.append("\tat ").append(element.toString()).append("\n");
        }
        // Add cause if present
        Throwable cause = throwable.getCause();
        while (cause != null) {
            sb.append("Caused by: ").append(cause.toString()).append("\n");
            for (StackTraceElement element : cause.getStackTrace()) {
                sb.append("\tat ").append(element.toString()).append("\n");
            }
            cause = cause.getCause();
        }
        return sb.toString();
    }

    /**
     * Set the API base URL.
     */
    public static void setApiBaseUrl(@NonNull String url) {
        apiBaseUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * Get the current UUID.
     */
    @Nullable
    public static String getUuid() {
        return uuid;
    }

    /**
     * Check if crash reporter is initialized.
     */
    public static boolean isInitialized() {
        return !uuid.isEmpty() && !apiBaseUrl.isEmpty();
    }
}