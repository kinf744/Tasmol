package com.vpnapp;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

public class WebAppInterface {
    private Context context;

    public WebAppInterface(Context context) {
        this.context = context;
    }

    @JavascriptInterface
    public void showToast(String message) {
        android.os.Handler handler = new android.os.Handler(context.getMainLooper());
        handler.post(() -> Toast.makeText(context, message, Toast.LENGTH_SHORT).show());
    }

    @JavascriptInterface
    public void copyToClipboard(String text) {
        android.os.Handler handler = new android.os.Handler(context.getMainLooper());
        handler.post(() -> {
            ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("VPN Config", text);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show();
        });
    }

    @JavascriptInterface
    public void openExternalUrl(String url) {
        android.os.Handler handler = new android.os.Handler(context.getMainLooper());
        handler.post(() -> {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
        });
    }

    @JavascriptInterface
    public void shareText(String text, String title) {
        android.os.Handler handler = new android.os.Handler(context.getMainLooper());
        handler.post(() -> {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT, text);
            intent.putExtra(Intent.EXTRA_SUBJECT, title);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(Intent.createChooser(intent, "Share via"));
        });
    }

    @JavascriptInterface
    public String getAppVersion() {
        return BuildConfig.VERSION_NAME;
    }

    @JavascriptInterface
    public boolean isDarkMode() {
        return VPNApplication.getInstance().isDarkModeEnabled();
    }

    /** Called by the Web UI main Connect button inside the APK. */
    @JavascriptInterface
    public void vpnToggle() {
        if (context instanceof MainActivity) {
            ((MainActivity) context).bridgeToggleVpn();
        }
    }

    @JavascriptInterface
    public void vpnConnect(String tunnelId) {
        if (context instanceof MainActivity) {
            ((MainActivity) context).bridgeConnect(tunnelId);
        }
    }

    @JavascriptInterface
    public void vpnDisconnect() {
        if (context instanceof MainActivity) {
            ((MainActivity) context).bridgeDisconnect();
        }
    }

    @JavascriptInterface
    public String vpnStatus() {
        return TasVpnService.controllerStatus();
    }

    @JavascriptInterface
    public boolean vpnRunning() {
        return TasVpnService.isRunning();
    }
}