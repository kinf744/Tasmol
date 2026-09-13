package com.vpnapp;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.util.List;
import java.util.Map;

public class MainActivity extends AppCompatActivity {
    private static final int REQ_VPN_PERMISSION = 1001;

    private WebView webView;
    private ProgressBar progressBar;
    private SwipeRefreshLayout swipeRefresh;
    private FloatingActionButton fabConnect;
    private VPNApplication app;
    private String pendingTunnelId = null;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable statusTick = new Runnable() {
        @Override
        public void run() {
            refreshFab();
            handler.postDelayed(this, 3000);
        }
    };

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        app = VPNApplication.getInstance();

        if (app.isDarkModeEnabled()) {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
        } else {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO);
        }

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        progressBar = findViewById(R.id.progress_bar);
        swipeRefresh = findViewById(R.id.swipe_refresh);
        fabConnect = findViewById(R.id.fab_connect);

        setupWebView();
        setupSwipeRefresh();

        fabConnect.setOnClickListener(v -> onConnectButton());

        // Management UI served by the in-app Go core (when the VPN runs),
        // otherwise fall back to the configured URL.
        loadUrl(app.getServerUrl());
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(statusTick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(statusTick);
    }

    private void setupWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setBuiltInZoomControls(true);
        settings.setDisplayZoomControls(false);
        settings.setSupportZoom(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            settings.setForceDark(app.isDarkModeEnabled() ? WebSettings.FORCE_DARK_ON : WebSettings.FORCE_DARK_OFF);
        }

        CookieManager.getInstance().setAcceptCookie(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);
        }

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                progressBar.setProgress(newProgress);
                progressBar.setVisibility(newProgress == 100 ? View.GONE : View.VISIBLE);
            }

            @Override
            public void onReceivedTitle(WebView view, String title) {
                if (title != null && !title.isEmpty()) {
                    setTitle(title);
                }
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                if (url.startsWith("http://127.0.0.1") || url.startsWith("http://localhost")) {
                    return false;
                }
                if (url.startsWith("http://") || url.startsWith("https://")) {
                    if (url.contains("://192.168.") || url.contains("://10.") || url.contains("://172.")) {
                        return false;
                    }
                }
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                startActivity(intent);
                return true;
            }

            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                swipeRefresh.setRefreshing(false);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                swipeRefresh.setRefreshing(false);
                progressBar.setVisibility(View.GONE);
            }
        });

        webView.addJavascriptInterface(new WebAppInterface(this), "Android");
    }

    private void setupSwipeRefresh() {
        swipeRefresh.setOnRefreshListener(() -> webView.reload());
        swipeRefresh.setColorSchemeResources(android.R.color.holo_blue_bright,
                android.R.color.holo_green_light,
                android.R.color.holo_orange_light,
                android.R.color.holo_red_light);
    }

    private void loadUrl(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }
        webView.loadUrl(url);
    }

    /** Reload the in-app management UI (served by the Go core). */
    public void loadManageUi() {
        loadUrl("http://127.0.0.1:" + app.getManagePort() + "/");
    }

    // --- VPN connect flow ---

    private void onConnectButton() {
        if (TasVpnService.isRunning()) {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_DISCONNECT);
            startService(intent);
            showToast("Disconnecting...");
            handler.postDelayed(this::refreshFab, 800);
            return;
        }
        pickTunnelAndConnect();
    }

    /** Called from the Web UI bridge (window.Android.vpnToggle). */
    public void bridgeToggleVpn() {
        runOnUiThread(this::onConnectButton);
    }

    public void bridgeConnect(String tunnelId) {
        runOnUiThread(() -> {
            if (TasVpnService.isRunning()) {
                showToast("Already connected");
                return;
            }
            requestVpnPermission(tunnelId);
        });
    }

    public void bridgeDisconnect() {
        runOnUiThread(() -> {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_DISCONNECT);
            startService(intent);
        });
    }

    private void pickTunnelAndConnect() {
        List<Map<String, String>> tunnels;
        try {
            tunnels = BinaryManager.listTunnels(this);
        } catch (Exception e) {
            tunnels = null;
        }
        if (tunnels == null || tunnels.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("No tunnel")
                    .setMessage("No tunnel is configured yet. Add one in config.yaml (filesDir) or via Import, then retry.")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }
        if (tunnels.size() == 1 && tunnels.get(0).containsKey("id")) {
            requestVpnPermission(tunnels.get(0).get("id"));
            return;
        }
        String[] names = new String[tunnels.size()];
        for (int i = 0; i < tunnels.size(); i++) {
            String name = tunnels.get(i).get("name");
            String type = tunnels.get(i).get("type");
            names[i] = (name != null ? name : "tunnel") + (type != null ? " (" + type + ")" : "");
        }
        new AlertDialog.Builder(this)
                .setTitle("Choose tunnel")
                .setItems(names, (d, which) -> {
                    String id = tunnels.get(which).get("id");
                    if (id == null || id.isEmpty()) {
                        showToast("Tunnel has no id");
                        return;
                    }
                    requestVpnPermission(id);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void requestVpnPermission(String tunnelId) {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            pendingTunnelId = tunnelId;
            startActivityForResult(prepare, REQ_VPN_PERMISSION);
        } else {
            startTasVpn(tunnelId);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN_PERMISSION) {
            if (resultCode == Activity.RESULT_OK) {
                startTasVpn(pendingTunnelId);
            } else {
                showToast("VPN permission denied");
            }
            pendingTunnelId = null;
        }
    }

    private void startTasVpn(String tunnelId) {
        Intent intent = new Intent(this, TasVpnService.class);
        intent.setAction(TasVpnService.ACTION_CONNECT);
        intent.putExtra(TasVpnService.EXTRA_TUNNEL_ID, tunnelId);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        showToast("Connecting...");
        handler.postDelayed(() -> {
            refreshFab();
            String err = TasVpnService.getLastError();
            if (err != null) {
                showToast("Failed: " + err);
            } else if (TasVpnService.isRunning()) {
                loadManageUi();
            }
        }, 1500);
    }

    private void refreshFab() {
        if (fabConnect == null) {
            return;
        }
        if (TasVpnService.isRunning()) {
            fabConnect.setImageResource(android.R.drawable.ic_media_pause);
        } else {
            fabConnect.setImageResource(android.R.drawable.ic_media_play);
        }
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && webView.canGoBack()) {
            webView.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    public void showToast(String message) {
        runOnUiThread(() -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show());
    }
}
