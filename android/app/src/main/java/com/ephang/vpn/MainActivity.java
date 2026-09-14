package com.ephang.vpn;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;

/**
 * Ephang VPN - modern native home (no browser/WebView dependency, fully
 * offline-capable). Bottom tabs: Home / Servers / Tools / Settings.
 */
public class MainActivity extends AppCompatActivity {
    private static final int REQ_VPN_PERMISSION = 1001;

    private VPNApplication app;
    private BottomNavigationView bottomNav;
    private String pendingTunnelId = null;
    private final Handler handler = new Handler(Looper.getMainLooper());

    private final Runnable statusTick = new Runnable() {
        @Override
        public void run() {
            Fragment f = getSupportFragmentManager().findFragmentById(R.id.fragment_container);
            if (f instanceof HomeFragment) {
                ((HomeFragment) f).refreshStatus();
            }
            handler.postDelayed(this, 2000);
        }
    };

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

        bottomNav = findViewById(R.id.bottom_nav);
        bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.nav_home) {
                showTab(new HomeFragment(), "home");
            } else if (id == R.id.nav_configs) {
                showTab(new ConfigsFragment(), "configs");
            } else if (id == R.id.nav_logs) {
                showTab(new LogsFragment(), "logs");
            } else if (id == R.id.nav_more) {
                showTab(new MoreFragment(), "more");
            } else {
                return false;
            }
            return true;
        });

        if (savedInstanceState == null) {
            showTab(new HomeFragment(), "home");
        }
    }

    private void showTab(Fragment fragment, String tag) {
        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.fragment_container, fragment, tag)
                .commit();
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

    @Override
    public void onBackPressed() {
        Fragment f = getSupportFragmentManager().findFragmentById(R.id.fragment_container);
        if (!(f instanceof HomeFragment)) {
            bottomNav.setSelectedItemId(R.id.nav_home);
        } else {
            super.onBackPressed();
        }
    }

    public void goToConfigs() {
        bottomNav.setSelectedItemId(R.id.nav_configs);
    }

    public void goToMore() {
        bottomNav.setSelectedItemId(R.id.nav_more);
    }

    // --- VPN connect flow (shared by Home tab and dialogs) ---

    public void toggleVpn() {
        if (TasVpnService.isRunning()) {
            disconnectVpn();
        } else {
            pickTunnelAndConnect();
        }
    }

    public void connectTunnel(String tunnelId) {
        if (TasVpnService.isRunning()) {
            showToast("Already connected - disconnect first");
            return;
        }
        requestVpnPermission(tunnelId);
    }

    public void disconnectVpn() {
        Intent intent = new Intent(this, TasVpnService.class);
        intent.setAction(TasVpnService.ACTION_DISCONNECT);
        startService(intent);
        showToast("Disconnecting...");
        // Watchdog: if the service is still alive after 7s (wedged
        // teardown, stuck VPN key), offer the nuclear option.
        handler.postDelayed(this::checkDisconnectStuck, 7000);
    }

    private boolean stuckDialogShowing = false;

    /** If a disconnect left the service alive, propose a nuclear cleanup. */
    private void checkDisconnectStuck() {
        if (!TasVpnService.isRunning() && !TasVpnService.isStarting()) {
            return;
        }
        if (stuckDialogShowing || isFinishing()) {
            return;
        }
        stuckDialogShowing = true;
        new AlertDialog.Builder(this)
                .setTitle("VPN stuck")
                .setMessage("The VPN service did not stop (key icon may still show). "
                        + "Force-close the app to kill every tunnel process and "
                        + "release the VPN? Unsaved edits in open forms will be lost.")
                .setPositiveButton("FORCE CLOSE", (d, w) -> {
                    stuckDialogShowing = false;
                    forceKillProcess();
                })
                .setNegativeButton("Keep waiting", (d, w) -> {
                    stuckDialogShowing = false;
                    handler.postDelayed(this::checkDisconnectStuck, 7000);
                })
                .setCancelable(false)
                .show();
    }

    /**
     * Nuclear disconnect: ask the service to stop, then — whether it
     * cooperates or not — kill our own process. Dying takes every child
     * (xray, zivpn, dnstt, ssh), thread and socket with us, and Android
     * always revokes the VPN (key icon) of a dead service. Guaranteed
     * cleanup for the "error + refuses to disconnect" case.
     */
    public void nuclearDisconnect() {
        try {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_DISCONNECT);
            startService(intent);
        } catch (Exception ignored) {
        }
        showToast("Nuclear disconnect: killing all VPN processes...");
        handler.postDelayed(() -> {
            if (TasVpnService.isRunning() || TasVpnService.isStarting()) {
                forceKillProcess();
            }
        }, 4000);
    }

    /** Kill our own process: children die, system revokes the VPN key. */
    public void forceKillProcess() {
        try {
            finishAffinity();
        } catch (Exception ignored) {
        }
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(10);
    }

    /** Restart the service so edited configs take effect. */
    public void restartVpn() {
        String active = TasVpnService.getActiveTunnelId();
        if (active == null || active.isEmpty()) {
            active = app.getActiveTunnelId();
        }
        disconnectVpn();
        final String id = active;
        handler.postDelayed(() -> {
            if (id != null && !id.isEmpty()) {
                requestVpnPermission(id);
            }
        }, 1200);
    }

    public void pickTunnelAndConnect() {
        java.util.LinkedHashSet<String> selected = app.getSelectedIds();
        if (selected.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("No server selected")
                    .setMessage("Tap one or more profiles in Configs to select them "
                            + "(green frame), then connect. 2+ selected = round-robin.")
                    .setPositiveButton("Open Configs", (d, w) -> bottomNav.setSelectedItemId(R.id.nav_configs))
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }
        // Home connects ALL selected profiles at once (single mode for 1,
        // round-robin for 2+).
        String first = selected.iterator().next();
        app.setActiveTunnelId(first);
        if (selected.size() >= 2) {
            showToast("Connecting " + selected.size() + " profiles (round-robin)...");
        }
        requestVpnPermission(first);
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
            String err = TasVpnService.getLastError();
            if (err != null) {
                showToast("Failed: " + err);
            }
        }, 2500);
    }

    public void showToast(String message) {
        runOnUiThread(() -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show());
    }
}
