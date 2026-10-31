package com.borum.vpn;

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

import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends AppCompatActivity {
    private static final int REQ_VPN_PERMISSION = 1001;

    private VPNApplication app;
    private BottomNavigationView bottomNav;
    private String pendingTunnelId = null;
    private final Handler handler = new Handler(Looper.getMainLooper());

    private long lastServerCheckMs = 0;
    private static final long SERVER_CHECK_INTERVAL_MS = 60_000;

    private final Runnable statusTick = new Runnable() {
        @Override
        public void run() {
            if (isFinishing() || isDestroyed()) {
                return;
            }
            Fragment f = getSupportFragmentManager().findFragmentById(R.id.fragment_container);
            if (f instanceof HomeFragment && ((HomeFragment) f).isAdded()) {
                ((HomeFragment) f).refreshStatus();
            }

            checkServerValidity();
            if (!isFinishing() && !isDestroyed()) {
                handler.postDelayed(this, 2000);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        app = VPNApplication.getInstance();

        super.onCreate(savedInstanceState);

        BinaryManager.appendLog("[APP] Démarrage Borum VPN");

        if (!ApiSession.isAuthenticated(this)) {
            Intent i = new Intent(this, AuthActivity.class);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(i);
            finish();
            return;
        }

        setContentView(R.layout.activity_main);

        bottomNav = findViewById(R.id.bottom_nav);
        offerCrashReport();
        bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.nav_home) {
                showTab(new HomeFragment(), "home");
            } else if (id == R.id.nav_profils) {
                showTab(new ProfilsFragment(), "profils");
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
            offerLaunchReconnect();
        }
        registerNetworkWatch();
    }

    public void showFragment(Fragment fragment, String tag) {
        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.fragment_container, fragment, tag)
                .commit();
    }

    private void offerLaunchReconnect() {
        if (!app.isLaunchOnBootEnabled()) {
            return;
        }
        if (TasVpnService.isRunning() || TasVpnService.isStarting()) {
            return;
        }
        String id = app.getActiveTunnelId();
        if (id == null || id.isEmpty()) {
            java.util.LinkedHashSet<String> sel = app.getSelectedIds();
            if (!sel.isEmpty()) {
                id = sel.iterator().next();
            }
        }
        if (id == null || id.isEmpty()) {
            return;
        }
        String name = id;
        try {
            for (Map<String, String> t : BinaryManager.listTunnels(this)) {
                if (id.equals(t.get("id"))) {
                    String n = t.get("name");
                    if (n != null && !n.isEmpty()) {
                        name = n;
                    }
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        final String target = id;
        new AlertDialog.Builder(this)
                .setTitle("Reconnect last session?")
                .setMessage("Connect \"" + name + "\" now?")
                .setPositiveButton("Connect", (d, w) -> requestVpnPermission(target))
                .setNegativeButton("Later", null)
                .show();
    }

    private android.net.ConnectivityManager.NetworkCallback networkWatch = null;

    private void registerNetworkWatch() {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.N) {
            return;
        }
        try {
            android.net.ConnectivityManager cm =
                    (android.net.ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) {
                return;
            }
            networkWatch = new android.net.ConnectivityManager.NetworkCallback() {
                @Override
                public void onLost(android.net.Network network) {
                    if (!app.isStopOnNetworkLossEnabled()) {
                        return;
                    }
                    if (TasVpnService.isRunning() || TasVpnService.isStarting()) {
                        runOnUiThread(() -> {
                            showToast("Network lost - disconnecting");
                            disconnectVpn();
                        });
                    }
                }
            };
            cm.registerDefaultNetworkCallback(networkWatch);
        } catch (Exception ignored) {
        }
    }

    @Override
    protected void onDestroy() {
        try {
            if (networkWatch != null
                    && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                android.net.ConnectivityManager cm =
                        (android.net.ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(networkWatch);
                }
            }
        } catch (Exception ignored) {
        }
        super.onDestroy();
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

        checkExpiry();

        checkServerValidity();
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
        bottomNav.setSelectedItemId(R.id.nav_home);
    }

    public void goToMore() {
        bottomNav.setSelectedItemId(R.id.nav_more);
    }

    public void toggleVpn() {

        if (TasVpnService.isRunning() || TasVpnService.isStarting()) {
            requestDisconnect();
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

        try {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_DISCONNECT);
            startService(intent);
        } catch (Exception e) {
            showToast("Disconnect blocked by Android: force stopping...");
            forceStopVpn();
            return;
        }
        showToast("Disconnecting...");

        handler.postDelayed(stuckToastTask, 8000);
        handler.postDelayed(stuckCheckTask, 18000);
    }

    private boolean vpnTeardownOutstanding() {
        return TasVpnService.hasSessionActivity();
    }

    private void forceStopVpn() {
        try {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_NUCLEAR_DISCONNECT);
            startService(intent);
        } catch (Exception ignored) {
        }
        handler.postDelayed(() -> {
            if (vpnTeardownOutstanding()) {
                forceKillProcess();
            }
        }, 3500);
    }

    public void requestDisconnect() {
        if ((TasVpnService.isRunning() || TasVpnService.isStarting())
                && app.isConfirmDisconnectEnabled()) {
            new AlertDialog.Builder(this)
                    .setTitle("Disconnect VPN?")
                    .setMessage("Stop the active session?")
                    .setPositiveButton("Disconnect", (d, w) -> disconnectVpn())
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }
        disconnectVpn();
    }

    private final Runnable stuckToastTask = () -> {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        if (vpnTeardownOutstanding()) {
            showToast("Still disconnecting...");
        }
    };
    private final Runnable stuckCheckTask = this::checkDisconnectStuck;

    private void cancelDisconnectWatchdogs() {
        handler.removeCallbacks(stuckToastTask);
        handler.removeCallbacks(stuckCheckTask);
        stuckDialogShowing = false;
    }

    private boolean stuckDialogShowing = false;

    private void checkDisconnectStuck() {
        if (!vpnTeardownOutstanding()) {
            return;
        }

        if (stuckDialogShowing || isFinishing() || isDestroyed()) {
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
                    handler.postDelayed(stuckCheckTask, 7000);
                })
                .setCancelable(false)
                .show();
    }

    public void nuclearDisconnect() {
        cancelDisconnectWatchdogs();

        try {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_NUCLEAR_DISCONNECT);
            startService(intent);
        } catch (Exception ignored) {
        }
        showToast("Nuclear disconnect: killing all VPN processes...");

        handler.postDelayed(() -> {
            if (TasVpnService.hasSessionActivity()) {
                forceKillProcess();
            }
        }, 3500);
    }

    public void forceKillProcess() {
        try {
            finishAffinity();
        } catch (Exception ignored) {
        }
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(10);
    }

    public void resetAppKeepingUuid() {

        if (TasVpnService.isRunning() || TasVpnService.isStarting()) {
            disconnectVpn();
        }

        ApiSession.resetAll(this);
        VPNApplication app = VPNApplication.getInstance();
        if (app != null) {
            app.resetAll();
            app.resetConfigFile(this);
        }
        handler.removeCallbacks(statusTick);
        cancelDisconnectWatchdogs();

        Intent i = new Intent(this, AuthActivity.class);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK |
                   Intent.FLAG_ACTIVITY_CLEAR_TOP);
        startActivity(i);
        finish();
        showToast("Application réinitialisée (UUID conservé)");
    }

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
        if (TasVpnService.isStarting()) {
            showToast("Connecting, please wait...");
            return;
        }
        java.util.LinkedHashSet<String> selected = app.getSelectedIds();
        if (selected.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("No server selected")
                    .setMessage("Tap one or more profiles in Configs to select them "
                            + "(green frame), then connect. 2+ selected = round-robin.")
                    .setPositiveButton("Open Configs", (d, w) -> bottomNav.setSelectedItemId(R.id.nav_home))
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }

        for (JSONObject t : ProfileTransfer.selectedTunnels(this, selected)) {
            String reason = ProfileTransfer.lockReason(this, t);
            if (reason != null && !reason.isEmpty()) {
                showToast(t.optString("name", "Server") + " : " + reason);
                return;
            }
        }

        String blockErr = SecurityGuard.checkConnectionAllowed(this);
        if (blockErr != null) {
            showToast(blockErr);
            return;
        }

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
        cancelDisconnectWatchdogs();
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
                showToast("Échec : " + TasVpnService.shortReason(err));
            }
        }, 2500);
    }

    public void showToast(String message) {
        runOnUiThread(() -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show());
    }

    private void offerCrashReport() {
        if (app == null || !app.hasPendingCrash()) {
            return;
        }
        String line = "";
        try {
            String report = app.consumeLastCrashReport();
            for (String l : report.split("\n")) {
                if (l.startsWith("Exception")) {
                    line = l.trim();
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
        final String firstLine = line;
        handler.postDelayed(() -> {
            if (isFinishing()) {
                return;
            }
            new androidx.appcompat.app.AlertDialog.Builder(this)
                    .setTitle("Crash détecté au dernier lancement")
                    .setMessage(firstLine.isEmpty()
                                    ? "Un rapport de crash a été enregistré."
                                    : firstLine + "\n\nLe rapport complet sera enregistré dans Download.")
                    .setPositiveButton("Enregistrer le rapport", (d, w) -> {
                        boolean ok = app.shareLastCrashReport();
                        showToast(ok ? "Rapport enregistré dans Download"
                                : "Enregistrement impossible : voir LOGS");
                    })
                    .setNegativeButton("Ignorer", null)
                    .show();
        }, 800);
    }

    private void checkExpiry() {
        String exp = ApiSession.expiresAt(this);
        if (exp == null || exp.isEmpty()) {
            return;
        }
        try {

            long nowServerMs = ApiSession.estimatedServerTimeMs(this);
            Date now = nowServerMs >= 0 ? new Date(nowServerMs) : new Date();

            SimpleDateFormat[] patterns = new SimpleDateFormat[]{
                    new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US),
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US),
                    new SimpleDateFormat("yyyy-MM-dd", Locale.US)
            };
            Date d = null;
            for (SimpleDateFormat fmt : patterns) {
                try {
                    d = fmt.parse(exp);
                    if (d != null) {
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
            if (d != null && d.before(now)) {

                ApiSession.resetAll(this);
                VPNApplication a = VPNApplication.getInstance();
                a.resetAll();
                a.resetConfigFile(this);
                handler.removeCallbacks(statusTick);
                Intent i = new Intent(this, AuthActivity.class);
                i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                startActivity(i);
                finish();
                showToast("Compte expiré - réinitialisation");
            }
        } catch (Exception ignored) {

        }
    }

    private void checkServerValidity() {
        if (!ApiSession.isAuthenticated(this)) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastServerCheckMs < SERVER_CHECK_INTERVAL_MS) {
            return;
        }
        lastServerCheckMs = now;

        PhoHelper.check(ApiSession.deviceUuid(this), (resp, err) -> {
            if (err != null || resp == null) {

                return;
            }
            boolean activated = resp.optBoolean("activated", false);
            JSONObject account = resp.optJSONObject("account");
            boolean active = account != null && account.optInt("active", 0) == 1;
            if (!activated || !active) {
                runOnUiThread(() -> {
                    ApiSession.resetAll(MainActivity.this);
                    VPNApplication a = VPNApplication.getInstance();
                    if (a != null) {
                        a.resetAll();
                        a.resetConfigFile(MainActivity.this);
                    }
                    handler.removeCallbacks(statusTick);
                    cancelDisconnectWatchdogs();
                    Intent i = new Intent(MainActivity.this, AuthActivity.class);
                    i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK
                            | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                    startActivity(i);
                    finish();
                    showToast("Compte désactivé côté serveur - réinitialisation");
                });
            }
        });
    }
}
