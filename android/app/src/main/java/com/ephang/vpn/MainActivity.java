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

import org.json.JSONObject;

import java.util.Map;

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
        offerCrashReport();
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
            offerLaunchReconnect();
        }
        registerNetworkWatch();
    }

    /** Public fragment swap for sub-screens (Settings / Hotspot under More). */
    public void showFragment(Fragment fragment, String tag) {
        showTab(fragment, tag);
    }

    // Onglets + sous-écrans gardés EN VIE : avant, chaque changement
    // d'onglet recréait le fragment (new + replace) → ré-inflation complète
    // du layout, rechargement de la liste des profils, relecture du journal…
    // d'où la lenteur de navigation. On cache/montre désormais (hide/show).
    private String currentTag = null;
    private static final String[] ALL_TAGS = {
            "home", "configs", "logs", "more", "settings", "hotspot"};

    private void showTab(Fragment fresh, String tag) {
        if (tag.equals(currentTag)) {
            return;
        }
        androidx.fragment.app.FragmentManager fm = getSupportFragmentManager();
        androidx.fragment.app.Fragment target = fm.findFragmentByTag(tag);
        if (target == null) {
            target = fresh;
        }
        androidx.fragment.app.FragmentTransaction tx = fm.beginTransaction();
        if (!target.isAdded()) {
            tx.add(R.id.fragment_container, target, tag);
        }
        for (String t : ALL_TAGS) {
            if (t.equals(tag)) {
                continue;
            }
            androidx.fragment.app.Fragment g = fm.findFragmentByTag(t);
            if (g != null && !g.isHidden()) {
                tx.hide(g);
            }
        }
        tx.show(target);
        tx.commit();
        currentTag = tag;
    }

    /** "Démarrer au lancement": offer one-tap reconnect of the last tunnel. */
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

    /** "Arrêter sur perte réseau": disconnect cleanly when uplink drops. */
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
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(statusTick);
    }

    @Override
    public void onBackPressed() {
        if (!"home".equals(currentTag)) {
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
        // Disconnect is always available: while CONNECTING it supersedes
        // the retry loop (plus nuclear long-press), while connected it
        // stops the session.
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
        // startService() can throw IllegalStateException when the app is not
        // in the foreground on API 31+ (background start restriction). Left
        // uncaught it crashed the main thread from the UncaughtExceptionHandler
        // and the disconnect simply never happened.
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
        // Two-stage watchdog. Teardown is time-bounded on both sides, so a
        // healthy disconnect finishes in ~1-3s and nothing shows. Only a
        // genuinely wedged service pops the dialog — the check is armed past
        // the 15s forced cleanup.
        handler.postDelayed(stuckToastTask, 8000);
        handler.postDelayed(stuckCheckTask, 18000);
    }

    /**
     * True while something is still up: a live session, a start in flight, or
     * a Go teardown that has not come back.
     *
     * <p>Délègue au prédicat complet du service (inclut le thread de
     * connexion en vol et le contrôleur publié non promu) : stopSession()
     * remet controller/starting à faux dès la première ligne, donc un
     * contrôle qui ne regarderait que ces deux drapeaux conclurait « propre »
     * pendant qu'une tentative reconstruit la session.
     */
    private boolean vpnTeardownOutstanding() {
        return TasVpnService.hasSessionActivity();
    }

    /**
     * Best-effort stop that does not depend on the service being startable:
     * flags the generation invalid, drops the notification and, past a short
     * delay, kills the process. Android always revokes the VPN key of a dead
     * service, so this is the guaranteed way to make the key disappear.
     */
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

    /** Power-button path: confirm first when the setting requires it. */
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

    // Watchdogs de déconnexion identifiés, annulés dès qu'une nouvelle
    // connexion démarre (sinon "VPN stuck" apparaît à tort ~18 s après,
    // pendant que le tunnel tourne).
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

    /** If a disconnect left the service alive, propose a nuclear cleanup. */
    private void checkDisconnectStuck() {
        if (!vpnTeardownOutstanding()) {
            return;
        }
        // BadTokenException sinon : l'activité peut être détruite entre le
        // postDelayed et l'affichage (long disconnect + sortie de l'app).
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

    /**
     * Nuclear disconnect: ask the service to stop, then — whether it
     * cooperates or not — kill our own process. Dying takes every child
     * (xray, zivpn, dnstt, ssh), thread and socket with us, and Android
     * always revokes the VPN (key icon) of a dead service. Guaranteed
     * cleanup for the "error + refuses to disconnect" case.
     */
    public void nuclearDisconnect() {
        cancelDisconnectWatchdogs();
        // The service tears down with a short bound (4s instead of 15s), drops
        // the notification immediately and arms its own process-kill watchdog
        // at 5s. The Go core now really does kill the helper processes (xray,
        // uz_core, hysteria, openssh, dnstt) on this path. Our own kill is
        // armed at 3.5s so that, when an Activity is alive, finishAffinity()
        // closes the task cleanly before the process goes; when it is not,
        // the service-side watchdog still guarantees the key is gone.
        try {
            Intent intent = new Intent(this, TasVpnService.class);
            intent.setAction(TasVpnService.ACTION_NUCLEAR_DISCONNECT);
            startService(intent);
        } catch (Exception ignored) {
        }
        showToast("Nuclear disconnect: killing all VPN processes...");
        // Dernier recours à 3.5s : le processus ne meurt QUE si une session
        // est encore vivante (teardown Go coincé ou tentative de connexion
        // toujours en vol — y compris en retry-sleep / avant publication du
        // contrôleur, via connectInFlight). Si la déconnexion a réussi
        // proprement (cas CONNECTED typique), l'application reste ouverte :
        // un nucléaire « propre » ne doit pas se fermer comme un crash.
        handler.postDelayed(() -> {
            if (TasVpnService.hasSessionActivity()) {
                forceKillProcess();
            }
        }, 3500);
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
                    .setPositiveButton("Open Configs", (d, w) -> bottomNav.setSelectedItemId(R.id.nav_configs))
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }
        // Locked profiles: refuse expired, foreign-device or rooted bindings.
        for (JSONObject t : ProfileTransfer.selectedTunnels(this, selected)) {
            String reason = ProfileTransfer.lockReason(this, t);
            if (reason != null && !reason.isEmpty()) {
                showToast(t.optString("name", "Server") + " : " + reason);
                return;
            }
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
                showToast("Failed: " + err);
            }
        }, 2500);
    }

    public void showToast(String message) {
        runOnUiThread(() -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show());
    }

    /**
     * Un crash du lancement precedent a ete enregistre : on propose de le
     * copier dans Download. Sans ce rappel l'utilisateur ne voit jamais le
     * rapport (l'app n'a pas le droit d'ecrire dans Download directement,
     * et le fichier interne est invisible depuis le gestionnaire de fichiers).
     */
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
}
