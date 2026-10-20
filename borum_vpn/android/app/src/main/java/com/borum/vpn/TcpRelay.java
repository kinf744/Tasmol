package com.borum.vpn;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * LAN proxy relay for Hotspot sharing (no root): listens on all interfaces
 * and pipes each TCP connection to the active tunnel's local SOCKS. TCP
 * only: UDP ASSOCIATE replies carry 127.0.0.1 and cannot cross hosts.
 *
 * The listen port is FIXED (8080) so client devices never have to be
 * reconfigured; the advertised proxy IP (172.16.x.x, fresh per launch) is
 * chosen by the caller. Byte counters track the real traffic relayed.
 */
public final class TcpRelay {
    /** Fixed proxy port, never changes between launches. */
    // Port du relais résolu par le natif (plus de littéral exploitable
    // dans le DEX) ; repli identique si libpho est indisponible.
    public static final int FIXED_PORT = nativeRelayPort();

    private static int nativeRelayPort() {
        try {
            return vpnlib.Vpnlib.phoPortRelay();
        } catch (Throwable t) {
            return 8080;
        }
    }

    // HARD crash fix (itel P662L, OOM pthread_create, 2187 threads):
    // newCachedThreadPool() acceptait une connexion = 3 threads (relais +
    // t1 up + t2 down) SANS LIMITE. Quelques dizaines de clients hotspot
    // navigant en parallèle faisaient dépasser 2000 threads natifs
    // (1 Mo de stack chacun) — OutOfMemoryError dans acceptLoop.
    // Pool BORNÉ à 32 relais simultanés (≈ 97 threads max) avec une
    // SynchronousQueue + CallerRunsPolicy : au-delà, la tâche tourne sur
    // le thread d'accept, donc accept() bloque et le backlog TCP gère la
    // file d'attente nativement — aucun thread n'est jamais créé en trop.
    private static final int MAX_CONCURRENT_RELAYS = 32;

    private static ThreadFactory daemonThreads(final String prefix) {
        return r -> {
            Thread t = new Thread(r, prefix);
            t.setDaemon(true);
            return t;
        };
    }

    private ServerSocket server;
    private ExecutorService pool;
    private Thread acceptThread;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private String targetHost = "127.0.0.1";
    private int targetPort;
    private int listenPort;
    private String proxyIp = "";

    // Cumulated bytes: up = client -> upstream (envoyés),
    // down = upstream -> client (reçus).
    private final AtomicLong upBytes = new AtomicLong(0);
    private final AtomicLong downBytes = new AtomicLong(0);

    public synchronized boolean start(String targetHost, int targetPort) {
        return start(targetHost, targetPort, "");
    }

    public synchronized boolean start(String targetHost, int targetPort, String proxyIp) {
        // Défaut sûr : écoute locale uniquement (jamais de relais ouvert
        // sur le réseau sans demande explicite).
        return start(targetHost, targetPort, proxyIp, false);
    }

    public synchronized boolean start(String targetHost, int targetPort, String proxyIp,
                                      boolean allowLan) {
        if (running.get()) {
            return true;
        }
        try {
            this.targetHost = targetHost;
            this.targetPort = targetPort;
            this.proxyIp = proxyIp == null ? "" : proxyIp;
            server = new ServerSocket();
            server.setReuseAddress(true);
            // Bind 0.0.0.0 SEULEMENT quand le partage hotspot est réellement
            // actif (les clients du point d'accès doivent joindre l'IP LAN du
            // téléphone). Sinon : 127.0.0.1 — un relais sans authentification
            // ne doit jamais être joignable depuis un réseau voisin
            // (hotspot éteint mais téléphone sur un Wi-Fi partagé).
            String bindAddr = allowLan ? "0.0.0.0" : "127.0.0.1";
            try {
                server.bind(new InetSocketAddress(bindAddr, FIXED_PORT));
            } catch (Exception busy) {
                server.bind(new InetSocketAddress(bindAddr, 0));
            }
            listenPort = server.getLocalPort();
            upBytes.set(0);
            downBytes.set(0);
            pool = new ThreadPoolExecutor(
                    0, MAX_CONCURRENT_RELAYS,
                    30L, TimeUnit.SECONDS,
                    new SynchronousQueue<>(),
                    daemonThreads("borum-relay-io"),
                    new CallerRunsPolicy());
            running.set(true);
            acceptThread = new Thread(this::acceptLoop, "borum-relay");
            acceptThread.setDaemon(true);
            acceptThread.start();
            return true;
        } catch (Exception e) {
            stop();
            return false;
        }
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = server.accept();
                pool.execute(() -> relay(client));
            } catch (Exception e) {
                if (!running.get()) {
                    break;
                }
            }
        }
    }

    private void relay(Socket client) {
        Socket upstream = new Socket();
        try {
            client.setTcpNoDelay(true);
            upstream.connect(new InetSocketAddress(targetHost, targetPort), 5000);
            upstream.setTcpNoDelay(true);
            Socket c = client;
            Socket u = upstream;
            Thread t1 = new Thread(() -> pipe(c, u, upBytes), "borum-relay-up");
            Thread t2 = new Thread(() -> pipe(u, c, downBytes), "borum-relay-down");
            t1.setDaemon(true);
            t2.setDaemon(true);
            t1.start();
            t2.start();
            try {
                t1.join();
            } catch (InterruptedException ignored) {
            }
            try {
                t2.join(2000);
            } catch (InterruptedException ignored) {
            }
        } catch (Exception ignored) {
        } finally {
            try {
                client.close();
            } catch (Exception ignored) {
            }
            try {
                upstream.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void pipe(Socket from, Socket to, AtomicLong counter) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[32768];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
                counter.addAndGet(n);
            }
        } catch (Exception ignored) {
        } finally {
            try {
                to.shutdownOutput();
            } catch (Exception e) {
                try {
                    to.close();
                } catch (Exception ignored2) {
                }
            }
        }
    }

    public synchronized void stop() {
        running.set(false);
        try {
            if (server != null) {
                server.close();
            }
        } catch (Exception ignored) {
        } finally {
            server = null;
        }
        if (pool != null) {
            pool.shutdownNow();
            pool = null;
        }
    }

    public boolean isRunning() {
        return running.get();
    }

    public int getListenPort() {
        return listenPort;
    }

    /** Advertised proxy IP (172.16.x.x), fresh at each launch. */
    public String getProxyIp() {
        return proxyIp;
    }

    /** Bytes sent by hotspot clients toward the tunnel (envoyés). */
    public long getUpBytes() {
        return upBytes.get();
    }

    /** Bytes received from the tunnel toward hotspot clients (reçus). */
    public long getDownBytes() {
        return downBytes.get();
    }

    /** Total relayed bytes (envoyés + reçus). */
    public long getTotalBytes() {
        return upBytes.get() + downBytes.get();
    }
}
