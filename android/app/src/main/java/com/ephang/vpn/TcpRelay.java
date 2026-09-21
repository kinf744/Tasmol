package com.ephang.vpn;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
    public static final int FIXED_PORT = 8080;

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
        if (running.get()) {
            return true;
        }
        try {
            this.targetHost = targetHost;
            this.targetPort = targetPort;
            this.proxyIp = proxyIp == null ? "" : proxyIp;
            server = new ServerSocket();
            server.setReuseAddress(true);
            // Fixed port first; fall back to a random port only if 8080 is
            // taken by another app (rare). Bind stays on 0.0.0.0 so every
            // hotspot client can reach us at the phone's LAN address.
            try {
                server.bind(new InetSocketAddress("0.0.0.0", FIXED_PORT));
            } catch (Exception busy) {
                server.bind(new InetSocketAddress("0.0.0.0", 0));
            }
            listenPort = server.getLocalPort();
            upBytes.set(0);
            downBytes.set(0);
            pool = Executors.newCachedThreadPool();
            running.set(true);
            acceptThread = new Thread(this::acceptLoop, "ephang-relay");
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
            Thread t1 = new Thread(() -> pipe(c, u, upBytes), "ephang-relay-up");
            Thread t2 = new Thread(() -> pipe(u, c, downBytes), "ephang-relay-down");
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
