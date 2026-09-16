package com.ephang.vpn;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * LAN proxy relay for Hotspot sharing (no root): listens on all interfaces
 * and pipes each TCP connection to the active tunnel's local SOCKS. TCP
 * only: UDP ASSOCIATE replies carry 127.0.0.1 and cannot cross hosts.
 */
public final class TcpRelay {
    private ServerSocket server;
    private ExecutorService pool;
    private Thread acceptThread;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private String targetHost = "127.0.0.1";
    private int targetPort;
    private int listenPort;

    public synchronized boolean start(String targetHost, int targetPort) {
        if (running.get()) {
            return true;
        }
        try {
            this.targetHost = targetHost;
            this.targetPort = targetPort;
            server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress("0.0.0.0", 0));
            listenPort = server.getLocalPort();
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
            Thread t1 = new Thread(() -> pipe(c, u), "ephang-relay-up");
            Thread t2 = new Thread(() -> pipe(u, c), "ephang-relay-down");
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

    private static void pipe(Socket from, Socket to) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[32768];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
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
}
