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

public final class TcpRelay {

    public static final int FIXED_PORT = nativeRelayPort();

    private static int nativeRelayPort() {
        try {
            return (int) vpnlib.Vpnlib.phoPortRelay();
        } catch (Throwable t) {
            return 8080;
        }
    }

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

    private final AtomicLong upBytes = new AtomicLong(0);
    private final AtomicLong downBytes = new AtomicLong(0);

    public synchronized boolean start(String targetHost, int targetPort) {
        return start(targetHost, targetPort, "");
    }

    public synchronized boolean start(String targetHost, int targetPort, String proxyIp) {

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

    public String getProxyIp() {
        return proxyIp;
    }

    public long getUpBytes() {
        return upBytes.get();
    }

    public long getDownBytes() {
        return downBytes.get();
    }

    public long getTotalBytes() {
        return upBytes.get() + downBytes.get();
    }
}
