package com.ephang.vpn;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Random;

/**
 * End-to-end latency through a SOCKS5 UDP ASSOCIATE relay: opens the
 * association, sends a DNS A query for www.google.com and times the answer.
 * Works with any UDP-capable SOCKS upstream (Xray, uz_core). Returns ms,
 * or -1 on any failure.
 */
public final class SocksUdpPing {
    private SocksUdpPing() {
    }

    public static long ping(String socksHost, int socksPort, int timeoutMs) {
        Socket ctrl = new Socket();
        DatagramSocket udp = null;
        try {
            ctrl.connect(new InetSocketAddress(socksHost, socksPort), timeoutMs);
            ctrl.setSoTimeout(timeoutMs);
            InputStream in = ctrl.getInputStream();
            OutputStream out = ctrl.getOutputStream();

            // Greeting: VER=5, 1 method, NO AUTH.
            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] greet = new byte[2];
            readFully(in, greet, 0, 2, timeoutMs);
            if (greet[0] != 0x05 || greet[1] != 0x00) {
                return -1;
            }

            // UDP ASSOCIATE to 0.0.0.0:0.
            out.write(new byte[]{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            out.flush();
            // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
            byte[] head = new byte[4];
            readFully(in, head, 0, 4, timeoutMs);
            if (head[0] != 0x05 || head[1] != 0x00) {
                return -1;
            }
            int atyp = head[3] & 0xFF;
            int addrLen;
            switch (atyp) {
                case 0x01:
                    addrLen = 4;
                    break;
                case 0x03: {
                    byte[] l = new byte[1];
                    readFully(in, l, 0, 1, timeoutMs);
                    addrLen = l[0] & 0xFF;
                    break;
                }
                case 0x04:
                    addrLen = 16;
                    break;
                default:
                    return -1;
            }
            byte[] rest = new byte[addrLen + 2];
            readFully(in, rest, 0, rest.length, timeoutMs);
            byte[] ip;
            int relayPort;
            if (atyp == 0x03) {
                return -1; // domain relay: resolve not worth it here
            } else {
                ip = new byte[addrLen];
                System.arraycopy(rest, 0, ip, 0, addrLen);
                relayPort = ((rest[addrLen] & 0xFF) << 8) | (rest[addrLen + 1] & 0xFF);
                if (isUnspecified(ip)) {
                    // 0.0.0.0 means "same as the SOCKS server".
                    ip = InetAddress.getByName(socksHost).getAddress();
                }
            }

            byte[] query = buildDnsQuery();
            int txid = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF);
            byte[] packet = new byte[4 + 4 + 2 + query.length];
            int o = 0;
            packet[o++] = 0x00;
            packet[o++] = 0x00; // RSV
            packet[o++] = 0x00; // FRAG
            packet[o++] = 0x01; // ATYP IPv4 (8.8.8.8)
            packet[o++] = 8;
            packet[o++] = 8;
            packet[o++] = 8;
            packet[o++] = 8;
            packet[o++] = 0x00;
            packet[o++] = 0x35; // port 53
            System.arraycopy(query, 0, packet, o, query.length);

            udp = new DatagramSocket();
            udp.setSoTimeout(timeoutMs);
            InetAddress relay = InetAddress.getByAddress(ip);
            long t0 = System.currentTimeMillis();
            udp.send(new DatagramPacket(packet, packet.length, relay, relayPort));

            byte[] buf = new byte[512];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            udp.receive(resp);
            long dt = System.currentTimeMillis() - t0;

            // Strip SOCKS UDP header, match DNS transaction id.
            int hlen = 4 + 4 + 2;
            if (resp.getLength() < hlen + 2) {
                return -1;
            }
            int rxid = ((buf[hlen] & 0xFF) << 8) | (buf[hlen + 1] & 0xFF);
            if (rxid != txid) {
                return -1;
            }
            return dt;
        } catch (Exception e) {
            return -1;
        } finally {
            try {
                if (udp != null) {
                    udp.close();
                }
            } catch (Exception ignored) {
            }
            try {
                ctrl.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void readFully(InputStream in, byte[] b, int off, int len, int timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n < 0) {
                throw new java.io.EOFException();
            }
            off += n;
            len -= n;
            if (len > 0 && System.currentTimeMillis() > deadline) {
                throw new java.net.SocketTimeoutException();
            }
        }
    }

    private static boolean isUnspecified(byte[] ip) {
        for (byte v : ip) {
            if (v != 0) {
                return false;
            }
        }
        return true;
    }

    /** Minimal DNS A query for www.google.com with random transaction id. */
    private static byte[] buildDnsQuery() {
        Random r = new Random();
        int id = r.nextInt(0xFFFF);
        byte[] qname = {3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0};
        byte[] q = new byte[12 + qname.length + 4];
        q[0] = (byte) (id >> 8);
        q[1] = (byte) id;
        q[2] = 0x01;
        q[3] = 0x00; // standard query, recursion desired
        q[4] = 0x00;
        q[5] = 0x01; // QDCOUNT=1
        System.arraycopy(qname, 0, q, 12, qname.length);
        int tail = 12 + qname.length;
        q[tail] = 0x00;
        q[tail + 1] = 0x01; // QTYPE A
        q[tail + 2] = 0x00;
        q[tail + 3] = 0x01; // QCLASS IN
        return q;
    }
}
