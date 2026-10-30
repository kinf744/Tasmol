package com.borum.vpn;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class SocksTcpPing {
    private SocksTcpPing() {
    }

    private static final byte[] TARGET_IP = {8, 8, 8, 8};
    private static final int TARGET_PORT = 53;

    public static long ping(String socksHost, int socksPort, int timeoutMs) {
        Socket s = new Socket();
        try {
            long t0 = System.currentTimeMillis();
            s.connect(new InetSocketAddress(socksHost, socksPort), timeoutMs);
            s.setSoTimeout(timeoutMs);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] greet = new byte[2];
            readFully(in, greet, 2);
            if (greet[0] != 0x05 || greet[1] != 0x00) {
                return -1;
            }

            byte[] req = {
                    0x05, 0x01, 0x00, 0x01,
                    TARGET_IP[0], TARGET_IP[1], TARGET_IP[2], TARGET_IP[3],
                    (byte) (TARGET_PORT >> 8), (byte) TARGET_PORT};
            out.write(req);
            out.flush();

            byte[] head = new byte[4];
            readFully(in, head, 4);
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
                    readFully(in, l, 1);
                    addrLen = l[0] & 0xFF;
                    break;
                }
                case 0x04:
                    addrLen = 16;
                    break;
                default:
                    return -1;
            }
            readFully(in, new byte[addrLen + 2], addrLen + 2);
            return System.currentTimeMillis() - t0;
        } catch (Exception e) {
            return -1;
        } finally {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void readFully(InputStream in, byte[] b, int len) throws Exception {
        int off = 0;
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n < 0) {
                throw new java.io.EOFException();
            }
            off += n;
            len -= n;
        }
    }
}
