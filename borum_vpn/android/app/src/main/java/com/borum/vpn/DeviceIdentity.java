package com.borum.vpn;

import android.content.Context;
import android.provider.Settings;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Formatter;
import java.util.Locale;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import vpnlib.Vpnlib;

public final class DeviceIdentity {
    private static final String PREFS = "borum_api_prefs";
    private static final String K_UUID = "api_device_uuid";   
    private static final String K_SECRET = "identity_secret"; 

    private static volatile String cachedUuid = null;

    private DeviceIdentity() {
    }

    public static String getUuid(Context ctx) {
        String c = cachedUuid;
        if (c != null && !c.isEmpty()) {
            return c;
        }
        synchronized (DeviceIdentity.class) {
            if (cachedUuid != null && !cachedUuid.isEmpty()) {
                return cachedUuid;
            }
            cachedUuid = loadOrCreate(ctx);
            return cachedUuid;
        }
    }

    public static String proof(Context ctx, String uuid) {
        try {
            String p = Vpnlib.phoDeviceProof(uuid, androidId(ctx));
            if (p != null && p.length() == 64) {
                return p;
            }
        } catch (Throwable ignored) {
        }
        return localProof(ctx, uuid);
    }

    private static String localProof(Context ctx, String uuid) {
        try {
            String aid = androidId(ctx);
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] key = sha.digest(aid.getBytes(StandardCharsets.UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] out = mac.doFinal(uuid.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            try (Formatter f = new Formatter(sb)) {
                for (byte b : out) {
                    f.format("%02x", b);
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    private static String loadOrCreate(Context ctx) {
        android.content.SharedPreferences sp =
                ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String existing = sp.getString(K_UUID, null);
        String aid = androidId(ctx);
        if (existing != null && existing.matches(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {

            try {
                Vpnlib.phoIdentityEnsure();
            } catch (Throwable ignored) {
            }
            return existing.toLowerCase(Locale.US);
        }

        try {
            String uuid = Vpnlib.phoIdentityUuid(aid);
            if (uuid != null && uuid.matches(
                    "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
                sp.edit().putString(K_UUID, uuid).apply();
                return uuid;
            }
        } catch (Throwable ignored) {
        }

        String secret = sp.getString(K_SECRET, null);
        if (secret == null || secret.isEmpty()) {

            byte[] raw = new byte[16];
            java.security.SecureRandom r = new java.security.SecureRandom();
            r.nextBytes(raw);
            StringBuilder sb = new StringBuilder(raw.length * 2);
            try (Formatter f = new Formatter(sb)) {
                for (byte b : raw) {
                    f.format("%02x", b);
                }
            }
            secret = sb.toString();
            sp.edit().putString(K_SECRET, secret).apply();
        }
        String derived = uuidFrom(secret, aid);

        String uuid;
        if (existing != null && existing.matches(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            uuid = existing.toLowerCase(Locale.US);
        } else {
            uuid = derived;
        }

        return uuid;
    }

    private static String uuidFrom(String secret, String androidId) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(secret.getBytes(StandardCharsets.UTF_8));
            md.update((byte) '|');
            md.update(androidId.getBytes(StandardCharsets.UTF_8));
            byte[] d = md.digest();
            d[6] = (byte) ((d[6] & 0x0F) | 0x40); 
            d[8] = (byte) ((d[8] & 0x3F) | 0x80); 
            long msb = 0, lsb = 0;
            for (int i = 0; i < 8; i++) {
                msb = (msb << 8) | (d[i] & 0xFF);
            }
            for (int i = 8; i < 16; i++) {
                lsb = (lsb << 8) | (d[i] & 0xFF);
            }
            return new UUID(msb, lsb).toString();
        } catch (Throwable t) {

            return UUID.randomUUID().toString();
        }
    }

    private static String androidId(Context ctx) {
        try {
            String a = Settings.Secure.getString(
                    ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
            return a == null ? "" : a.trim();
        } catch (Throwable t) {
            return "";
        }
    }
}
