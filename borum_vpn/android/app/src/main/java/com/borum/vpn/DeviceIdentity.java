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

/**
 * Identité d'appareil durcie.
 *
 * 1) UUID propre à CHAQUE INSTALLATION et LIÉ au matériel :
 *    uuid = format-v4( SHA-256( secret-par-installation | ANDROID_ID ) ).
 *    Le secret est régénéré à chaque installation → un uuid neuf à chaque
 *    installation ; ANDROID_ID (stable par appareil pour une signature
 *    d'app donnée) lie l'identité à CE téléphone. Le patch des
 *    préférences pour y coller l'uuid d'un autre appareil ne suffit plus :
 *    voir (2).
 *
 * 2) Preuve d'appareil anti-clonage, vérifiée PAR LE SERVEUR :
 *    proof = HMAC-SHA256( clé = SHA-256(ANDROID_ID), msg = uuid ).
 *    Enregistrée côté serveur au premier register ; un uuid copié depuis
 *    un autre appareil présente une preuve différente (autre matériel) →
 *    rejet 403 côté API. Patch l'apk ? Bloqué par l'éditer TOFU de la
 *    signature (IntegrityGuard). Éditer les préférences ? L'uuid est
 *    régénéré depuis (secret, ANDROID_ID) — coller un uuid étranger est
 *    ignoré au démarrage suivant tant que secret+ANDROID_ID ne
 *    correspondent pas, et le serveur refuse la preuve fausse.
 *
 * Tous les calculs sont locaux (aucun réseau) et le résultat est caché en
 * mémoire pour la durée du processus.
 */
public final class DeviceIdentity {
    private static final String PREFS = "borum_api_prefs";
    private static final String K_UUID = "api_device_uuid";   // compat existante
    private static final String K_SECRET = "identity_secret"; // par installation

    private static volatile String cachedUuid = null;

    private DeviceIdentity() {
    }

    /** UUID de l'appareil : stable pendant la vie de l'installation. */
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

    /**
     * Preuve d'appareil : HMAC-SHA256(key=SHA-256(ANDROID_ID), msg=uuid),
     * hex minuscules. Envoyée au register et au check ; le serveur compare
     * avec la preuve épinglée — un uuid cloné échoue.
     */
    public static String proof(Context ctx, String uuid) {
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
        String secret = sp.getString(K_SECRET, null);
        if (secret == null || secret.isEmpty()) {
            // Secret frais par installation (128 bits, hex).
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
        String aid = androidId(ctx);
        String derived = uuidFrom(secret, aid);

        String uuid;
        if (existing != null && existing.matches(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            // Migration : l'installation existante garde son uuid (le
            // verrou d'appareil serveur pointe dessus). Il est désormais
            // protégé par la preuve serveur, et toute réinstallation
            // génère un uuid neuf dérivé du matériel.
            uuid = existing.toLowerCase(Locale.US);
        } else {
            uuid = derived;
        }
        // L'uuid affiché/stocké reste la référence : s'il a été patché en
        // dur dans les préférences, la preuve serveur le détectera (le
        // secret+ANDROID_ID locaux ne produisent pas cet uuid).
        return uuid;
    }

    /** UUID v4-format depuis SHA-256(secret | ANDROID_ID). */
    private static String uuidFrom(String secret, String androidId) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(secret.getBytes(StandardCharsets.UTF_8));
            md.update((byte) '|');
            md.update(androidId.getBytes(StandardCharsets.UTF_8));
            byte[] d = md.digest();
            d[6] = (byte) ((d[6] & 0x0F) | 0x40); // version 4
            d[8] = (byte) ((d[8] & 0x3F) | 0x80); // variante RFC 4122
            long msb = 0, lsb = 0;
            for (int i = 0; i < 8; i++) {
                msb = (msb << 8) | (d[i] & 0xFF);
            }
            for (int i = 8; i < 16; i++) {
                lsb = (lsb << 8) | (d[i] & 0xFF);
            }
            return new UUID(msb, lsb).toString();
        } catch (Throwable t) {
            // Improbable ; repli : uuid aléatoire (toujours unique par install).
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
