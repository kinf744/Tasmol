package com.ephang.vpn;

import android.content.Context;
import android.provider.Settings;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Profile transfer: .epha files and ephang:// clipboard links, with
 * Picko-style locks (lockConfiguration, expiry date, hardware-id binding).
 * Locked profiles cannot be edited or cloned after import; expired or
 * foreign-device profiles refuse to connect.
 */
public final class ProfileTransfer {
    private ProfileTransfer() {
    }

    public static final int SCHEMA_VERSION = 1;
    public static final String APPLICATION = "Ephang VPN";
    public static final String CLIPBOARD_PREFIX = "ephang://";
    private static final int MAX_IMPORT_BYTES = 1_000_000;

    // --- device hardware id (Picko-compatible: MD5(ANDROID_ID), uppercase) ---

    public static String deviceHardwareId(Context ctx) {
        try {
            String androidId = Settings.Secure.getString(
                    ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
            if (androidId == null || androidId.isEmpty()) {
                return "";
            }
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(androidId.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format(Locale.US, "%02X", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // --- per-profile lock state (stored in Advanced map) ---

    public static boolean isLocked(JSONObject tunnel) {
        if (tunnel == null) {
            return false;
        }
        JSONObject adv = tunnel.optJSONObject("advanced");
        return adv != null && adv.optBoolean("locked", false);
    }

    public static String lockExpiry(JSONObject tunnel) {
        if (tunnel == null) {
            return "";
        }
        JSONObject adv = tunnel.optJSONObject("advanced");
        if (adv == null) {
            return "";
        }
        String v = adv.optString("lock_expires", "").trim();
        return v.matches("\\d{4}-\\d{2}-\\d{2}") ? v : "";
    }

    public static List<String> lockHwids(JSONObject tunnel) {
        List<String> out = new ArrayList<>();
        if (tunnel == null) {
            return out;
        }
        JSONObject adv = tunnel.optJSONObject("advanced");
        if (adv == null) {
            return out;
        }
        for (String part : adv.optString("lock_hwids", "").split("[,;\\n]+")) {
            String id = part.trim().replaceAll("\\s+", "").toUpperCase(Locale.US);
            if (id.matches("[A-F0-9]{32}")) {
                out.add(id);
            }
        }
        return out;
    }

    public static boolean isExpired(JSONObject tunnel) {
        String exp = lockExpiry(tunnel);
        if (exp.isEmpty()) {
            return false;
        }
        try {
            String today = new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date());
            return today.compareTo(exp) > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /** False when bound to other devices. Empty list = any device. */
    public static boolean isHwidAllowed(Context ctx, JSONObject tunnel) {
        List<String> allowed = lockHwids(tunnel);
        if (allowed.isEmpty()) {
            return true;
        }
        String mine = deviceHardwareId(ctx);
        return !mine.isEmpty() && allowed.contains(mine);
    }

    public static String lockReason(Context ctx, JSONObject tunnel) {
        if (isExpired(tunnel)) {
            return "Profil expiré le " + lockExpiry(tunnel);
        }
        if (!isHwidAllowed(ctx, tunnel)) {
            return "Profil lié à un autre appareil";
        }
        if (isBlockRoot(tunnel) && isRooted()) {
            return "Profil interdit sur appareil rooté";
        }
        if (!isIspAllowed(ctx, tunnel)) {
            String want = lockIsp(tunnel);
            return "Profil lié à l'opérateur « " + want + " » (SIM actuelle différente)";
        }
        return "";
    }

    /** Nom d'opérateur courant en minuscules (MTN/Orange/Camtel…). */
    public static String currentIsp(Context ctx) {
        try {
            android.telephony.TelephonyManager tm =
                    (android.telephony.TelephonyManager)
                            ctx.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) {
                return "";
            }
            String n = tm.getSimOperatorName();
            if (n == null || n.trim().isEmpty()) {
                try {
                    n = tm.getNetworkOperatorName();
                } catch (Throwable ignored) {
                }
            }
            return n == null ? "" : n.trim().toLowerCase(Locale.US);
        } catch (Throwable t) {
            return "";
        }
    }

    // Opérateur imposé par l'export ("lock_isp"), "" = toutes SIMs.
    public static String lockIsp(JSONObject tunnel) {
        if (tunnel == null || tunnel.optJSONObject("advanced") == null) {
            return "";
        }
        return tunnel.optJSONObject("advanced").optString("lock_isp", "").trim();
    }

    public static boolean isIspAllowed(Context ctx, JSONObject tunnel) {
        String want = lockIsp(tunnel);
        if (want.isEmpty()) {
            return true;
        }
        String cur = currentIsp(ctx);
        return !cur.isEmpty() && cur.contains(want);
    }

    public static boolean isBlockRoot(JSONObject tunnel) {
        return tunnel != null && tunnel.optJSONObject("advanced") != null
                && tunnel.optJSONObject("advanced").optBoolean("block_root", false);
    }

    public static boolean isHideServer(JSONObject tunnel) {
        return tunnel != null && tunnel.optJSONObject("advanced") != null
                && tunnel.optJSONObject("advanced").optBoolean("hide_server", false);
    }

    public static boolean isExternalAllowed(JSONObject tunnel) {
        // Un profil importe n'est jamais re-exportable : le verrou est
        // pose a l'import, independamment du drapeau "external" du fichier.
        if (isImported(tunnel)) {
            return false;
        }
        // Absent = allowed (legacy exports). Explicit false blocks re-share.
        return tunnel == null || tunnel.optJSONObject("advanced") == null
                || tunnel.optJSONObject("advanced").optBoolean("external", true);
    }

    /**
     * Profil issu d'un import (fichier .epha ou lien presse-papiers).
     * Ces profils ne peuvent plus jamais etre exportes ni re-partages :
     * le marquage est pose a l'import et survit aux modifications de
     * l'application.
     */
    public static boolean isImported(JSONObject tunnel) {
        if (tunnel == null || tunnel.optJSONObject("advanced") == null) {
            return false;
        }
        JSONObject adv = tunnel.optJSONObject("advanced");
        return adv.optBoolean("imported", false) || adv.optString("imported", "").equals("1");
    }

    /**
     * Regle unique d'export appliquee par le fichier ET le presse-papiers.
     * Un profil verrouille est nécessairement issu d'un import (l'editeur
     * ne sait pas verrouiller un profil local) : il est donc lui aussi
     * non exportable, ce qui couvre les profils deja installes avant que
     * le marqueur "imported" n'existe.
     */
    public static boolean canExport(JSONObject tunnel) {
        return !isImported(tunnel) && !isLocked(tunnel);
    }

    public static boolean isRemoveBanner(JSONObject tunnel) {
        return tunnel != null && tunnel.optJSONObject("advanced") != null
                && tunnel.optJSONObject("advanced").optBoolean("remove_banner", false);
    }

    public static String customBanner(JSONObject tunnel) {
        if (tunnel == null || tunnel.optJSONObject("advanced") == null) {
            return "";
        }
        if (!tunnel.optJSONObject("advanced").optBoolean("custom_banner", false)) {
            return "";
        }
        return tunnel.optJSONObject("advanced").optString("user_note", "").trim();
    }

    public static boolean isRooted() {
        for (String p : new String[]{"/system/xbin/su", "/system/bin/su", "/sbin/su",
                "/system/sd/xbin/su", "/data/local/xbin/su"}) {
            try {
                if (new java.io.File(p).exists()) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    // --- export ---

    public static class Restrictions {
        public boolean lockConfiguration = false;
        public boolean external = true;
        public boolean hideServer = false;
        public boolean hideUpass = false;
        public boolean blockRoot = false;
        public boolean removeBanner = false;
        public boolean customBanner = false;
        public String expiresAt = "";
        public String userNote = "";
        public String password = ""; // chiffrement fort (vide = pas de chiffrement)
        public String allowedIsp = ""; // opérateur imposé, ex "mtn" (vide = tous)
        public List<String> allowedHardwareIds = new ArrayList<>();
    }

    // --- chiffrement fort des exports (optionnel, par mot de passe) ---

    private static final String ENC_SCHEME = "PBKDF2-AES256-GCM";
    private static final int ENC_ITERATIONS = 310_000; // ligne 2024+ OWASP PBKDF2-HMAC-SHA256
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    /** Levée quand l'import détecte un export chiffré sans mot de passe. */
    public static class PasswordRequiredException extends Exception {
        public PasswordRequiredException() {
            super("Export chiffré — mot de passe requis");
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iter) throws Exception {
        javax.crypto.spec.PBEKeySpec spec =
                new javax.crypto.spec.PBEKeySpec(password, salt, iter, 256);
        javax.crypto.SecretKeyFactory skf =
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return key;
    }

    /**
     * Chiffre la charge JSON de l'export : PBKDF2-HMAC-SHA256 (310k itérations,
     * sel aléatoire 128 bits) -> clé AES-256, puis AES-GCM (IV 96 bits aléatoire,
     * tag 128 bits). Le GCM authentifie : toute modification du fichier ou
     * mot de passe erroné échoue à l'ouverture, impossible à craquer offline
     * à moindre coût et impossible à altérer silencieusement.
     */
    public static String buildExportEncrypted(String payload, String password) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        new java.security.SecureRandom().nextBytes(salt);
        new java.security.SecureRandom().nextBytes(iv);
        byte[] key = deriveKey(password.toCharArray(), salt, ENC_ITERATIONS);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = c.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        JSONObject root = new JSONObject();
        root.put("schemaVersion", SCHEMA_VERSION);
        root.put("application", APPLICATION);
        root.put("enc", ENC_SCHEME);
        root.put("iter", ENC_ITERATIONS);
        root.put("salt", Base64.encodeToString(salt, Base64.NO_WRAP));
        root.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP));
        root.put("ct", Base64.encodeToString(ct, Base64.NO_WRAP));
        return root.toString();
    }

    /** Déchiffre un export chiffré; échoue proprement sur mauvais mot de passe. */
    public static String decryptExport(JSONObject root, String password) throws Exception {
        if (!ENC_SCHEME.equals(root.optString("enc", ""))) {
            throw new Exception("Chiffrement d'export inconnu.");
        }
        byte[] salt = Base64.decode(root.optString("salt", ""), Base64.DEFAULT);
        byte[] iv = Base64.decode(root.optString("iv", ""), Base64.DEFAULT);
        byte[] ct = Base64.decode(root.optString("ct", ""), Base64.DEFAULT);
        int iter = root.optInt("iter", ENC_ITERATIONS);
        byte[] key = deriveKey(password.toCharArray(), salt, iter);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.GCMParameterSpec(GCM_TAG_BITS, iv));
        return new String(c.doFinal(ct), StandardCharsets.UTF_8);
    }

    /** Build the .epha / clipboard JSON for the given tunnel objects. */
    public static String buildExport(List<JSONObject> tunnels, Restrictions r, String filename)
            throws Exception {
        JSONArray arr = new JSONArray();
        for (JSONObject t : tunnels) {
            JSONObject copy = new JSONObject(t.toString());
            copy.remove("id");
            JSONObject adv = copy.optJSONObject("advanced");
            if (adv == null) {
                adv = new JSONObject();
                copy.put("advanced", adv);
            }
            if (r.lockConfiguration || !r.expiresAt.isEmpty() || !r.allowedHardwareIds.isEmpty()) {
                adv.put("locked", true);
            }
            if (!r.expiresAt.isEmpty()) {
                adv.put("lock_expires", r.expiresAt);
            }
            if (!r.allowedHardwareIds.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (String id : r.allowedHardwareIds) {
                    if (sb.length() > 0) {
                        sb.append(',');
                    }
                    sb.append(id);
                }
                adv.put("lock_hwids", sb.toString());
            }
            adv.put("external", r.external);
            if (r.hideServer) {
                adv.put("hide_server", true);
            }
            if (r.hideUpass) {
                adv.put("hide_upass", true);
            }
            if (r.blockRoot) {
                adv.put("block_root", true);
            }
            if (r.removeBanner) {
                adv.put("remove_banner", true);
            }
            if (r.customBanner) {
                adv.put("custom_banner", true);
            }
            if (r.userNote != null && !r.userNote.isEmpty()) {
                adv.put("user_note", r.userNote.length() > 600
                        ? r.userNote.substring(0, 600) : r.userNote);
            }
            if (r.allowedIsp != null && !r.allowedIsp.isEmpty()) {
                adv.put("locked", true);
                adv.put("lock_isp", r.allowedIsp.trim().toLowerCase(Locale.US));
            }
            arr.put(copy);
        }
        JSONObject root = new JSONObject();
        root.put("schemaVersion", SCHEMA_VERSION);
        root.put("application", APPLICATION);
        root.put("exportedAt", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(new Date()));
        root.put("containsSecrets", true);
        if (filename != null && !filename.isEmpty()) {
            root.put("filename", filename);
        }
        JSONObject rr = new JSONObject();
        rr.put("lockConfiguration", r.lockConfiguration);
        rr.put("external", r.external);
        rr.put("hideServer", r.hideServer);
        rr.put("hideUpass", r.hideUpass);
        rr.put("blockRoot", r.blockRoot);
        rr.put("removeBanner", r.removeBanner);
        rr.put("customBanner", r.customBanner);
        rr.put("expiresAt", r.expiresAt);
        rr.put("userNote", r.userNote == null ? "" : r.userNote);
        rr.put("allowedIsp", r.allowedIsp == null ? "" : r.allowedIsp);
        JSONArray hw = new JSONArray();
        for (String id : r.allowedHardwareIds) {
            hw.put(id);
        }
        rr.put("allowedHardwareIds", hw);
        root.put("restrictions", rr);
        root.put("tunnels", arr);
        return root.toString();
    }

    public static String toClipboard(String exportJson) {
        String b64 = Base64.encodeToString(
                exportJson.getBytes(StandardCharsets.UTF_8),
                Base64.NO_WRAP | Base64.URL_SAFE);
        return CLIPBOARD_PREFIX + b64;
    }

    // --- import ---

    public static class ImportResult {
        public final List<JSONObject> tunnels = new ArrayList<>();
        public int skipped = 0;
        public boolean locked = false;
    }

    private static final java.util.Set<String> KNOWN_TYPES = new java.util.HashSet<>(
            java.util.Arrays.asList("ssh", "ssh_slowdns", "xray", "xray_slowdns", "zivpn", "hysteria"));

    /** Parse .epha content or an ephang:// link. Throws with a clear message. */
    public static ImportResult parseImport(String raw) throws Exception {
        return parseImport(raw, null);
    }

    /** Parse with password for encrypted exports (PasswordRequiredException sinon). */
    public static ImportResult parseImport(String raw, String password) throws Exception {
        String content = raw == null ? "" : raw.trim();
        if (content.startsWith(CLIPBOARD_PREFIX)) {
            String b64 = content.substring(CLIPBOARD_PREFIX.length()).trim()
                    .replace('-', '+').replace('_', '/');
            while (b64.length() % 4 != 0) {
                b64 += "=";
            }
            if (!b64.matches("[A-Za-z0-9+/=]*")) {
                throw new Exception("Clipboard invalide (Base64).");
            }
            byte[] decoded = Base64.decode(b64, Base64.DEFAULT);
            content = new String(decoded, StandardCharsets.UTF_8);
        }
        if (content.isEmpty() || content.length() > MAX_IMPORT_BYTES) {
            throw new Exception("Contenu vide ou trop volumineux (1 Mo max).");
        }
        JSONObject root;
        try {
            root = new JSONObject(content);
        } catch (Exception e) {
            throw new Exception("JSON invalide.");
        }
        // Export chiffré ? Le contenu utile est dans "ct".
        if (!root.optString("enc", "").isEmpty()) {
            if (password == null || password.isEmpty()) {
                throw new PasswordRequiredException();
            }
            content = decryptExport(root, password);
            try {
                root = new JSONObject(content);
            } catch (Exception e) {
                throw new Exception("Mot de passe invalide (déchiffrement impossible).");
            }
        }
        if (root.optInt("schemaVersion", -1) != SCHEMA_VERSION
                || !APPLICATION.equals(root.optString("application", ""))
                || root.optJSONArray("tunnels") == null) {
            throw new Exception("Fichier non compatible Ephang VPN (.epha).");
        }
        JSONObject rr = root.optJSONObject("restrictions");
        boolean lockCfg = rr != null && rr.optBoolean("lockConfiguration", false);
        String exp = "";
        List<String> hwids = new ArrayList<>();
        // "external" du fichier est volontairement ignore : a l'import le
        // profil devient non re-exportable (voir adv2.put plus bas).
        boolean hideServer = rr != null && rr.optBoolean("hideServer", false);
        boolean hideUpass = rr != null && rr.optBoolean("hideUpass", false);
        boolean blockRoot = rr != null && rr.optBoolean("blockRoot", false);
        boolean removeBanner = rr != null && rr.optBoolean("removeBanner", false);
        boolean customBanner = rr != null && rr.optBoolean("customBanner", false);
        String userNote = rr != null ? rr.optString("userNote", "") : "";
        if (rr != null) {
            String e = rr.optString("expiresAt", "").trim();
            if (e.matches("\\d{4}-\\d{2}-\\d{2}")) {
                exp = e;
            }
            JSONArray ha = rr.optJSONArray("allowedHardwareIds");
            if (ha != null) {
                for (int i = 0; i < ha.length(); i++) {
                    String id = ha.optString(i, "").trim()
                            .replaceAll("\\s+", "").toUpperCase(Locale.US);
                    if (id.matches("[A-F0-9]{32}") && !hwids.contains(id)) {
                        hwids.add(id);
                    }
                }
            }
        }
        ImportResult out = new ImportResult();
        JSONArray arr = root.optJSONArray("tunnels");
        for (int i = 0; i < arr.length(); i++) {
            JSONObject t = arr.optJSONObject(i);
            if (t == null || !KNOWN_TYPES.contains(t.optString("type", ""))) {
                out.skipped++;
                continue;
            }
            // Les profils du plan de contrôle (API) ne sont NI exportables
            // NI importables : un fichier contenant ce marqueur est refusé.
            if (isApiManaged(t)) {
                out.skipped++;
                continue;
            }
            JSONObject copy;
            try {
                copy = new JSONObject(t.toString());
            } catch (Exception e) {
                out.skipped++;
                continue;
            }
            copy.remove("id");
            String name = copy.optString("name", "").trim();
            if (name.isEmpty()) {
                name = "Profil importé";
            }
            copy.put("name", name.length() > 120 ? name.substring(0, 120) : name);
            if (lockCfg || !exp.isEmpty() || !hwids.isEmpty()) {
                JSONObject adv = copy.optJSONObject("advanced");
                if (adv == null) {
                    adv = new JSONObject();
                    copy.put("advanced", adv);
                }
                adv.put("locked", true);
                if (!exp.isEmpty()) {
                    adv.put("lock_expires", exp);
                }
                if (!hwids.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (String id : hwids) {
                        if (sb.length() > 0) {
                            sb.append(',');
                        }
                        sb.append(id);
                    }
                    adv.put("lock_hwids", sb.toString());
                }
                out.locked = true;
            } else if (copy.optJSONObject("advanced") != null
                    && copy.optJSONObject("advanced").optBoolean("locked", false)) {
                out.locked = true;
            }
            // Per-profile display/policy flags travel in advanced too.
            JSONObject adv2 = copy.optJSONObject("advanced");
            if (adv2 == null) {
                adv2 = new JSONObject();
                copy.put("advanced", adv2);
            }
            // Marqueur definitive : un profil importe (fichier OU lien
            // presse-papiers) ne peut jamais etre re-exporte, meme si le
            // fichier d'origine autorisait "external" ou n'etait pas verrouille.
            adv2.put("imported", true);
            adv2.put("external", false);
            if (hideServer) {
                adv2.put("hide_server", true);
            }
            if (hideUpass) {
                adv2.put("hide_upass", true);
            }
            if (blockRoot) {
                adv2.put("block_root", true);
            }
            if (removeBanner) {
                adv2.put("remove_banner", true);
            }
            if (customBanner) {
                adv2.put("custom_banner", true);
            }
            if (userNote != null && !userNote.isEmpty()) {
                adv2.put("user_note",
                        userNote.length() > 600 ? userNote.substring(0, 600) : userNote);
            }
            out.tunnels.add(copy);
        }
        if (out.tunnels.isEmpty()) {
            throw new Exception("Aucun profil importable trouvé.");
        }
        return out;
    }

    /** True for profiles materialized from the secured remote API: they
     *  must NEVER be exportable/importable (credentials belong to the
     *  control plane, not to shareable files). */
    public static boolean isApiManaged(JSONObject t) {
        JSONObject adv = t != null ? t.optJSONObject("advanced") : null;
        return adv != null && adv.optBoolean(ApiSession.ADV_API_MANAGED, false);
    }

    /** Full tunnel JSON objects of the selected ids, in selection order.
     *  API-managed profiles are excluded: they stay bound to the account. */
    public static List<JSONObject> selectedTunnels(Context ctx, LinkedHashSet<String> ids) {
        List<JSONObject> out = new ArrayList<>();
        if (ids == null || ids.isEmpty()) {
            return out;
        }
        try {
            String cfgPath = BinaryManager.configPath(ctx).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath));
            java.util.Map<String, JSONObject> byId = new java.util.HashMap<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.optJSONObject(i);
                if (t != null && !isApiManaged(t)) {
                    byId.put(t.optString("id", ""), t);
                }
            }
            for (String id : ids) {
                JSONObject t = byId.get(id);
                if (t != null) {
                    out.add(t);
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }
}
