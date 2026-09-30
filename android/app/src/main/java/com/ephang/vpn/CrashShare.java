package com.ephang.vpn;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Diffusion d'un fichier de diagnostic (crash.txt, kighmu.txt) vers le
 * dossier public Download.
 *
 * Depuis Android 10 (API 29), l'app n'a plus le droit d'ecrire dans
 * Download/ : les enregistrements echouent silencieusement et
 * l'utilisateur ne voit jamais le fichier. MediaStore.Downloads est le
 * seul chemin accepte sans permission de stockage, et il apparait
 * immediatement dans le gestionnaire de fichiers de l'utilisateur.
 * En dessous de l'API 29 on retombe sur l'ecriture directe.
 */
final class CrashShare {

    private CrashShare() {
    }

    /** Ecrit le contenu dans Download/<name>. Retourne true si visible. */
    static boolean publishToDownload(Context ctx, String name, String content) {
        if (ctx == null) {
            return false;
        }
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (publishMediaStore(ctx, name, bytes)) {
                return true;
            }
        }
        return publishLegacy(ctx, name, bytes);
    }

    /** API 29+ : insertion dans MediaStore.Downloads (visible immediat). */
    private static boolean publishMediaStore(Context ctx, String name, byte[] bytes) {
        try {
            ContentValues cv = new ContentValues();
            cv.put(android.provider.MediaStore.Downloads.DISPLAY_NAME, name);
            cv.put(android.provider.MediaStore.Downloads.MIME_TYPE, "text/plain");
            cv.put(android.provider.MediaStore.Downloads.IS_PENDING, 1);
            Uri item = ctx.getContentResolver().insert(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            if (item == null) {
                return false;
            }
            try (OutputStream out = ctx.getContentResolver().openOutputStream(item)) {
                if (out == null) {
                    return false;
                }
                out.write(bytes);
                out.flush();
            }
            cv.clear();
            cv.put(android.provider.MediaStore.Downloads.IS_PENDING, 0);
            ctx.getContentResolver().update(item, cv, null, null);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** API < 29 : ecriture directe (autorisee sur ces versions). */
    private static boolean publishLegacy(Context ctx, String name, byte[] bytes) {
        try {
            java.io.File dir =
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (dir == null || !dir.exists()) {
                return false;
            }
            File out = new File(dir, name);
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(out, false)) {
                fos.write(bytes);
                fos.flush();
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Lit un fichier interne de l'app (logDir/crash.txt) ou renvoie "". */
    static String readInternal(Context ctx, String name) {
        try {
            File f = new File(BinaryManager.logDir(), name);
            if (!f.exists() || f.length() == 0) {
                return "";
            }
            // Un rapport de crash trop long ne doit pas saturer la memoire.
            long max = 512 * 1024L;
            try (InputStream in = new FileInputStream(f)) {
                long size = in.available();
                int len = (int) Math.min(size, max);
                byte[] buf = new byte[len];
                int read = in.read(buf, 0, len);
                if (read <= 0) {
                    return "";
                }
                return new String(buf, 0, read, StandardCharsets.UTF_8);
            }
        } catch (Throwable t) {
            return "";
        }
    }

    /** Nom horodate : crash-2026-09-30-0312.txt, pour ne rien ecraser. */
    static String timestampedName(String base, String extension) {
        java.text.SimpleDateFormat fmt =
                new java.text.SimpleDateFormat("yyyy-MM-dd-HHmm", java.util.Locale.US);
        return base + "-" + fmt.format(new java.util.Date()) + extension;
    }
}
