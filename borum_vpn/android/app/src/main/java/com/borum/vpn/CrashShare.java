package com.borum.vpn;

import android.content.Context;
import android.os.Build;
import android.os.Environment;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

final class CrashShare {

    private CrashShare() {
    }

    /**
     * Cette classe ne ecrit plus aucun fichier dans le dossier public Download.
     * Les rapports de crash sont ecrits uniquement dans le repertoire prive
     * de l'application (filesDir/logs/crash.txt).
     */
    static String readInternal(Context ctx, String name) {
        try {
            File f = new File(BinaryManager.logDir(), name);
            if (!f.exists() || f.length() == 0) {
                return "";
            }
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

    static String timestampedName(String base, String extension) {
        java.text.SimpleDateFormat fmt =
                new java.text.SimpleDateFormat("yyyy-MM-dd-HHmm", java.util.Locale.US);
        return base + "-" + fmt.format(new java.util.Date()) + extension;
    }
}
