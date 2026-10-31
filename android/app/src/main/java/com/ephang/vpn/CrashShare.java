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


final class CrashShare {

    private CrashShare() {
    }

    
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
