package com.ephang.vpn;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/** Tools tab: config import/export + connection log. Works fully offline. */
public class ToolsFragment extends Fragment {
    private static final int REQ_IMPORT = 2001;
    private static final int REQ_EXPORT = 2002;

    private TextView logView;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_tools, container, false);
        logView = v.findViewById(R.id.tools_log);

        v.findViewById(R.id.tools_import).setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_IMPORT);
        });

        v.findViewById(R.id.tools_export).setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, "ephang-vpn-config.yaml");
            startActivityForResult(i, REQ_EXPORT);
        });

        v.findViewById(R.id.tools_clear_log).setOnClickListener(view -> {
            TasVpnService.clearLog();
            refreshLog();
        });

        refreshLog();
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshLog();
    }

    private void refreshLog() {
        if (logView != null) {
            logView.setText(TasVpnService.getLog());
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        Uri uri = data.getData();
        try {
            File cfg = BinaryManager.configPath(requireContext());
            if (requestCode == REQ_IMPORT) {
                try (InputStream in = requireContext().getContentResolver().openInputStream(uri)) {
                    byte[] content = readAll(in);
                    if (content.length == 0) {
                        throw new IllegalStateException("empty file");
                    }
                    Files.write(cfg.toPath(), content);
                    TasVpnService.logEvent("config imported (" + content.length + " bytes)");
                    toast("Config imported - restart VPN to apply");
                }
            } else if (requestCode == REQ_EXPORT) {
                if (!cfg.exists()) {
                    toast("Nothing to export yet");
                    return;
                }
                try (OutputStream out = requireContext().getContentResolver().openOutputStream(uri)) {
                    Files.copy(cfg.toPath(), out);
                    toast("Config exported");
                }
            }
        } catch (Exception e) {
            toast("Failed: " + e.getMessage());
        }
        refreshLog();
    }

    private static byte[] readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = in.read(tmp)) > 0) {
            buf.write(tmp, 0, n);
        }
        return buf.toByteArray();
    }

    private void toast(String msg) {
        Toast.makeText(getContext(), msg, Toast.LENGTH_SHORT).show();
    }
}
