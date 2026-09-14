package com.ephang.vpn;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/** LOGS tab (NPV Tunnel style): timestamped event rows, clear button. */
public class LogsFragment extends Fragment {
    private TextView logText;
    private ScrollView scroller;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 2000);
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_logs, container, false);
        logText = v.findViewById(R.id.logs_text);
        scroller = v.findViewById(R.id.logs_scroll);
        v.findViewById(R.id.logs_clear).setOnClickListener(view -> {
            TasVpnService.clearLog();
            refresh();
        });
        refresh();
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    public void onPause() {
        super.onPause();
        handler.removeCallbacks(tick);
    }

    private void refresh() {
        if (logText == null) {
            return;
        }
        logText.setText(formatLog(TasVpnService.getLog()));
        if (scroller != null) {
            scroller.post(() -> scroller.fullScroll(View.FOCUS_DOWN));
        }
    }

    /** Render "HH:mm:ss  message" lines as "HH:mm:ss  > message" rows. */
    private static String formatLog(String raw) {
        if (raw == null || raw.trim().isEmpty() || raw.equals("No events yet.")) {
            return "No events yet.";
        }
        StringBuilder sb = new StringBuilder();
        for (String line : raw.split("\n")) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            int sep = line.indexOf("  ");
            if (sep > 0) {
                sb.append(line, 0, sep).append("\n  > ").append(line.substring(sep).trim()).append("\n\n");
            } else {
                sb.append("> ").append(line).append("\n\n");
            }
        }
        return sb.toString().trim();
    }
}
