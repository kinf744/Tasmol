package com.ephang.vpn;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

/**
 * Trophy-icon screen: activate this device against the remote config API.
 * On success the credentials are stored and the Home "SERVER CONFIGS"
 * section becomes available.
 */
public class AuthActivity extends AppCompatActivity {
    private EditText phoneInput;
    private EditText codeInput;
    private TextView validateBtn;
    private TextView statusText;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);

        TextView uuidText = findViewById(R.id.auth_uuid);
        phoneInput = findViewById(R.id.auth_phone);
        codeInput = findViewById(R.id.auth_code);
        validateBtn = findViewById(R.id.auth_validate);
        statusText = findViewById(R.id.auth_status);

        uuidText.setText(ApiSession.deviceUuid(this));
        if (ApiSession.isAuthenticated(this)) {
            phoneInput.setText(ApiSession.phone(this));
            codeInput.setText(ApiSession.code(this));
            String exp = ApiSession.expiresAt(this);
            statusText.setText("Connecté à l'API" + (exp.isEmpty() ? "" : " — expire: " + exp));
            statusText.setTextColor(getColor(R.color.npv_green));
            validateBtn.setText("RE-VALIDER");
        }

        findViewById(R.id.auth_copy).setOnClickListener(v -> {
            ClipboardManager cm =
                    (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("device uuid",
                    ApiSession.deviceUuid(this)));
            Toast.makeText(this, "UUID copié", Toast.LENGTH_SHORT).show();
        });

        validateBtn.setOnClickListener(v -> {
            // Ligne de trace immédiate au clic: permet de distinguer
            // "le bouton ne répond pas" de "la requête échoue".
            TasVpnService.logEvent("info", "api", "[activation] clic VALIDER");
            validate();
        });
    }

    private void validate() {
        String phone = phoneInput.getText().toString().trim();
        String code = codeInput.getText().toString().trim();
        if (phone.isEmpty()) {
            toast("Numéro de téléphone requis");
            return;
        }
        if (code.length() != 6) {
            toast("Le code doit contenir 6 chiffres");
            return;
        }

        validateBtn.setEnabled(false);
        statusText.setTextColor(getColor(R.color.npv_grey));
        statusText.setText("Vérification…");
        String uuid = ApiSession.deviceUuid(this);
        TasVpnService.logEvent("info", "api", "[activation] début — téléphone=" + phone
                + " uuid=" + uuid + " code=****" + code.substring(4));

        PhoHelper.activate(phone, code, uuid, (resp, err) -> {
            validateBtn.setEnabled(true);
            if (err != null) {
                statusText.setTextColor(getColor(R.color.npv_red));
                statusText.setText("Réseau: " + err.getMessage());
                return;
            }
            boolean ok = resp != null && resp.optBoolean("success", false);
            if (!ok) {
                String msg = resp != null ? resp.optString("message", "Activation refusée")
                        : "Réponse vide";
                TasVpnService.logEvent("error", "api", "[activation] refusé: " + msg);
                statusText.setTextColor(getColor(R.color.npv_red));
                statusText.setText(msg);
                return;
            }
            String expires = resp.optString("expires_at", "");
            TasVpnService.logEvent("info", "api", "[activation] succès — expire="
                    + (expires.isEmpty() ? "-" : expires));
            ApiSession.saveAuth(this, phone, code, expires);
            statusText.setTextColor(getColor(R.color.npv_green));
            statusText.setText("Connecté à l'API"
                    + (expires.isEmpty() ? "" : " — expire: " + expires));
            toast("Activation réussie");
            // Prefetch configs so Home shows the list immediately.
            PhoHelper.configs(uuid, code, (r2, e2) -> {
                if (r2 != null && r2.optBoolean("success", false)) {
                    ApiSession.saveConfigs(this, r2.optJSONArray("configs"));
                }
                finish(); // back to Home -> SERVER CONFIGS visible
            });
        });
    }

    private void toast(String m) {
        Toast.makeText(this, m, Toast.LENGTH_SHORT).show();
    }
}
