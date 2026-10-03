package com.ephang.vpn;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

/**
 * Trophy-icon screen: activate this device against the remote config API.
 * On success the credentials are stored, the Home "SERVER CONFIGS"
 * section becomes available, and a "Client" card (name / phone / plan /
 * expiry / data limit / data remaining) is shown below the button.
 *
 * The card is visible ONLY while the account is validated AND active;
 * it refreshes every 30s so "Données restantes" tracks real consumption.
 */
public class AuthActivity extends AppCompatActivity {
    private EditText phoneInput;
    private EditText codeInput;
    private TextView validateBtn;
    private TextView statusText;

    private View accountCard;
    private TextView accName;
    private TextView accPhone;
    private TextView accPlan;
    private TextView accExpiry;
    private TextView accLimit;
    private TextView accRemaining;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean cardVisible = false;
    private static final long REFRESH_MS = 30000;

    private final Runnable refreshTask = this::refreshAccount;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);

        TextView uuidText = findViewById(R.id.auth_uuid);
        phoneInput = findViewById(R.id.auth_phone);
        codeInput = findViewById(R.id.auth_code);
        validateBtn = findViewById(R.id.auth_validate);
        statusText = findViewById(R.id.auth_status);

        accountCard = findViewById(R.id.auth_account_card);
        accName = findViewById(R.id.auth_acc_name);
        accPhone = findViewById(R.id.auth_acc_phone);
        accPlan = findViewById(R.id.auth_acc_plan);
        accExpiry = findViewById(R.id.auth_acc_expiry);
        accLimit = findViewById(R.id.auth_acc_limit);
        accRemaining = findViewById(R.id.auth_acc_remaining);

        uuidText.setText(ApiSession.deviceUuid(this));
        if (ApiSession.isAuthenticated(this)) {
            phoneInput.setText(ApiSession.phone(this));
            codeInput.setText(ApiSession.code(this));
            String exp = ApiSession.expiresAt(this);
            statusText.setText("Connecté à l'API" + (exp.isEmpty() ? "" : " — expire: " + exp));
            statusText.setTextColor(getColor(R.color.npv_green));
            validateBtn.setText("RE-VALIDER");
            // Cache local, puis rafraîchissement réseau : la carte ne reste
            // visible que si le compte est toujours actif côté serveur.
            JSONObject cached = ApiSession.accountCard(this);
            if (cached != null) {
                cardVisible = true;
                accountCard.setVisibility(View.VISIBLE);
                fillCard(cached);
            }
            refreshAccount();
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

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(refreshTask);
        super.onDestroy();
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
                hideCard();
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
            // Carte compte : uniquement pour un compte validé ET actif.
            JSONObject account = resp.optJSONObject("account");
            if (account != null && account.optInt("active", 0) == 1) {
                showCard(account);
            } else {
                hideCard();
            }
            // Prefetch configs so Home shows the list immediately.
            PhoHelper.configs(uuid, code, (r2, e2) -> {
                if (r2 != null && r2.optBoolean("success", false)) {
                    ApiSession.saveConfigs(this, r2.optJSONArray("configs"));
                }
            });
        });
    }

    /** Rafraîchit la carte depuis /api/v1/devices/check (uuid d'appareil). */
    private void refreshAccount() {
        if (!cardVisible) {
            return;
        }
        if (!ApiSession.isAuthenticated(this)) {
            hideCard();
            return;
        }
        PhoHelper.check(ApiSession.deviceUuid(this), (resp, err) -> {
            if (err != null || resp == null) {
                // Coupure réseau : conserver le cache affiché ET reprogrammer
                // — sans ce re-arm, une seule erreur figeait le quota pour
                // toute la session (bug "données restantes toujours fixes").
                scheduleRefresh();
                return;
            }
            JSONObject account = resp.optJSONObject("account");
            if (resp.optBoolean("activated", false)
                    && account != null && account.optInt("active", 0) == 1) {
                showCard(account);
            } else {
                hideCard();
                ApiSession.clearAccountCard(this);
                statusText.setTextColor(getColor(R.color.npv_red));
                statusText.setText(resp.optString("message", "Compte inactif ou expiré"));
            }
        });
    }

    private void scheduleRefresh() {
        handler.removeCallbacks(refreshTask);
        if (cardVisible) {
            handler.postDelayed(refreshTask, REFRESH_MS);
        }
    }

    private void showCard(JSONObject account) {
        fillCard(account);
        ApiSession.saveAccountCard(this, account);
        if (!cardVisible) {
            cardVisible = true;
            accountCard.setVisibility(View.VISIBLE);
        }
        scheduleRefresh();
    }

    private void hideCard() {
        cardVisible = false;
        accountCard.setVisibility(View.GONE);
        handler.removeCallbacks(refreshTask);
    }

    private void fillCard(JSONObject a) {
        accName.setText(a.optString("name", "-"));
        accPhone.setText(a.optString("phone", "-"));
        accPlan.setText(a.optString("plan", "-"));
        String exp = a.optString("expires_at", "");
        accExpiry.setText(exp.isEmpty() ? "Jamais" : exp);
        if (a.optBoolean("unlimited", false)) {
            accLimit.setText("Illimité");
            accRemaining.setText("Illimité");
        } else {
            accLimit.setText(fmtData(a.optLong("data_limit_bytes", 0)));
            accRemaining.setText(fmtData(a.optLong("data_remaining_bytes", 0)));
        }
    }

    private static String fmtData(long bytes) {
        if (bytes < 0) {
            return "Illimité";
        }
        if (bytes >= 1073741824L) {
            return String.format(java.util.Locale.US, "%.2f Go", bytes / 1073741824.0);
        }
        if (bytes >= 1048576L) {
            return String.format(java.util.Locale.US, "%.2f Mo", bytes / 1048576.0);
        }
        if (bytes >= 1024L) {
            return String.format(java.util.Locale.US, "%.1f Ko", bytes / 1024.0);
        }
        return bytes + " o";
    }

    private void toast(String m) {
        Toast.makeText(this, m, Toast.LENGTH_SHORT).show();
    }
}
