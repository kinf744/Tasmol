package com.ephang.vpn;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** Native server editor: same fields as the Web UI, fully offline. */
public class TunnelEditorActivity extends AppCompatActivity {
    public static final String EXTRA_TUNNEL_ID = "tunnel_id";

    // "Xray + SlowDNS" n'est plus un type séparé : c'est le type Xray avec
    // la case SlowDNS cochée (sw_xray_slowdns) -> type effectif xray_slowdns.
    // "SSH + SlowDNS" est devenu le mode SSH-DNSTT du tunnel SSH.
    private static final String[] TYPES = {"ssh", "xray", "zivpn", "hysteria"};
    private static final String[] TYPE_LABELS = {"SSH", "Xray", "Zivpn UDP", "Hysteria UDP"};

    // 9 modes SSH (alignes sur l'editeur de reference). Le mode DNSTT
    // remplace l'ancien type ssh_slowdns (type effectif ssh_slowdns).
    private static final String[] SSH_MODES = {
            "SSH-Direct", "SSH-Proxy", "SSH-Payload", "SSH-Proxy-Payload",
            "SSH-TLS", "SSH-TLS-Proxy", "SSH-TLS-Payload", "SSH-TLS-Proxy-Payload",
            "SSH-DNSTT"};
    private static final String[] SSH_MODES_KEYS = {
            "direct", "proxy", "payload", "proxy_payload",
            "tls", "tls_proxy", "tls_payload", "tls_proxy_payload",
            "dnstt"};
    private static final String[] SSH_TLS_VERSIONS = {"DEFAULT", "TLS 1.2", "TLS 1.3"};
    private static final String[] SSH_TLS_VERSIONS_KEYS = {"default", "1.2", "1.3"};
    private static final String[] SSH_AUTH_MODES = {"Password", "Private key"};
    private static final String[] DNSTT_MODES = {"UDP", "TCP"};
    private static final String[] NETWORKS = {"tcp", "udp", "ws", "grpc", "xhttp", "httpupgrade"};
    private static final String[] SECURITIES = {"", "tls", "reality"};
    private static final String[] SECURITY_LABELS = {"None", "TLS", "Reality"};
    private static final String[] OBFSS = {"salamander", "plain"};

    private String editId = null;

    private EditText edName;
    private Spinner edType;
    private Switch edEnabled;
    private LinearLayout secServer;
    private TextView lblHost;
    private EditText edHost;
    private EditText edPort;
    private TextView lblPort;
    // Les plages de ports ZIVPN sont FIXES (usage commercial — champ non
    // exposé) : 8 sous-plages couvrant 6000-19999, round-robin interne.
    private static final String ZIVPN_FIXED_RANGES =
            "6000-7750,7751-9500,9501-11250,11251-13000,"
            + "13001-14750,14751-16500,16501-18250,18251-19999";
    private LinearLayout secSsh;
    private EditText edUsername;
    private EditText edPassword;
    private EditText edSshProxy;
    private EditText edSshPayload;
    private LinearLayout secXray;
    private EditText edUuid;
    private EditText edFlow;
    private EditText edXpass;
    private EditText edMethod;
    private LinearLayout secXrayLink;
    private RadioGroup rgXrayMode;
    private RadioButton rbModeLink;
    private RadioButton rbModeJson;
    private EditText edXrayInput;
    // Per-mode stash so Link/JSON contents survive a radio switch.
    private String stashLink = "";
    private String stashJson = "";

    private static final String HINT_LINK = "vless://... / vmess://... / trojan://... / ss://...";
    private static final String HINT_JSON = "{\"outbounds\":[{\"protocol\":\"vless\",...}]}";

    // Xray manual form ("Configure manually"): structured builder that
    // generates the same outbound_json the Go core consumes verbatim.
    private static final String[] XM_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks"};
    private static final String[] XM_PROTOCOL_LABELS = {"VMess", "VLESS", "Trojan", "Shadowsocks"};
    private static final String[] XM_NETWORKS = {"tcp", "ws", "grpc", "xhttp", "httpupgrade"};
    private static final String[] XM_NETWORK_LABELS = {"TCP", "WebSocket (ws)", "gRPC", "XHTTP", "HTTPUpgrade"};
    private static final String[] XM_ENC_VMESS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"};
    private static final String[] XM_ENC_SS = {"aes-256-gcm", "aes-128-gcm",
            "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"};

    private LinearLayout cardXrayManualToggle;
    private Switch swXrayManual;
    private LinearLayout cardXraySlowdns;
    private Switch swXraySlowdns;
    private Button btnXrayImport;
    private LinearLayout xrayManualForm;
    private LinearLayout xrayPasteBox;
    private LinearLayout rowXrayPasteActions;
    private Button btnXrayPaste;
    private Button btnXrayClear;
    private Spinner spXmProtocol;
    private EditText edXmHost;
    private EditText edXmPort;
    private LinearLayout secXmUuid;
    private EditText edXmUuid;
    private LinearLayout secXmPass;
    private EditText edXmPass;
    private LinearLayout secXmFlow;
    private EditText edXmFlow;
    private LinearLayout secXmEnc;
    private TextView lblXmEnc;
    private Spinner spXmEnc;
    private Spinner spXmNetwork;
    private LinearLayout secXmPath;
    private EditText edXmPath;
    private EditText edXmHostHeader;
    private LinearLayout secXmHeaders;
    private LinearLayout llXmHeaders;
    private Spinner spXmSecurity;
    private LinearLayout secXmTls;
    private EditText edXmSni;
    private EditText edXmFp;
    private EditText edXmAlpn;
    private LinearLayout secXmReality;
    private EditText edXmPubkey;
    private EditText edXmSid;
    // Header rows of the manual form (each row = 2 EditTexts + remove view).
    private final List<View> xmHeaderRows = new ArrayList<>();
    // Link used by "IMPORT LINK INTO FORM" (stored back as advanced.link).
    private String lastImportedLink = "";

    // SSH multi-mode (9 protocols, cf. section SSH de l'editeur de reference).
    private LinearLayout secSshProtocol;
    private Spinner spSshProtocol;
    private Spinner spSshAuth;
    private LinearLayout secSshPassword;
    private LinearLayout secSshKey;
    private EditText edSshKey;
    private EditText edSshPassphrase;
    private EditText edSshUdpgwPort;
    private CheckBox swSshUdpgwDns;
    private LinearLayout secSshProxy;
    private CheckBox swSshProxyAuth;
    private LinearLayout secSshProxyAuth;
    private EditText edSshProxyUser;
    private EditText edSshProxyPass;
    private LinearLayout secSshTls;
    private Spinner spSshTlsVersion;
    private EditText edSshTlsSni;
    private LinearLayout secSshPayload;
    private TextView lblSshDnsttMode;
    private Spinner spSshDnsttMode;
    private LinearLayout secZivpn;
    private EditText edZpass;
    private LinearLayout secHysteria;
    private EditText edHyAuth;
    private EditText edHyObfs;
    private EditText edHyPortRange;
    private EditText edHyUp;
    private EditText edHyDown;
    private Spinner edObfs;
    private EditText edObfsParam;
    private LinearLayout secSlowdns;
    private EditText edPubkey;
    private EditText edNsdomain;
    private EditText edResolver;
    private LinearLayout secTransport;
    private Spinner edNetwork;
    private Spinner edSecurity;
    private LinearLayout secPath;
    private EditText edPath;
    private EditText edWshost;
    private LinearLayout secReality;
    private EditText edSni;
    private EditText edRealityPubkey;
    private EditText edShortid;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tunnel_editor);

        editId = getIntent().getStringExtra(EXTRA_TUNNEL_ID);

        bindViews();
        setupSpinners();

        TextView title = findViewById(R.id.editor_title);
        title.setText(editId == null ? "Add server" : "Edit server");

        findViewById(R.id.btn_cancel).setOnClickListener(v -> finish());
        findViewById(R.id.btn_save).setOnClickListener(v -> save());

        // One field, two exclusive modes: switching Link/JSON stashes the
        // current content and restores the other mode's own content.
        rgXrayMode.setOnCheckedChangeListener((group, checkedId) -> onXrayModeChanged());

        if (editId != null) {
            if (isStoredLocked(editId)) {
                toast("Profil verrouillé : modification impossible");
                finish();
                return;
            }
            loadTunnel(editId);
        }
        refreshSections();
    }

    private void bindViews() {
        edName = findViewById(R.id.ed_name);
        edType = findViewById(R.id.ed_type);
        edEnabled = findViewById(R.id.ed_enabled);
        secServer = findViewById(R.id.sec_server);
        lblHost = findViewById(R.id.lbl_host);
        edHost = findViewById(R.id.ed_host);
        edPort = findViewById(R.id.ed_port);
        lblPort = findViewById(R.id.lbl_port);
        secSsh = findViewById(R.id.sec_ssh);
        edUsername = findViewById(R.id.ed_username);
        edPassword = findViewById(R.id.ed_password);
        edSshProxy = findViewById(R.id.ed_ssh_proxy);
        edSshPayload = findViewById(R.id.ed_ssh_payload);
        // SSH multi-mode (9 protocols).
        secSshProtocol = findViewById(R.id.sec_ssh_protocol);
        spSshProtocol = findViewById(R.id.sp_ssh_protocol);
        spSshAuth = findViewById(R.id.sp_ssh_auth);
        secSshPassword = findViewById(R.id.sec_ssh_password);
        secSshKey = findViewById(R.id.sec_ssh_key);
        edSshKey = findViewById(R.id.ed_ssh_key);
        edSshPassphrase = findViewById(R.id.ed_ssh_passphrase);
        edSshUdpgwPort = findViewById(R.id.ed_ssh_udpgw_port);
        swSshUdpgwDns = findViewById(R.id.sw_ssh_udpgw_dns);
        secSshProxy = findViewById(R.id.sec_ssh_proxy);
        swSshProxyAuth = findViewById(R.id.sw_ssh_proxy_auth);
        secSshProxyAuth = findViewById(R.id.sec_ssh_proxy_auth);
        edSshProxyUser = findViewById(R.id.ed_ssh_proxy_user);
        edSshProxyPass = findViewById(R.id.ed_ssh_proxy_pass);
        secSshTls = findViewById(R.id.sec_ssh_tls);
        spSshTlsVersion = findViewById(R.id.sp_ssh_tls_version);
        edSshTlsSni = findViewById(R.id.ed_ssh_tls_sni);
        secSshPayload = findViewById(R.id.sec_ssh_payload);
        lblSshDnsttMode = findViewById(R.id.lbl_ssh_dnstt_mode);
        spSshDnsttMode = findViewById(R.id.sp_ssh_dnstt_mode);
        secXray = findViewById(R.id.sec_xray);
        edUuid = findViewById(R.id.ed_uuid);
        edFlow = findViewById(R.id.ed_flow);
        edXpass = findViewById(R.id.ed_xpass);
        edMethod = findViewById(R.id.ed_method);
        secXrayLink = findViewById(R.id.sec_xray_link);
        rgXrayMode = findViewById(R.id.rg_xray_mode);
        rbModeLink = findViewById(R.id.rb_mode_link);
        rbModeJson = findViewById(R.id.rb_mode_json);
        edXrayInput = findViewById(R.id.ed_xray_input);
        secZivpn = findViewById(R.id.sec_zivpn);
        edZpass = findViewById(R.id.ed_zpass);
        secHysteria = findViewById(R.id.sec_hysteria);
        edHyAuth = findViewById(R.id.ed_hy_auth);
        edHyObfs = findViewById(R.id.ed_hy_obfs);
        edHyPortRange = findViewById(R.id.ed_hy_port_range);
        edHyUp = findViewById(R.id.ed_hy_up);
        edHyDown = findViewById(R.id.ed_hy_down);
        edObfs = findViewById(R.id.ed_obfs);
        edObfsParam = findViewById(R.id.ed_obfs_param);
        secSlowdns = findViewById(R.id.sec_slowdns);
        edPubkey = findViewById(R.id.ed_pubkey);
        edNsdomain = findViewById(R.id.ed_nsdomain);
        edResolver = findViewById(R.id.ed_resolver);
        secTransport = findViewById(R.id.sec_transport);
        edNetwork = findViewById(R.id.ed_network);
        edSecurity = findViewById(R.id.ed_security);
        secPath = findViewById(R.id.sec_path);
        edPath = findViewById(R.id.ed_path);
        edWshost = findViewById(R.id.ed_wshost);
        secReality = findViewById(R.id.sec_reality);
        edSni = findViewById(R.id.ed_sni);
        edRealityPubkey = findViewById(R.id.ed_reality_pubkey);
        edShortid = findViewById(R.id.ed_shortid);
        // Xray manual form ("Configure manually").
        cardXrayManualToggle = findViewById(R.id.card_xray_manual_toggle);
        swXrayManual = findViewById(R.id.sw_xray_manual);
        cardXraySlowdns = findViewById(R.id.card_xray_slowdns);
        swXraySlowdns = findViewById(R.id.sw_xray_slowdns);
        btnXrayImport = findViewById(R.id.btn_xray_import);
        xrayManualForm = findViewById(R.id.xray_manual_form);
        xrayPasteBox = findViewById(R.id.xray_paste_box);
        rowXrayPasteActions = findViewById(R.id.row_xray_paste_actions);
        btnXrayPaste = findViewById(R.id.btn_xray_paste);
        btnXrayClear = findViewById(R.id.btn_xray_clear);
        spXmProtocol = findViewById(R.id.sp_xm_protocol);
        edXmHost = findViewById(R.id.ed_xm_host);
        edXmPort = findViewById(R.id.ed_xm_port);
        secXmUuid = findViewById(R.id.sec_xm_uuid);
        edXmUuid = findViewById(R.id.ed_xm_uuid);
        secXmPass = findViewById(R.id.sec_xm_pass);
        edXmPass = findViewById(R.id.ed_xm_pass);
        secXmFlow = findViewById(R.id.sec_xm_flow);
        edXmFlow = findViewById(R.id.ed_xm_flow);
        secXmEnc = findViewById(R.id.sec_xm_enc);
        lblXmEnc = findViewById(R.id.lbl_xm_enc);
        spXmEnc = findViewById(R.id.sp_xm_enc);
        spXmNetwork = findViewById(R.id.sp_xm_network);
        secXmPath = findViewById(R.id.sec_xm_path);
        edXmPath = findViewById(R.id.ed_xm_path);
        edXmHostHeader = findViewById(R.id.ed_xm_host_header);
        secXmHeaders = findViewById(R.id.sec_xm_headers);
        llXmHeaders = findViewById(R.id.ll_xm_headers);
        spXmSecurity = findViewById(R.id.sp_xm_security);
        secXmTls = findViewById(R.id.sec_xm_tls);
        edXmSni = findViewById(R.id.ed_xm_sni);
        edXmFp = findViewById(R.id.ed_xm_fp);
        edXmAlpn = findViewById(R.id.ed_xm_alpn);
        secXmReality = findViewById(R.id.sec_xm_reality);
        edXmPubkey = findViewById(R.id.ed_xm_pubkey);
        edXmSid = findViewById(R.id.ed_xm_sid);
    }

    private void setupSpinners() {
        edType.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, TYPE_LABELS));
        edNetwork.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, NETWORKS));
        edSecurity.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, SECURITY_LABELS));
        edObfs.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, OBFSS));
        // SSH multi-mode spinners.
        spSshProtocol.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, SSH_MODES));
        spSshAuth.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, SSH_AUTH_MODES));
        spSshTlsVersion.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, SSH_TLS_VERSIONS));
        spSshDnsttMode.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, DNSTT_MODES));
        // Xray manual form spinners.
        spXmProtocol.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, XM_PROTOCOL_LABELS));
        spXmNetwork.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, XM_NETWORK_LABELS));
        spXmSecurity.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, SECURITY_LABELS));
        spXmEnc.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, XM_ENC_VMESS));

        AdapterView.OnItemSelectedListener refresh = new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                refreshSections();
            }

            @Override
            public void onNothingSelected(AdapterView<?> p) {
            }
        };
        edType.setOnItemSelectedListener(refresh);
        edNetwork.setOnItemSelectedListener(refresh);
        edSecurity.setOnItemSelectedListener(refresh);

        // SSH : protocol / auth / proxy-auth change la visibilite des blocs.
        AdapterView.OnItemSelectedListener refreshSsh = new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                refreshSections();
            }

            @Override
            public void onNothingSelected(AdapterView<?> p) {
            }
        };
        spSshProtocol.setOnItemSelectedListener(refreshSsh);
        spSshAuth.setOnItemSelectedListener(refreshSsh);
        swSshProxyAuth.setOnCheckedChangeListener((b, on) -> refreshSections());
        findViewById(R.id.btn_ssh_payload_gen).setOnClickListener(v -> showPayloadGenerator());

        AdapterView.OnItemSelectedListener refreshManual = new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                refreshXrayManualFields();
            }

            @Override
            public void onNothingSelected(AdapterView<?> p) {
            }
        };
        spXmProtocol.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                onXmProtocolChanged();
            }

            @Override
            public void onNothingSelected(AdapterView<?> p) {
            }
        });
        spXmNetwork.setOnItemSelectedListener(refreshManual);
        spXmSecurity.setOnItemSelectedListener(refreshManual);

        swXrayManual.setOnCheckedChangeListener((b, on) -> refreshSections());
        swXraySlowdns.setOnCheckedChangeListener((b, on) -> refreshSections());
        btnXrayPaste.setOnClickListener(v -> pasteIntoXrayInput());
        btnXrayClear.setOnClickListener(v -> {
            edXrayInput.setText("");
            stashLink = "";
            stashJson = "";
        });
        btnXrayImport.setOnClickListener(v -> importLinkIntoForm());
        findViewById(R.id.btn_xm_add_header).setOnClickListener(v -> addHeaderRow("", ""));
    }

    // ------------------------------------------------------------------
    // Generateur de payload (modes SSH-Payload*)
    // ------------------------------------------------------------------

    /**
     * Payload generator: assemble an injector-style HTTP request for the
     * proxy hop. The token set is the one the Go engine understands:
     * [host] [port] [host_port] [crlf] [lf] [split] [delay] [proxy_host]
     * [proxy_port] [protocol] [split] [delay].
     */
    private void showPayloadGenerator() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);

        final Spinner method = new Spinner(this);
        method.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                new String[]{"GET", "POST", "CONNECT", "PUT"}));
        box.addView(method);

        final EditText pathIn = new EditText(this);
        pathIn.setHint("Path (ex: / or /index.html)");
        pathIn.setSingleLine(true);
        box.addView(pathIn);

        final EditText hostIn = new EditText(this);
        hostIn.setHint("Host header (ex: domain.com)");
        hostIn.setSingleLine(true);
        box.addView(hostIn);

        final EditText bodyIn = new EditText(this);
        bodyIn.setHint("Request body (POST only, optional)");
        box.addView(bodyIn);

        final CheckBox crlfBox = new CheckBox(this);
        crlfBox.setText("Terminate headers with [crlf][lf]");
        crlfBox.setChecked(true);
        box.addView(crlfBox);

        final EditText out = new EditText(this);
        out.setHint("Payload preview");
        out.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        out.setMinLines(3);
        out.setTextSize(11);
        out.setTypeface(android.graphics.Typeface.MONOSPACE);
        out.setFocusable(false);
        box.addView(out);

        final Runnable build = new Runnable() {
            @Override
            public void run() {
                String m = String.valueOf(method.getSelectedItem());
                String path = pathIn.getText().toString().trim();
                String host = hostIn.getText().toString().trim();
                String body = bodyIn.getText().toString();
                if (path.isEmpty()) {
                    path = "/";
                }
                StringBuilder sb = new StringBuilder();
                sb.append(m).append(' ').append(path).append(" HTTP/1.1[crlf]");
                if (!host.isEmpty()) {
                    sb.append("Host: ").append(host).append("[crlf]");
                }
                sb.append("User-Agent: Mozilla/5.0[crlf]");
                if ("POST".equals(m) || "PUT".equals(m)) {
                    sb.append("Content-Length: ").append(body.length()).append("[crlf]");
                    sb.append("Content-Type: application/x-www-form-urlencoded[crlf]");
                }
                if (crlfBox.isChecked()) {
                    sb.append("[crlf][lf]");
                }
                if (!body.isEmpty()) {
                    sb.append(body);
                }
                out.setText(sb.toString());
            }
        };
        method.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                build.run();
            }

            @Override
            public void onNothingSelected(AdapterView<?> p) {
            }
        });
        pathIn.addTextChangedListener(new android.text.TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int c) {
                build.run();
            }

            @Override
            public void afterTextChanged(android.text.Editable s) {
            }
        });
        hostIn.addTextChangedListener(new android.text.TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int c) {
                build.run();
            }

            @Override
            public void afterTextChanged(android.text.Editable s) {
            }
        });

        final android.app.AlertDialog dlg = new android.app.AlertDialog.Builder(this)
                .setTitle("Payload generator")
                .setView(box)
                .setPositiveButton("Apply", null)
                .setNegativeButton("Cancel", null)
                .create();
        dlg.setOnShowListener(d -> dlg.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(v -> {
                    String payload = out.getText().toString();
                    if (!payload.isEmpty()) {
                        edSshPayload.setText(payload);
                    }
                    dlg.dismiss();
                }));
        dlg.show();
        build.run();
    }

    private String currentType() {
        int pos = edType.getSelectedItemPosition();
        if (pos < 0 || pos >= TYPES.length) {
            return "ssh";
        }
        return TYPES[pos];
    }

    // ------------------------------------------------------------------
    // SSH : 9 protocoles (Direct, Proxy, Payload, TLS, DNSTT et leurs
    // combinaisons). Le mode est persiste dans advanced["ssh_mode"].
    // ------------------------------------------------------------------

    /** Cle du mode SSH courant (direct, proxy, payload, tls, dnstt, ...). */
    private String sshModeKey() {
        int pos = spSshProtocol != null ? spSshProtocol.getSelectedItemPosition() : -1;
        if (pos < 0 || pos >= SSH_MODES_KEYS.length) {
            return "direct";
        }
        return SSH_MODES_KEYS[pos];
    }

    /** Le mode contient-il la capacite demandee ("proxy" / "tls" / "payload") ? */
    private boolean sshModeUses(String modeKey, String capability) {
        return modeKey.contains(capability);
    }

    private boolean sshAuthIsPassword() {
        return spSshAuth != null && spSshAuth.getSelectedItemPosition() == 0;
    }

    private void selectSshMode(String modeKey) {
        int idx = -1;
        for (int i = 0; i < SSH_MODES_KEYS.length; i++) {
            if (SSH_MODES_KEYS[i].equals(modeKey)) {
                idx = i;
                break;
            }
        }
        if (idx >= 0) {
            spSshProtocol.setSelection(idx);
        }
    }

    private void refreshSections() {
        String type = currentType();
        String network = (String) edNetwork.getSelectedItem();
        int secPos = edSecurity.getSelectedItemPosition();
        String security = secPos >= 0 ? SECURITIES[secPos] : "";

        // SlowDNS n'est plus un type du spinner : case a cocher sur Xray.
        boolean xrayUi = type.equals("xray");
        boolean slowXray = xrayUi && swXraySlowdns != null && swXraySlowdns.isChecked();
        // SSH : le type "ssh_slowdns" est devenu le mode SSH-DNSTT.
        String sshModeKey = sshModeKey();
        boolean sshDnstt = type.equals("ssh") && sshModeKey.equals("dnstt");
        boolean isSSH = type.equals("ssh");
        boolean isXray = xrayUi;
        boolean isSlowDNS = sshDnstt || slowXray;
        boolean isZivpn = type.equals("zivpn");
        boolean isHysteria = type.equals("hysteria");
        boolean showServer = !type.equals("xray");

        // xray uses link/JSON exclusively; the manual form builds the
        // outbound. No visible transport section for xray.
        boolean showXrayAuth = false;
        // No visible transport section: Xray works from link/JSON only.
        boolean showTransport = false;
        boolean isXraySlowDns = slowXray;

        secSshProtocol.setVisibility(isSSH ? View.VISIBLE : View.GONE);
        secSsh.setVisibility(isSSH ? View.VISIBLE : View.GONE);
        secSshPassword.setVisibility(sshAuthIsPassword() ? View.VISIBLE : View.GONE);
        secSshKey.setVisibility(sshAuthIsPassword() ? View.GONE : View.VISIBLE);
        secSshProxy.setVisibility(isSSH && sshModeUses(sshModeKey, "proxy") ? View.VISIBLE : View.GONE);
        secSshProxyAuth.setVisibility(swSshProxyAuth.isChecked() ? View.VISIBLE : View.GONE);
        secSshTls.setVisibility(isSSH && sshModeUses(sshModeKey, "tls") ? View.VISIBLE : View.GONE);
        secSshPayload.setVisibility(isSSH && sshModeUses(sshModeKey, "payload") ? View.VISIBLE : View.GONE);
        // Le mode DNSTT du SSH remplace l'ancien "NS / resolver / cle publique"
        // de la section SlowDNS, avec en plus le choix UDP/TCP.
        lblSshDnsttMode.setVisibility(sshDnstt ? View.VISIBLE : View.GONE);
        spSshDnsttMode.setVisibility(sshDnstt ? View.VISIBLE : View.GONE);
        secXray.setVisibility(showXrayAuth ? View.VISIBLE : View.GONE);
        secXrayLink.setVisibility(isXray ? View.VISIBLE : View.GONE);
        secZivpn.setVisibility(isZivpn ? View.VISIBLE : View.GONE);
        secHysteria.setVisibility(isHysteria ? View.VISIBLE : View.GONE);
        secSlowdns.setVisibility(isSlowDNS ? View.VISIBLE : View.GONE);
        secServer.setVisibility(showServer && !isXraySlowDns ? View.VISIBLE : View.GONE);
        secTransport.setVisibility(showTransport ? View.VISIBLE : View.GONE);
        // xray_slowdns is link-only: no JSON mode, radio forced to Link.
        if (isXraySlowDns) {
            rbModeJson.setVisibility(View.GONE);
            if (!rbModeLink.isChecked()) {
                rbModeLink.setChecked(true);
            }
        } else {
            rbModeJson.setVisibility(View.VISIBLE);
        }
        boolean showPath = isXray && (network.equals("ws") || network.equals("grpc")
                || network.equals("xhttp") || network.equals("httpupgrade"));
        secPath.setVisibility(!isXraySlowDns && showPath ? View.VISIBLE : View.GONE);
        secReality.setVisibility(!isXraySlowDns && isXray && security.equals("reality") ? View.VISIBLE : View.GONE);

        // Xray "Configure manually" mode (xray UI incl. SlowDNS checkbox).
        boolean manualXray = xrayUi && swXrayManual != null && swXrayManual.isChecked();
        cardXrayManualToggle.setVisibility(xrayUi ? View.VISIBLE : View.GONE);
        cardXraySlowdns.setVisibility(xrayUi ? View.VISIBLE : View.GONE);
        btnXrayImport.setVisibility(manualXray ? View.VISIBLE : View.GONE);
        xrayManualForm.setVisibility(manualXray ? View.VISIBLE : View.GONE);
        xrayPasteBox.setVisibility(manualXray ? View.GONE : View.VISIBLE);
        rowXrayPasteActions.setVisibility(xrayUi ? View.VISIBLE : View.GONE);
        if (manualXray) {
            refreshXrayManualFields();
        }
        syncXrayInputVisuals();

        // Port masqué pour zivpn ET hysteria : le hopping 20000-50000 est
        // la norme — un port fixe n'a pas lieu d'être saisi.
        int portVis = (isZivpn || isHysteria) ? View.GONE : View.VISIBLE;
        edPort.setVisibility(portVis);
        lblPort.setVisibility(portVis);
    }

    private void loadTunnel(String id) {
        boolean found = false;
        try {
            String cfgPath = BinaryManager.configPath(this).getAbsolutePath();
            String raw = VpnlibHelper.listTunnels(cfgPath).trim();
            if (raw.startsWith("{")) {
                // Error object, not a list: never present an empty form that
                // could overwrite the real profile on save.
                String msg = raw;
                try {
                    msg = new JSONObject(raw).optString("error", raw);
                } catch (Exception ignored) {
                }
                toast("Load failed: " + msg);
                finish();
                return;
            }
            JSONArray arr = new JSONArray(raw);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (!id.equals(t.optString("id", ""))) {
                    continue;
                }
                edName.setText(t.optString("name", ""));
                String storedType = t.optString("type", "ssh");
                JSONObject advEarly = t.optJSONObject("advanced");
                // Retro-compatibilite : xray_slowdns => spinner Xray + case
                // SlowDNS ; ssh_slowdns => spinner SSH + mode SSH-DNSTT.
                if (storedType.equals("xray_slowdns")) {
                    selectSpinner(edType, TYPES, "xray");
                    swXraySlowdns.setChecked(true);
                } else if (storedType.equals("ssh_slowdns")) {
                    selectSpinner(edType, TYPES, "ssh");
                    selectSshMode("dnstt");
                } else {
                    swXraySlowdns.setChecked(false);
                    selectSpinner(edType, TYPES, storedType);
                    // Un profil "ssh" enregistre avec un mode avance (TLS,
                    // proxy, payload) doit le retrouver a l'ouverture.
                    if (storedType.equals("ssh") && advEarly != null) {
                        String mode = advEarly.optString("ssh_mode", "");
                        if (!mode.isEmpty()) {
                            selectSshMode(mode);
                        }
                    }
                }
                edEnabled.setChecked(t.optBoolean("enabled", true));

                JSONObject server = t.optJSONObject("server");
                if (server != null) {
                    edHost.setText(server.optString("host", ""));
                    int port = server.optInt("port", 0);
                    edPort.setText(port == 0 ? "" : String.valueOf(port));
                    edPubkey.setText(server.optString("public_key", ""));
                    edNsdomain.setText(server.optString("nameserver", server.optString("hostname", "")));
                    edResolver.setText(server.optString("dns_resolver", "8.8.8.8:53"));
                    edSni.setText(server.optString("sni", ""));
                    edRealityPubkey.setText(server.optString("public_key", ""));
                    edShortid.setText(server.optString("short_id", ""));
                }
                JSONObject ssh = t.optJSONObject("ssh");
                if (ssh != null) {
                    edSshProxy.setText(ssh.optString("proxy", ""));
                    edSshPayload.setText(ssh.optString("payload", ""));
                }
                JSONObject auth = t.optJSONObject("auth");
                if (auth != null) {
                    edUsername.setText(auth.optString("username", ""));
                    edPassword.setText(auth.optString("password", ""));
                    edUuid.setText(auth.optString("uuid", ""));
                    edFlow.setText(auth.optString("flow", ""));
                    edXpass.setText(auth.optString("password", ""));
                    edMethod.setText(auth.optString("method", ""));
                    edZpass.setText(auth.optString("password", ""));
                    edHyAuth.setText(auth.optString("password", ""));
                    // Cle privee : bascule l'onglet Authentication.
                    String pk = auth.optString("private_key", "");
                    if (!pk.isEmpty()) {
                        spSshAuth.setSelection(1);
                        edSshKey.setText(pk);
                        edSshPassphrase.setText(auth.optString("passphrase", ""));
                    } else {
                        spSshAuth.setSelection(0);
                    }
                }
                JSONObject adv0 = t.optJSONObject("advanced");
                if (adv0 != null) {
                    edHyObfs.setText(adv0.optString("hysteria_obfs", ""));
                    edHyPortRange.setText(adv0.optString("port_range", ""));
                    int up = adv0.optInt("up_mbps", 0);
                    int down = adv0.optInt("down_mbps", 0);
                    if (up > 0) {
                        edHyUp.setText(String.valueOf(up));
                    }
                    if (down > 0) {
                        edHyDown.setText(String.valueOf(down));
                    }
                    // Options SSH avancees (TLS, proxy, DNSTT, UDPGW).
                    if (adv0.has("ssh_tls_version")) {
                        selectSpinner(spSshTlsVersion, SSH_TLS_VERSIONS_KEYS,
                                adv0.optString("ssh_tls_version", "default"));
                    }
                    edSshTlsSni.setText(server != null ? server.optString("sni", "") : "");
                    if (!adv0.optString("proxy_user", "").isEmpty()) {
                        swSshProxyAuth.setChecked(true);
                        edSshProxyUser.setText(adv0.optString("proxy_user", ""));
                        edSshProxyPass.setText(adv0.optString("proxy_pass", ""));
                    }
                    if (adv0.has("dnstt_tcp")) {
                        spSshDnsttMode.setSelection(adv0.optBoolean("dnstt_tcp", false) ? 1 : 0);
                    }
                    if (adv0.has("udpgw_port")) {
                        edSshUdpgwPort.setText(String.valueOf(adv0.optInt("udpgw_port", 7300)));
                    }
                    if (adv0.has("udpgw_dns")) {
                        swSshUdpgwDns.setChecked(adv0.optBoolean("udpgw_dns", true));
                    }
                }
                JSONObject transport = t.optJSONObject("transport");
                if (transport != null) {
                    selectSpinner(edNetwork, NETWORKS, transport.optString("network", "tcp"));
                    selectSpinnerByValue(edSecurity, SECURITIES, transport.optString("security", ""));
                    edPath.setText(transport.optString("path", ""));
                    edWshost.setText(transport.optString("host", ""));
                    selectSpinner(edObfs, OBFSS, transport.optString("obfs", "salamander"));
                    edObfsParam.setText(transport.optString("obfs_param", "zivpn"));
                }
                JSONObject adv = t.optJSONObject("advanced");
                if (adv != null) {
                    String link = adv.optString("link", "");
                    String json = adv.optString("outbound_json", "");
                    // JSON mode wins when a stored config exists (and the
                    // type allows it); the link stays stashed for a switch.
                    boolean jsonMode = !json.isEmpty() && !storedType.equals("xray_slowdns");
                    if (jsonMode) {
                        rbModeJson.setChecked(true);
                    } else {
                        rbModeLink.setChecked(true);
                    }
                    stashLink = link;
                    stashJson = json;
                    edXrayInput.setText(jsonMode ? json : link);
                    lastXrayLinkMode = xrayLinkMode();
                    // Profile built with the manual form: restore it as-is
                    // (the outbound JSON carries every field back).
                    if ((storedType.equals("xray") || storedType.equals("xray_slowdns"))
                            && adv.optString("manual_form", "").equals("1")
                            && !json.isEmpty()) {
                        lastImportedLink = link;
                        try {
                            fillManualFromOutbound(new JSONObject(json));
                            swXrayManual.setChecked(true);
                        } catch (Exception ignored) {
                        }
                    }
                    // xray_slowdns keeps its SlowDNS key in advanced (the
                    // server key belongs to Reality): prefer it on load.
                    if (storedType.equals("xray_slowdns")
                            && !adv.optString("slowdns_pubkey", "").isEmpty()) {
                        edPubkey.setText(adv.optString("slowdns_pubkey"));
                    }
                }
                found = true;
                break;
            }
        } catch (Exception e) {
            toast("Load failed: " + e.getMessage());
            finish();
            return;
        }
        if (!found) {
            toast("Profile not found");
            finish();
            return;
        }
        refreshSections();
    }

    private void selectSpinner(Spinner spinner, String[] values, String value) {
        for (int i = 0; i < values.length; i++) {
            if (values[i].equalsIgnoreCase(value)) {
                spinner.setSelection(i);
                return;
            }
        }
        spinner.setSelection(0);
    }

    private void selectSpinnerByValue(Spinner spinner, String[] values, String value) {
        selectSpinner(spinner, values, value == null ? "" : value);
    }

    /** True when the Xray input is in Link mode (JSON otherwise). */
    private boolean xrayLinkMode() {
        return rbModeLink.isChecked();
    }

    // Tracks the mode before a radio switch so its content can be stashed.
    private boolean lastXrayLinkMode = true;

    /** RadioGroup is single-selection by construction: the two modes can
     *  never be active together. Switching stashes the old mode's content
     *  and restores the new mode's own content. */
    private void onXrayModeChanged() {
        boolean linkMode = xrayLinkMode();
        if (linkMode == lastXrayLinkMode) {
            return;
        }
        String current = edXrayInput.getText().toString();
        if (linkMode) {
            stashJson = current;
            edXrayInput.setText(stashLink);
        } else {
            stashLink = current;
            edXrayInput.setText(stashJson);
        }
        lastXrayLinkMode = linkMode;
        syncXrayInputVisuals();
    }

    private void syncXrayInputVisuals() {
        if (edXrayInput != null) {
            edXrayInput.setHint(xrayLinkMode() ? HINT_LINK : HINT_JSON);
        }
    }

    // ------------------------------------------------------------------
    // Xray manual form ("Configure manually")
    // ------------------------------------------------------------------

    private String xmProtocol() {
        int pos = spXmProtocol.getSelectedItemPosition();
        if (pos < 0 || pos >= XM_PROTOCOLS.length) {
            return "vmess";
        }
        return XM_PROTOCOLS[pos];
    }

    private String xmNetwork() {
        int pos = spXmNetwork.getSelectedItemPosition();
        if (pos < 0 || pos >= XM_NETWORKS.length) {
            return "tcp";
        }
        return XM_NETWORKS[pos];
    }

    private String xmSecurity() {
        int pos = spXmSecurity.getSelectedItemPosition();
        return pos >= 0 && pos < SECURITIES.length ? SECURITIES[pos] : "";
    }

    /** Protocol switch: credentials fields + encryption choices follow it. */
    private void onXmProtocolChanged() {
        String proto = xmProtocol();
        secXmUuid.setVisibility((proto.equals("vmess") || proto.equals("vless")) ? View.VISIBLE : View.GONE);
        secXmPass.setVisibility((proto.equals("trojan") || proto.equals("shadowsocks")) ? View.VISIBLE : View.GONE);
        secXmFlow.setVisibility(proto.equals("vless") ? View.VISIBLE : View.GONE);
        if (proto.equals("vmess")) {
            lblXmEnc.setText("Security (security)");
            spXmEnc.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, XM_ENC_VMESS));
            secXmEnc.setVisibility(View.VISIBLE);
        } else if (proto.equals("shadowsocks")) {
            lblXmEnc.setText("Method (encryption)");
            spXmEnc.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, XM_ENC_SS));
            secXmEnc.setVisibility(View.VISIBLE);
        } else {
            // VLESS encryption is always "none", Trojan uses none.
            secXmEnc.setVisibility(View.GONE);
        }
        refreshXrayManualFields();
    }

    /** Network/security dependent sub-blocks of the manual form. */
    private void refreshXrayManualFields() {
        String net = xmNetwork();
        boolean hasPath = net.equals("ws") || net.equals("grpc") || net.equals("xhttp")
                || net.equals("httpupgrade");
        secXmPath.setVisibility(hasPath ? View.VISIBLE : View.GONE);
        // Custom headers are a WebSocket feature (wsSettings.headers).
        secXmHeaders.setVisibility(net.equals("ws") ? View.VISIBLE : View.GONE);
        String sec = xmSecurity();
        secXmTls.setVisibility((sec.equals("tls") || sec.equals("reality")) ? View.VISIBLE : View.GONE);
        secXmReality.setVisibility(sec.equals("reality") ? View.VISIBLE : View.GONE);
    }

    /** One custom WS header row: key + value + remove. */
    private void addHeaderRow(String key, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        int top = (int) (6 * getResources().getDisplayMetrics().density);
        row.setPadding(0, top, 0, 0);

        EditText k = new EditText(this);
        LinearLayout.LayoutParams kp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        kp.setMarginEnd((int) (8 * getResources().getDisplayMetrics().density));
        k.setLayoutParams(kp);
        k.setHint("Header (ex: Host)");
        k.setSingleLine(true);
        k.setTextSize(13);
        k.setText(key);

        EditText v = new EditText(this);
        LinearLayout.LayoutParams vp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        v.setLayoutParams(vp);
        v.setHint("Value");
        v.setSingleLine(true);
        v.setTextSize(13);
        v.setText(value);

        TextView rm = new TextView(this);
        rm.setText("✕");
        rm.setTextSize(16);
        rm.setTextColor(0xFFFF5252);
        int pad = (int) (10 * getResources().getDisplayMetrics().density);
        rm.setPadding(pad, pad, pad, pad);
        rm.setOnClickListener(btn -> {
            llXmHeaders.removeView(row);
            xmHeaderRows.remove(row);
        });

        row.addView(k);
        row.addView(v);
        row.addView(rm);
        row.setTag(new EditText[]{k, v});
        llXmHeaders.addView(row);
        xmHeaderRows.add(row);
    }

    private void clearHeaderRows() {
        llXmHeaders.removeAllViews();
        xmHeaderRows.clear();
    }

    /** Custom WS headers collected as a JSON object (key -> value). */
    private JSONObject collectCustomHeaders() {
        JSONObject headers = new JSONObject();
        for (View row : xmHeaderRows) {
            EditText[] kv = (EditText[]) row.getTag();
            String key = kv[0].getText().toString().trim();
            if (key.isEmpty()) {
                continue;
            }
            try {
                headers.put(key, kv[1].getText().toString().trim());
            } catch (Exception ignored) {
            }
        }
        return headers;
    }

    private void pasteIntoXrayInput() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = cm != null ? cm.getPrimaryClip() : null;
        if (clip == null || clip.getItemCount() == 0 || clip.getItemAt(0).getText() == null) {
            toast("Clipboard is empty");
            return;
        }
        String text = clip.getItemAt(0).getText().toString().trim();
        if (text.isEmpty()) {
            toast("Clipboard is empty");
            return;
        }
        // Auto-select the right tab: JSON object or subscription link.
        boolean isJson = text.startsWith("{");
        RadioButton target = isJson ? rbModeJson : rbModeLink;
        if (isJson && currentType().equals("xray_slowdns")) {
            target = rbModeLink; // slowdns is link-only
        }
        if (!target.isChecked()) {
            target.setChecked(true); // listener stashes + swaps, may overwrite
            edXrayInput.setText(text);
        } else {
            edXrayInput.setText(text);
        }
    }

    /**
     * "IMPORT LINK INTO FORM": parse a subscription link (clipboard first,
     * manual input fallback) through the Go core and fill the manual form.
     */
    private void importLinkIntoForm() {
        String link = "";
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = cm != null ? cm.getPrimaryClip() : null;
        if (clip != null && clip.getItemCount() > 0 && clip.getItemAt(0).getText() != null) {
            link = clip.getItemAt(0).getText().toString().trim();
        }
        if (!(link.contains("://") && (link.startsWith("vless") || link.startsWith("vmess")
                || link.startsWith("trojan") || link.startsWith("ss")))) {
            String typed = edXrayInput.getText().toString().trim();
            if (!typed.isEmpty() && !typed.startsWith("{")) {
                link = typed;
            }
        }
        if (link.isEmpty()) {
            toast("Copy a vless/vmess/trojan/ss link first");
            return;
        }
        JSONObject parsed = parseLinkConfig(link);
        if (parsed == null) {
            return;
        }
        lastImportedLink = link;
        JSONObject adv = parsed.optJSONObject("advanced");
        String raw = adv != null ? adv.optString("outbound_json", "") : "";
        if (!raw.isEmpty()) {
            try {
                fillManualFromOutbound(new JSONObject(raw));
                toast("Link imported");
                return;
            } catch (Exception e) {
                toast("Import failed: " + e.getMessage());
                return;
            }
        }
        // Fallback: structured fields only (no outbound JSON produced).
        fillManualFromConfig(parsed);
        toast("Link imported");
    }

    /** Fill the manual form from a parsed link's structured fields. */
    private void fillManualFromConfig(JSONObject parsed) {
        JSONObject server = parsed.optJSONObject("server");
        if (server != null) {
            edXmHost.setText(server.optString("host", ""));
            int port = server.optInt("port", 0);
            edXmPort.setText(port == 0 ? "" : String.valueOf(port));
            edXmSni.setText(server.optString("sni", ""));
            edXmPubkey.setText(server.optString("public_key", ""));
            edXmSid.setText(server.optString("short_id", ""));
        }
        JSONObject auth = parsed.optJSONObject("auth");
        if (auth != null) {
            edXmUuid.setText(auth.optString("uuid", ""));
            edXmFlow.setText(auth.optString("flow", ""));
            edXmPass.setText(auth.optString("password", ""));
            selectSpinner(spXmEnc, currentEncValues(), auth.optString("method", "auto"));
        }
        JSONObject transport = parsed.optJSONObject("transport");
        if (transport != null) {
            selectSpinner(spXmNetwork, XM_NETWORKS, transport.optString("network", "tcp"));
            selectSpinnerByValue(spXmSecurity, SECURITIES, transport.optString("security", ""));
            edXmPath.setText(transport.optString("path", ""));
            edXmHostHeader.setText(transport.optString("host", ""));
        }
        String name = parsed.optString("name", "");
        if (!name.isEmpty() && edName.getText().toString().trim().isEmpty()) {
            edName.setText(name);
        }
        refreshXrayManualFields();
    }

    /** Current encryption spinner values (protocol-dependent). */
    private String[] currentEncValues() {
        String proto = xmProtocol();
        if (proto.equals("shadowsocks")) {
            return XM_ENC_SS;
        }
        return XM_ENC_VMESS;
    }

    /** Fill every manual field from a stored/imported outbound JSON object. */
    private void fillManualFromOutbound(JSONObject ob) {
        String proto = ob.optString("protocol", "vless");
        selectSpinner(spXmProtocol, XM_PROTOCOLS, proto);
        onXmProtocolChanged();

        JSONObject settings = ob.optJSONObject("settings");
        JSONObject endpoint = null;
        if (settings != null) {
            JSONArray vnext = settings.optJSONArray("vnext");
            if (vnext != null && vnext.length() > 0) {
                endpoint = vnext.optJSONObject(0);
            }
            JSONArray servers = settings.optJSONArray("servers");
            if (endpoint == null && servers != null && servers.length() > 0) {
                endpoint = servers.optJSONObject(0);
            }
        }
        if (endpoint != null) {
            edXmHost.setText(endpoint.optString("address", ""));
            int port = endpoint.optInt("port", 0);
            edXmPort.setText(port == 0 ? "" : String.valueOf(port));
            JSONArray users = endpoint.optJSONArray("users");
            if (users != null && users.length() > 0) {
                JSONObject u = users.optJSONObject(0);
                if (u != null) {
                    edXmUuid.setText(u.optString("id", ""));
                    edXmFlow.setText(u.optString("flow", ""));
                    selectSpinner(spXmEnc, currentEncValues(), u.optString("security", "auto"));
                }
            }
            if (endpoint.has("password")) {
                edXmPass.setText(endpoint.optString("password", ""));
            }
            if (endpoint.has("method")) {
                selectSpinner(spXmEnc, XM_ENC_SS, endpoint.optString("method", "aes-256-gcm"));
            }
        }

        JSONObject ss = ob.optJSONObject("streamSettings");
        if (ss != null) {
            selectSpinner(spXmNetwork, XM_NETWORKS, ss.optString("network", "tcp"));
            String sec = ss.optString("security", "");
            selectSpinnerByValue(spXmSecurity, SECURITIES, sec.equals("none") ? "" : sec);
            JSONObject ws = ss.optJSONObject("wsSettings");
            if (ws != null) {
                edXmPath.setText(ws.optString("path", ""));
                JSONObject headers = ws.optJSONObject("headers");
                clearHeaderRows();
                if (headers != null) {
                    Iterator<String> it = headers.keys();
                    while (it.hasNext()) {
                        String k = it.next();
                        if (k.equalsIgnoreCase("host")) {
                            edXmHostHeader.setText(headers.optString(k, ""));
                        } else {
                            addHeaderRow(k, headers.optString(k, ""));
                        }
                    }
                }
            }
            JSONObject grpc = ss.optJSONObject("grpcSettings");
            if (grpc != null) {
                edXmPath.setText(grpc.optString("serviceName", ""));
                edXmHostHeader.setText(grpc.optString("authority", ""));
            }
            JSONObject xhttp = ss.optJSONObject("xhttpSettings");
            if (xhttp != null) {
                edXmPath.setText(xhttp.optString("path", ""));
                edXmHostHeader.setText(xhttp.optString("host", ""));
            }
            JSONObject hu = ss.optJSONObject("httpupgradeSettings");
            if (hu != null) {
                edXmPath.setText(hu.optString("path", ""));
                edXmHostHeader.setText(hu.optString("host", ""));
            }
            JSONObject tls = ss.optJSONObject("tlsSettings");
            if (tls == null) {
                tls = ss.optJSONObject("realitySettings");
            }
            if (tls != null) {
                edXmSni.setText(tls.optString("serverName", ""));
                edXmFp.setText(tls.optString("fingerprint", ""));
                JSONArray alpn = tls.optJSONArray("alpn");
                if (alpn != null && alpn.length() > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < alpn.length(); i++) {
                        if (i > 0) {
                            sb.append(',');
                        }
                        sb.append(alpn.optString(i, ""));
                    }
                    edXmAlpn.setText(sb.toString());
                }
                edXmPubkey.setText(tls.optString("publicKey", ""));
                edXmSid.setText(tls.optString("shortId", ""));
            }
        }
        refreshXrayManualFields();
    }

    /**
     * Build the manual form as an outbound object, exactly what the Go core
     * consumes verbatim via advanced.outbound_json (same shapes as
     * BuildVlessOutbound/BuildVmessOutbound/... in Go). Null after a toast.
     */
    private JSONObject buildManualOutbound() {
        String proto = xmProtocol();
        String host = edXmHost.getText().toString().trim();
        int port = 0;
        try {
            port = Integer.parseInt(edXmPort.getText().toString().trim());
        } catch (NumberFormatException ignored) {
        }
        if (host.isEmpty()) {
            toast("Server address is required");
            return null;
        }
        if (port < 1 || port > 65535) {
            toast("Valid port is required (1-65535)");
            return null;
        }
        String uuid = edXmUuid.getText().toString().trim();
        String pass = edXmPass.getText().toString();
        if ((proto.equals("vmess") || proto.equals("vless")) && uuid.isEmpty()) {
            toast("User ID / UUID is required");
            return null;
        }
        if ((proto.equals("trojan") || proto.equals("shadowsocks")) && pass.isEmpty()) {
            toast("Password is required");
            return null;
        }
        String security = xmSecurity();
        if (security.equals("reality") && edXmPubkey.getText().toString().trim().isEmpty()) {
            toast("Reality public key is required");
            return null;
        }

        try {
            JSONObject settings = new JSONObject();
            if (proto.equals("vmess")) {
                JSONObject user = new JSONObject()
                        .put("id", uuid)
                        .put("alterId", 0)
                        .put("security", spXmEnc.getSelectedItem().toString());
                settings.put("vnext", new JSONArray().put(new JSONObject()
                        .put("address", host)
                        .put("port", port)
                        .put("users", new JSONArray().put(user))));
            } else if (proto.equals("vless")) {
                JSONObject user = new JSONObject()
                        .put("id", uuid)
                        .put("encryption", "none")
                        .put("flow", edXmFlow.getText().toString().trim());
                settings.put("vnext", new JSONArray().put(new JSONObject()
                        .put("address", host)
                        .put("port", port)
                        .put("users", new JSONArray().put(user))));
            } else if (proto.equals("trojan")) {
                settings.put("servers", new JSONArray().put(new JSONObject()
                        .put("address", host)
                        .put("port", port)
                        .put("password", pass)));
            } else { // shadowsocks
                settings.put("servers", new JSONArray().put(new JSONObject()
                        .put("address", host)
                        .put("port", port)
                        .put("method", spXmEnc.getSelectedItem().toString())
                        .put("password", pass)));
            }

            String network = xmNetwork();
            String path = edXmPath.getText().toString().trim();
            String hostHeader = edXmHostHeader.getText().toString().trim();
            if (network.equals("ws") && path.isEmpty()) {
                path = "/";
            }
            JSONObject stream = new JSONObject()
                    .put("network", network)
                    .put("security", security.isEmpty() ? "none" : security);
            if (network.equals("ws")) {
                JSONObject headers = collectCustomHeaders();
                if (!hostHeader.isEmpty()) {
                    headers.put("Host", hostHeader);
                }
                stream.put("wsSettings", new JSONObject()
                        .put("path", path)
                        .put("headers", headers));
            } else if (network.equals("grpc")) {
                JSONObject g = new JSONObject()
                        .put("serviceName", path)
                        .put("multiMode", false);
                if (!hostHeader.isEmpty()) {
                    g.put("authority", hostHeader);
                }
                stream.put("grpcSettings", g);
            } else if (network.equals("xhttp")) {
                JSONObject x = new JSONObject().put("path", path);
                if (!hostHeader.isEmpty()) {
                    x.put("host", hostHeader);
                }
                stream.put("xhttpSettings", x);
            } else if (network.equals("httpupgrade")) {
                JSONObject h = new JSONObject().put("path", path);
                if (!hostHeader.isEmpty()) {
                    h.put("host", hostHeader);
                }
                stream.put("httpupgradeSettings", h);
            } else {
                stream.put("tcpSettings", new JSONObject()
                        .put("header", new JSONObject().put("type", "none")));
            }

            String sni = edXmSni.getText().toString().trim();
            String fp = edXmFp.getText().toString().trim();
            if (security.equals("tls")) {
                JSONObject tls = new JSONObject().put("serverName", sni.isEmpty() ? host : sni);
                if (!fp.isEmpty()) {
                    tls.put("fingerprint", fp);
                }
                String alpn = edXmAlpn.getText().toString().trim();
                if (!alpn.isEmpty()) {
                    JSONArray arr = new JSONArray();
                    for (String a : alpn.split(",")) {
                        a = a.trim();
                        if (!a.isEmpty()) {
                            arr.put(a);
                        }
                    }
                    if (arr.length() > 0) {
                        tls.put("alpn", arr);
                    }
                }
                stream.put("tlsSettings", tls);
            } else if (security.equals("reality")) {
                JSONObject r = new JSONObject()
                        .put("serverName", sni)
                        .put("publicKey", edXmPubkey.getText().toString().trim())
                        .put("shortId", edXmSid.getText().toString().trim());
                if (!fp.isEmpty()) {
                    r.put("fingerprint", fp);
                }
                stream.put("realitySettings", r);
            }

            return new JSONObject()
                    .put("protocol", proto)
                    .put("tag", "proxy")
                    .put("settings", settings)
                    .put("streamSettings", stream);
        } catch (Exception e) {
            toast("Invalid form: " + e.getMessage());
            return null;
        }
    }

    /**
     * Base config for a manual-form save (plain xray or xray+slowdns):
     * server/auth/transport/advanced sections built from the form and the
     * generated outbound (already validated by buildManualOutbound).
     */
    private JSONObject buildManualBase(JSONObject manualOb) {
        try {
            JSONObject base = new JSONObject();
            JSONObject server = new JSONObject();
            server.put("host", edXmHost.getText().toString().trim());
            int port = 0;
            try {
                port = Integer.parseInt(edXmPort.getText().toString().trim());
            } catch (NumberFormatException ignored) {
            }
            server.put("port", port);
            JSONObject stream = manualOb != null ? manualOb.optJSONObject("streamSettings") : null;
            JSONObject tls = stream != null ? stream.optJSONObject("tlsSettings") : null;
            if (tls == null && stream != null) {
                tls = stream.optJSONObject("realitySettings");
            }
            if (tls != null) {
                if (!tls.optString("serverName", "").isEmpty()) {
                    server.put("sni", tls.optString("serverName"));
                }
                if (!tls.optString("publicKey", "").isEmpty()) {
                    server.put("public_key", tls.optString("publicKey"));
                }
                if (!tls.optString("shortId", "").isEmpty()) {
                    server.put("short_id", tls.optString("shortId"));
                }
            }
            base.put("server", server);

            JSONObject auth = new JSONObject();
            auth.put("uuid", edXmUuid.getText().toString().trim());
            auth.put("flow", edXmFlow.getText().toString().trim());
            auth.put("password", edXmPass.getText().toString());
            String proto = xmProtocol();
            String method = "";
            if ((proto.equals("vmess") || proto.equals("shadowsocks"))
                    && spXmEnc.getSelectedItem() != null) {
                method = spXmEnc.getSelectedItem().toString();
            }
            auth.put("method", method);
            base.put("auth", auth);

            JSONObject transport = new JSONObject();
            transport.put("network", xmNetwork());
            transport.put("security", xmSecurity());
            transport.put("path", edXmPath.getText().toString().trim());
            transport.put("host", edXmHostHeader.getText().toString().trim());
            base.put("transport", transport);

            JSONObject adv = new JSONObject();
            if (manualOb != null) {
                adv.put("outbound_json", manualOb.toString());
            }
            adv.put("manual_form", "1");
            if (!lastImportedLink.isEmpty()) {
                adv.put("link", lastImportedLink);
            }
            base.put("advanced", adv);
            return base;
        } catch (Exception e) {
            toast("Invalid form: " + e.getMessage());
            return null;
        }
    }

    /** Parse a subscription link through the Go core; null after a toast. */
    private JSONObject parseLinkConfig(String link) {
        try {
            String res = VpnlibHelper.parseLink(link);
            JSONObject parsed = new JSONObject(res);
            if (parsed.has("error")) {
                toast("Parse failed: " + parsed.optString("error"));
                return null;
            }
            return parsed;
        } catch (Exception e) {
            toast("Parse failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Base config for xray_slowdns saves: parse the link now (auto-parse on
     * save), or reuse the stored profile when no link is given (legacy /
     * manual setups). Returns null after showing the reason.
     */
    private JSONObject resolveXraySlowDnsBase() {
        String link = edXrayInput.getText().toString().trim();
        if (!link.isEmpty()) {
            return parseLinkConfig(link);
        }
        JSONObject stored = storedTunnel();
        if (stored == null) {
            toast("Link is required");
            return null;
        }
        try {
            return new JSONObject(stored.toString());
        } catch (Exception e) {
            toast("Load failed: " + e.getMessage());
            return null;
        }
    }

    private void save() {
        String uiType = currentType();
        boolean xrayUi = uiType.equals("xray");
        // "Configure manually" builds the outbound from the structured form
        // instead of the pasted link/JSON (works with or without SlowDNS).
        boolean manualXray = xrayUi && swXrayManual.isChecked();
        // Case SlowDNS cochée sur Xray => type effectif xray_slowdns.
        // Idem pour le SSH : le mode SSH-DNSTT => type effectif ssh_slowdns.
        String sshKey = sshModeKey();
        boolean sshDnstt = uiType.equals("ssh") && sshKey.equals("dnstt");
        String type = xrayUi && swXraySlowdns.isChecked() ? "xray_slowdns" : uiType;
        if (sshDnstt) {
            type = "ssh_slowdns";
        }

        // Xray: validate/auto-parse the single input now (no Parse button).
        // Link mode parses through the Go core and uses the parsed profile
        // as the save base; JSON mode is stored verbatim and just needs
        // to be a valid object.
        JSONObject xrayBase = null;
        String xrayJson = "";
        JSONObject manualOb = null;
        if (type.equals("xray") && !manualXray) {
            String input = edXrayInput.getText().toString().trim();
            if (input.isEmpty()) {
                toast(xrayLinkMode() ? "Link is required" : "JSON config is required");
                return;
            }
            if (xrayLinkMode()) {
                xrayBase = parseLinkConfig(input);
                if (xrayBase == null) {
                    return;
                }
            } else {
                try {
                    new JSONObject(input);
                } catch (Exception e) {
                    toast("Invalid JSON: " + e.getMessage());
                    return;
                }
                xrayJson = input;
            }
        }
        if (manualXray) {
            manualOb = buildManualOutbound();
            if (manualOb == null) {
                return;
            }
        }

        String name = edName.getText().toString().trim();
        if (name.isEmpty() && xrayBase != null) {
            name = xrayBase.optString("name", "").trim();
            if (!name.isEmpty()) {
                edName.setText(name);
            }
        }
        if (name.isEmpty() && manualXray) {
            name = edXmHost.getText().toString().trim();
            if (!name.isEmpty()) {
                edName.setText(name);
            }
        }
        if (name.isEmpty()) {
            toast("Name is required");
            return;
        }
        if (editId != null && isStoredLocked(editId)) {
            toast("Profil verrouillé : modification impossible");
            return;
        }
        try {
            // xray_slowdns is link-driven: the link is parsed now (or the
            // stored profile reused for legacy/manual setups) and provides
            // host/port/uuid/transport/outbound. The form only adds the
            // SlowDNS key + NS + resolver.
            JSONObject slowBase = null;
            if (type.equals("xray_slowdns")) {
                // Manual form: the generated outbound IS the base (the Go
                // core rewrites its address to the dnstt forward at start).
                slowBase = manualXray ? buildManualBase(manualOb)
                        : resolveXraySlowDnsBase();
                if (slowBase == null) {
                    return;
                }
            }
            JSONObject server = new JSONObject();
            if (type.equals("xray_slowdns")) {
                JSONObject bs = slowBase.optJSONObject("server");
                if (bs != null) {
                    server = new JSONObject(bs.toString());
                }
            } else if (type.equals("xray")) {
                // Link mode: host/port/sni come from the parsed link. JSON
                // mode: none needed, the pasted config carries everything.
                // Manual mode: the form fields ARE the endpoint.
                if (manualXray) {
                    server.put("host", edXmHost.getText().toString().trim());
                    int mport = 0;
                    try {
                        mport = Integer.parseInt(edXmPort.getText().toString().trim());
                    } catch (NumberFormatException ignored) {
                    }
                    server.put("port", mport);
                    if (manualOb != null) {
                        JSONObject stream = manualOb.optJSONObject("streamSettings");
                        JSONObject tls = stream != null ? stream.optJSONObject("tlsSettings") : null;
                        if (tls == null && stream != null) {
                            tls = stream.optJSONObject("realitySettings");
                        }
                        if (tls != null && !tls.optString("serverName", "").isEmpty()) {
                            server.put("sni", tls.optString("serverName"));
                        }
                        if (tls != null && !tls.optString("publicKey", "").isEmpty()) {
                            server.put("public_key", tls.optString("publicKey"));
                        }
                        if (tls != null && !tls.optString("shortId", "").isEmpty()) {
                            server.put("short_id", tls.optString("shortId"));
                        }
                    }
                } else if (xrayBase != null) {
                    JSONObject xs = xrayBase.optJSONObject("server");
                    if (xs != null) {
                        server = new JSONObject(xs.toString());
                    }
                }
            } else {
                server.put("host", edHost.getText().toString().trim());
                int port = 0;
                try {
                    port = Integer.parseInt(edPort.getText().toString().trim());
                } catch (NumberFormatException ignored) {
                }
                server.put("port", port);
                // SNI du mode SSH-TLS* (le SNI est aussi le nom de domaine
                // present dans le certificat du tunnel).
                if ((type.equals("ssh") || type.equals("ssh_slowdns")) && sshModeUses(sshKey, "tls")) {
                    String tlsSni = edSshTlsSni.getText().toString().trim();
                    if (!tlsSni.isEmpty()) {
                        server.put("sni", tlsSni);
                    }
                }
            }
            if (type.equals("zivpn")) {
                // Plages fixes hardcodées (8 sous-plages, round-robin
                // interne) — pas de champ utilisateur.
                server.put("port_range", ZIVPN_FIXED_RANGES);
            }
            if (type.equals("ssh_slowdns") || type.equals("xray_slowdns")) {
                String pubkey = edPubkey.getText().toString().trim();
                String nsdomain = edNsdomain.getText().toString().trim();
                String resolver = edResolver.getText().toString().trim();
                // Never store blanks over saved values: a hidden/untouched
                // field must not wipe the stored SlowDNS settings.
                if (pubkey.isEmpty()) {
                    pubkey = storedSlowdnsKey();
                    if (!pubkey.isEmpty()) {
                        edPubkey.setText(pubkey);
                        toast("Kept saved public key");
                    }
                }
                if (nsdomain.isEmpty()) {
                    nsdomain = storedServerField("nameserver");
                    if (nsdomain.isEmpty()) {
                        nsdomain = storedServerField("hostname");
                    }
                    if (!nsdomain.isEmpty()) {
                        edNsdomain.setText(nsdomain);
                    }
                }
                if (resolver.isEmpty()) {
                    resolver = "8.8.8.8:53";
                    edResolver.setText(resolver);
                }
                // Strict host:port shape: a mistyped resolver (ex:
                // "8.8.8.8:53tomp") kills dnstt with a cryptic error.
                int rport = -1;
                try {
                    String rp = resolver.substring(resolver.lastIndexOf(':') + 1);
                    if (resolver.lastIndexOf(':') <= 0 || !rp.matches("\\d{1,5}")) {
                        throw new NumberFormatException();
                    }
                    rport = Integer.parseInt(rp);
                } catch (Exception ignored) {
                }
                if (rport < 1 || rport > 65535) {
                    toast("DNS resolver must be ip:port (ex: 8.8.8.8:53)");
                    return;
                }
                if (type.equals("ssh_slowdns")) {
                    server.put("public_key", pubkey);
                }
                // xray_slowdns: server.public_key belongs to Reality (from
                // the parsed link); the SlowDNS key goes to advanced below.
                server.put("nameserver", nsdomain);
                server.put("dns_resolver", resolver);
            }
            if (type.equals("xray") && !manualXray) {
                if (!edSni.getText().toString().trim().isEmpty()) {
                    server.put("sni", edSni.getText().toString().trim());
                }
                if (!edRealityPubkey.getText().toString().trim().isEmpty()) {
                    server.put("public_key", edRealityPubkey.getText().toString().trim());
                }
                if (!edShortid.getText().toString().trim().isEmpty()) {
                    server.put("short_id", edShortid.getText().toString().trim());
                }
            }

            // xray never needs manual host/port: link (parsed) or JSON
            // config carries the endpoint (full configs accepted too).
            // SSH (y compris SSH-DNSTT) exige l'hote du serveur.
            if (!type.equals("xray_slowdns")
                    && !type.equals("xray")
                    && edHost.getText().toString().trim().isEmpty()) {
                toast("Host is required");
                return;
            }
            if (type.equals("ssh_slowdns")) {
                if (edUsername.getText().toString().trim().isEmpty()) {
                    toast("Username is required");
                    return;
                }
                if (edNsdomain.getText().toString().trim().isEmpty()
                        || edPubkey.getText().toString().trim().isEmpty()) {
                    toast("NS domain and public key are required");
                    return;
                }
            }
            if (type.equals("xray_slowdns")) {
                if (edNsdomain.getText().toString().trim().isEmpty()
                        || edPubkey.getText().toString().trim().isEmpty()) {
                    toast("NS domain and public key are required");
                    return;
                }
            }
            if (type.equals("zivpn") && edZpass.getText().toString().isEmpty()) {
                toast("Password is required");
                return;
            }
            if (type.equals("hysteria")) {
                if (edHyAuth.getText().toString().trim().isEmpty()) {
                    toast("Auth (mot de passe) Hysteria requis");
                    return;
                }
                // Plage par défaut si vide : jamais de port fixe seul.
                if (edHyPortRange.getText().toString().trim().isEmpty()) {
                    edHyPortRange.setText("20000-50000");
                }
                String hpr = edHyPortRange.getText().toString().replaceAll("\\s+", "");
                if (!hpr.matches("\\d+(-\\d+)?(,\\d+(-\\d+)?)*")) {
                    toast("Port hopping invalide (ex : 20000-50000)");
                    return;
                }
            }

            JSONObject auth = new JSONObject();
            JSONObject ssh = new JSONObject();
            if (type.equals("xray_slowdns") && slowBase != null) {
                JSONObject ba = slowBase.optJSONObject("auth");
                if (ba != null) {
                    auth = new JSONObject(ba.toString());
                }
            }
            if (type.equals("ssh") || type.equals("ssh_slowdns")) {
                auth.put("username", edUsername.getText().toString().trim());
                // Mode d'authentification : mot de passe ou cle privee.
                if (sshAuthIsPassword()) {
                    auth.put("password", edPassword.getText().toString());
                } else {
                    String key = edSshKey.getText().toString().trim();
                    if (key.isEmpty()) {
                        toast("Private key is required in this authentication mode");
                        return;
                    }
                    auth.put("private_key", key);
                    auth.put("passphrase", edSshPassphrase.getText().toString());
                }
            }
            if (type.equals("ssh")) {
                // Proxy CONNECT et payload ne s'appliquent qu'aux modes qui
                // les declarent (SSH-Proxy*, SSH-*Payload*).
                ssh.put("proxy", sshModeUses(sshKey, "proxy")
                        ? edSshProxy.getText().toString().trim() : "");
                ssh.put("payload", sshModeUses(sshKey, "payload")
                        ? edSshPayload.getText().toString() : "");
            }
            if (type.equals("xray") && manualXray) {
                // Manual form: credentials typed directly by the user.
                String proto = xmProtocol();
                auth.put("uuid", edXmUuid.getText().toString().trim());
                auth.put("flow", edXmFlow.getText().toString().trim());
                auth.put("password", edXmPass.getText().toString());
                String method = "";
                if ((proto.equals("vmess") || proto.equals("shadowsocks"))
                        && spXmEnc.getSelectedItem() != null) {
                    method = spXmEnc.getSelectedItem().toString();
                }
                auth.put("method", method);
            } else if (type.equals("xray") && xrayBase != null) {
                JSONObject ba = xrayBase.optJSONObject("auth");
                if (ba != null) {
                    auth = new JSONObject(ba.toString());
                }
            } else if (type.equals("xray") || type.equals("xray_slowdns")) {
                auth.put("uuid", edUuid.getText().toString().trim());
                auth.put("flow", edFlow.getText().toString().trim());
                auth.put("password", edXpass.getText().toString());
                auth.put("method", edMethod.getText().toString().trim());
            }
            if (type.equals("zivpn")) {
                auth.put("password", edZpass.getText().toString());
            }
            if (type.equals("hysteria")) {
                auth.put("password", edHyAuth.getText().toString().trim());
            }

            int secPos = edSecurity.getSelectedItemPosition();
            String security = secPos >= 0 ? SECURITIES[secPos] : "";
            JSONObject transport = new JSONObject();
            // Transport only matters for Xray-family tunnels (zivpn obfs is
            // hardcoded server-side, ssh uses none).
            if (type.equals("xray") && manualXray) {
                String msec = xmSecurity();
                transport.put("network", xmNetwork());
                transport.put("security", msec);
                transport.put("path", edXmPath.getText().toString().trim());
                transport.put("host", edXmHostHeader.getText().toString().trim());
            } else if (type.equals("xray_slowdns") && slowBase != null) {
                JSONObject bt = slowBase.optJSONObject("transport");
                if (bt != null) {
                    transport = new JSONObject(bt.toString());
                }
            } else if (type.equals("xray") && xrayBase != null) {
                JSONObject bt = xrayBase.optJSONObject("transport");
                if (bt != null) {
                    transport = new JSONObject(bt.toString());
                }
            } else if (type.equals("xray") || type.equals("xray_slowdns")) {
                transport.put("network", edNetwork.getSelectedItem().toString());
                transport.put("security", security);
                transport.put("path", edPath.getText().toString().trim());
                transport.put("host", edWshost.getText().toString().trim());
            }
            JSONObject advanced = new JSONObject();
            if (type.equals("xray_slowdns") && slowBase != null) {
                JSONObject ba = slowBase.optJSONObject("advanced");
                if (ba != null) {
                    advanced = new JSONObject(ba.toString());
                }
                advanced.put("link", edXrayInput.getText().toString().trim());
                String slowKey = edPubkey.getText().toString().trim();
                if (!slowKey.isEmpty()) {
                    advanced.put("slowdns_pubkey", slowKey);
                }
            } else if (type.equals("xray") && manualXray) {
                // Structured form: the generated outbound is authoritative.
                advanced.put("outbound_json", manualOb.toString());
                advanced.put("manual_form", "1");
                if (!lastImportedLink.isEmpty()) {
                    advanced.put("link", lastImportedLink);
                }
            } else if (type.equals("xray")) {
                if (xrayBase != null) {
                    // Parsed link: keep its outbound JSON, remember the link.
                    JSONObject ba = xrayBase.optJSONObject("advanced");
                    if (ba != null) {
                        advanced = new JSONObject(ba.toString());
                    }
                advanced.put("link", manualXray ? lastImportedLink
                        : edXrayInput.getText().toString().trim());
                } else {
                    // Full client config or single outbound, stored verbatim;
                    // the Go core detects full configs by the "outbounds" key.
                    advanced.put("outbound_json", xrayJson);
                }
                if (!advanced.has("outbound_json")) {
                    toast("Xray needs a link or a JSON config");
                    return;
                }
            }

            if (type.equals("ssh") || type.equals("ssh_slowdns")) {
                // Les 9 protocoles SSH sont decrits par advanced["ssh_mode"].
                advanced.put("ssh_mode", sshKey);
                // Couche TLS autour du handshake SSH (modes SSH-TLS*).
                boolean useTls = sshModeUses(sshKey, "tls");
                advanced.put("ssh_tls", useTls);
                if (useTls) {
                    int tv = spSshTlsVersion.getSelectedItemPosition();
                    advanced.put("ssh_tls_version",
                            (tv >= 0 && tv < SSH_TLS_VERSIONS_KEYS.length)
                                    ? SSH_TLS_VERSIONS_KEYS[tv] : "default");
                }
                // Authentification du proxy HTTP CONNECT.
                if (sshModeUses(sshKey, "proxy") && swSshProxyAuth.isChecked()) {
                    String pu = edSshProxyUser.getText().toString().trim();
                    if (pu.isEmpty()) {
                        toast("Proxy username is required when Authenticate Proxy is on");
                        return;
                    }
                    advanced.put("proxy_user", pu);
                    advanced.put("proxy_pass", edSshProxyPass.getText().toString());
                }
                // Mode DNSTT (UDP par defaut, TCP boost) : remplace l'ancien
                // type ssh_slowdns, desormais le mode SSH-DNSTT.
                if (type.equals("ssh_slowdns")) {
                    advanced.put("dnstt_tcp", spSshDnsttMode.getSelectedItemPosition() == 1);
                }
                // UDPGW par profil (port + DNS transparent).
                String uport = edSshUdpgwPort.getText().toString().trim();
                if (!uport.isEmpty()) {
                    try {
                        int pv = Integer.parseInt(uport);
                        if (pv < 1 || pv > 65535) {
                            throw new NumberFormatException();
                        }
                        advanced.put("udpgw_port", pv);
                    } catch (NumberFormatException e) {
                        toast("Udpgw port must be a number (1-65535)");
                        return;
                    }
                }
                advanced.put("udpgw_dns", swSshUdpgwDns.isChecked());
                // Ces modes exigent le moteur SSH natif (le binaire openssh
                // ne sait ni faire le TLS, ni le payload, ni le proxy).
                if (useTls || sshModeUses(sshKey, "proxy") || sshModeUses(sshKey, "payload")) {
                    advanced.put("native_ssh", true);
                }
            }

            if (type.equals("hysteria")) {
                String hyObfs = edHyObfs.getText().toString().trim();
                if (!hyObfs.isEmpty()) {
                    advanced.put("hysteria_obfs", hyObfs);
                }
                String hyRange = edHyPortRange.getText().toString().trim();
                if (!hyRange.isEmpty()) {
                    advanced.put("port_range", hyRange);
                }
                try {
                    int up = Integer.parseInt(edHyUp.getText().toString().trim());
                    if (up >= 1) {
                        advanced.put("up_mbps", up);
                    }
                } catch (NumberFormatException ignored) {
                }
                try {
                    int down = Integer.parseInt(edHyDown.getText().toString().trim());
                    if (down >= 1) {
                        advanced.put("down_mbps", down);
                    }
                } catch (NumberFormatException ignored) {
                }
            }

            JSONObject tunnel = new JSONObject();
            tunnel.put("name", name);
            tunnel.put("type", type);
            tunnel.put("enabled", edEnabled.isChecked());
            tunnel.put("priority", 0);
            tunnel.put("server", server);
            tunnel.put("auth", auth);
            tunnel.put("ssh", ssh);
            tunnel.put("transport", transport);
            tunnel.put("advanced", advanced);
            tunnel.put("routing", new JSONObject("{\"domain_strategy\":\"AsIs\",\"rules\":[],\"dns\":{\"servers\":[\"1.1.1.1\",\"8.8.8.8\"]}}"));

            String cfgPath = BinaryManager.configPath(this).getAbsolutePath();
            String res;
            if (editId == null) {
                res = VpnlibHelper.configAdd(cfgPath, tunnel.toString());
            } else {
                res = VpnlibHelper.configUpdate(cfgPath, editId, tunnel.toString());
            }
            if (res != null && !res.isEmpty()) {
                try {
                    JSONObject o = new JSONObject(res);
                    if (o.has("error")) {
                        toast("Save failed: " + o.optString("error"));
                        return;
                    }
                } catch (Exception ignored) {
                }
            }
            toast(editId == null ? "Server added" : "Server updated");

            if (TasVpnService.isRunning()) {
                toast("Restarting VPN to apply...");
                restartService();
            } else {
                finish();
            }
        } catch (Exception e) {
            toast("Save failed: " + e.getMessage());
        }
    }

    /** True when the stored profile is locked (defense in depth). */
    private boolean isStoredLocked(String id) {
        try {
            String cfgPath = BinaryManager.configPath(this).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath).trim());
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (id.equals(t.optString("id", ""))) {
                    return ProfileTransfer.isLocked(t);
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /** Read one stored server.* field of the profile being edited ("" if none). */
    private String storedServerField(String field) {
        JSONObject t = storedTunnel();
        if (t == null) {
            return "";
        }
        JSONObject server = t.optJSONObject("server");
        if (server != null) {
            return server.optString(field, "");
        }
        return "";
    }

    /** Full stored JSON of the profile being edited (null if new/missing). */
    private JSONObject storedTunnel() {
        if (editId == null || editId.isEmpty()) {
            return null;
        }
        try {
            String cfgPath = BinaryManager.configPath(this).getAbsolutePath();
            JSONArray arr = new JSONArray(VpnlibHelper.listTunnels(cfgPath).trim());
            for (int i = 0; i < arr.length(); i++) {
                JSONObject t = arr.getJSONObject(i);
                if (editId.equals(t.optString("id", ""))) {
                    return t;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /** Stored SlowDNS key: advanced.slowdns_pubkey first (xray_slowdns),
     *  then the legacy server.public_key. */
    private String storedSlowdnsKey() {
        JSONObject t = storedTunnel();
        if (t == null) {
            return "";
        }
        JSONObject adv = t.optJSONObject("advanced");
        if (adv != null && !adv.optString("slowdns_pubkey", "").isEmpty()) {
            return adv.optString("slowdns_pubkey");
        }
        JSONObject server = t.optJSONObject("server");
        if (server != null) {
            return server.optString("public_key", "");
        }
        return "";
    }

    private void restartService() {        String active = TasVpnService.getActiveTunnelId();
        if (active == null || active.isEmpty()) {
            active = VPNApplication.getInstance().getActiveTunnelId();
        }
        android.content.Intent stop = new android.content.Intent(this, TasVpnService.class);
        stop.setAction(TasVpnService.ACTION_DISCONNECT);
        startService(stop);
        final String id = active;
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            if (id != null && !id.isEmpty()) {
                android.content.Intent start = new android.content.Intent(this, TasVpnService.class);
                start.setAction(TasVpnService.ACTION_CONNECT);
                start.putExtra(TasVpnService.EXTRA_TUNNEL_ID, id);
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    startForegroundService(start);
                } else {
                    startService(start);
                }
            }
            finish();
        }, 1500);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
