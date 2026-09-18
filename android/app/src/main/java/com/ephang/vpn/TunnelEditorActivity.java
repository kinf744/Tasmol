package com.ephang.vpn;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
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

/** Native server editor: same fields as the Web UI, fully offline. */
public class TunnelEditorActivity extends AppCompatActivity {
    public static final String EXTRA_TUNNEL_ID = "tunnel_id";

    private static final String[] TYPES = {"ssh", "ssh_slowdns", "xray", "xray_slowdns", "zivpn"};
    private static final String[] TYPE_LABELS = {"SSH", "SSH + SlowDNS", "Xray", "Xray + SlowDNS", "Zivpn UDP"};
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
    private TextView lblPortRange;
    private EditText edPortRange;
    private LinearLayout secSsh;
    private EditText edUsername;
    private EditText edPassword;
    private TextView lblSshProxy;
    private EditText edSshProxy;
    private TextView lblSshPayload;
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
    private LinearLayout secZivpn;
    private EditText edZpass;
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
    private LinearLayout secChain;
    private EditText edProxyTag;
    private Switch edTransportLayer;

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
        lblPortRange = findViewById(R.id.lbl_port_range);
        edPortRange = findViewById(R.id.ed_port_range);
        secSsh = findViewById(R.id.sec_ssh);
        edUsername = findViewById(R.id.ed_username);
        edPassword = findViewById(R.id.ed_password);
        lblSshProxy = findViewById(R.id.lbl_ssh_proxy);
        edSshProxy = findViewById(R.id.ed_ssh_proxy);
        lblSshPayload = findViewById(R.id.lbl_ssh_payload);
        edSshPayload = findViewById(R.id.ed_ssh_payload);
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
        secChain = findViewById(R.id.sec_chain);
        edProxyTag = findViewById(R.id.ed_proxy_tag);
        edTransportLayer = findViewById(R.id.ed_transport_layer);
    }

    private void setupSpinners() {
        edType.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, TYPE_LABELS));
        edNetwork.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, NETWORKS));
        edSecurity.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, SECURITY_LABELS));
        edObfs.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, OBFSS));

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
    }

    private String currentType() {
        int pos = edType.getSelectedItemPosition();
        if (pos < 0 || pos >= TYPES.length) {
            return "ssh";
        }
        return TYPES[pos];
    }

    private void refreshSections() {
        String type = currentType();
        String network = (String) edNetwork.getSelectedItem();
        int secPos = edSecurity.getSelectedItemPosition();
        String security = secPos >= 0 ? SECURITIES[secPos] : "";

        boolean isSSH = type.equals("ssh") || type.equals("ssh_slowdns");
        boolean isXray = type.equals("xray") || type.equals("xray_slowdns");
        boolean isSlowDNS = type.equals("ssh_slowdns") || type.equals("xray_slowdns");
        boolean isZivpn = type.equals("zivpn");
        boolean showServer = !type.equals("ssh_slowdns") && !type.equals("xray");

        // xray uses link/JSON exclusively; xray_slowdns keeps manual fields.
        // xray_slowdns is link-only too (auto-parsed on save): no manual
        // host/port, no Xray auth section, no outbound JSON, no Parse button.
        boolean showXrayAuth = false;
        // No visible transport section: Xray works from link/JSON only.
        boolean showTransport = false;
        boolean isXraySlowDns = type.equals("xray_slowdns");

        secSsh.setVisibility(isSSH ? View.VISIBLE : View.GONE);
        // Proxy/payload are plain-SSH only: ssh_slowdns dials through the
        // dnstt forward and needs username/password/pubkey/NS/DNS instead.
        int proxyVis = type.equals("ssh") ? View.VISIBLE : View.GONE;
        lblSshProxy.setVisibility(proxyVis);
        edSshProxy.setVisibility(proxyVis);
        lblSshPayload.setVisibility(proxyVis);
        edSshPayload.setVisibility(proxyVis);
        secXray.setVisibility(showXrayAuth ? View.VISIBLE : View.GONE);
        secXrayLink.setVisibility(isXray ? View.VISIBLE : View.GONE);
        secZivpn.setVisibility(isZivpn ? View.VISIBLE : View.GONE);
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
        secChain.setVisibility(isXray || isSlowDNS ? View.VISIBLE : View.GONE);
        syncXrayInputVisuals();

        edPort.setVisibility(isZivpn ? View.GONE : View.VISIBLE);
        lblPort.setVisibility(isZivpn ? View.GONE : View.VISIBLE);
        lblPortRange.setVisibility(isZivpn ? View.VISIBLE : View.GONE);
        edPortRange.setVisibility(isZivpn ? View.VISIBLE : View.GONE);
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
                selectSpinner(edType, TYPES, t.optString("type", "ssh"));
                edEnabled.setChecked(t.optBoolean("enabled", true));

                JSONObject server = t.optJSONObject("server");
                if (server != null) {
                    edHost.setText(server.optString("host", ""));
                    int port = server.optInt("port", 0);
                    edPort.setText(port == 0 ? "" : String.valueOf(port));
                    edPortRange.setText(server.optString("port_range", ""));
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
                }
                JSONObject transport = t.optJSONObject("transport");
                if (transport != null) {
                    selectSpinner(edNetwork, NETWORKS, transport.optString("network", "tcp"));
                    selectSpinnerByValue(edSecurity, SECURITIES, transport.optString("security", ""));
                    edPath.setText(transport.optString("path", ""));
                    edWshost.setText(transport.optString("host", ""));
                    selectSpinner(edObfs, OBFSS, transport.optString("obfs", "salamander"));
                    edObfsParam.setText(transport.optString("obfs_param", "zivpn"));
                    edTransportLayer.setChecked(transport.optBoolean("transport_layer", false));
                }
                JSONObject adv = t.optJSONObject("advanced");
                if (adv != null) {
                    String link = adv.optString("link", "");
                    String json = adv.optString("outbound_json", "");
                    // JSON mode wins when a stored config exists (and the
                    // type allows it); the link stays stashed for a switch.
                    boolean jsonMode = !json.isEmpty() && !currentType().equals("xray_slowdns");
                    if (jsonMode) {
                        rbModeJson.setChecked(true);
                    } else {
                        rbModeLink.setChecked(true);
                    }
                    stashLink = link;
                    stashJson = json;
                    edXrayInput.setText(jsonMode ? json : link);
                    lastXrayLinkMode = xrayLinkMode();
                    JSONObject ps = adv.optJSONObject("proxy_settings");
                    if (ps != null) {
                        edProxyTag.setText(ps.optString("tag", ""));
                    }
                    // xray_slowdns keeps its SlowDNS key in advanced (the
                    // server key belongs to Reality): prefer it on load.
                    if (currentType().equals("xray_slowdns")
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
        String type = currentType();

        // Xray: validate/auto-parse the single input now (no Parse button).
        // Link mode parses through the Go core and uses the parsed profile
        // as the save base; JSON mode is stored verbatim and just needs
        // to be a valid object.
        JSONObject xrayBase = null;
        String xrayJson = "";
        if (type.equals("xray")) {
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

        String name = edName.getText().toString().trim();
        if (name.isEmpty() && xrayBase != null) {
            name = xrayBase.optString("name", "").trim();
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
                slowBase = resolveXraySlowDnsBase();
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
                if (xrayBase != null) {
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
            }
            if (type.equals("zivpn")) {
                String ranges = edPortRange.getText().toString().trim();
                if (ranges.isEmpty()) {
                    // Never store a blank range: a hidden/untouched field
                    // must not wipe the stored ranges. Reuse them, else
                    // fall back to the default.
                    ranges = storedServerField("port_range");
                    if (ranges.isEmpty()) {
                        ranges = "6000-19999";
                    } else {
                        toast("Kept saved port range(s)");
                    }
                    edPortRange.setText(ranges);
                }
                server.put("port_range", ranges);
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
            if (type.equals("xray")) {
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
            if (!type.equals("ssh_slowdns") && !type.equals("xray_slowdns")
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
                auth.put("password", edPassword.getText().toString());
            }
            if (type.equals("ssh")) {
                ssh.put("proxy", edSshProxy.getText().toString().trim());
                ssh.put("payload", edSshPayload.getText().toString());
            }
            if (type.equals("xray") && xrayBase != null) {
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

            int secPos = edSecurity.getSelectedItemPosition();
            String security = secPos >= 0 ? SECURITIES[secPos] : "";
            JSONObject transport = new JSONObject();
            // Transport only matters for Xray-family tunnels (zivpn obfs is
            // hardcoded server-side, ssh uses none).
            if (type.equals("xray_slowdns") && slowBase != null) {
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
            if ((type.equals("xray") || type.equals("xray_slowdns"))
                    && edTransportLayer.isChecked()) {
                transport.put("transport_layer", true);
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
            } else if (type.equals("xray")) {
                if (xrayBase != null) {
                    // Parsed link: keep its outbound JSON, remember the link.
                    JSONObject ba = xrayBase.optJSONObject("advanced");
                    if (ba != null) {
                        advanced = new JSONObject(ba.toString());
                    }
                    advanced.put("link", edXrayInput.getText().toString().trim());
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

            // Proxy chaining: transport-layer proxy / proxySettings.tag.
            String proxyTag = edProxyTag.getText().toString().trim();
            if (!proxyTag.isEmpty()) {
                JSONObject existing = advanced.optJSONObject("proxy_settings");
                JSONObject ps = existing != null ? new JSONObject(existing.toString()) : new JSONObject();
                ps.put("tag", proxyTag);
                advanced.put("proxy_settings", ps);
            } else if (advanced.optJSONObject("proxy_settings") != null) {
                advanced.remove("proxy_settings");
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
