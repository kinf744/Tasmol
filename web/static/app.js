let ws = null;
let currentSection = 'dashboard';
let tunnels = [];
let features = {};

function init() {
    connectWS();
    setupEventListeners();
    showSection('dashboard');
    loadInitialData();
}

function connectWS() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => console.log('WebSocket connected');
    ws.onclose = () => setTimeout(connectWS, 3000);
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateUI(data);
    };
    ws.onerror = (err) => console.error('WebSocket error:', err);
}

function setupEventListeners() {
    document.getElementById('dark-mode-icon').classList.toggle('fa-moon', !document.documentElement.classList.contains('dark'));
    document.getElementById('dark-mode-icon').classList.toggle('fa-sun', document.documentElement.classList.contains('dark'));
}

function loadInitialData() {
    fetch('/api/v1/status')
        .then(res => res.json())
        .then(data => updateUI(data))
        .catch(err => console.error('Failed to load initial data:', err));

    fetch('/api/v1/features')
        .then(res => res.json())
        .then(data => {
            features = data;
            updateFeatureToggles();
        })
        .catch(err => console.error('Failed to load features:', err));
}

function updateUI(data) {
    updateConnectionStatus(data.running);
    updateStats(data);
    updateTunnelTable(data.tunnels);
    updateTunnelsGrid(data.tunnels);
    updateUDPGWStats(data.udpgw);
    tunnels = data.tunnels;
}

function updateConnectionStatus(running) {
    const indicator = document.getElementById('status-indicator');
    const text = document.getElementById('status-text');
    const btn = document.getElementById('main-toggle');

    if (running) {
        indicator.className = 'fas fa-circle text-xs mr-1 text-green-500';
        text.textContent = 'Connected';
        text.className = 'text-green-600 dark:text-green-400';
        btn.innerHTML = '<i class="fas fa-power-off"></i><span>Disconnect</span>';
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-danger');
    } else {
        indicator.className = 'fas fa-circle text-xs mr-1 text-gray-400';
        text.textContent = 'Disconnected';
        text.className = 'text-gray-600 dark:text-gray-300';
        btn.innerHTML = '<i class="fas fa-power-off"></i><span>Connect</span>';
        btn.classList.remove('btn-danger');
        btn.classList.add('btn-primary');
    }
}

function updateStats(data) {
    let activeCount = 0;
    let totalUp = 0;
    let totalDown = 0;
    let minLatency = Infinity;

    data.tunnels.forEach(t => {
        if (t.status === 'running') {
            activeCount++;
            totalUp += t.bytes_up;
            totalDown += t.bytes_down;
            if (t.latency > 0 && t.latency < minLatency) minLatency = t.latency;
        }
    });

    document.getElementById('stat-active-tunnels').textContent = activeCount;
    document.getElementById('stat-bytes-up').textContent = formatBytes(totalUp);
    document.getElementById('stat-bytes-down').textContent = formatBytes(totalDown);
    document.getElementById('stat-latency').textContent = minLatency === Infinity ? '-- ms' : `${minLatency} ms`;
}

function updateTunnelTable(tunnels) {
    const tbody = document.getElementById('tunnel-table-body');
    tbody.innerHTML = '';

    tunnels.forEach(t => {
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50 dark:hover:bg-gray-700/50';
        row.innerHTML = `
            <td class="py-3 px-4 font-medium text-gray-900 dark:text-white">${t.name}</td>
            <td class="py-3 px-4 text-gray-600 dark:text-gray-300">${formatTunnelType(t.type)}</td>
            <td class="py-3 px-4">
                <span class="px-2 py-1 rounded-full text-xs font-medium ${getStatusClass(t.status)}">
                    ${t.status}
                </span>
            </td>
            <td class="py-3 px-4 text-gray-600 dark:text-gray-300">${formatUptime(t.uptime)}</td>
            <td class="py-3 px-4">
                <div class="flex items-center space-x-2">
                    <button onclick="toggleTunnel('${t.id}', '${t.status}')" class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="${t.status === 'running' ? 'Stop' : 'Start'}">
                        <i class="fas ${t.status === 'running' ? 'fa-stop text-red-500' : 'fa-play text-green-500'}"></i>
                    </button>
                    <button onclick="restartTunnel('${t.id}')" class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Restart">
                        <i class="fas fa-redo text-blue-500"></i>
                    </button>
                    <button onclick="editTunnel('${t.id}')" class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Edit">
                        <i class="fas fa-edit text-primary"></i>
                    </button>
                    <button onclick="deleteTunnel('${t.id}')" class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Delete">
                        <i class="fas fa-trash text-red-500"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function updateTunnelsGrid(tunnels) {
    const grid = document.getElementById('tunnels-grid');
    grid.innerHTML = '';

    tunnels.forEach(t => {
        const card = document.createElement('div');
        card.className = 'bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4';
        card.innerHTML = `
            <div class="flex justify-between items-start mb-3">
                <div>
                    <h4 class="font-semibold text-gray-900 dark:text-white">${t.name}</h4>
                    <span class="text-sm text-gray-500 dark:text-gray-400">${formatTunnelType(t.type)}</span>
                </div>
                <span class="px-2 py-1 rounded-full text-xs font-medium ${getStatusClass(t.status)}">${t.status}</span>
            </div>
            <div class="space-y-2 text-sm text-gray-600 dark:text-gray-300 mb-4">
                <div class="flex justify-between"><span>Server:</span><span>${t.config?.server?.host}:${t.config?.server?.port}</span></div>
                <div class="flex justify-between"><span>Up:</span><span>${formatBytes(t.bytes_up)}</span></div>
                <div class="flex justify-between"><span>Down:</span><span>${formatBytes(t.bytes_down)}</span></div>
                <div class="flex justify-between"><span>Latency:</span><span>${t.latency > 0 ? t.latency + ' ms' : '--'}</span></div>
                <div class="flex justify-between"><span>Uptime:</span><span>${formatUptime(t.uptime)}</span></div>
            </div>
            <div class="flex space-x-2">
                <button onclick="toggleTunnel('${t.id}', '${t.status}')" class="flex-1 py-2 px-3 rounded text-sm ${t.status === 'running' ? 'btn-danger' : 'btn-primary'}">
                    ${t.status === 'running' ? 'Stop' : 'Start'}
                </button>
                <button onclick="editTunnel('${t.id}')" class="flex-1 py-2 px-3 rounded text-sm btn-secondary">Edit</button>
            </div>
        `;
        grid.appendChild(card);
    });
}

function updateUDPGWStats(stats) {
    // Could add UDPGW stats display here
}

function updateFeatureToggles() {
    const toggles = {
        'kill_switch': 'kill-switch-toggle',
        'split_tunneling': 'split-tunnel-toggle',
        'dns_leak_protection': 'dns-leak-toggle',
        'auto_reconnect': 'auto-reconnect-toggle'
    };

    Object.entries(toggles).forEach(([key, id]) => {
        const el = document.getElementById(id);
        if (el && features[key] !== undefined) {
            el.checked = features[key];
        }
    });
}

function showSection(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
    document.querySelectorAll('.menu-btn').forEach(b => {
        b.classList.remove('bg-primary/10', 'dark:bg-primary/20', 'text-primary');
        b.classList.add('text-gray-700', 'dark:text-gray-300');
    });

    document.getElementById(`${section}-section`).classList.remove('hidden');
    const activeBtn = document.querySelector(`[data-section="${section}"]`);
    if (activeBtn) {
        activeBtn.classList.add('bg-primary/10', 'dark:bg-primary/20', 'text-primary');
        activeBtn.classList.remove('text-gray-700', 'dark:text-gray-300');
    }
    currentSection = section;
}

function toggleVPN() {
    // Inside the Android APK, the Connect button drives the native VpnService.
    if (window.Android && typeof Android.vpnToggle === 'function') {
        Android.vpnToggle();
        return;
    }
    const running = document.getElementById('status-text').textContent === 'Connected';
    fetch(`/api/v1/tunnels/${running ? 'stop-all' : 'start-all'}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => loadInitialData())
        .catch(err => console.error('Failed to toggle VPN:', err));
}

function toggleFeature(feature, enabled) {
    fetch('/api/v1/features', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [feature]: enabled })
    })
    .then(res => res.json())
    .then(data => loadInitialData())
    .catch(err => console.error('Failed to toggle feature:', err));
}

function openTunnelModal(tunnel = null) {
    const modal = document.getElementById('tunnel-modal');
    const form = document.getElementById('tunnel-form');
    const title = document.getElementById('modal-title');

    form.reset();
    document.getElementById('tunnel-id').value = '';
    document.getElementById('tunnel-enabled').checked = true;

    if (tunnel) {
        title.textContent = 'Edit Tunnel';
        document.getElementById('tunnel-id').value = tunnel.id;
        document.getElementById('tunnel-name').value = tunnel.name;
        document.getElementById('tunnel-type').value = tunnel.type;
        document.getElementById('tunnel-enabled').checked = tunnel.enabled;

        // Defensive: handle missing config gracefully
        const cfg = tunnel.config || {};
        const server = cfg.server || {};
        const auth = cfg.auth || {};
        const ssh = cfg.ssh || {};
        const transport = cfg.transport || {};
        const advanced = cfg.advanced || {};

        document.getElementById('tunnel-id').value = tunnel.id;
        document.getElementById('tunnel-name').value = tunnel.name;
        document.getElementById('tunnel-type').value = tunnel.type;
        document.getElementById('tunnel-enabled').checked = tunnel.enabled;
        document.getElementById('tunnel-host').value = server.host || '';
        document.getElementById('tunnel-port').value = server.port || '';
        document.getElementById('tunnel-zivpn-port-range').value = server.port_range || '';

        document.getElementById('tunnel-slowdns-pubkey').value = server.public_key || '';
        document.getElementById('tunnel-slowdns-domain').value = server.nameserver || server.hostname || '';
        document.getElementById('tunnel-slowdns-ns').value = server.dns_resolver || '8.8.8.8:53';
        document.getElementById('tunnel-reality-pubkey').value = server.public_key || '';
        document.getElementById('tunnel-reality-shortid').value = server.short_id || '';
        document.getElementById('tunnel-reality-sni').value = server.sni || '';
        document.getElementById('tunnel-zivpn-port-range').value = server.port_range || '';

        document.getElementById('tunnel-username').value = auth.username || '';
        document.getElementById('tunnel-password').value = auth.password || '';
        document.getElementById('tunnel-private-key').value = auth.private_key || '';
        document.getElementById('tunnel-ssh-payload').value = ssh.payload || '';
        document.getElementById('tunnel-ssh-proxy').value = ssh.proxy || '';
        document.getElementById('tunnel-uuid').value = auth.uuid || '';
        document.getElementById('tunnel-flow').value = auth.flow || '';
        document.getElementById('tunnel-xray-password').value = auth.password || '';
        document.getElementById('tunnel-xray-method').value = auth.method || '';
        document.getElementById('tunnel-zivpn-uuid').value = auth.uuid || '';
        document.getElementById('tunnel-zivpn-password').value = auth.password || '';

        document.getElementById('tunnel-network').value = transport.network || 'tcp';
        document.getElementById('tunnel-security').value = transport.security || '';
        document.getElementById('tunnel-ws-path').value = transport.path || '';
        document.getElementById('tunnel-ws-host').value = transport.host || '';
        document.getElementById('tunnel-zivpn-obfs').value = transport.obfs || 'salamander';
        document.getElementById('tunnel-zivpn-obfs-param').value = transport.obfs_param || 'zivpn';

        document.getElementById('tunnel-link').value = advanced.link || '';
        document.getElementById('tunnel-outbound-json').value = advanced.outbound_json || '';
        document.getElementById('tunnel-xray-json').value = advanced.outbound_json || '';

        // Fill the new three-section panel/hidden links for xray only.
        xraySetMode('manual');
        if (tunnel.type === 'xray') {
            xrayLoadIntoPanel(tunnel);
        }
    } else {
        title.textContent = 'Add Tunnel';
        xrayResetPanel();
    }

    updateTunnelFields();
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}
function closeTunnelModal() {
    document.getElementById('tunnel-modal').classList.add('hidden');
    document.getElementById('tunnel-modal').classList.remove('flex');
}

function updateTunnelFields() {
    const type = document.getElementById('tunnel-type').value;
    const network = document.getElementById('tunnel-network').value;
    const security = document.getElementById('tunnel-security').value;

    const isSSH = ['ssh', 'ssh_slowdns'].includes(type);
    const isXray = ['xray', 'xray_slowdns'].includes(type);
    const isSlowDNS = ['ssh_slowdns', 'xray_slowdns'].includes(type);
    const isZivpn = type === 'zivpn';
    const isUtunnel = type === 'utunnel';
    // ssh_slowdns dials through dnstt and xray uses link/JSON only:
    // no direct server host/port.
    const showServer = type !== 'ssh_slowdns' && type !== 'xray';
    // Transport is only meaningful for Xray-family tunnels.
    const showTransport = false;

    document.getElementById('ssh-auth-fields').classList.toggle('hidden', !isSSH);
    // xray uses the new three-section panel (manual link import or pasted
    // JSON); xray_slowdns keeps the legacy manual + link/JSON blocks.
    document.getElementById('xray-auth-fields').classList.toggle('hidden', type !== 'xray_slowdns');
    document.getElementById('xray-link-fields').classList.toggle('hidden', type !== 'xray_slowdns');
    document.getElementById('xray-manual-fields').classList.toggle('hidden', type !== 'xray');
    if (type === 'xray') {
        xraySetMode(xrayMode);
        xrayProtoChange();
        xrayNetworkChange();
        xraySecurityChange();
    }
    document.getElementById('zivpn-auth-fields').classList.toggle('hidden', !isZivpn);
    document.getElementById('utunnel-auth-fields').classList.toggle('hidden', !isUtunnel);
    document.getElementById('slowdns-fields').classList.toggle('hidden', !isSlowDNS);
    document.getElementById('server-fields').classList.toggle('hidden', !showServer);
    document.getElementById('transport-fields').classList.add('hidden'); // Always hide transport

    const showPath = isXray && ['ws', 'grpc', 'xhttp', 'httpupgrade'].includes(network);
    document.getElementById('ws-fields').classList.toggle('hidden', !showPath);
    document.getElementById('reality-fields').classList.toggle('hidden', !(isXray && security === 'reality'));

    // Hidden required inputs would block submit: toggle required flags.
    document.getElementById('tunnel-host').required = showServer;
    // zivpn uses a port range instead of the numeric port.
    const portInput = document.getElementById('tunnel-port');
    portInput.required = showServer && !isZivpn;
    portInput.parentElement.style.display = isZivpn ? 'none' : '';
}

function saveTunnel(event) {
    event.preventDefault();

    const id = document.getElementById('tunnel-id').value;
    const type = document.getElementById('tunnel-type').value;
    const network = document.getElementById('tunnel-network').value;
    const security = document.getElementById('tunnel-security').value;

    const portRaw = document.getElementById('tunnel-port').value;
    const tunnel = {
        name: document.getElementById('tunnel-name').value,
        type: type,
        enabled: document.getElementById('tunnel-enabled').checked,
        priority: 0,
        server: {
            host: document.getElementById('tunnel-host').value,
            port: parseInt(portRaw) || 0,
            port_range: type === 'zivpn' ? document.getElementById('tunnel-zivpn-port-range').value.trim() : '',
            public_key: document.getElementById('tunnel-slowdns-pubkey').value || document.getElementById('tunnel-reality-pubkey').value,
            nameserver: document.getElementById('tunnel-slowdns-domain').value,
            dns_resolver: document.getElementById('tunnel-slowdns-ns').value,
            sni: document.getElementById('tunnel-reality-sni').value,
            short_id: document.getElementById('tunnel-reality-shortid').value
        },
        auth: {},
        transport: {
            network: isXray ? 'tcp' : network,
            security: isXray ? 'none' : security,
            path: isXray ? '' : document.getElementById('tunnel-ws-path').value,
            host: isXray ? '' : document.getElementById('tunnel-ws-host').value,
            obfs: isXray ? '' : document.getElementById('tunnel-zivpn-obfs').value,
            obfs_param: isXray ? '' : document.getElementById('tunnel-zivpn-obfs-param').value
        },
        advanced: {},
        routing: {
            domain_strategy: 'AsIs',
            rules: [],
            dns: { servers: ['1.1.1.1', '8.8.8.8'] }
        }
    };

    if (['ssh', 'ssh_slowdns'].includes(type)) {
        tunnel.auth.username = document.getElementById('tunnel-username').value;
        tunnel.auth.password = document.getElementById('tunnel-password').value;
        tunnel.auth.private_key = document.getElementById('tunnel-private-key').value;
        tunnel.ssh = {
            payload: document.getElementById('tunnel-ssh-payload').value,
            proxy: document.getElementById('tunnel-ssh-proxy').value.trim()
        };
    }

    if (type === 'xray_slowdns') {
        // Legacy manual + link/JSON blocks (unchanged).
        tunnel.auth.uuid = document.getElementById('tunnel-uuid').value;
        tunnel.auth.flow = document.getElementById('tunnel-flow').value;
        tunnel.auth.password = document.getElementById('tunnel-xray-password').value;
        tunnel.auth.method = document.getElementById('tunnel-xray-method').value;
        // Outbound JSON (from a parsed link or pasted) wins at runtime.
        const manualJson = document.getElementById('tunnel-xray-json').value.trim();
        if (manualJson !== '') {
            try {
                JSON.parse(manualJson);
            } catch (e) {
                showNotification('Invalid outbound JSON: ' + e.message, 'error');
                return;
            }
            document.getElementById('tunnel-outbound-json').value = manualJson;
        }
        tunnel.advanced.outbound_json = document.getElementById('tunnel-outbound-json').value;
        tunnel.advanced.link = document.getElementById('tunnel-link').value;
    }

    if (type === 'xray') {
        // New three-section panel: manual build or pasted full config.
        if (!xrayCollectAndBuild(tunnel)) return;
    }

    if (type === 'zivpn') {
        tunnel.auth.password = document.getElementById('tunnel-zivpn-password').value;
    }

    if (type === 'utunnel') {
        // server.port = REAL listen port (e.g. 5669); the client range is
        // DNAT'd server-side, never dialed.
        tunnel.auth.password = document.getElementById('tunnel-utunnel-key').value;
        const hopRaw = document.getElementById('tunnel-utunnel-hop').value.trim();
        if (hopRaw !== '') {
            const hop = parseInt(hopRaw);
            if (!isNaN(hop) && hop >= 0) {
                tunnel.advanced.utunnel_hop = hop;
            }
        }
    }

    const url = id ? `/api/v1/tunnels/${id}` : '/api/v1/tunnels';
    const method = id ? 'PUT' : 'POST';

    fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(tunnel)
    })
    .then(res => res.json())
    .then(data => {
        closeTunnelModal();
        loadInitialData();
        showNotification(id ? 'Tunnel updated' : 'Tunnel created', 'success');
    })
    .catch(err => {
        console.error('Failed to save tunnel:', err);
        showNotification('Failed to save tunnel', 'error');
    });
}

function editTunnel(id) {
    const tunnel = tunnels.find(t => t.id === id);
    if (tunnel) openTunnelModal(tunnel);
}

function parseXrayLink() {
    const type = document.getElementById('tunnel-type').value;
    // Xray reads the new paste tab; xray_slowdns keeps its legacy textarea.
    const link = (type === 'xray'
        ? document.getElementById('tunnel-xray-paste').value
        : document.getElementById('tunnel-xray-link').value).trim();
    if (!link) {
        showNotification('Paste a vmess/vless/trojan/ss link first', 'error');
        return;
    }
    if (!/^(vmess|vless|trojan|ss|shadowsocks):\/\//i.test(link)) {
        showNotification('No link detected. "Import link into form" expects a vmess/vless/trojan/ss link.', 'error');
        return;
    }
    fetch('/api/v1/tunnels/parse-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link: link })
    })
    .then(async res => {
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || 'parse failed');
        }
        return data.tunnel;
    })
    .then(t => {
        if (type === 'xray') {
            xrayFillManual(t);
            xraySetMode('manual');
        } else {
            // Legacy fill for xray_slowdns.
            if (t.name) document.getElementById('tunnel-name').value = t.name;
            if (t.server) {
                if (t.server.host) document.getElementById('tunnel-host').value = t.server.host;
                if (t.server.port) document.getElementById('tunnel-port').value = t.server.port;
                if (t.server.sni) document.getElementById('tunnel-reality-sni').value = t.server.sni;
            }
            if (t.auth) {
                if (t.auth.uuid) document.getElementById('tunnel-uuid').value = t.auth.uuid;
                if (t.auth.flow) document.getElementById('tunnel-flow').value = t.auth.flow;
                if (t.auth.password) document.getElementById('tunnel-xray-password').value = t.auth.password;
                if (t.auth.method) document.getElementById('tunnel-xray-method').value = t.auth.method;
            }
            if (t.transport) {
                if (t.transport.network) document.getElementById('tunnel-network').value = t.transport.network;
                if (t.transport.security) document.getElementById('tunnel-security').value = t.transport.security;
                if (t.transport.path) document.getElementById('tunnel-ws-path').value = t.transport.path;
                if (t.transport.host) document.getElementById('tunnel-ws-host').value = t.transport.host;
            }
        }
        if (t.advanced && t.advanced.outbound_json) {
            document.getElementById('tunnel-outbound-json').value = t.advanced.outbound_json;
            const legacyJson = document.getElementById('tunnel-xray-json');
            if (type !== 'xray' && legacyJson) legacyJson.value = t.advanced.outbound_json;
        }
        if (t.advanced && t.advanced.link) document.getElementById('tunnel-link').value = t.advanced.link;
        if (type === 'xray' && t.name && !document.getElementById('tunnel-name').value) document.getElementById('tunnel-name').value = t.name;
        updateTunnelFields();
        showNotification('Link parsed', 'success');
    })
    .catch(err => {
        console.error('Link parse failed:', err);
        showNotification('Link parse failed: ' + err.message, 'error');
    });
}

function toggleTunnel(id, status) {
    const action = status === 'running' ? 'stop' : 'start';
    fetch(`/api/v1/tunnels/${id}/${action}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => loadInitialData())
        .catch(err => console.error(`Failed to ${action} tunnel:`, err));
}

function restartTunnel(id) {
    fetch(`/api/v1/tunnels/${id}/restart`, { method: 'POST' })
        .then(res => res.json())
        .then(data => loadInitialData())
        .catch(err => console.error('Failed to restart tunnel:', err));
}

function deleteTunnel(id) {
    if (!confirm('Are you sure you want to delete this tunnel?')) return;

    fetch(`/api/v1/tunnels/${id}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => loadInitialData())
        .catch(err => console.error('Failed to delete tunnel:', err));
}

function exportConfig() {
    const format = document.getElementById('export-format').value;
    const password = document.getElementById('export-password').value;

    fetch(`/api/v1/export?format=${format}&password=${encodeURIComponent(password)}`, { method: 'POST' })
        .then(res => res.blob())
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vpn-config.${format === 'zip' ? 'zip' : format}`;
            a.click();
            window.URL.revokeObjectURL(url);
            showNotification('Config exported', 'success');
        })
        .catch(err => {
            console.error('Export failed:', err);
            showNotification('Export failed', 'error');
        });
}

function importConfig() {
    const file = document.getElementById('import-file').files[0];
    const password = document.getElementById('import-password').value;

    if (!file) {
        showNotification('Please select a file', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);
    if (password) formData.append('password', password);

    fetch('/api/v1/import', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
            showNotification('Config imported', 'success');
            loadInitialData();
        })
        .catch(err => {
            console.error('Import failed:', err);
            showNotification('Import failed', 'error');
        });
}

function saveSettings() {
    const config = {
        app: {
            web_port: parseInt(document.getElementById('web-port').value),
            web_host: document.getElementById('web-host').value,
            log_level: document.getElementById('log-level').value
        },
        network: {
            interface: document.getElementById('interface-name').value,
            mtu: parseInt(document.getElementById('mtu').value),
            dns: document.getElementById('dns-servers').value.split(',').map(s => s.trim())
        }
    };

    fetch('/api/v1/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    })
    .then(res => res.json())
    .then(data => showNotification('Settings saved', 'success'))
    .catch(err => showNotification('Failed to save settings', 'error'));
}

function clearLogs() {
    document.getElementById('logs-container').innerHTML = '<div class="text-gray-500">Logs cleared...</div>';
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    if (!seconds || seconds < 1) return '--';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

function formatTunnelType(type) {
    const types = {
        'ssh': 'SSH',
        'ssh_slowdns': 'SSH + SlowDNS',
        'xray': 'Xray',
        'xray_slowdns': 'Xray + SlowDNS',
        'zivpn': 'Zivpn',
        'utunnel': 'Utunnel UDP'
    };
    return types[type] || type;
}

function getStatusClass(status) {
    const classes = {
        'running': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
        'starting': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
        'stopping': 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
        'stopped': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
        'error': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
    };
    return classes[status] || classes.stopped;
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 ${
        type === 'success' ? 'bg-green-600' : type === 'error' ? 'bg-red-600' : 'bg-blue-600'
    } text-white`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 3000);
}

function toggleDarkMode() {
    document.documentElement.classList.toggle('dark');
    const icon = document.getElementById('dark-mode-icon');
    icon.classList.toggle('fa-moon');
    icon.classList.toggle('fa-sun');
    localStorage.setItem('darkMode', document.documentElement.classList.contains('dark'));
}

if (localStorage.getItem('darkMode') === 'true') {
    document.documentElement.classList.add('dark');
}

// ---------------------------------------------------------------------------
// Xray "Add Server" panel (manual 3-section form + paste link/JSON tab).
// Only type=xray uses this; xray_slowdns keeps the legacy blocks.
// ---------------------------------------------------------------------------

let xrayMode = 'manual';

const xraySegActive = ['bg-white', 'dark:bg-gray-800', 'shadow-sm', 'text-gray-900', 'dark:text-white'];
const xraySegInactive = ['text-gray-600', 'dark:text-gray-400'];

function xraySetMode(mode) {
    xrayMode = mode;
    ['manual', 'paste'].forEach(m => {
        const btn = document.getElementById('xray-mode-' + m);
        if (!btn) return;
        btn.classList.remove(...xraySegActive, ...xraySegInactive);
        btn.classList.add(...(m === mode ? xraySegActive : xraySegInactive));
    });
    const paste = document.getElementById('xray-paste-mode');
    if (paste) paste.classList.toggle('hidden', mode !== 'paste');
    const manual = document.getElementById('xray-manual-mode');
    if (manual) manual.classList.toggle('hidden', mode !== 'manual');
}

async function xrayClipboardPaste() {
    const field = document.getElementById('tunnel-xray-paste');
    try {
        const text = await navigator.clipboard.readText();
        field.value = (text || '').trim();
    } catch (e) {
        field.focus();
        showNotification('Clipboard unavailable — paste into the field manually (Ctrl+V)', 'error');
    }
}

function xrayClearPaste() {
    document.getElementById('tunnel-xray-paste').value = '';
}

function xrayMethodOptions(proto) {
    if (proto === 'vmess') return ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'];
    if (proto === 'shadowsocks') return ['aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];
    return ['none']; // vless
}

function xrayProtoChange() {
    const proto = document.getElementById('xray-proto').value;
    document.getElementById('xray-uuid-field').classList.toggle('hidden', !(proto === 'vless' || proto === 'vmess'));
    document.getElementById('xray-flow-field').classList.toggle('hidden', proto !== 'vless');
    document.getElementById('xray-password-field').classList.toggle('hidden', !(proto === 'trojan' || proto === 'shadowsocks'));
    document.getElementById('xray-method-field').classList.toggle('hidden', proto === 'trojan');
    const sel = document.getElementById('xray-method');
    const cur = sel.value;
    sel.innerHTML = '';
    xrayMethodOptions(proto).forEach(v => {
        const opt = document.createElement('option');
        opt.value = v;
        opt.textContent = v;
        sel.appendChild(opt);
    });
    if (Array.from(sel.options).some(o => o.value === cur)) sel.value = cur;
}

function xrayNetworkChange() {
    const net = document.getElementById('xray-network').value;
    const showPath = ['ws', 'grpc', 'xhttp', 'httpupgrade'].includes(net);
    document.getElementById('xray-path-field').classList.toggle('hidden', !showPath);
    document.getElementById('xray-wshost-field').classList.toggle('hidden', !showPath);
    document.getElementById('xray-wsheaders-field').classList.toggle('hidden', net !== 'ws');
    document.getElementById('xray-path-label').textContent = net === 'grpc' ? 'Service Name' : 'Path (e.g. / or /ws)';
}

function xraySecurityChange() {
    const sec = document.getElementById('xray-tlssec').value;
    document.getElementById('xray-tls-group').classList.toggle('hidden', !(sec === 'tls' || sec === 'reality'));
    document.getElementById('xray-reality-group').classList.toggle('hidden', sec !== 'reality');
}

function xrayAddWsHeader(k, v) {
    const box = document.getElementById('xray-ws-headers');
    const row = document.createElement('div');
    row.className = 'flex items-center space-x-2';
    const keyInput = document.createElement('input');
    keyInput.type = 'text';
    keyInput.placeholder = 'Header';
    keyInput.value = k || '';
    keyInput.className = 'input-field w-2/5';
    const valInput = document.createElement('input');
    valInput.type = 'text';
    valInput.placeholder = 'Value';
    valInput.value = v || '';
    valInput.className = 'input-field flex-1';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'px-2 py-1 text-red-500 hover:text-red-700 dark:hover:text-red-400 shrink-0';
    btn.innerHTML = '<i class="fas fa-trash"></i>';
    btn.onclick = () => row.remove();
    row.appendChild(keyInput);
    row.appendChild(valInput);
    row.appendChild(btn);
    box.appendChild(row);
}

function xrayResetWsHeaders() {
    const box = document.getElementById('xray-ws-headers');
    if (box) box.innerHTML = '';
}

function xrayReadWsHeaders() {
    const out = {};
    document.querySelectorAll('#xray-ws-headers > div').forEach(row => {
        const inputs = row.querySelectorAll('input');
        const k = inputs[0].value.trim();
        if (k) out[k] = inputs[1].value;
    });
    return out;
}

// Builds the outbound JSON from the manual form — same shape as the Go
// builders (BuildVlessOutbound / BuildVmessOutbound / BuildTrojanOutbound /
// BuildShadowsocksOutbound + buildStreamSettings).
function xrayBuildOutboundJSON(t) {
    const proto = document.getElementById('xray-proto').value;
    const addr = t.server.host;
    const port = t.server.port;
    const stream = xrayBuildStreamSettings(t);
    switch (proto) {
        case 'vless': {
            const user = { id: t.auth.uuid, encryption: 'none' };
            if (t.auth.flow) user.flow = t.auth.flow;
            return { protocol: 'vless', tag: 'proxy', settings: { vnext: [{ address: addr, port: port, users: [user] }] }, streamSettings: stream };
        }
        case 'vmess':
            return { protocol: 'vmess', tag: 'proxy', settings: { vnext: [{ address: addr, port: port, users: [{ id: t.auth.uuid, alterId: 0, security: t.auth.method || 'auto' }] }] }, streamSettings: stream };
        case 'trojan':
            return { protocol: 'trojan', tag: 'proxy', settings: { servers: [{ address: addr, port: port, password: t.auth.password }] }, streamSettings: stream };
        case 'shadowsocks':
            return { protocol: 'shadowsocks', tag: 'proxy', settings: { servers: [{ address: addr, port: port, method: t.auth.method || 'aes-256-gcm', password: t.auth.password }] }, streamSettings: stream };
        default:
            throw new Error('unsupported protocol');
    }
}

function xrayBuildStreamSettings(t) {
    const net = t.transport.network;
    const sec = t.transport.security; // 'tls' | 'reality' | ''
    const ss = { network: net, security: sec === '' ? 'none' : sec };
    if (net === 'ws') {
        const headers = xrayReadWsHeaders();
        headers.Host = t.transport.host || ''; // mirror buildStreamSettings
        ss.wsSettings = { path: t.transport.path || '/', headers: headers };
    } else if (net === 'grpc') {
        const g = { serviceName: t.transport.path || '', multiMode: false };
        if (t.transport.host) g.authority = t.transport.host;
        ss.grpcSettings = g;
    } else if (net === 'xhttp') {
        const x = { path: t.transport.path || '/' };
        if (t.transport.host) x.host = t.transport.host;
        ss.xhttpSettings = x;
    } else if (net === 'httpupgrade') {
        const h = { path: t.transport.path || '/' };
        if (t.transport.host) h.host = t.transport.host;
        ss.httpupgradeSettings = h;
    } else if (net === 'tcp') {
        ss.tcpSettings = { header: { type: 'none' } };
    }
    if (sec === 'tls') {
        const tls = { serverName: t.server.sni || '', alpn: t.transport.alpn || [] };
        if (t.transport.fingerprint) tls.fingerprint = t.transport.fingerprint;
        ss.tlsSettings = tls;
    } else if (sec === 'reality') {
        const reality = { serverName: t.server.sni || '', publicKey: t.server.public_key || '', shortId: t.server.short_id || '' };
        if (t.transport.fingerprint) reality.fingerprint = t.transport.fingerprint;
        ss.realitySettings = reality;
    }
    return ss;
}

// Fills the manual form (3 sections) from a parsed link / stored config.
function xrayFillManual(t) {
    const server = t.server || {};
    const auth = t.auth || {};
    const transport = t.transport || {};
    const advanced = t.advanced || {};
    let proto = 'vless';
    try {
        const ob = JSON.parse(advanced.outbound_json || '{}');
        if (ob.protocol) proto = ob.protocol;
    } catch (e) { /* ignore */ }
    if (!['vless', 'vmess', 'trojan', 'shadowsocks'].includes(proto)) proto = 'vless';
    document.getElementById('xray-proto').value = proto;
    xrayProtoChange();
    document.getElementById('xray-host').value = server.host || '';
    document.getElementById('xray-port').value = server.port || '';
    document.getElementById('xray-uuid').value = auth.uuid || '';
    document.getElementById('xray-password').value = auth.password || '';
    document.getElementById('xray-flow').value = auth.flow || '';
    const methodOpts = xrayMethodOptions(proto);
    document.getElementById('xray-method').value = methodOpts.includes(auth.method) ? auth.method : methodOpts[0];
    if (!['vless', 'vmess'].includes(proto)) document.getElementById('xray-method').value = auth.method || methodOpts[0];
    document.getElementById('xray-network').value = transport.network || 'ws';
    xrayNetworkChange();
    document.getElementById('xray-path').value = transport.path || '';
    document.getElementById('xray-wshost').value = transport.host || '';
    document.getElementById('xray-tlssec').value = transport.security || 'none';
    xraySecurityChange();
    document.getElementById('xray-sni').value = server.sni || '';
    document.getElementById('xray-pbk').value = server.public_key || '';
    document.getElementById('xray-shortid').value = server.short_id || '';
    const fp = transport.fingerprint || '';
    const fpSel = document.getElementById('xray-fp');
    fpSel.value = Array.from(fpSel.options).some(o => o.value === fp) ? fp : '';
    document.getElementById('xray-alpn').value = (transport.alpn || []).join(',');
    xrayResetWsHeaders();
    if (advanced.xray_ws_headers) {
        try {
            Object.entries(JSON.parse(advanced.xray_ws_headers)).forEach(([k, v]) => xrayAddWsHeader(k, v));
        } catch (e) { /* ignore */ }
    }
}

// Validates the Xray form and fills the outgoing tunnel object. Returns
// false when validation fails (notification already shown).
function xrayCollectAndBuild(tunnel) {
    if (xrayMode === 'paste') {
        const text = document.getElementById('tunnel-xray-paste').value.trim();
        if (text === '') {
            showNotification('Xray: configure manually or paste a link / JSON config', 'error');
            return false;
        }
        if (/^(vmess|vless|trojan|ss|shadowsocks):\/\//i.test(text)) {
            showNotification('Link detected: click "Import link into form" first', 'error');
            return false;
        }
        try {
            JSON.parse(text);
        } catch (e) {
            showNotification('Invalid JSON config: ' + e.message, 'error');
            return false;
        }
        tunnel.advanced.outbound_json = text;
        tunnel.advanced.link = '';
        delete tunnel.advanced.xray_ws_headers;
        // Keep the current manual server fields for display/round-trip; the
        // pasted JSON wins at runtime.
        tunnel.server.host = document.getElementById('xray-host').value.trim();
        tunnel.server.port = parseInt(document.getElementById('xray-port').value) || 0;
        return true;
    }

    const host = document.getElementById('xray-host').value.trim();
    const port = parseInt(document.getElementById('xray-port').value) || 0;
    const proto = document.getElementById('xray-proto').value;
    if (!host) {
        showNotification('Xray: server address is required', 'error');
        return false;
    }
    if (!port) {
        showNotification('Xray: port is required', 'error');
        return false;
    }
    const uuid = document.getElementById('xray-uuid').value.trim();
    const password = document.getElementById('xray-password').value.trim();
    if ((proto === 'vless' || proto === 'vmess') && !uuid) {
        showNotification('Xray: UUID is required for ' + proto.toUpperCase(), 'error');
        return false;
    }
    if ((proto === 'trojan' || proto === 'shadowsocks') && !password) {
        showNotification('Xray: password is required for ' + proto, 'error');
        return false;
    }

    // Structured fields (round-trip + local builds).
    tunnel.server.host = host;
    tunnel.server.port = port;
    tunnel.server.sni = document.getElementById('xray-sni').value.trim();
    tunnel.server.public_key = document.getElementById('xray-pbk').value.trim();
    tunnel.server.short_id = document.getElementById('xray-shortid').value.trim();
    tunnel.auth.uuid = uuid;
    tunnel.auth.password = password;
    tunnel.auth.flow = document.getElementById('xray-flow').value.trim();
    tunnel.auth.method = document.getElementById('xray-method').value;
    const sec = document.getElementById('xray-tlssec').value;
    tunnel.transport.network = document.getElementById('xray-network').value;
    tunnel.transport.security = sec === 'none' ? '' : sec;
    tunnel.transport.path = document.getElementById('xray-path').value;
    tunnel.transport.host = document.getElementById('xray-wshost').value.trim();
    tunnel.transport.fingerprint = document.getElementById('xray-fp').value;
    const alpn = document.getElementById('xray-alpn').value.trim();
    tunnel.transport.alpn = alpn ? alpn.split(',').map(s => s.trim()).filter(Boolean) : [];

    // Custom WS headers (ws only).
    if (tunnel.transport.network === 'ws') {
        const headers = xrayReadWsHeaders();
        if (Object.keys(headers).length) tunnel.advanced.xray_ws_headers = JSON.stringify(headers);
        else delete tunnel.advanced.xray_ws_headers;
    } else {
        delete tunnel.advanced.xray_ws_headers;
    }

    try {
        tunnel.advanced.outbound_json = JSON.stringify(xrayBuildOutboundJSON(tunnel));
    } catch (e) {
        showNotification('Xray: ' + e.message, 'error');
        return false;
    }
    tunnel.advanced.link = '';
    return true;
}

// Loads an existing xray tunnel into the new panel (edit mode).
function xrayLoadIntoPanel(tunnel) {
    const cfg = tunnel.config || {};
    xrayFillManual({ server: cfg.server || {}, auth: cfg.auth || {}, transport: cfg.transport || {}, advanced: cfg.advanced || {} });
    const adv = cfg.advanced || {};
    const isFullConfig = typeof adv.outbound_json === 'string' && adv.outbound_json.indexOf('"outbounds"') !== -1;
    const link = adv.link || '';
    document.getElementById('tunnel-xray-paste').value = link || (isFullConfig ? adv.outbound_json : '');
    document.getElementById('tunnel-outbound-json').value = adv.outbound_json || '';
    document.getElementById('tunnel-link').value = link;
    xraySetMode(isFullConfig ? 'paste' : 'manual');
}

function xrayResetPanel() {
    document.getElementById('xray-proto').value = 'vless';
    xrayProtoChange();
    ['xray-host', 'xray-port', 'xray-uuid', 'xray-password', 'xray-flow', 'xray-path', 'xray-wshost', 'xray-sni', 'xray-pbk', 'xray-shortid', 'xray-alpn', 'tunnel-xray-paste'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    document.getElementById('xray-network').value = 'ws';
    xrayNetworkChange();
    document.getElementById('xray-tlssec').value = 'none';
    xraySecurityChange();
    document.getElementById('xray-fp').value = '';
    xrayResetWsHeaders();
    xraySetMode('manual');
}

document.addEventListener('DOMContentLoaded', init);