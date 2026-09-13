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
        document.getElementById('tunnel-host').value = tunnel.config?.server?.host || '';
        document.getElementById('tunnel-port').value = tunnel.config?.server?.port || '';

        if (tunnel.config?.auth) {
            document.getElementById('tunnel-username').value = tunnel.config.auth.username || '';
            document.getElementById('tunnel-password').value = tunnel.config.auth.password || '';
            document.getElementById('tunnel-private-key').value = tunnel.config.auth.private_key || '';
            document.getElementById('tunnel-ssh-payload').value = (tunnel.config.ssh && tunnel.config.ssh.payload) || '';
            document.getElementById('tunnel-ssh-proxy').value = (tunnel.config.ssh && tunnel.config.ssh.proxy) || '';
            document.getElementById('tunnel-uuid').value = tunnel.config.auth.uuid || '';
            document.getElementById('tunnel-flow').value = tunnel.config.auth.flow || '';
            document.getElementById('tunnel-xray-password').value = tunnel.config.auth.password || '';
            document.getElementById('tunnel-xray-method').value = tunnel.config.auth.method || '';
            document.getElementById('tunnel-zivpn-uuid').value = tunnel.config.auth.uuid || '';
            document.getElementById('tunnel-zivpn-password').value = tunnel.config.auth.password || '';
        }

        if (tunnel.config?.server) {
            document.getElementById('tunnel-slowdns-pubkey').value = tunnel.config.server.public_key || '';
            document.getElementById('tunnel-slowdns-domain').value = tunnel.config.server.nameserver || tunnel.config.server.hostname || '';
            document.getElementById('tunnel-slowdns-ns').value = tunnel.config.server.dns_resolver || '8.8.8.8:53';
            document.getElementById('tunnel-reality-pubkey').value = tunnel.config.server.public_key || '';
            document.getElementById('tunnel-reality-shortid').value = tunnel.config.server.short_id || '';
            document.getElementById('tunnel-reality-sni').value = tunnel.config.server.sni || '';
            document.getElementById('tunnel-zivpn-port-range').value = tunnel.config.server.port_range || '';
        }

        if (tunnel.config?.transport) {
            document.getElementById('tunnel-network').value = tunnel.config.transport.network || '';
            document.getElementById('tunnel-security').value = tunnel.config.transport.security || '';
            document.getElementById('tunnel-ws-path').value = tunnel.config.transport.path || '';
            document.getElementById('tunnel-ws-host').value = tunnel.config.transport.host || '';
            document.getElementById('tunnel-zivpn-obfs').value = tunnel.config.transport.obfs || 'salamander';
            document.getElementById('tunnel-zivpn-obfs-param').value = tunnel.config.transport.obfs_param || 'zivpn';
        }

        const adv = tunnel.config?.advanced || {};
        document.getElementById('tunnel-link').value = adv.link || '';
        document.getElementById('tunnel-outbound-json').value = adv.outbound_json || '';
        document.getElementById('tunnel-xray-json').value = adv.outbound_json || '';
    } else {
        title.textContent = 'Add Tunnel';
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
    // ssh_slowdns dials through dnstt and xray uses link/JSON only:
    // no direct server host/port.
    const showServer = type !== 'ssh_slowdns' && type !== 'xray';
    // Transport is only meaningful for Xray-family tunnels.
    const showTransport = isXray;

    document.getElementById('ssh-auth-fields').classList.toggle('hidden', !isSSH);
    // xray uses link/JSON exclusively; xray_slowdns keeps manual fields.
    document.getElementById('xray-auth-fields').classList.toggle('hidden', type !== 'xray_slowdns');
    document.getElementById('xray-link-fields').classList.toggle('hidden', !isXray);
    document.getElementById('zivpn-auth-fields').classList.toggle('hidden', !isZivpn);
    document.getElementById('slowdns-fields').classList.toggle('hidden', !isSlowDNS);
    document.getElementById('server-fields').classList.toggle('hidden', !showServer);
    document.getElementById('transport-fields').classList.toggle('hidden', !showTransport);

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
            network: network,
            security: security,
            path: document.getElementById('tunnel-ws-path').value,
            host: document.getElementById('tunnel-ws-host').value,
            obfs: document.getElementById('tunnel-zivpn-obfs').value,
            obfs_param: document.getElementById('tunnel-zivpn-obfs-param').value
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

    if (['xray', 'xray_slowdns'].includes(type)) {
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
        if (type === 'xray' && !tunnel.advanced.outbound_json) {
            showNotification('Xray needs a link (Parse) or a JSON config', 'error');
            return;
        }
    }

    if (type === 'zivpn') {
        tunnel.auth.password = document.getElementById('tunnel-zivpn-password').value;
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
    const link = document.getElementById('tunnel-xray-link').value.trim();
    if (!link) {
        showNotification('Paste a vmess/vless/trojan/ss link first', 'error');
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
        if (t.advanced) {
            if (t.advanced.outbound_json) {
                document.getElementById('tunnel-outbound-json').value = t.advanced.outbound_json;
                document.getElementById('tunnel-xray-json').value = t.advanced.outbound_json;
            }
            if (t.advanced.link) document.getElementById('tunnel-link').value = t.advanced.link;
        }
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
        'zivpn': 'Zivpn'
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

document.addEventListener('DOMContentLoaded', init);