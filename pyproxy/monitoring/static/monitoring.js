async function fetchMonitoringData() {
    try {
        const response = await fetch('/monitoring');
        const data = await response.json();

        document.getElementById('status-section').innerHTML = `
            <h2>Main Process</h2>
            <p><strong>Name:</strong> ${data.name}</p>
            <p><strong>PID:</strong> ${data.pid}</p>
            <p><strong>Status:</strong> <span class="badge ${data.status}">${data.status}</span></p>
            <p><strong>Start Time:</strong> ${data.start_time}</p>
        `;

        document.getElementById('subprocesses-section').innerHTML = `
            <h2>Subprocesses</h2>
            ${Object.values(data.subprocesses).map(proc => `
                <div class="subprocess">
                    <h3>${proc.name}</h3>
                    <p><strong>PID:</strong> ${proc.pid}</p>
                    <p><strong>Status:</strong> <span class="badge ${proc.status}">${proc.status}</span></p>
                    <ul>${proc.threads.map(t => `<li>${t.name} (${t.thread_id})</li>`).join('')}</ul>
                </div>
            `).join('')}
        `;

        document.getElementById('connections-section').innerHTML = `
            <h2>Active Connections</h2>
            ${data.active_connections.length === 0
                ? '<p>No active connections.</p>'
                : data.active_connections.map(conn => `
                    <div class="connection">
                        <p><strong>Client:</strong> ${conn.client_ip}:${conn.client_port}</p>
                        <p><strong>Target:</strong> ${conn.target_domain} (${conn.target_ip}:${conn.target_port})</p>
                        <p><strong>Sent:</strong> ${conn.bytes_sent} bytes</p>
                        <p><strong>Received:</strong> ${formatBytes(conn.bytes_received)}</p>
                    </div>
                `).join('')}
        `;
    } catch (err) {
        console.error('Error loading data:', err);
    }
}

async function fetchConfigData() {
    try {
        const response = await fetch('/config');
        const config = await response.json();

        document.getElementById('config-section').innerHTML = `
            <h2>Configuration ${config.debug ? '<span class="badge stopped small">DEBUG</span>' : ''}</h2>
            <p><strong>Port:</strong> ${config.port ? `<span class="path">${config.port}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Flask Port:</strong> ${config.flask_port ? `<span class="path">${config.flask_port}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>HTML 403:</strong> ${config.html_403 ? `<span class="path">${config.html_403}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <h3>Filter Configuration <span class="checkmark ${config.filter_config.no_filter ? 'false' : ''}">${config.filter_config.no_filter ? '✗' : '✓'}</span></h3>
            <p><strong>Blocked Sites File:</strong> ${config.filter_config.blocked_sites ? `<span class="path">${config.filter_config.blocked_sites}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Blocked URL File:</strong> ${config.filter_config.blocked_url ? `<span class="path">${config.filter_config.blocked_url}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Filter Mode:</strong> <span class="path">${config.filter_config.filter_mode}</span></p>
            <h3>Logger Configuration</h3>
            <p><strong>Access Log:</strong> ${config.logger_config.no_logging_access ? '<span class="checkmark false">✗</span>' : '<span class="checkmark">✓</span>'} ${config.logger_config.access_log ? `<span class="path">${config.logger_config.access_log}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Block Log:</strong> ${config.logger_config.no_logging_block ? '<span class="checkmark false">✗</span>' : '<span class="checkmark">✓</span>'} ${config.logger_config.block_log ? `<span class="path">${config.logger_config.block_log}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <h3>SSL Inspection <span class="checkmark ${config.ssl_config.ssl_inspect ? '' : 'false'}">${config.ssl_config.ssl_inspect ? '✓' : '✗'}</span></h3>
            <p><strong>Inspect CA Cert:</strong> ${config.ssl_config.inspect_ca_cert ? `<span class="path">${config.ssl_config.inspect_ca_cert}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Inspect CA Key:</strong> ${config.ssl_config.inspect_ca_key ? `<span class="path">${config.ssl_config.inspect_ca_key}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Inspect certs folder:</strong> ${config.ssl_config.inspect_certs_folder ? `<span class="path">${config.ssl_config.inspect_certs_folder}</span>` : '<span class="checkmark false">✗</span>'}</p>
            <p><strong>Cancel inspect:</strong> ${config.ssl_config.cancel_inspect ? `<span class="path">${config.ssl_config.cancel_inspect}</span>` : '<span class="checkmark false">✗</span>'}</p>
        `;
    } catch (err) {
        console.error('Error loading config data:', err);
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const value = bytes / Math.pow(1024, i);
    return value.toFixed(2) + ' ' + sizes[i];
}

const tabs = document.querySelectorAll('.tab');
const contents = document.querySelectorAll('.tab-content');

function activateTab(tab) {
    tabs.forEach(t => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
        t.setAttribute('tabindex', '-1');
    });
    contents.forEach(c => c.classList.remove('active'));

    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    tab.setAttribute('tabindex', '0');
    const contentId = tab.getAttribute('aria-controls');
    document.getElementById(contentId).classList.add('active');

    localStorage.setItem('activeTabId', tab.id);
}

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        activateTab(tab);
    });

    tab.addEventListener('keydown', e => {
        let index = Array.from(tabs).indexOf(e.target);
        if (e.key === 'ArrowRight') {
            index = (index + 1) % tabs.length;
            tabs[index].focus();
        } else if (e.key === 'ArrowLeft') {
            index = (index - 1 + tabs.length) % tabs.length;
            tabs[index].focus();
        }
    });
});

window.addEventListener('DOMContentLoaded', () => {
    const savedTabId = localStorage.getItem('activeTabId');
    if (savedTabId) {
        const savedTab = document.getElementById(savedTabId);
        if (savedTab) {
            activateTab(savedTab);
            return;
        }
    }
    activateTab(tabs[0]);
});

fetchMonitoringData();
fetchConfigData();
setInterval(fetchMonitoringData, 5000);
setInterval(fetchConfigData, 5000);
