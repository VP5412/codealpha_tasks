const elements = {
    radarContainer: document.getElementById('radarContainer'),
    ppsVal: document.getElementById('ppsVal'),
    alertsFeed: document.getElementById('alertsFeed'),
    alertCount: document.getElementById('alertCount'),
    systemLogs: document.getElementById('systemLogs'),
    ipInput: document.getElementById('ipInput'),
    blockBtn: document.getElementById('blockBtn'),
    unblockBtn: document.getElementById('unblockBtn'),
    autoMitigateToggle: document.getElementById('autoMitigateToggle')
};

let ws;
let packetCount = 0;
let totalAlerts = 0;
const MAX_RADAR_NODES = 20;

function logSys(msg, type = "sys") {
    const entry = document.createElement("div");
    entry.className = `log-entry ${type}`;
    const time = new Date().toLocaleTimeString();
    entry.innerText = `[${time}] ${msg}`;
    elements.systemLogs.prepend(entry);
}

function connectWebSocket() {
    logSys("Connecting to Nexus Engine...", "sys");
    ws = new WebSocket('ws://localhost:8000/ws');

    ws.onopen = () => {
        logSys("WebSocket Connection Established.", "success");
    };

    ws.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        handleServerMessage(payload);
    };

    ws.onerror = (error) => {
        logSys("WebSocket Error detected.", "err");
    };

    ws.onclose = () => {
        logSys("Connection Disconnected. Retrying in 3s...", "err");
        setTimeout(connectWebSocket, 3000);
    };
}

function handleServerMessage(payload) {
    if (payload.type === 'traffic') {
        const data = payload.data;
        packetCount++;
        spawnRadarNode(data.src_ip, data.alert ? true : false);
    } 
    else if (payload.type === 'alert') {
        const data = payload.data;
        addAlert(data);
    }
    else if (payload.type === 'response') {
        const data = payload.data;
        logSys(data.message, data.status === 'success' ? 'sys' : 'act');
    }
    else if (payload.type === 'mitigation') {
        const data = payload.data;
        logSys(`Auto-Mitigation Active: Blocked ${data.ip}`, 'act');
    }
}

// PPS Counter Calculation
setInterval(() => {
    elements.ppsVal.innerText = packetCount;
    packetCount = 0; // reset
}, 1000);

function spawnRadarNode(ip, isSevere) {
    // Limit DOM elements to keep performance high
    if (elements.radarContainer.children.length > MAX_RADAR_NODES + 2) { 
        // offset loop to account for grid / sweep divs
        // We will remove nodes periodically instead of one by one for performance, or simply remove oldest node.
        const nodes = elements.radarContainer.querySelectorAll('.radar-node');
        if (nodes.length > MAX_RADAR_NODES) {
            nodes[0].remove();
        }
    }

    const node = document.createElement('div');
    node.className = `radar-node ${isSevere ? 'severe' : ''}`;
    node.title = ip;
    
    // random placement within circle
    const angle = Math.random() * Math.PI * 2;
    const radius = Math.random() * 45; // percentage
    
    node.style.top = `${50 + radius * Math.sin(angle)}%`;
    node.style.left = `${50 + radius * Math.cos(angle)}%`;
    
    elements.radarContainer.appendChild(node);
    
    // Fade out eventually
    setTimeout(() => {
        if(node.parentElement) node.remove();
    }, 4000);
}

function addAlert(data) {
    const placeholder = elements.alertsFeed.querySelector('.alert-placeholder');
    if (placeholder) placeholder.remove();

    totalAlerts++;
    elements.alertCount.innerText = totalAlerts;

    const card = document.createElement('div');
    // Severity normalization
    const severityClass = data.severity.toLowerCase();
    card.className = `alert-card ${severityClass}`;
    
    const time = new Date(data.timestamp * 1000).toLocaleTimeString();
    
    card.innerHTML = `
        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <strong>[${data.severity}] - Score: ${data.score}</strong>
            <span>${time}</span>
        </div>
        <div>Threat: ${data.message}</div>
        <div>Source: <span style="text-decoration:underline; cursor:pointer;" onclick="document.getElementById('ipInput').value='${data.src_ip}'">${data.src_ip}</span></div>
    `;

    elements.alertsFeed.prepend(card);
}

// Interactions
elements.blockBtn.onclick = () => {
    const ip = elements.ipInput.value.trim();
    if (!ip) return;
    logSys(`Manual Override: Initiating block on ${ip}...`, 'sys');
    ws.send(JSON.stringify({ command: 'block_ip', ip: ip }));
    elements.ipInput.value = '';
};

elements.unblockBtn.onclick = () => {
    const ip = elements.ipInput.value.trim();
    if (!ip) return;
    logSys(`Manual Override: Initiating unblock on ${ip}...`, 'sys');
    ws.send(JSON.stringify({ command: 'unblock_ip', ip: ip }));
    elements.ipInput.value = '';
};

elements.autoMitigateToggle.onchange = (e) => {
    const state = e.target.checked;
    logSys(`Toggling Auto-Mitigation: ${state ? 'ON' : 'OFF'}`, 'sys');
    ws.send(JSON.stringify({ command: 'toggle_automitigate', state: state }));
}

// Init
connectWebSocket();
