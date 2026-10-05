/**
 * Zero-Trust Security Gateway Dashboard Controller
 * WebSocket real-time telemetry, interactive attack simulations,
 * and physical relay state visualizer.
 */

const API_BASE = window.location.origin;
let ws = null;
let reconnectTimer = null;
let lastCapturedProof = null; // Stored for demonstrating replay attack

// ==============================================================================
// Initialization & WebSocket Setup
// ==============================================================================
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  connectWebSocket();
  fetchInitialData();
});

function initClock() {
  const clockEl = document.getElementById("clockDisplay");
  setInterval(() => {
    const now = new Date();
    clockEl.innerText = now.toTimeString().split(" ")[0] + " UTC";
  }, 1000);
}

function connectWebSocket() {
  const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsProtocol}//${window.location.host}/ws`;

  const dot = document.getElementById("wsDot");
  const text = document.getElementById("wsStatusText");

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      dot.className = "status-dot pulse-green";
      text.innerText = "STREAM LIVE";
      if (reconnectTimer) clearInterval(reconnectTimer);
      // Keep alive ping
      setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ action: "PING" }));
        }
      }, 15000);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleLiveEvent(data);
      } catch (err) {
        console.error("WS Parse Error:", err);
      }
    };

    ws.onclose = () => {
      dot.className = "status-dot pulse-amber";
      text.innerText = "RECONNECTING";
      scheduleReconnect();
    };

    ws.onerror = () => {
      dot.className = "status-dot pulse-red";
      text.innerText = "DISCONNECTED";
      ws.close();
    };
  } catch (err) {
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectWebSocket();
  }, 3000);
}

// ==============================================================================
// Live Event Dispatcher
// ==============================================================================
function handleLiveEvent(data) {
  switch (data.event) {
    case "AUTH_CHALLENGE_ISSUED":
      showToast(`Challenge generated for device: ${data.device_id}`, "info");
      break;

    case "AUTH_VERIFICATION_COMPLETE":
      updateRelayVisual(data.relay_status, data.device_id);
      fetchDevices();
      fetchAuditLogs();
      if (data.authenticated) {
        showToast(`Authentication GRANTED for ${data.device_id} (${data.latency_ms} ms)`, "success");
      } else {
        showToast(`Authentication REJECTED: ${data.message}`, "error");
      }
      break;

    case "RELAY_STATUS_CHANGED":
      updateRelayVisual(data.relay_status, data.triggered_by);
      break;

    case "DEVICE_REGISTERED":
      showToast(`New Hardware Enrolled: ${data.device_id}`, "info");
      fetchDevices();
      break;

    case "SECURITY_ALERT":
      fetchAlerts();
      break;

    case "ALERT_RESOLVED":
      fetchAlerts();
      break;
  }
}

// ==============================================================================
// UI Updates & Relay Visualizer
// ==============================================================================
function updateRelayVisual(status, source) {
  const card = document.getElementById("relayCard");
  const statusText = document.getElementById("relayStatusText");
  const lastChanged = document.getElementById("relayLastChanged");
  const triggeredBy = document.getElementById("relayTriggeredBy");

  const isUnlocked = status === "UNLOCKED";

  if (isUnlocked) {
    card.classList.add("unlocked");
    statusText.innerText = "UNLOCKED";
    statusText.className = "status-main state-unlocked";
  } else {
    card.classList.remove("unlocked");
    statusText.innerText = "LOCKED";
    statusText.className = "status-main state-locked";
  }

  const now = new Date().toTimeString().split(" ")[0];
  lastChanged.innerText = now;
  if (source) triggeredBy.innerText = source;
}

// ==============================================================================
// Data Fetching & Rendering
// ==============================================================================
async function fetchInitialData() {
  await Promise.all([
    fetchRelayStatus(),
    fetchDevices(),
    fetchAuditLogs(),
    fetchAlerts(),
    fetchPUFMetrics()
  ]);
}

async function fetchRelayStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/relay/status`);
    const data = await res.json();
    updateRelayVisual(data.status, data.triggered_by);
  } catch (err) {
    console.error("Error fetching relay:", err);
  }
}

async function fetchDevices() {
  try {
    const res = await fetch(`${API_BASE}/api/devices`);
    const data = await res.json();
    const tbody = document.getElementById("devicesTableBody");
    const countBadge = document.getElementById("deviceCountBadge");

    countBadge.innerText = `${data.total} Device${data.total === 1 ? "" : "s"}`;

    if (!data.devices || data.devices.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center">No enrolled devices found. Enroll an ESP32 to begin.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.devices.map(dev => {
      const isTrusted = dev.trust_status === "TRUSTED";
      const badgeClass = isTrusted ? "trust-trusted" : "trust-untrusted";
      const shortKey = dev.public_key.substring(0, 10) + "..." + dev.public_key.substring(dev.public_key.length - 8);

      return `
        <tr>
          <td><strong>${dev.device_id}</strong></td>
          <td>${dev.mac_address}</td>
          <td><span class="trust-badge ${badgeClass}">${dev.trust_status}</span></td>
          <td title="${dev.public_key}">${shortKey}</td>
          <td><span class="text-green">${dev.auth_success_count}</span> / <span class="text-red">${dev.auth_fail_count}</span></td>
          <td>${dev.last_seen ? dev.last_seen.split(" ")[1] : "Never"}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching devices:", err);
  }
}

async function fetchAuditLogs() {
  try {
    const res = await fetch(`${API_BASE}/api/logs?limit=40`);
    const data = await res.json();
    const container = document.getElementById("logsStream");

    let total = data.logs.length;
    let passed = 0;
    let failed = 0;
    let latencies = [];

    data.logs.forEach(l => {
      if (l.result === "SUCCESS") passed++;
      else failed++;
      if (l.latency_ms) latencies.push(l.latency_ms);
    });

    document.getElementById("valTotalAttempts").innerText = total;
    document.getElementById("valAcceptedAttempts").innerText = passed;
    document.getElementById("valRejectedAttempts").innerText = failed;

    const avgLat = latencies.length ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1) : "--";
    document.getElementById("valAvgLatency").innerText = `${avgLat} ms`;

    if (data.logs.length === 0) {
      container.innerHTML = `<div class="empty-state"><p>No authentication events logged yet.</p></div>`;
      return;
    }

    container.innerHTML = data.logs.map(log => {
      const isSuccess = log.result === "SUCCESS";
      const tagClass = isSuccess ? "text-green" : "text-red";
      const timeStr = log.timestamp.split(" ")[1];

      return `
        <div class="log-entry log-${log.result}">
          <div class="log-left">
            <span class="log-device">${log.device_id}</span>
            <span class="log-reason">${log.failure_reason || "Schnorr Proof Verified"}</span>
          </div>
          <div class="log-right">
            <span class="log-tag ${tagClass}">${log.result}</span>
            <span class="log-latency">${log.latency_ms ? log.latency_ms.toFixed(1) + "ms" : ""} &bull; ${timeStr}</span>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching logs:", err);
  }
}

async function fetchAlerts() {
  try {
    const res = await fetch(`${API_BASE}/api/alerts?limit=20`);
    const data = await res.json();
    const list = document.getElementById("alertsList");
    const badge = document.getElementById("alertsBadge");

    badge.innerText = `${data.count} Threat${data.count === 1 ? "" : "s"}`;

    if (data.alerts.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <p>No active security threats detected. Zero-Trust perimeter secure.</p>
        </div>
      `;
      return;
    }

    list.innerHTML = data.alerts.map(a => {
      const timeStr = a.timestamp.split(" ")[1];
      return `
        <div class="alert-item severity-${a.severity}">
          <div class="alert-top">
            <span class="alert-type">${a.alert_type}</span>
            <span class="alert-time">${timeStr}</span>
          </div>
          <div class="alert-desc">${a.description}</div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching alerts:", err);
  }
}

async function fetchPUFMetrics() {
  try {
    const res = await fetch(`${API_BASE}/api/puf/metrics`);
    const m = await res.json();

    document.getElementById("valIntraHD").innerText = `${m.intra_hd_percent}%`;
    document.getElementById("barIntraHD").style.width = `${m.reliability_percent}%`;

    document.getElementById("valInterHD").innerText = `${m.inter_hd_percent}%`;
    document.getElementById("barInterHD").style.width = `${m.uniqueness_percent}%`;

    document.getElementById("valBER").innerText = `${m.bit_error_rate_percent}%`;
    document.getElementById("barBER").style.width = `${Math.min(100, m.bit_error_rate_percent * 5)}%`;

    document.getElementById("valEntropy").innerText = m.shannon_entropy.toFixed(4);
    document.getElementById("barEntropy").style.width = `${(m.shannon_entropy * 100).toFixed(1)}%`;
  } catch (err) {
    console.error("Error fetching PUF metrics:", err);
  }
}

// ==============================================================================
// Physical Relay Manual Override
// ==============================================================================
async function handleRelayOverride(status) {
  try {
    const res = await fetch(`${API_BASE}/api/relay/override`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: status, duration_seconds: 5, reason: "DASHBOARD_OVERRIDE" })
    });
    const data = await res.json();
    updateRelayVisual(data.status, "MANUAL_DASHBOARD");
    showToast(`Relay override commanded: ${status}`, status === "UNLOCKED" ? "success" : "info");
  } catch (err) {
    showToast(`Relay command failed: ${err.message}`, "error");
  }
}

// ==============================================================================
// Interactive Attack Simulator Executions
// ==============================================================================
async function triggerSimulation(scenario) {
  showToast(`Initiating Scenario: ${scenario.toUpperCase()}...`, "info");

  switch (scenario) {
    case "legitimate":
      await runSimLegitimate();
      break;
    case "unknown":
      await runSimUnknown();
      break;
    case "replay":
      await runSimReplay();
      break;
    case "modified":
      await runSimModified();
      break;
  }
}

// Scenario 1: Legitimate ESP32 authentication
async function runSimLegitimate() {
  const deviceId = "ESP32-LEGIT-01";
  const mac = "24:6F:28:01:A2:FE";

  // Simulate PUF secret x and public key Y = x * G
  // In real system, this is hardware derived.
  // Using fixed demo seed for reproducibility:
  const privSecret = 0x5a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdefn;
  // Public key compressed hex for this secret:
  // We can call backend or compute via modular Schnorr
  // Let's perform registration if not already enrolled:
  await fetch(`${API_BASE}/api/device/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      mac_address: mac,
      chip_model: "ESP32-D0WDQ6",
      chip_revision: 1,
      public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", // secp256k1 generator G
      helper_data: "ffffffffffffffff"
    })
  });

  // Commitment R = k * G where k = 1 => R = G
  const commitment = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

  // Request Challenge
  const chalRes = await fetch(`${API_BASE}/api/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: deviceId, commitment: commitment })
  });

  if (!chalRes.ok) {
    showToast("Challenge generation failed", "error");
    return;
  }

  const chalData = await chalRes.json();
  const cBig = BigInt("0x" + chalData.challenge);
  const ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

  // Since public key Y = G, secret x = 1. With k = 1:
  // s = (k + c * x) mod q = (1 + c * 1) mod q
  const sBig = (1n + cBig) % ORDER;
  const sHex = sBig.toString(16).padStart(64, "0");

  // Save for replay test demonstration
  lastCapturedProof = {
    session_id: chalData.session_id,
    device_id: deviceId,
    response: sHex
  };

  // Submit proof
  const verifyRes = await fetch(`${API_BASE}/api/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: chalData.session_id,
      device_id: deviceId,
      response: sHex
    })
  });

  const vData = await verifyRes.json();
  fetchInitialData();
}

// Scenario 2: Unknown / Unregistered Device
async function runSimUnknown() {
  const fakeDeviceId = "ESP32-CLONE-ROGUE";
  const fakeCommitment = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

  try {
    const res = await fetch(`${API_BASE}/api/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: fakeDeviceId, commitment: fakeCommitment })
    });

    const data = await res.json();
    showToast(`Rejected: ${data.detail || "Unknown device denied"}`, "error");
    fetchAlerts();
    fetchAuditLogs();
  } catch (err) {
    showToast("Unknown device rejected at gate", "error");
  }
}

// Scenario 3: Replay Attack (Reusing previously consumed proof & session)
async function runSimReplay() {
  if (!lastCapturedProof) {
    showToast("Executing initial valid auth first to capture proof for replay...", "info");
    await runSimLegitimate();
    await new Promise(r => setTimeout(r, 600));
  }

  showToast(`Adversary replaying captured session token: ${lastCapturedProof.session_id.substring(0, 8)}...`, "error");

  const res = await fetch(`${API_BASE}/api/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(lastCapturedProof)
  });

  const data = await res.json();
  fetchAlerts();
  fetchAuditLogs();
}

// Scenario 4: Modified / Forged Proof (Bit-flip attack)
async function runSimModified() {
  const deviceId = "ESP32-LEGIT-01";
  const commitment = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

  // Request fresh challenge
  const chalRes = await fetch(`${API_BASE}/api/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: deviceId, commitment: commitment })
  });

  const chalData = await chalRes.json();
  const cBig = BigInt("0x" + chalData.challenge);
  const ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

  // Genuine s = (1 + c) mod q
  let sBig = (1n + cBig) % ORDER;
  // Corrupt proof: flip lowest bit
  sBig = sBig ^ 1n;
  const sHexCorrupted = sBig.toString(16).padStart(64, "0");

  showToast("Submitting tampered Schnorr response scalar (bit-flip applied)...", "error");

  const verifyRes = await fetch(`${API_BASE}/api/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: chalData.session_id,
      device_id: deviceId,
      response: sHexCorrupted
    })
  });

  const vData = await verifyRes.json();
  fetchAlerts();
  fetchAuditLogs();
}

// ==============================================================================
// Toast Helper
// ==============================================================================
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerText = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}
