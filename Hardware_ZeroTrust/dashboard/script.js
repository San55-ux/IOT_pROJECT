/**
 * Zero-Trust Security Gateway Dashboard Controller
 * WebSocket real-time telemetry, interactive attack simulations,
 * and physical relay state visualizer.
 */

// Automatically detect if opened inside VS Code (Live Server port 5500/3000, Live Preview, or file://)
const isVsCodeOrFile = window.location.protocol === "file:" ||
                       (window.location.port && window.location.port !== "8000") ||
                       !window.location.host;

const API_BASE = isVsCodeOrFile ? "http://localhost:8000" : window.location.origin;
let ws = null;
let reconnectTimer = null;
let lastCapturedProof = null; // Stored for demonstrating replay attack

// ==============================================================================
// Initialization & WebSocket Setup
// ==============================================================================
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  initMlGraph();
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
  const wsHost = isVsCodeOrFile ? "localhost:8000" : window.location.host;
  const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsProtocol}//${wsHost}/ws`;

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
  if (data.puf_health) {
    updatePufHealthVisual(data.puf_health);
  }

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

    case "DEVICE_DEREGISTERED":
      showToast(`Device Deregistered: ${data.device_id}`, "info");
      fetchDevices();
      fetchAuditLogs();
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

  // SG90 Servo Actuator Elements
  const servoHorn = document.getElementById("servoHorn");
  const servoAngleText = document.getElementById("servoAngleText");

  const isUnlocked = status === "UNLOCKED";

  if (isUnlocked) {
    card.classList.add("unlocked");
    statusText.innerText = "UNLOCKED";
    statusText.className = "status-main state-unlocked";

    if (servoHorn && servoAngleText) {
      servoHorn.className = "servo-horn horn-unlocked";
      servoAngleText.innerText = "90° UNLOCKED";
      servoAngleText.className = "servo-angle unlocked";
    }
  } else {
    card.classList.remove("unlocked");
    statusText.innerText = "LOCKED";
    statusText.className = "status-main state-locked";

    if (servoHorn && servoAngleText) {
      servoHorn.className = "servo-horn horn-locked";
      servoAngleText.innerText = "0° LOCKED";
      servoAngleText.className = "servo-angle";
    }
  }

  const now = new Date().toTimeString().split(" ")[0];
  lastChanged.innerText = now;
  if (source) triggeredBy.innerText = source;
}

// Option 3 ML Telemetry & Silicon Health Visualizer
function updatePufHealthVisual(h) {
  if (!h) return;
  const scoreEl = document.getElementById("mlHealthScore");
  const badgeEl = document.getElementById("pufHealthBadge");
  const tempEl = document.getElementById("telTemp");
  const voltEl = document.getElementById("telVolt");
  const berEl = document.getElementById("telBer");
  const statusEl = document.getElementById("telStatus");
  const berBar = document.getElementById("mlBerBar");
  const marginEl = document.getElementById("telStabilityMargin");

  const health = Number(h.health_score || 94.0).toFixed(1);
  const ber = Number(h.predicted_ber_pct !== undefined ? h.predicted_ber_pct : (h.predicted_ber || 2.0)).toFixed(2);
  const temp = Number(h.temperature_c !== undefined ? h.temperature_c : (h.temperature || 35.0)).toFixed(1);
  const volt = Number(h.voltage_v !== undefined ? h.voltage_v : (h.voltage || 3.3)).toFixed(2);
  const status = h.status || "HEALTHY";

  if (scoreEl) scoreEl.innerText = `${health}%`;
  if (tempEl) tempEl.innerText = `${temp} °C`;
  if (voltEl) voltEl.innerText = `${volt} V`;
  if (berEl) berEl.innerText = `${ber} %`;
  if (statusEl) statusEl.innerText = status;

  // Margin calculation (15% is max tolerable BER)
  const margin = Math.max(0, 100 - (Number(ber) / 15.0 * 100)).toFixed(1);
  if (marginEl) marginEl.innerText = `${margin}% Stability Margin`;
  if (berBar) berBar.style.width = `${Math.min(100, Math.max(5, (Number(ber) / 15.0) * 100))}%`;

  if (status === "PHYSICAL_TAMPER" || h.is_tamper) {
    if (badgeEl) { badgeEl.innerText = "TAMPER ALERT"; badgeEl.className = "badge badge-alert"; }
    if (statusEl) statusEl.className = "tel-val text-red";
    if (scoreEl) scoreEl.style.color = "var(--red)";
  } else if (health < 60) {
    if (badgeEl) { badgeEl.innerText = "DEGRADED"; badgeEl.className = "badge badge-alert"; }
    if (statusEl) statusEl.className = "tel-val text-amber";
    if (scoreEl) scoreEl.style.color = "var(--amber)";
  } else {
    if (badgeEl) { badgeEl.innerText = "ML OPTIMAL"; badgeEl.className = "badge badge-green"; }
    if (statusEl) statusEl.className = "tel-val text-green";
    if (scoreEl) scoreEl.style.color = "var(--green)";
  }

  // Live feed to the ML Graph
  if (typeof addTelemetryPoint === "function") {
    addTelemetryPoint({
      temperature: temp,
      voltage: volt,
      predicted_ber: ber,
      health_score: health,
      status: status,
      is_tamper: Boolean(status === "PHYSICAL_TAMPER" || h.is_tamper)
    });
  }
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
  // Initialize the ML Graph in the center column
  initMlGraph();
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
      tbody.innerHTML = `<tr><td colspan="7" class="text-center">No enrolled devices found. Enroll an ESP32 to begin.</td></tr>`;
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
          <td>
            <button class="btn-deregister" onclick="handleDeregisterDevice('${dev.device_id}')" title="Deregister this device so it becomes unrecognized">
              Deregister
            </button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching devices:", err);
  }
}

async function handleDeregisterDevice(deviceId) {
  if (!confirm(`Are you sure you want to deregister device '${deviceId}'?\n\nIt will be removed from the Zero-Trust Gateway directory and any future access attempts will be DENIED as an unregistered rogue device.`)) {
    return;
  }
  try {
    const res = await fetch(`${API_BASE}/api/device/${encodeURIComponent(deviceId)}`, {
      method: "DELETE"
    });
    const data = await res.json();
    if (res.ok) {
      showToast(`Device ${deviceId} deregistered. Now treated as UNREGISTERED.`, "info");
      fetchDevices();
      fetchAuditLogs();
    } else {
      showToast(`Deregistration failed: ${data.detail || data.message}`, "error");
    }
  } catch (err) {
    showToast(`Error deregistering device: ${err.message}`, "error");
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
    case "freeze_tamper":
      await runSimFreezeTamper();
      break;
    case "voltage_glitch":
      await runSimVoltageGlitch();
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

  // Request Challenge with ML Telemetry
  const chalRes = await fetch(`${API_BASE}/api/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      commitment: commitment,
      telemetry: { temperature: 36.2, voltage: 3.30, boot_count: 14 }
    })
  });

  if (!chalRes.ok) {
    showToast("Challenge generation failed", "error");
    return;
  }

  const chalData = await chalRes.json();
  if (chalData.puf_health) {
    updatePufHealthVisual(chalData.puf_health);
  }

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
  if (vData.puf_health) {
    updatePufHealthVisual(vData.puf_health);
  }
}

// Scenario 5: Freeze Tamper Attack Simulation (-15°C)
async function runSimFreezeTamper() {
  const deviceId = "ESP32-LEGIT-01";
  const commitment = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

  showToast("Simulating Extreme Freeze Spray Tamper (-15.0°C)...", "error");

  const chalRes = await fetch(`${API_BASE}/api/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      commitment: commitment,
      telemetry: { temperature: -15.0, voltage: 3.30, boot_count: 50 }
    })
  });

  const chalData = await chalRes.json();
  if (chalData.puf_health) {
    updatePufHealthVisual(chalData.puf_health);
  }
  fetchAlerts();
  fetchAuditLogs();
}

// Scenario 6: Voltage Glitch Fault Injection Simulation (2.65V)
async function runSimVoltageGlitch() {
  const deviceId = "ESP32-LEGIT-01";
  const commitment = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

  showToast("Simulating Power Rail Fault Injection (2.65V Glitch)...", "error");

  const chalRes = await fetch(`${API_BASE}/api/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      commitment: commitment,
      telemetry: { temperature: 35.0, voltage: 2.65, boot_count: 50 }
    })
  });

  const chalData = await chalRes.json();
  if (chalData.puf_health) {
    updatePufHealthVisual(chalData.puf_health);
  }
  fetchAlerts();
  fetchAuditLogs();
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

// ==============================================================================
// Interactive ML Silicon Drift & Anomaly Predictor Canvas Engine
// ==============================================================================
let g_mlCurrentTab = "trend"; // "trend" or "phase"
let g_mlTelemetryHistory = [];
let g_hoverTelemetryIdx = -1;

function initMlGraph() {
  const canvas = document.getElementById("mlGraphCanvas");
  if (!canvas) return;

  // Immediately seed baseline telemetry and render so the graph is NEVER empty
  if (!g_mlTelemetryHistory || g_mlTelemetryHistory.length === 0) {
    seedBaselineTelemetry();
  }
  resizeMlCanvas();
  renderActiveMlGraph();

  // Setup Canvas sizing & resize observer
  window.addEventListener("resize", () => {
    resizeMlCanvas();
    renderActiveMlGraph();
  });

  if (window.ResizeObserver && canvas.parentElement) {
    const ro = new ResizeObserver(() => {
      resizeMlCanvas();
      renderActiveMlGraph();
    });
    ro.observe(canvas.parentElement);
  }

  // Canvas Mouse Interaction for Tooltips
  const tooltip = document.getElementById("mlGraphTooltip");
  canvas.addEventListener("mousemove", (e) => {
    if (g_mlCurrentTab !== "trend" || g_mlTelemetryHistory.length === 0) {
      if (tooltip) tooltip.style.display = "none";
      return;
    }
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const padL = 46, padR = 46;
    const chartW = rect.width - padL - padR;
    const n = g_mlTelemetryHistory.length;
    const stepX = chartW / Math.max(1, n - 1);

    let closestIdx = Math.round((mouseX - padL) / stepX);
    closestIdx = Math.max(0, Math.min(n - 1, closestIdx));
    g_hoverTelemetryIdx = closestIdx;

    const pt = g_mlTelemetryHistory[closestIdx];
    if (pt && tooltip) {
      tooltip.style.display = "block";
      tooltip.style.left = `${padL + closestIdx * stepX}px`;
      tooltip.style.top = `${Math.max(10, mouseY - 15)}px`;
      tooltip.innerHTML = `
        <strong style="color:#38bdf8;">Sample #${closestIdx + 1}</strong> (${pt.timestamp || "Live"})<br/>
        • Die Temp: <span style="color:#38bdf8;">${pt.temperature}°C</span><br/>
        • VDD Rail: <span style="color:#34d399;">${pt.voltage}V</span><br/>
        • Pred BER: <span style="color:#c084fc;">${pt.predicted_ber}%</span><br/>
        • Health: <span style="color:#34d399;">${pt.health_score}%</span><br/>
        • Status: <span style="color:${pt.is_tamper ? '#f87171' : '#34d399'};">${pt.status}</span>
      `;
    }
    renderActiveMlGraph();
  });

  canvas.addEventListener("mouseleave", () => {
    g_hoverTelemetryIdx = -1;
    if (tooltip) tooltip.style.display = "none";
    renderActiveMlGraph();
  });

  // Fetch historical data or retain baseline
  fetch(`${API_BASE}/api/puf/telemetry?limit=20`)
    .then(r => r.json())
    .then(data => {
      if (data && data.telemetry && data.telemetry.length >= 5) {
        g_mlTelemetryHistory = data.telemetry.reverse().map(row => ({
          timestamp: row.timestamp ? row.timestamp.split(" ")[1] : "",
          temperature: Number(row.temperature).toFixed(1),
          voltage: Number(row.voltage).toFixed(2),
          predicted_ber: Number(row.predicted_ber).toFixed(2),
          health_score: Number(row.health_score).toFixed(1),
          status: row.status,
          is_tamper: Boolean(row.status === "PHYSICAL_TAMPER")
        }));
      }
      resizeMlCanvas();
      renderActiveMlGraph();
    })
    .catch(() => {
      resizeMlCanvas();
      renderActiveMlGraph();
    });
}

function seedBaselineTelemetry() {
  const baseTemps = [33.8, 34.2, 34.0, 34.5, 35.1, 34.8, 35.4, 35.0, 34.7, 35.2, 34.9, 35.0];
  const baseVolts = [3.31, 3.30, 3.29, 3.30, 3.31, 3.30, 3.29, 3.30, 3.31, 3.30, 3.29, 3.30];
  const baseBers  = [ 1.72, 1.78, 1.75, 1.82, 1.89, 1.84, 1.91, 1.85, 1.80, 1.86, 1.83, 1.85];
  const baseHealth= [ 95.2, 94.6, 95.0, 94.1, 93.5, 94.0, 93.2, 94.2, 94.8, 93.9, 94.5, 94.5];

  g_mlTelemetryHistory = baseTemps.map((temp, i) => {
    const minsAgo = (12 - i) * 2;
    return {
      timestamp: `T-${minsAgo}m`,
      temperature: temp.toFixed(1),
      voltage: baseVolts[i].toFixed(2),
      predicted_ber: baseBers[i].toFixed(2),
      health_score: baseHealth[i].toFixed(1),
      status: "OPTIMAL",
      is_tamper: false
    };
  });
}

function switchMlGraphTab(tab) {
  g_mlCurrentTab = tab;
  const btnTrend = document.getElementById("tabTrendBtn");
  const btnPhase = document.getElementById("tabPhaseBtn");
  const legend = document.getElementById("mlGraphLegend");

  if (tab === "trend") {
    if (btnTrend) btnTrend.classList.add("active");
    if (btnPhase) btnPhase.classList.remove("active");
    if (legend) {
      legend.innerHTML = `
        <div class="legend-item"><span class="legend-dot cyan-dot"></span> Die Temp (°C)</div>
        <div class="legend-item"><span class="legend-dot purple-dot"></span> ML Predicted BER (%)</div>
        <div class="legend-item"><span class="legend-dot green-dot"></span> Health Score (%)</div>
        <div class="legend-item"><span class="legend-line red-dash"></span> 15% Error Budget Limit</div>
      `;
    }
  } else {
    if (btnTrend) btnTrend.classList.remove("active");
    if (btnPhase) btnPhase.classList.add("active");
    if (legend) {
      legend.innerHTML = `
        <div class="legend-item"><span class="legend-dot green-dot"></span> Optimal Envelope (15-50°C, 3.1-3.4V)</div>
        <div class="legend-item"><span class="legend-dot" style="background:#fbbf24;box-shadow:0 0 6px #fbbf24;"></span> Thermal Drift Warning</div>
        <div class="legend-item"><span class="legend-dot" style="background:#f87171;box-shadow:0 0 6px #f87171;"></span> Tamper / Glitch Anomaly</div>
      `;
    }
  }
  renderActiveMlGraph();
}

function addTelemetryPoint(pt) {
  if (!pt) return;
  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0];

  const newPt = {
    timestamp: timeStr,
    temperature: Number(pt.temperature || pt.temperature_c || 35.0).toFixed(1),
    voltage: Number(pt.voltage || pt.voltage_v || 3.30).toFixed(2),
    predicted_ber: Number(pt.predicted_ber || pt.predicted_ber_pct || 1.85).toFixed(2),
    health_score: Number(pt.health_score || 94.5).toFixed(1),
    status: pt.status || "OPTIMAL",
    is_tamper: Boolean(pt.is_tamper || pt.status === "PHYSICAL_TAMPER")
  };

  g_mlTelemetryHistory.push(newPt);
  if (g_mlTelemetryHistory.length > 25) {
    g_mlTelemetryHistory.shift();
  }

  // Update Quickstat Pills
  const sTemp = document.getElementById("gStatTemp");
  const sVolt = document.getElementById("gStatVolt");
  const sBer = document.getElementById("gStatBer");
  const sStatus = document.getElementById("gStatStatus");

  if (sTemp) sTemp.innerText = `${newPt.temperature} °C`;
  if (sVolt) sVolt.innerText = `${newPt.voltage} V`;
  if (sBer) sBer.innerText = `${newPt.predicted_ber}%`;

  if (sStatus) {
    if (newPt.is_tamper) {
      sStatus.innerText = "TAMPER DETECTED";
      sStatus.className = "badge badge-alert";
    } else if (Number(newPt.health_score) < 65) {
      sStatus.innerText = "DEGRADED DRIFT";
      sStatus.className = "badge badge-amber";
    } else {
      sStatus.innerText = "NOMINAL (SECURE)";
      sStatus.className = "badge badge-green";
    }
  }

  renderActiveMlGraph();
}

function resizeMlCanvas() {
  const canvas = document.getElementById("mlGraphCanvas");
  if (!canvas) return;
  const parent = canvas.parentElement || canvas;
  const rect = parent.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = rect.width > 50 ? rect.width : (parent.clientWidth > 50 ? parent.clientWidth : 600);
  const h = rect.height > 50 ? rect.height : 220;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
}

function renderActiveMlGraph() {
  const canvas = document.getElementById("mlGraphCanvas");
  if (!canvas) return;
  const parent = canvas.parentElement || canvas;
  const rect = parent.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = rect.width > 50 ? rect.width : (parent.clientWidth > 50 ? parent.clientWidth : 600);
  const h = rect.height > 50 ? rect.height : 220;

  if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
    resizeMlCanvas();
  }

  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, w, h);

  if (g_mlCurrentTab === "trend") {
    renderMlTrendChart(canvas, ctx, w, h);
  } else {
    renderMlPhaseSpaceChart(canvas, ctx, w, h);
  }
}

// ------------------------------------------------------------------------------
// Chart 1: Real-Time Environmental Drift & BER Curve
// ------------------------------------------------------------------------------
function renderMlTrendChart(canvas, ctx, w, h) {
  const padL = 46, padR = 46, padT = 24, padB = 28;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  if (plotW <= 0 || plotH <= 0) return;

  // Grid Lines & Axis Labels
  ctx.strokeStyle = "rgba(148, 163, 184, 0.12)";
  ctx.lineWidth = 1;
  ctx.fillStyle = "rgba(148, 163, 184, 0.7)";
  ctx.font = "10px JetBrains Mono, monospace";

  // BER Y-axis: 0% to 20% (left) | Temp Y-axis: 0°C to 60°C (right)
  const steps = 4;
  for (let i = 0; i <= steps; i++) {
    const y = padT + (plotH / steps) * i;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    ctx.stroke();

    const berVal = ((1 - i / steps) * 20).toFixed(0);
    ctx.textAlign = "right";
    ctx.fillStyle = "#c084fc";
    ctx.fillText(`${berVal}%`, padL - 8, y + 3);

    const tempVal = ((1 - i / steps) * 60).toFixed(0);
    ctx.textAlign = "left";
    ctx.fillStyle = "#38bdf8";
    ctx.fillText(`${tempVal}°C`, padL + plotW + 8, y + 3);
  }

  // 15% Error Correction Limit Line
  const y15 = padT + plotH * (1 - 15.0 / 20.0);
  ctx.save();
  ctx.strokeStyle = "rgba(248, 113, 113, 0.65)";
  ctx.setLineDash([5, 5]);
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(padL, y15);
  ctx.lineTo(padL + plotW, y15);
  ctx.stroke();
  ctx.fillStyle = "#f87171";
  ctx.textAlign = "right";
  ctx.font = "bold 9px JetBrains Mono, monospace";
  ctx.fillText("BCH 15% ECC LIMIT", padL + plotW - 6, y15 - 4);
  ctx.restore();

  const data = g_mlTelemetryHistory;
  if (!data || data.length === 0) return;

  const n = data.length;
  const stepX = plotW / Math.max(1, n - 1);

  // Helper coordinate mappers
  const getX = (idx) => padL + idx * stepX;
  const getYBer = (ber) => padT + plotH * (1 - Math.min(20, Math.max(0, ber)) / 20.0);
  const getYTemp = (temp) => padT + plotH * (1 - Math.min(60, Math.max(0, temp)) / 60.0);

  // Gradient area fill under BER curve
  const gradBer = ctx.createLinearGradient(0, padT, 0, padT + plotH);
  gradBer.addColorStop(0, "rgba(192, 132, 252, 0.28)");
  gradBer.addColorStop(1, "rgba(192, 132, 252, 0.0)");

  ctx.beginPath();
  ctx.moveTo(getX(0), padT + plotH);
  for (let i = 0; i < n; i++) {
    ctx.lineTo(getX(i), getYBer(Number(data[i].predicted_ber)));
  }
  ctx.lineTo(getX(n - 1), padT + plotH);
  ctx.closePath();
  ctx.fillStyle = gradBer;
  ctx.fill();

  // Draw Temperature Line (Cyan)
  ctx.save();
  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 2;
  ctx.shadowColor = "#38bdf8";
  ctx.shadowBlur = 6;
  ctx.beginPath();
  for (let i = 0; i < n; i++) {
    const x = getX(i);
    const y = getYTemp(Number(data[i].temperature));
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
  ctx.restore();

  // Draw Predicted BER Line (Purple)
  ctx.save();
  ctx.strokeStyle = "#c084fc";
  ctx.lineWidth = 2.5;
  ctx.shadowColor = "#c084fc";
  ctx.shadowBlur = 8;
  ctx.beginPath();
  for (let i = 0; i < n; i++) {
    const x = getX(i);
    const y = getYBer(Number(data[i].predicted_ber));
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
  ctx.restore();

  // Draw Data Points
  for (let i = 0; i < n; i++) {
    const x = getX(i);
    const yBer = getYBer(Number(data[i].predicted_ber));
    const isTamper = data[i].is_tamper;

    ctx.beginPath();
    ctx.arc(x, yBer, isTamper ? 5 : 3.5, 0, Math.PI * 2);
    ctx.fillStyle = isTamper ? "#ef4444" : "#c084fc";
    ctx.fill();
    ctx.strokeStyle = "#0f172a";
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }

  // Draw Hover Indicator Line
  if (g_hoverTelemetryIdx >= 0 && g_hoverTelemetryIdx < n) {
    const hx = getX(g_hoverTelemetryIdx);
    ctx.save();
    ctx.strokeStyle = "rgba(255, 255, 255, 0.4)";
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(hx, padT);
    ctx.lineTo(hx, padT + plotH);
    ctx.stroke();
    ctx.restore();
  }
}

// ------------------------------------------------------------------------------
// Chart 2: 2D ML Anomaly & Tamper Phase Space (Temperature vs Voltage)
// ------------------------------------------------------------------------------
function renderMlPhaseSpaceChart(canvas, ctx, w, h) {
  const padL = 50, padR = 25, padT = 24, padB = 30;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  if (plotW <= 0 || plotH <= 0) return;

  // Temperature X-Axis: -20°C to 80°C (range = 100)
  // Voltage Y-Axis: 2.40V to 3.60V (range = 1.20)
  const mapX = (t) => padL + plotW * ((t - (-20)) / 100);
  const mapY = (v) => padT + plotH * (1 - (v - 2.40) / 1.20);

  // 1. Draw Critical Danger Zones
  // Freeze Attack Zone (T < -10°C)
  const xFreeze = mapX(-10);
  ctx.fillStyle = "rgba(56, 189, 248, 0.12)";
  ctx.fillRect(padL, padT, xFreeze - padL, plotH);

  // Undervoltage Glitch Zone (V < 2.80V)
  const yGlitch = mapY(2.80);
  ctx.fillStyle = "rgba(239, 68, 68, 0.14)";
  ctx.fillRect(padL, yGlitch, plotW, padT + plotH - yGlitch);

  // 2. Draw Safe Operating Envelope (T: 15°C to 50°C, V: 3.10V to 3.45V)
  const xSafe1 = mapX(15), xSafe2 = mapX(50);
  const ySafeTop = mapY(3.45), ySafeBottom = mapY(3.10);
  ctx.fillStyle = "rgba(52, 211, 153, 0.15)";
  ctx.fillRect(xSafe1, ySafeTop, xSafe2 - xSafe1, ySafeBottom - ySafeTop);
  ctx.strokeStyle = "rgba(52, 211, 153, 0.5)";
  ctx.lineWidth = 1;
  ctx.strokeRect(xSafe1, ySafeTop, xSafe2 - xSafe1, ySafeBottom - ySafeTop);

  // Safe Zone Watermark Text
  ctx.fillStyle = "rgba(52, 211, 153, 0.7)";
  ctx.font = "bold 9px JetBrains Mono, monospace";
  ctx.textAlign = "center";
  ctx.fillText("OPTIMAL PUF STABILITY", (xSafe1 + xSafe2) / 2, (ySafeTop + ySafeBottom) / 2);

  // Glitch Attack Text
  ctx.fillStyle = "rgba(248, 113, 113, 0.8)";
  ctx.fillText("VOLTAGE GLITCH TAMPER (V < 2.8V)", padL + plotW / 2, padT + plotH - 8);

  // Freeze Attack Text
  ctx.save();
  ctx.translate(padL + 12, padT + plotH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = "rgba(56, 189, 248, 0.8)";
  ctx.fillText("FREEZE ATTACK ZONE (T < -10°C)", 0, 0);
  ctx.restore();

  // 3. Grid Lines and Axes
  ctx.strokeStyle = "rgba(148, 163, 184, 0.15)";
  ctx.lineWidth = 1;
  ctx.fillStyle = "rgba(148, 163, 184, 0.7)";
  ctx.font = "10px JetBrains Mono, monospace";

  // Y-axis ticks (Voltage: 2.6V, 2.8V, 3.0V, 3.2V, 3.4V, 3.6V)
  for (let v = 2.6; v <= 3.6; v += 0.2) {
    const y = mapY(v);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + plotW, y);
    ctx.stroke();
    ctx.textAlign = "right";
    ctx.fillText(`${v.toFixed(1)}V`, padL - 8, y + 3);
  }

  // X-axis ticks (Temp: -20, 0, 20, 40, 60, 80)
  for (let t = -20; t <= 80; t += 20) {
    const x = mapX(t);
    ctx.beginPath();
    ctx.moveTo(x, padT);
    ctx.lineTo(x, padT + plotH);
    ctx.stroke();
    ctx.textAlign = "center";
    ctx.fillText(`${t}°C`, x, padT + plotH + 16);
  }

  // 4. Plot Historical Operating Points
  const data = g_mlTelemetryHistory;
  if (!data || data.length === 0) return;

  for (let i = 0; i < data.length - 1; i++) {
    const t = Number(data[i].temperature);
    const v = Number(data[i].voltage);
    const x = mapX(t);
    const y = mapY(v);

    ctx.beginPath();
    ctx.arc(x, y, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = data[i].is_tamper ? "rgba(239, 68, 68, 0.6)" : "rgba(192, 132, 252, 0.5)";
    ctx.fill();
  }

  // 5. Highlight Current Active Operating Point with Pulsating Radar Ring
  const latest = data[data.length - 1];
  const curT = Number(latest.temperature);
  const curV = Number(latest.voltage);
  const curX = mapX(curT);
  const curY = mapY(curV);

  ctx.save();
  // Outer glowing pulse ring
  ctx.beginPath();
  ctx.arc(curX, curY, 11, 0, Math.PI * 2);
  ctx.strokeStyle = latest.is_tamper ? "#ef4444" : "#34d399";
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Inner center blip
  ctx.beginPath();
  ctx.arc(curX, curY, 5, 0, Math.PI * 2);
  ctx.fillStyle = latest.is_tamper ? "#ef4444" : "#34d399";
  ctx.shadowColor = latest.is_tamper ? "#ef4444" : "#34d399";
  ctx.shadowBlur = 10;
  ctx.fill();

  // Label tag above point
  ctx.fillStyle = "#ffffff";
  ctx.font = "bold 9px JetBrains Mono, monospace";
  ctx.textAlign = "center";
  ctx.fillText(`CURRENT (${curT}°C, ${curV}V)`, curX, curY - 14);
  ctx.restore();
}
