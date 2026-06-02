const pairOutput = document.getElementById('pairOutput');
const logsOutput = document.getElementById('logsOutput');
const storageKeys = {
  baseUrl: 'gsam.baseUrl',
  deviceToken: 'gsam.deviceToken',
  deviceId: 'gsam.deviceId',
  deviceName: 'gsam.deviceName'
};

function saved(key, fallback = '') {
  return window.localStorage.getItem(key) || fallback;
}

function save(key, value) {
  window.localStorage.setItem(key, value);
}

function log(message) {
  const line = `${new Date().toLocaleTimeString()} ${message}`;
  logsOutput.textContent = `${line}\n${logsOutput.textContent || ''}`.trim();
}

function refreshStatus() {
  const baseUrl = saved(storageKeys.baseUrl, document.getElementById('baseUrl').value).replace(/\/+$/, '');
  document.getElementById('statusBaseUrl').textContent = baseUrl || 'Not configured';
  document.getElementById('statusToken').textContent = saved(storageKeys.deviceToken) ? 'Stored locally' : 'Not paired';
  document.getElementById('deviceName').value = saved(storageKeys.deviceName, 'Windows Companion');
}

async function pair() {
  const baseUrl = document.getElementById('baseUrl').value.replace(/\/+$/, '');
  const code = document.getElementById('pairingCode').value.trim();
  const deviceName = document.getElementById('deviceName').value.trim() || 'Windows Companion';
  pairOutput.textContent = 'Pairing...';
  try {
    const response = await fetch(`${baseUrl}/api/companion/pair/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        device_name: deviceName,
        companion_version: '0.1.0'
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Pairing failed.');
    save(storageKeys.baseUrl, baseUrl);
    save(storageKeys.deviceToken, data.token);
    save(storageKeys.deviceId, String(data.device.id));
    save(storageKeys.deviceName, deviceName);
    pairOutput.textContent = `Paired device ${data.device.id}. Device token saved locally.`;
    log(`Paired device ${data.device.id}.`);
    refreshStatus();
  } catch (error) {
    pairOutput.textContent = error.message;
    log(`Pairing failed: ${error.message}`);
  }
}

async function heartbeat() {
  const baseUrl = saved(storageKeys.baseUrl).replace(/\/+$/, '');
  const token = saved(storageKeys.deviceToken);
  if (!baseUrl || !token) {
    log('Heartbeat skipped: device is not paired.');
    return;
  }
  try {
    const response = await fetch(`${baseUrl}/api/companion/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ companion_version: '0.1.0' })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Heartbeat failed.');
    document.getElementById('statusHeartbeat').textContent = new Date().toLocaleString();
    log('Heartbeat sent.');
  } catch (error) {
    log(`Heartbeat failed: ${error.message}`);
  }
}

document.getElementById('pairButton').addEventListener('click', pair);
document.getElementById('heartbeatButton').addEventListener('click', heartbeat);
document.getElementById('saveSettingsButton').addEventListener('click', () => {
  save(storageKeys.deviceName, document.getElementById('deviceName').value.trim() || 'Windows Companion');
  log('Settings placeholder saved.');
  refreshStatus();
});

document.addEventListener('click', event => {
  const button = event.target.closest('[data-tab-button]');
  if (!button) return;
  document.querySelectorAll('[data-tab-button]').forEach(item => item.classList.toggle('active', item === button));
  document.querySelectorAll('[data-tab-panel]').forEach(panel => {
    panel.hidden = panel.dataset.tabPanel !== button.dataset.tabButton;
  });
});

document.getElementById('baseUrl').value = saved(storageKeys.baseUrl, 'https://gsaccountmanager.com');
refreshStatus();

window.gsCompanion.safetySummary().then(summary => {
  log(`Safety mode: ${summary.automationMode}`);
});
