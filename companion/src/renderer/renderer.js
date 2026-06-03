const pairOutput = document.getElementById('pairOutput');
const logsOutput = document.getElementById('logsOutput');
const jobOutput = document.getElementById('jobOutput');
const clientsOutput = document.getElementById('clientsOutput');
const instancesOutput = document.getElementById('instancesOutput');
const profilesOutput = document.getElementById('profilesOutput');
let currentJob = null;
let detectedClients = [];
const storageKeys = {
  baseUrl: 'gsam.baseUrl',
  deviceToken: 'gsam.deviceToken',
  deviceId: 'gsam.deviceId',
  deviceName: 'gsam.deviceName',
  localProfileName: 'gsam.localProfileName',
  localExecutablePath: 'gsam.localExecutablePath',
  localLaunchArgs: 'gsam.localLaunchArgs'
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
  document.getElementById('localProfileName').value = saved(storageKeys.localProfileName);
  document.getElementById('localExecutablePath').value = saved(storageKeys.localExecutablePath);
  document.getElementById('localLaunchArgs').value = saved(storageKeys.localLaunchArgs);
  profilesOutput.textContent = saved(storageKeys.localExecutablePath)
    ? `Local profile: ${saved(storageKeys.localProfileName, 'Unnamed profile')}\nPath: ${saved(storageKeys.localExecutablePath)}`
    : 'No local launch profile saved.';
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

function authHeaders() {
  const token = saved(storageKeys.deviceToken);
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`
  };
}

async function fetchNextJob() {
  const baseUrl = saved(storageKeys.baseUrl).replace(/\/+$/, '');
  const token = saved(storageKeys.deviceToken);
  if (!baseUrl || !token) {
    log('Job fetch skipped: device is not paired.');
    return;
  }
  try {
    const response = await fetch(`${baseUrl}/api/companion/jobs/poll`, {
      headers: authHeaders()
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not fetch job.');
    currentJob = data.job || null;
    jobOutput.textContent = currentJob ? JSON.stringify(currentJob, null, 2) : 'No queued jobs.';
    log(currentJob ? `Fetched job ${currentJob.id}.` : 'No queued jobs.');
  } catch (error) {
    log(`Job fetch failed: ${error.message}`);
  }
}

async function updateJobStatus(status, message) {
  const baseUrl = saved(storageKeys.baseUrl).replace(/\/+$/, '');
  if (!currentJob) {
    log('No current job loaded.');
    return;
  }
  try {
    const response = await fetch(`${baseUrl}/api/companion/jobs/${currentJob.id}/status`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ status, message })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Status update failed.');
    currentJob.status = status;
    jobOutput.textContent = JSON.stringify(currentJob, null, 2);
    log(`Job ${currentJob.id} marked ${status}.`);
  } catch (error) {
    log(`Job status failed: ${error.message}`);
  }
}

async function runCurrentLaunchJob() {
  if (!currentJob) {
    log('No current job loaded.');
    return;
  }
  if (currentJob.job_type !== 'launch_client') {
    log(`Current job is ${currentJob.job_type}, not launch_client.`);
    return;
  }
  const executablePath = saved(storageKeys.localExecutablePath);
  const args = saved(storageKeys.localLaunchArgs);
  if (!executablePath) {
    log('Launch job needs a local executable path in Settings.');
    return;
  }
  if (!window.confirm('Run this launch job visibly on this PC now?')) {
    log('Launch job cancelled by user.');
    return;
  }
  try {
    const launch = await window.gsCompanion.launchClient({ executablePath, args });
    const baseUrl = saved(storageKeys.baseUrl).replace(/\/+$/, '');
    const clientInstance = {
      client_profile_id: currentJob.client_profile_id,
      account_id: currentJob.account_id,
      proxy_id: currentJob.proxy_id,
      instance_name: currentJob.payload && currentJob.payload.client_profile ? currentJob.payload.client_profile.name : saved(storageKeys.localProfileName),
      process_name: launch.process_name,
      process_id: launch.process_id,
      window_title: saved(storageKeys.localProfileName, launch.process_name),
      status: 'launching',
      running: true
    };
    const response = await fetch(`${baseUrl}/api/companion/jobs/${currentJob.id}/status`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        status: 'running',
        message: 'User launched configured local client visibly.',
        client_instance: clientInstance
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Launch status update failed.');
    currentJob.status = 'running';
    jobOutput.textContent = JSON.stringify(currentJob, null, 2);
    log(`Launch job ${currentJob.id} started.`);
  } catch (error) {
    log(`Launch job failed: ${error.message}`);
    await updateJobStatus('failed', 'Local launch failed.');
  }
}

async function sendManualClientStatus() {
  const baseUrl = saved(storageKeys.baseUrl).replace(/\/+$/, '');
  const token = saved(storageKeys.deviceToken);
  if (!baseUrl || !token) {
    log('Client status skipped: device is not paired.');
    return;
  }
  try {
    const payload = detectedClients.length ? { instances: detectedClients } : {
      instances: [{
        process_name: 'manual-placeholder',
        window_title: 'User-controlled status placeholder',
        running: true,
        status: 'running',
        matched_account_hint: ''
      }]
    };
    const response = await fetch(`${baseUrl}/api/companion/clients/status`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Client status failed.');
    log(`Manual client status sent (${data.count || 1}).`);
  } catch (error) {
    log(`Client status failed: ${error.message}`);
  }
}

async function detectClients() {
  const names = document.getElementById('processNames').value.split(',').map(item => item.trim()).filter(Boolean);
  clientsOutput.textContent = 'Detecting local windows...';
  try {
    const result = await window.gsCompanion.detectClients(names);
    detectedClients = result.clients || [];
    clientsOutput.textContent = detectedClients.length
      ? JSON.stringify(detectedClients, null, 2)
      : (result.warning || 'No clients detected.');
    if (instancesOutput) {
      instancesOutput.textContent = detectedClients.length
        ? JSON.stringify(detectedClients, null, 2)
        : (result.warning || 'No instances detected.');
    }
    log(`Detected ${detectedClients.length} client window(s).`);
    if (result.warning) log(`Detection note: ${result.warning}`);
  } catch (error) {
    clientsOutput.textContent = error.message;
    if (instancesOutput) instancesOutput.textContent = error.message;
    log(`Detection failed: ${error.message}`);
  }
}

function saveLocalProfile() {
  save(storageKeys.localProfileName, document.getElementById('localProfileName').value.trim());
  save(storageKeys.localExecutablePath, document.getElementById('localExecutablePath').value.trim());
  save(storageKeys.localLaunchArgs, document.getElementById('localLaunchArgs').value.trim());
  log('Local launch profile saved.');
  refreshStatus();
}

async function launchLocalProfile() {
  const executablePath = document.getElementById('localExecutablePath').value.trim();
  const args = document.getElementById('localLaunchArgs').value.trim();
  if (!executablePath) {
    log('Launch skipped: executable path is required.');
    return;
  }
  if (!window.confirm('Launch this configured local client visibly now?')) {
    log('Launch cancelled by user.');
    return;
  }
  try {
    const result = await window.gsCompanion.launchClient({ executablePath, args });
    profilesOutput.textContent = JSON.stringify(result, null, 2);
    detectedClients = [{
      process_name: result.process_name,
      process_id: result.process_id,
      window_title: document.getElementById('localProfileName').value.trim() || result.process_name,
      status: 'launching',
      running: true
    }];
    if (instancesOutput) instancesOutput.textContent = JSON.stringify(detectedClients, null, 2);
    log(`Launch requested for ${result.process_name}.`);
  } catch (error) {
    log(`Launch failed: ${error.message}`);
  }
}

document.getElementById('pairButton').addEventListener('click', pair);
document.getElementById('heartbeatButton').addEventListener('click', heartbeat);
document.getElementById('sendStatusButton').addEventListener('click', sendManualClientStatus);
document.getElementById('detectClientsButton').addEventListener('click', detectClients);
document.getElementById('stopTrackingButton').addEventListener('click', () => {
  detectedClients = detectedClients.map(item => ({ ...item, status: 'stopped', running: false }));
  clientsOutput.textContent = JSON.stringify(detectedClients, null, 2);
  if (instancesOutput) instancesOutput.textContent = JSON.stringify(detectedClients, null, 2);
  log('Local tracking marked stopped. Send Status Update to publish.');
});
document.getElementById('takeSnapshotButton').addEventListener('click', () => {
  log('Snapshot capture is placeholder only. Enable snapshots on the website and add selected-window capture before use.');
});
document.getElementById('saveProfileButton').addEventListener('click', saveLocalProfile);
document.getElementById('launchProfileButton').addEventListener('click', launchLocalProfile);
document.getElementById('fetchJobButton').addEventListener('click', fetchNextJob);
document.getElementById('runLaunchJobButton').addEventListener('click', runCurrentLaunchJob);
document.getElementById('markRunningButton').addEventListener('click', () => updateJobStatus('running', 'Visible browser placeholder started.'));
document.getElementById('markWaitingButton').addEventListener('click', () => updateJobStatus('waiting_for_user', 'Paused for manual CAPTCHA, 2FA, verification, or security check.'));
document.getElementById('markCompleteButton').addEventListener('click', () => updateJobStatus('completed', 'User marked workflow complete.'));
document.getElementById('markFailedButton').addEventListener('click', () => updateJobStatus('failed', 'User marked workflow failed.'));
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
