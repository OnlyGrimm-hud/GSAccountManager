const pairOutput = document.getElementById('pairOutput');
const logsOutput = document.getElementById('logsOutput');
const jobOutput = document.getElementById('jobOutput');
const clientsOutput = document.getElementById('clientsOutput');
const instancesOutput = document.getElementById('instancesOutput');
const profilesOutput = document.getElementById('profilesOutput');
const browserOutput = document.getElementById('browserOutput');
let currentJob = null;
let detectedClients = [];
const storageKeys = {
  baseUrl: 'gsam.baseUrl',
  deviceToken: 'gsam.deviceToken',
  deviceId: 'gsam.deviceId',
  deviceName: 'gsam.deviceName',
  localProfileName: 'gsam.localProfileName',
  localExecutablePath: 'gsam.localExecutablePath',
  localLaunchArgs: 'gsam.localLaunchArgs',
  localDetectionEnabled: 'gsam.localDetectionEnabled',
  processNames: 'gsam.processNames',
  allowScreenshots: 'gsam.allowScreenshots'
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

function browserLog(message) {
  const line = `${new Date().toLocaleTimeString()} ${message}`;
  browserOutput.textContent = `${line}\n${browserOutput.textContent || ''}`.trim();
  log(message);
}

function refreshStatus() {
  const baseUrl = saved(storageKeys.baseUrl, document.getElementById('baseUrl').value).replace(/\/+$/, '');
  const processNames = saved(storageKeys.processNames, 'RuneLite,Jagex Launcher,JagexLauncher,osclient,DreamBot');
  const detectionEnabled = saved(storageKeys.localDetectionEnabled) === 'true';
  document.getElementById('statusBaseUrl').textContent = baseUrl || 'Not configured';
  document.getElementById('statusToken').textContent = saved(storageKeys.deviceToken) ? 'Stored locally' : 'Not paired';
  document.getElementById('deviceName').value = saved(storageKeys.deviceName, 'Windows Local App');
  document.getElementById('localProfileName').value = saved(storageKeys.localProfileName);
  document.getElementById('localExecutablePath').value = saved(storageKeys.localExecutablePath);
  document.getElementById('localLaunchArgs').value = saved(storageKeys.localLaunchArgs);
  document.getElementById('enableLocalDetection').checked = detectionEnabled;
  document.getElementById('settingsEnableLocalDetection').checked = detectionEnabled;
  document.getElementById('processNames').value = processNames;
  document.getElementById('settingsProcessNames').value = processNames;
  document.getElementById('allowScreenshots').checked = saved(storageKeys.allowScreenshots) === 'true';
  profilesOutput.textContent = saved(storageKeys.localExecutablePath)
    ? `Local profile: ${saved(storageKeys.localProfileName, 'Unnamed profile')}\nPath: ${saved(storageKeys.localExecutablePath)}`
    : 'No local launch profile saved.';
}

function clientStateLabel(state) {
  return {
    active: 'Active / Running',
    idle: 'Idle / Login Screen',
    offline: 'Offline / Last Seen',
    error: 'Error',
    unknown: 'Detected / Unknown State'
  }[state || 'unknown'] || 'Detected / Unknown State';
}

function clientStateActivity(state) {
  return {
    active: 'In Game / Active',
    idle: 'Login Screen / Idle',
    offline: 'Offline / Last Seen',
    error: 'Error',
    unknown: 'Detected / Unknown State'
  }[state || 'unknown'] || 'Detected / Unknown State';
}

function formatOptionalNumber(value) {
  if (value === null || value === undefined || value === '') return 'Unknown';
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number).toLocaleString() : 'Unknown';
}

function renderClientSummary() {
  const first = detectedClients[0] || {};
  document.getElementById('detectedClientState').textContent = clientStateLabel(first.client_state);
  document.getElementById('linkedAccountLabel').textContent = first.linked_account_label || (first.account_id ? `Account ${first.account_id}` : 'Unlinked');
  document.getElementById('lastDisplayName').textContent = first.reported_display_name || 'Unknown';
  document.getElementById('lastWealthValue').textContent = formatOptionalNumber(first.reported_wealth_value);
}

async function pair() {
  const baseUrl = document.getElementById('baseUrl').value.replace(/\/+$/, '');
  const code = document.getElementById('pairingCode').value.trim();
  const deviceName = document.getElementById('deviceName').value.trim() || 'Windows Local App';
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

function isBrowserJob(job) {
  return job && ['workflow_run', 'run_workflow', 'open_browser', 'fill_visible_fields'].includes(job.job_type);
}

async function runCurrentBrowserJob() {
  if (!currentJob) {
    log('No current job loaded.');
    return;
  }
  if (!isBrowserJob(currentJob)) {
    log(`Current job is ${currentJob.job_type}, not a Browser Automator job.`);
    return;
  }
  if (!window.confirm('Run this Browser Automator job in a visible local browser now?')) {
    log('Browser Automator job cancelled before start.');
    return;
  }
  const baseUrl = saved(storageKeys.baseUrl).replace(/\/+$/, '');
  const token = saved(storageKeys.deviceToken);
  if (!baseUrl || !token) {
    log('Browser Automator skipped: device is not paired.');
    return;
  }
  browserLog(`Starting Browser Automator job ${currentJob.id}.`);
  try {
    const result = await window.gsCompanion.runBrowserJob({
      baseUrl,
      token,
      job: currentJob,
      allowScreenshots: saved(storageKeys.allowScreenshots) === 'true'
    });
    currentJob.status = result.status || 'completed';
    jobOutput.textContent = JSON.stringify(currentJob, null, 2);
    browserLog(`Browser Automator job ${currentJob.id} ${currentJob.status}.`);
  } catch (error) {
    browserLog(`Browser Automator failed: ${error.message}`);
  }
}

async function closeAutomationBrowser() {
  try {
    await window.gsCompanion.closeBrowser();
    browserLog('Automation browser closed.');
  } catch (error) {
    browserLog(`Close browser failed: ${error.message}`);
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
    const now = new Date().toISOString();
    const clientInstance = {
      client_profile_id: currentJob.client_profile_id,
      account_id: currentJob.account_id,
      proxy_id: currentJob.proxy_id,
      instance_name: currentJob.payload && currentJob.payload.client_profile ? currentJob.payload.client_profile.name : saved(storageKeys.localProfileName),
      process_name: launch.process_name,
      process_id: launch.process_id,
      window_title: saved(storageKeys.localProfileName, launch.process_name),
      detected_at: now,
      last_seen_at: now,
      linked_account_label: currentJob.payload && currentJob.payload.account ? currentJob.payload.account.label : '',
      client_state: 'unknown',
      current_activity: 'Detected / Unknown State',
      status: 'launching',
      running: true,
      metadata: {
        detection_method: 'user_triggered_visible_launch',
        safe_detection_only: true,
        no_injection: true,
        no_memory_read: true,
        screenshots_captured: false
      }
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
  if (saved(storageKeys.localDetectionEnabled) !== 'true') {
    log('Client status skipped: local detection is disabled in Local App settings.');
    return;
  }
  if (!detectedClients.length) {
    log('Client status skipped: no detected clients to report.');
    return;
  }
  try {
    const payload = {
      detection_enabled: true,
      instances: detectedClients
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
  if (!document.getElementById('enableLocalDetection').checked) {
    clientsOutput.textContent = 'Local client detection is disabled. Enable it on this tab before scanning.';
    log('Detection skipped: local detection is disabled.');
    return;
  }
  const names = document.getElementById('processNames').value.split(',').map(item => item.trim()).filter(Boolean);
  save(storageKeys.localDetectionEnabled, 'true');
  save(storageKeys.processNames, names.join(','));
  clientsOutput.textContent = 'Detecting local windows...';
  try {
    const result = await window.gsCompanion.detectClients(names);
    detectedClients = result.clients || [];
    clientsOutput.textContent = detectedClients.length
      ? JSON.stringify(detectedClients, null, 2)
      : (result.warning || 'No clients detected.');
    renderClientSummary();
    if (instancesOutput) {
      instancesOutput.textContent = detectedClients.length
        ? JSON.stringify(detectedClients, null, 2)
        : (result.warning || 'No live sessions detected.');
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
    const now = new Date().toISOString();
    detectedClients = [{
      process_name: result.process_name,
      process_id: result.process_id,
      window_title: document.getElementById('localProfileName').value.trim() || result.process_name,
      detected_at: now,
      last_seen_at: now,
      linked_account_label: '',
      client_state: 'unknown',
      current_activity: 'Detected / Unknown State',
      status: 'launching',
      running: true,
      metadata: {
        detection_method: 'user_triggered_visible_launch',
        safe_detection_only: true,
        no_injection: true,
        no_memory_read: true,
        screenshots_captured: false
      }
    }];
    if (instancesOutput) instancesOutput.textContent = JSON.stringify(detectedClients, null, 2);
    renderClientSummary();
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
  detectedClients = detectedClients.map(item => ({ ...item, status: 'stopped', client_state: 'offline', current_activity: 'Offline / Last Seen', running: false, last_seen_at: new Date().toISOString() }));
  clientsOutput.textContent = JSON.stringify(detectedClients, null, 2);
  if (instancesOutput) instancesOutput.textContent = JSON.stringify(detectedClients, null, 2);
  renderClientSummary();
  log('Local tracking marked stopped. Send Status Update to publish.');
});
document.getElementById('takeSnapshotButton').addEventListener('click', () => {
  log('Snapshot capture is placeholder only. Enable snapshots on the website and add selected-window capture before use.');
});
document.getElementById('saveProfileButton').addEventListener('click', saveLocalProfile);
document.getElementById('launchProfileButton').addEventListener('click', launchLocalProfile);
document.getElementById('fetchJobButton').addEventListener('click', fetchNextJob);
document.getElementById('fetchJobButton2').addEventListener('click', fetchNextJob);
document.getElementById('runBrowserJobButton').addEventListener('click', runCurrentBrowserJob);
document.getElementById('runBrowserJobButton2').addEventListener('click', runCurrentBrowserJob);
document.getElementById('closeBrowserButton').addEventListener('click', closeAutomationBrowser);
document.getElementById('closeBrowserButton2').addEventListener('click', closeAutomationBrowser);
document.getElementById('runLaunchJobButton').addEventListener('click', runCurrentLaunchJob);
document.getElementById('markRunningButton').addEventListener('click', () => updateJobStatus('running', 'Visible browser placeholder started.'));
document.getElementById('markWaitingButton').addEventListener('click', () => updateJobStatus('waiting_for_user', 'Paused for manual CAPTCHA, 2FA, verification, or security check.'));
document.getElementById('markCompleteButton').addEventListener('click', () => updateJobStatus('completed', 'User marked automation job complete.'));
document.getElementById('markFailedButton').addEventListener('click', () => updateJobStatus('failed', 'User marked automation job failed.'));
document.getElementById('saveSettingsButton').addEventListener('click', () => {
  save(storageKeys.deviceName, document.getElementById('deviceName').value.trim() || 'Windows Local App');
  save(storageKeys.localDetectionEnabled, document.getElementById('settingsEnableLocalDetection').checked ? 'true' : 'false');
  save(storageKeys.processNames, document.getElementById('settingsProcessNames').value.trim() || 'RuneLite,Jagex Launcher,JagexLauncher,osclient,DreamBot');
  save(storageKeys.allowScreenshots, document.getElementById('allowScreenshots').checked ? 'true' : 'false');
  log('Settings placeholder saved.');
  refreshStatus();
});

document.getElementById('applyManualBankReportButton').addEventListener('click', () => {
  if (!detectedClients.length) {
    log('Manual bank report skipped: detect or launch a client first.');
    return;
  }
  const displayName = document.getElementById('manualDisplayName').value.trim();
  const clientState = document.getElementById('manualClientState').value;
  const gp = document.getElementById('manualGpAmount').value;
  const bank = document.getElementById('manualBankValue').value;
  const wealth = document.getElementById('manualWealthValue').value;
  const nextState = clientState || detectedClients[0].client_state || 'unknown';
  detectedClients[0] = {
    ...detectedClients[0],
    client_state: nextState,
    status: nextState === 'active' ? 'running' : nextState === 'offline' ? 'stopped' : 'detected',
    current_activity: clientStateActivity(nextState),
    running: nextState !== 'offline',
    last_seen_at: new Date().toISOString(),
    reported_display_name: displayName || detectedClients[0].reported_display_name || '',
    reported_gp_amount: gp === '' ? null : Number(gp),
    reported_bank_value: bank === '' ? null : Number(bank),
    reported_wealth_value: wealth === '' ? null : Number(wealth),
    wealth_source: 'companion_reported',
    wealth_updated_at: new Date().toISOString()
  };
  clientsOutput.textContent = JSON.stringify(detectedClients, null, 2);
  if (instancesOutput) instancesOutput.textContent = JSON.stringify(detectedClients, null, 2);
  renderClientSummary();
  log('Manual bank report added to the selected detection. Click Send Status Update to publish it.');
});

document.getElementById('enableLocalDetection').addEventListener('change', event => {
  save(storageKeys.localDetectionEnabled, event.target.checked ? 'true' : 'false');
  document.getElementById('settingsEnableLocalDetection').checked = event.target.checked;
});

document.getElementById('processNames').addEventListener('change', event => {
  save(storageKeys.processNames, event.target.value.trim());
  document.getElementById('settingsProcessNames').value = event.target.value.trim();
});

document.getElementById('settingsEnableLocalDetection').addEventListener('change', event => {
  save(storageKeys.localDetectionEnabled, event.target.checked ? 'true' : 'false');
  document.getElementById('enableLocalDetection').checked = event.target.checked;
});

document.getElementById('settingsProcessNames').addEventListener('change', event => {
  save(storageKeys.processNames, event.target.value.trim());
  document.getElementById('processNames').value = event.target.value.trim();
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
renderClientSummary();

window.gsCompanion.safetySummary().then(summary => {
  log(`Safety mode: ${summary.automationMode}`);
});

window.gsCompanion.onBrowserJobLog(progress => {
  if (!progress) return;
  browserLog(`${progress.type}: ${progress.message}`);
});
