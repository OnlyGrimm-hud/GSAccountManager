const pairOutput = document.getElementById('pairOutput');
const logsOutput = document.getElementById('logsOutput');
const jobOutput = document.getElementById('jobOutput');
const clientsOutput = document.getElementById('clientsOutput');
const instancesOutput = document.getElementById('instancesOutput');
const profilesOutput = document.getElementById('profilesOutput');
const browserOutput = document.getElementById('browserOutput');
let currentJob = null;
let detectedClients = [];
const maxLogLines = 120;
const storageKeys = {
  baseUrl: 'gsam.baseUrl',
  deviceToken: 'gsam.deviceToken',
  deviceId: 'gsam.deviceId',
  installId: 'gsam.installId',
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

function el(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const node = el(id);
  if (node) node.textContent = value || '';
}

function statusClass(value) {
  return String(value || 'idle').toLowerCase().replace(/[^a-z0-9_ -]/g, '').replace(/\s+/g, '_');
}

function setPill(id, label, state) {
  const node = el(id);
  if (!node) return;
  node.textContent = label || 'Idle';
  node.className = `status-pill ${statusClass(state || label)}`;
}

function prependLogLine(target, line) {
  const existing = String(target.textContent || '').split('\n').filter(Boolean);
  target.textContent = [line, ...existing].slice(0, maxLogLines).join('\n');
}

function getInstallId() {
  const existing = saved(storageKeys.installId);
  if (existing) return existing;
  const generated = window.crypto && window.crypto.randomUUID
    ? window.crypto.randomUUID()
    : `gs-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  save(storageKeys.installId, generated);
  return generated;
}

function shortInstallId() {
  const installId = getInstallId();
  return installId.length > 12 ? `${installId.slice(0, 8)}...${installId.slice(-4)}` : installId;
}

function log(message) {
  const line = `${new Date().toLocaleTimeString()} ${message}`;
  prependLogLine(logsOutput, line);
}

function browserLog(message) {
  const line = `${new Date().toLocaleTimeString()} ${message}`;
  prependLogLine(browserOutput, line);
  setText('browserLastEvent', message);
  log(message);
}

function refreshStatus() {
  const baseUrl = saved(storageKeys.baseUrl, document.getElementById('baseUrl').value).replace(/\/+$/, '');
  const processNames = saved(storageKeys.processNames, 'RuneLite,Jagex Launcher,JagexLauncher,osclient,DreamBot');
  const detectionEnabled = saved(storageKeys.localDetectionEnabled) === 'true';
  const paired = Boolean(saved(storageKeys.deviceToken));
  document.getElementById('statusBaseUrl').textContent = baseUrl || 'Not configured';
  document.getElementById('statusToken').textContent = paired ? 'Stored locally' : 'Not paired';
  document.getElementById('statusInstallId').textContent = shortInstallId();
  setText('pairWebsite', baseUrl || 'Not configured');
  setText('pairDeviceId', paired ? `Device ${saved(storageKeys.deviceId, 'paired')}` : 'Not paired');
  setText('pairInstallId', shortInstallId());
  setPill('pairStatusPill', paired ? 'Paired' : 'Not paired', paired ? 'ready' : 'needs');
  document.getElementById('deviceName').value = saved(storageKeys.deviceName, 'GS Agent');
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
  renderCurrentJob();
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

function browserJob(job) {
  return job && ['workflow_run', 'run_workflow', 'open_browser', 'fill_visible_fields'].includes(job.job_type);
}

function jobTitle(job) {
  if (!job) return 'No job loaded';
  const payload = job.payload || {};
  if (payload.workflow && payload.workflow.name) return payload.workflow.name;
  if (payload.client_profile && payload.client_profile.name) return payload.client_profile.name;
  return job.job_type.replace(/_/g, ' ');
}

function jobTarget(job) {
  if (!job) return 'None';
  const payload = job.payload || {};
  const parts = [];
  if (payload.account && payload.account.label) parts.push(payload.account.label);
  if (payload.proxy && payload.proxy.name) parts.push(`Proxy: ${payload.proxy.name}`);
  if (!parts.length && job.account_id) parts.push(`Account ${job.account_id}`);
  if (!parts.length && job.client_profile_id) parts.push(`Profile ${job.client_profile_id}`);
  return parts.join(' / ') || 'GS Agent';
}

function jobHint(job, note = '') {
  if (note) return note;
  if (!job) return 'Click Fetch Next Job after queueing a launch or Browser Automator job on the website.';
  if (job.status === 'waiting_for_user') return 'Complete the manual step in the visible browser, then click Continue After Manual Step.';
  if (job.job_type === 'launch_client') return 'Click Run Current Launch Job to start the configured local executable visibly on this PC.';
  if (browserJob(job)) return 'Click Run Browser Automator Job. CAPTCHA, 2FA, email verification, and final submit remain manual.';
  return 'Use the action buttons below to update this local job.';
}

function renderCurrentJob(note = '') {
  setText('currentJobTitle', jobTitle(currentJob));
  setText('currentJobId', currentJob ? String(currentJob.id) : 'None');
  setText('currentJobType', currentJob ? currentJob.job_type.replace(/_/g, ' ') : 'None');
  setText('currentJobTarget', jobTarget(currentJob));
  setText('currentJobUpdated', currentJob ? new Date().toLocaleString() : 'Never');
  setText('currentJobHint', jobHint(currentJob, note));
  setPill('currentJobStatus', currentJob ? currentJob.status : 'Idle', currentJob ? currentJob.status : 'idle');
  setText('browserJobId', currentJob && browserJob(currentJob) ? `Job ${currentJob.id}` : 'No browser job loaded');
  setText('browserJobStatus', currentJob && browserJob(currentJob) ? currentJob.status : 'Idle');
  setPill('pairStatusPill', saved(storageKeys.deviceToken) ? 'Paired' : 'Not paired', saved(storageKeys.deviceToken) ? 'ready' : 'needs');
}

async function pair() {
  const baseUrl = document.getElementById('baseUrl').value.replace(/\/+$/, '');
  const code = document.getElementById('pairingCode').value.trim();
  const deviceName = document.getElementById('deviceName').value.trim() || 'GS Agent';
  pairOutput.textContent = 'Pairing...';
  try {
    const response = await fetch(`${baseUrl}/api/companion/pair/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        device_name: deviceName,
        device_install_id: getInstallId(),
        device_role: 'agent_browser',
        companion_version: '0.1.0'
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Pairing failed.');
    save(storageKeys.baseUrl, baseUrl);
    save(storageKeys.deviceToken, data.token);
    save(storageKeys.deviceId, String(data.device.id));
    save(storageKeys.deviceName, deviceName);
    pairOutput.textContent = `${data.pairing && data.pairing.reused_existing_device ? 'Re-paired' : 'Paired'} device ${data.device.id}. This install is trusted until you revoke it or clear local app data.`;
    log(`${data.pairing && data.pairing.reused_existing_device ? 'Re-paired' : 'Paired'} device ${data.device.id}.`);
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
      body: JSON.stringify({ companion_version: '0.1.0', device_install_id: getInstallId() })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Heartbeat failed.');
    document.getElementById('statusHeartbeat').textContent = new Date().toLocaleString();
    setPill('pairStatusPill', 'Paired', 'ready');
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
    renderCurrentJob();
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
    renderCurrentJob(message);
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
    currentJob.status = 'running';
    renderCurrentJob('Visible browser is running this job.');
    const result = await window.gsCompanion.runBrowserJob({
      baseUrl,
      token,
      job: currentJob,
      allowScreenshots: saved(storageKeys.allowScreenshots) === 'true'
    });
    currentJob.status = result.status || 'completed';
    jobOutput.textContent = JSON.stringify(currentJob, null, 2);
    renderCurrentJob('Browser Automator finished. Review the visible browser before closing it.');
    browserLog(`Browser Automator job ${currentJob.id} ${currentJob.status}.`);
  } catch (error) {
    currentJob.status = 'failed';
    renderCurrentJob('Browser Automator failed. Check the local logs for safe details.');
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
  const jobProfile = currentJob.payload && currentJob.payload.client_profile ? currentJob.payload.client_profile : {};
  const args = saved(storageKeys.localLaunchArgs) || jobProfile.launch_args_template || '';
  if (!executablePath) {
    log('Launch job needs a local executable path in Settings.');
    renderCurrentJob('Add the executable path in Settings before running this launch job.');
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
      instance_name: jobProfile.name || saved(storageKeys.localProfileName),
      process_name: launch.process_name,
      process_id: launch.process_id,
      window_title: saved(storageKeys.localProfileName, jobProfile.name || launch.process_name),
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
    renderCurrentJob('Local client launch started visibly on this PC.');
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
    log('Client status skipped: local detection is disabled in GS Agent settings.');
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
document.getElementById('heartbeatButtonPair').addEventListener('click', heartbeat);
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
document.getElementById('continueJobButton').addEventListener('click', () => updateJobStatus('running', 'User continued after manual step.'));
document.getElementById('markWaitingButton').addEventListener('click', () => updateJobStatus('waiting_for_user', 'Paused for manual CAPTCHA, 2FA, verification, or security check.'));
document.getElementById('markCompleteButton').addEventListener('click', () => updateJobStatus('completed', 'User marked automation job complete.'));
document.getElementById('markFailedButton').addEventListener('click', () => updateJobStatus('failed', 'User marked automation job failed.'));
document.getElementById('browserPauseButton').addEventListener('click', () => updateJobStatus('waiting_for_user', 'Paused for manual CAPTCHA, 2FA, email verification, phone verification, Cloudflare, or security check.'));
document.getElementById('browserContinueButton').addEventListener('click', () => updateJobStatus('running', 'User continued after manual browser step.'));
document.getElementById('clearBrowserLogsButton').addEventListener('click', () => {
  browserOutput.textContent = 'Browser logs cleared.';
  setText('browserLastEvent', 'Logs cleared');
});
document.getElementById('clearLogsButton').addEventListener('click', () => {
  logsOutput.textContent = 'Logs cleared.';
});
document.getElementById('saveSettingsButton').addEventListener('click', () => {
  save(storageKeys.deviceName, document.getElementById('deviceName').value.trim() || 'GS Agent');
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
  if (currentJob && progress.job_id && String(currentJob.id) === String(progress.job_id)) {
    if (['running', 'waiting_for_user', 'completed', 'failed'].includes(progress.type)) {
      currentJob.status = progress.type === 'waiting_for_user' ? 'waiting_for_user' : progress.type;
      renderCurrentJob(progress.message);
    } else {
      setText('browserJobStatus', currentJob.status || 'running');
    }
  }
  browserLog(`${progress.type}: ${progress.message}`);
});
