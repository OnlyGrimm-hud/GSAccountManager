const { app, BrowserWindow, ipcMain } = require('electron');
const { execFile, spawn } = require('child_process');
const path = require('path');
const { runBrowserAutomationJob, closeAutomationBrowser } = require('./browser-automator');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 980,
    height: 720,
    minWidth: 860,
    minHeight: 600,
    title: 'GS Local App',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

ipcMain.handle('companion:safety-summary', () => ({
  automationMode: 'user-triggered-fill-only',
  noCaptchaBypass: true,
  noSecurityBypass: true,
  noAutoSubmit: true,
  noClientInjection: true,
  visibleActionsOnly: true
}));

ipcMain.handle('companion:detect-clients', async (event, processNames = []) => {
  if (process.platform !== 'win32') {
    return { clients: [], warning: 'Client detection is currently implemented for Windows only.' };
  }
  const defaultNames = ['dreambot', 'runelite', 'jagex launcher', 'jagexlauncher', 'osclient', 'old school runescape'];
  const names = Array.isArray(processNames)
    ? processNames.map(item => String(item || '').toLowerCase()).filter(Boolean)
    : [];
  const filters = names.length ? names : defaultNames;
  const command = [
    'Get-Process |',
    'Where-Object { $_.MainWindowTitle } |',
    'Select-Object ProcessName,Id,MainWindowTitle |',
    'ConvertTo-Json -Compress'
  ].join(' ');
  return new Promise(resolve => {
    execFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], { windowsHide: true, timeout: 8000 }, (error, stdout) => {
      if (error) return resolve({ clients: [], warning: error.message });
      let parsed = [];
      try {
        const json = stdout.trim();
        if (json) parsed = JSON.parse(json);
      } catch (parseError) {
        return resolve({ clients: [], warning: parseError.message });
      }
      const now = new Date().toISOString();
      const list = (Array.isArray(parsed) ? parsed : [parsed]).filter(Boolean).map(item => ({
        process_name: item.ProcessName || '',
        process_id: item.Id || null,
        window_title: item.MainWindowTitle || '',
        detected_at: now,
        last_seen_at: now,
        status: statusForClientState(detectClientState(item.ProcessName || '', item.MainWindowTitle || '')),
        running: true,
        client_label: classifyClient(item.ProcessName || '', item.MainWindowTitle || ''),
        client_state: detectClientState(item.ProcessName || '', item.MainWindowTitle || ''),
        current_activity: activityForClientState(detectClientState(item.ProcessName || '', item.MainWindowTitle || '')),
        reported_display_name: '',
        reported_gp_amount: null,
        reported_bank_value: null,
        reported_wealth_value: null,
        wealth_source: 'unknown',
        match_hint: item.MainWindowTitle || item.ProcessName || '',
        metadata: {
          detection_method: 'windows_process_window_title',
          safe_detection_only: true,
          no_injection: true,
          no_memory_read: true,
          screenshots_captured: false
        }
      }));
      const filtered = filters.length
        ? list.filter(item => filters.some(name => item.process_name.toLowerCase().includes(name) || item.window_title.toLowerCase().includes(name)))
        : list;
      resolve({ clients: filtered.slice(0, 50), warning: null });
    });
  });
});

ipcMain.handle('companion:launch-client', async (event, launchRequest = {}) => {
  const executablePath = String(launchRequest.executablePath || '').trim();
  const args = parseLaunchArgs(String(launchRequest.args || ''));
  if (!executablePath) throw new Error('Executable path is required.');
  const child = spawn(executablePath, args, {
    detached: true,
    stdio: 'ignore',
    windowsHide: false
  });
  child.unref();
  return {
    process_id: child.pid || null,
    process_name: path.basename(executablePath),
    status: 'launching'
  };
});

ipcMain.handle('companion:run-browser-job', async (event, request = {}) => {
  return runBrowserAutomationJob(
    request,
    progress => event.sender.send('companion:browser-job-log', progress),
    mainWindow
  );
});

ipcMain.handle('companion:close-browser', async () => closeAutomationBrowser());

function parseLaunchArgs(raw) {
  const args = [];
  const matches = String(raw || '').match(/"([^"]*)"|'([^']*)'|\S+/g) || [];
  for (const part of matches) {
    args.push(part.replace(/^['"]|['"]$/g, ''));
  }
  return args;
}

function classifyClient(processName, windowTitle) {
  const text = `${processName} ${windowTitle}`.toLowerCase();
  if (text.includes('dreambot')) return 'DreamBot';
  if (text.includes('runelite')) return 'RuneLite';
  if (text.includes('jagex launcher') || text.includes('jagexlauncher')) return 'Jagex Launcher';
  if (text.includes('old school runescape') || text.includes('osclient')) return 'Official OSRS Client';
  return 'Custom Client';
}

function detectClientState(processName, windowTitle) {
  const text = `${processName} ${windowTitle}`.toLowerCase();
  if (/(login|sign in|signed out|authenticator|launcher)/.test(text)) return 'idle';
  if (/(in game|logged in|playing|active session)/.test(text)) return 'active';
  return 'unknown';
}

function statusForClientState(state) {
  if (state === 'active') return 'running';
  if (state === 'idle' || state === 'unknown') return 'detected';
  if (state === 'offline') return 'stopped';
  return 'detected';
}

function activityForClientState(state) {
  return {
    active: 'In Game / Active',
    idle: 'Login Screen / Idle',
    offline: 'Offline / Last Seen',
    unknown: 'Detected / Unknown State'
  }[state] || 'Detected / Unknown State';
}
