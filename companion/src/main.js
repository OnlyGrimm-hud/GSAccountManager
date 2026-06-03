const { app, BrowserWindow, ipcMain } = require('electron');
const { execFile, spawn } = require('child_process');
const path = require('path');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 980,
    height: 720,
    minWidth: 860,
    minHeight: 600,
    title: 'GS Account Manager Companion',
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
  const names = Array.isArray(processNames) ? processNames.map(item => String(item || '').toLowerCase()).filter(Boolean) : [];
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
      const list = (Array.isArray(parsed) ? parsed : [parsed]).filter(Boolean).map(item => ({
        process_name: item.ProcessName || '',
        process_id: item.Id || null,
        window_title: item.MainWindowTitle || '',
        status: 'running',
        running: true
      }));
      const filtered = names.length
        ? list.filter(item => names.some(name => item.process_name.toLowerCase().includes(name) || item.window_title.toLowerCase().includes(name)))
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

function parseLaunchArgs(raw) {
  const args = [];
  const matches = String(raw || '').match(/"([^"]*)"|'([^']*)'|\S+/g) || [];
  for (const part of matches) {
    args.push(part.replace(/^['"]|['"]$/g, ''));
  }
  return args;
}
