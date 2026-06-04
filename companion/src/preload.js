const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gsCompanion', {
  safetySummary: () => ipcRenderer.invoke('companion:safety-summary'),
  detectClients: processNames => ipcRenderer.invoke('companion:detect-clients', processNames),
  launchClient: launchRequest => ipcRenderer.invoke('companion:launch-client', launchRequest),
  runBrowserJob: request => ipcRenderer.invoke('companion:run-browser-job', request),
  closeBrowser: () => ipcRenderer.invoke('companion:close-browser'),
  onBrowserJobLog: callback => {
    const listener = (_event, progress) => callback(progress);
    ipcRenderer.on('companion:browser-job-log', listener);
    return () => ipcRenderer.removeListener('companion:browser-job-log', listener);
  }
});
