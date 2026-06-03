const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gsCompanion', {
  safetySummary: () => ipcRenderer.invoke('companion:safety-summary'),
  detectClients: processNames => ipcRenderer.invoke('companion:detect-clients', processNames),
  launchClient: launchRequest => ipcRenderer.invoke('companion:launch-client', launchRequest)
});
