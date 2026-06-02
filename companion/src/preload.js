const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gsCompanion', {
  safetySummary: () => ipcRenderer.invoke('companion:safety-summary')
});
