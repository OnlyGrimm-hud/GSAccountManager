const output = document.getElementById('output');

async function pair() {
  const baseUrl = document.getElementById('baseUrl').value.replace(/\/+$/, '');
  const code = document.getElementById('pairingCode').value.trim();
  output.textContent = 'Pairing...';
  try {
    const response = await fetch(`${baseUrl}/api/companion/pair/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        device_name: 'Windows Companion',
        companion_version: '0.1.0'
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Pairing failed.');
    output.textContent = `Paired device ${data.device.id}. Store token securely in a future build.`;
  } catch (error) {
    output.textContent = error.message;
  }
}

document.getElementById('pairButton').addEventListener('click', pair);

window.gsCompanion.safetySummary().then(summary => {
  console.log('GS Companion safety mode', summary);
});
