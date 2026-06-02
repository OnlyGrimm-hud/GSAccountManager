async function copyFromApi(url, button) {
  const original = button.textContent;
  try {
    const response = await fetch(url, { credentials: 'same-origin' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Copy failed');
    await navigator.clipboard.writeText(data.value || '');
    button.textContent = 'Copied';
  } catch (error) {
    button.textContent = 'Copy failed';
  } finally {
    window.setTimeout(() => { button.textContent = original; }, 1400);
  }
}

document.addEventListener('click', event => {
  const button = event.target.closest('.copy-api');
  if (!button) return;
  event.preventDefault();
  copyFromApi(button.dataset.url, button);
});

document.querySelectorAll('[data-countdown]').forEach(el => {
  let remaining = Number(el.dataset.countdown || 0);
  window.setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) window.location.reload();
    else el.textContent = `${remaining}s`;
  }, 1000);
});

document.addEventListener('click', event => {
  const button = event.target.closest('.reveal-secret');
  if (!button) return;
  const input = button.parentElement.querySelector('input');
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
  button.textContent = input.type === 'password' ? 'Reveal' : 'Hide';
});

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-generate-password]');
  if (!button) return;
  event.preventDefault();
  const target = document.querySelector(button.dataset.generatePassword);
  if (!target) return;
  const response = await fetch('/generate/password', { credentials: 'same-origin' });
  const data = await response.json();
  target.value = data.value || '';
});
