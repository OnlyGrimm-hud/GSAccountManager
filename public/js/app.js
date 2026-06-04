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

document.addEventListener('click', async event => {
  const button = event.target.closest('.copy-text');
  if (!button) return;
  event.preventDefault();
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(button.dataset.copyText || '');
    button.textContent = 'Copied';
  } catch (error) {
    button.textContent = 'Copy failed';
  } finally {
    window.setTimeout(() => { button.textContent = original; }, 1400);
  }
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
  const button = event.target.closest('.reveal-api');
  if (!button) return;
  event.preventDefault();
  const target = button.dataset.target ? document.querySelector(button.dataset.target) : null;
  const input = button.parentElement.querySelector('input');
  if ((!input && !target) || !button.dataset.url) return;
  const original = button.textContent;
  if (button.dataset.revealed === 'true') {
    if (input) {
      input.type = 'password';
      input.value = '';
    }
    if (target) {
      target.textContent = target.dataset.hiddenLabel || 'Hidden until Reveal';
      target.classList.remove('revealed');
    }
    button.dataset.revealed = 'false';
    button.textContent = 'Reveal';
    return;
  }
  try {
    const response = await fetch(button.dataset.url, { credentials: 'same-origin' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Reveal failed');
    if (input) {
      input.value = data.value || '';
      input.type = 'text';
    }
    if (target) {
      target.dataset.hiddenLabel ||= target.textContent || 'Hidden until Reveal';
      target.textContent = data.value || 'No value saved';
      target.classList.add('revealed');
    }
    button.dataset.revealed = 'true';
    button.textContent = 'Hide';
  } catch (error) {
    button.textContent = 'Reveal failed';
    window.setTimeout(() => { button.textContent = original; }, 1400);
  }
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

document.addEventListener('submit', event => {
  const form = event.target.closest('[data-confirm]');
  if (!form) return;
  if (!window.confirm(form.dataset.confirm || 'Continue?')) event.preventDefault();
});

document.addEventListener('change', event => {
  const control = event.target.closest('[data-select-all]');
  if (!control) return;
  document.querySelectorAll(control.dataset.selectAll).forEach(input => {
    input.checked = control.checked;
  });
});

document.addEventListener('click', event => {
  const opener = event.target.closest('[data-open-modal]');
  if (!opener) return;
  const modal = document.getElementById(opener.dataset.openModal);
  if (modal) modal.hidden = false;
});

document.addEventListener('click', event => {
  const closer = event.target.closest('[data-close-modal]');
  if (!closer) return;
  const modal = closer.closest('.modal');
  if (modal) modal.hidden = true;
});

document.addEventListener('change', event => {
  const control = event.target.closest('[data-delete-after-export], [data-post-export-action]');
  if (!control) return;
  const block = document.querySelector('.delete-confirm-block');
  const deleteCheckbox = document.querySelector('[data-delete-after-export]');
  const postAction = document.querySelector('[data-post-export-action]');
  const deleting = Boolean((deleteCheckbox && deleteCheckbox.checked) || (postAction && postAction.value === 'delete'));
  if (block) block.hidden = !deleting;
});

function parseDelimitedRows(text, delimiter, type) {
  return String(text || '').split(/\r?\n/).map((line, index) => {
    const raw = line.trim();
    if (!raw) return null;
    const parts = raw.split(delimiter || ':').map(part => part.trim());
    const row = { line: index + 1, raw, valid: parts.length >= 2 && parts[0] && parts[1], parts, error: '' };
    if (!row.valid) row.error = 'Expected at least login/email and password';
    if (type === 'jagex' && parts.length > 6) row.extra = `${parts.length - 4} extra field(s)`;
    if (type !== 'jagex' && parts.length > 4) row.extra = `${parts.length - 4} extra field(s)`;
    return row;
  }).filter(Boolean);
}

function previewRows(container, rows) {
  if (!container) return;
  const valid = rows.filter(row => row.valid).length;
  const invalid = rows.length - valid;
  const body = rows.slice(0, 80).map(row => `
    <tr class="${row.valid ? '' : 'invalid'}">
      <td>${row.line}</td>
      <td>${escapeHtml(row.parts[0] || '')}</td>
      <td>${row.valid ? 'valid' : escapeHtml(row.error)}</td>
      <td>${escapeHtml(row.extra || '')}</td>
    </tr>
  `).join('');
  container.innerHTML = `
    <p class="row-line"><span>Valid rows</span><strong>${valid}</strong></p>
    <p class="row-line"><span>Invalid rows</span><strong>${invalid}</strong></p>
    <table><thead><tr><th>Line</th><th>Login / Host</th><th>Status</th><th>Notes</th></tr></thead><tbody>${body}</tbody></table>
  `;
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

document.addEventListener('click', event => {
  const button = event.target.closest('[data-preview-account-import]');
  if (!button) return;
  const form = button.closest('form');
  const rows = parseDelimitedRows(
    form.querySelector('[data-account-import-text]').value,
    form.querySelector('[data-account-import-delimiter]').value || ':',
    form.querySelector('[data-account-import-type]').value
  );
  previewRows(form.querySelector('[data-account-import-preview]'), rows);
  const confirm = form.querySelector('[data-confirm-account-import]');
  const hidden = form.querySelector('[name="confirm_import"]');
  if (confirm) confirm.disabled = rows.filter(row => row.valid).length === 0;
  if (hidden) hidden.value = 'yes';
});

document.addEventListener('input', event => {
  if (!event.target.closest('[data-account-import-text], [data-account-import-delimiter], [data-account-import-type]')) return;
  const form = event.target.closest('form');
  if (!form) return;
  const confirm = form.querySelector('[data-confirm-account-import]');
  const hidden = form.querySelector('[name="confirm_import"]');
  if (confirm) confirm.disabled = true;
  if (hidden) hidden.value = '';
});

document.addEventListener('click', event => {
  const button = event.target.closest('[data-preview-proxy-import]');
  if (!button) return;
  const form = button.closest('form');
  const delimiter = form.querySelector('[data-proxy-import-delimiter]').value || ':';
  const rows = String(form.querySelector('[data-proxy-import-text]').value || '').split(/\r?\n/).map((line, index) => {
    const raw = line.trim();
    if (!raw) return null;
    const parts = raw.split(delimiter).map(part => part.trim());
    const port = Number(parts[1]);
    const valid = (parts.length === 2 || parts.length === 4) && parts[0] && port > 0 && port < 65536;
    return { line: index + 1, parts, valid, error: valid ? '' : 'Expected host:port or host:port:username:password' };
  }).filter(Boolean);
  previewRows(form.querySelector('[data-proxy-import-preview]'), rows);
  const confirm = form.querySelector('[data-confirm-proxy-import]');
  const hidden = form.querySelector('[name="confirm_import"]');
  if (confirm) confirm.disabled = rows.filter(row => row.valid).length === 0;
  if (hidden) hidden.value = 'yes';
});

document.addEventListener('input', event => {
  if (!event.target.closest('[data-proxy-import-text], [data-proxy-import-delimiter]')) return;
  const form = event.target.closest('form');
  if (!form) return;
  const confirm = form.querySelector('[data-confirm-proxy-import]');
  const hidden = form.querySelector('[name="confirm_import"]');
  if (confirm) confirm.disabled = true;
  if (hidden) hidden.value = '';
});
