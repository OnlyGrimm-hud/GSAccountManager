const { dialog } = require('electron');
const { chromium } = require('playwright');

let automationBrowser = null;
let automationContext = null;
let automationPage = null;
let automationProxyKey = '';

const browserJobTypes = new Set(['workflow_run', 'run_workflow', 'open_browser', 'fill_visible_fields']);
const manualCheckPatterns = [
  ['captcha', /\bcaptcha\b|cloudflare|checking your browser|verify you are human/i],
  ['two_factor', /\b2fa\b|two[- ]factor|authenticator|verification code|one[- ]time code|otp/i],
  ['email_verification', /email verification|verify your email|check your email|confirmation email/i],
  ['phone_verification', /phone verification|verify your phone|sms code|text message code/i],
  ['security_check', /security check|suspicious activity|unusual activity|account protection|additional verification/i]
];

async function runBrowserAutomationJob(request, emit = () => {}, ownerWindow = null) {
  const ctx = normalizeRequest(request, emit, ownerWindow);
  if (!browserJobTypes.has(ctx.job.job_type)) {
    throw new Error(`Current job type ${ctx.job.job_type || 'unknown'} is not a Browser Automator job.`);
  }

  const steps = normalizeSteps(ctx.job);
  if (!steps.length) throw new Error('Browser Automator job has no executable steps.');

  try {
    await postJobStatus(ctx, 'running', 'Visible Browser Automator started.', {
      browser_left_visible: true,
      safe_automation: true
    });
    emitProgress(ctx, 'started', 'Visible Browser Automator started.');

    const page = await ensureAutomationPage(ctx);
    if (ctx.payload.proxy) {
      await postJobEvent(ctx, 'proxy_selected', 'Selected proxy will be applied to the visible browser launch when credentials are available.', {
        proxy_id: ctx.job.proxy_id || ctx.payload.proxy.id || null
      });
    }

    let completedSteps = 0;
    for (const step of steps) {
      await executeStep(ctx, page, step);
      completedSteps += 1;
    }

    await postJobStatus(ctx, 'completed', 'Browser Automator job completed. Browser left open for user review.', {
      steps_completed: completedSteps,
      browser_left_open: true
    });
    emitProgress(ctx, 'completed', `Browser Automator completed ${completedSteps} step(s).`);
    return { ok: true, status: 'completed', steps_completed: completedSteps, browser_left_open: true };
  } catch (error) {
    emitProgress(ctx, 'failed', error.message);
    await postJobStatus(ctx, 'failed', 'Browser Automator job failed. See local app logs for safe details.', {
      error_message: error.message
    }).catch(() => {});
    throw error;
  }
}

async function closeAutomationBrowser() {
  if (automationContext) {
    await automationContext.close().catch(() => {});
    automationContext = null;
  }
  if (automationBrowser) {
    await automationBrowser.close().catch(() => {});
    automationBrowser = null;
  }
  automationPage = null;
  automationProxyKey = '';
  return { ok: true };
}

async function executeStep(ctx, page, step) {
  const type = step.type || step.step_type || 'note';
  const label = step.label || type;
  const config = step.config || {};
  await postJobEvent(ctx, 'step_started', `Started step: ${label}`, { step_type: type, step_order: step.order || step.step_order || null });
  emitProgress(ctx, 'step_started', label);

  if (step.manual_pause || type === 'pause_for_user' || type === 'wait_for_user_continue') {
    await pauseForUser(ctx, page, config.message || label || 'Manual action required.', 'manual_pause');
  } else if (type === 'open_url') {
    await openUrl(ctx, page, config.url);
  } else if (type === 'wait_for_selector') {
    await waitForConfiguredElement(ctx, page, config);
  } else if (type === 'fill_field') {
    await fillConfiguredField(ctx, page, config);
  } else if (type === 'click') {
    await clickConfiguredElement(ctx, page, config);
  } else if (type === 'screenshot') {
    await captureUserApprovedScreenshot(ctx, page, config);
  } else if (type === 'mark_complete') {
    await postJobEvent(ctx, 'mark_complete', config.message || 'Step marked complete.');
  } else if (type === 'fail') {
    throw new Error(config.message || 'Workflow fail step reached.');
  } else if (type === 'note') {
    await postJobEvent(ctx, 'note', config.message || label || 'Automation note.');
  } else {
    throw new Error(`Unsupported Browser Automator step type: ${type}`);
  }

  if (!['pause_for_user', 'wait_for_user_continue', 'screenshot', 'note'].includes(type)) {
    await pauseIfManualCheckDetected(ctx, page);
  }
  await postJobEvent(ctx, 'step_completed', `Completed step: ${label}`, { step_type: type, step_order: step.order || step.step_order || null });
  emitProgress(ctx, 'step_completed', label);
}

async function openUrl(ctx, page, url) {
  const target = safeHttpUrl(url);
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await postJobEvent(ctx, 'open_url', 'Opened URL in visible browser.', { hostname: new URL(target).hostname });
}

async function waitForConfiguredElement(ctx, page, config) {
  const timeout = safeTimeout(config.timeout, 30000);
  const locator = await locatorFromConfig(page, config);
  await locator.waitFor({ state: 'visible', timeout });
  await postJobEvent(ctx, 'wait_for_selector', 'Element is visible.', { matcher: safeMatcherLabel(config) });
}

async function fillConfiguredField(ctx, page, config) {
  const valueRefs = configuredValueRefs(config);
  const valueRefLabel = configuredValueLabel(valueRefs);
  if (valueRefs.some(valueRef => /otp_secret/i.test(valueRef))) {
    throw new Error('Filling raw OTP secrets is not allowed. Use account.otp_code with explicit user confirmation.');
  }
  const value = await resolveStepValue(ctx, config);
  if (value === undefined || value === null || value === '') {
    if (config.optional === true) {
      await postJobEvent(ctx, 'optional_fill_skipped', `Skipped optional field: ${valueRefLabel || 'configured field'} was not available.`, {
        value_ref: valueRefs.length === 1 ? valueRefs[0] : null,
        value_refs: valueRefs.length > 1 ? valueRefs : null
      });
      return;
    }
    throw new Error(`No value available for ${valueRefLabel || 'configured field'}.`);
  }
  const sensitive = valueRefs.some(value => isSensitiveReference(value)) || config.sensitive === true;
  if (sensitive) {
    await confirmSensitiveFill(ctx, valueRefLabel || 'sensitive field');
  }
  let locator;
  try {
    locator = await locatorFromConfig(page, config);
    await locator.waitFor({ state: 'visible', timeout: safeTimeout(config.timeout, config.optional === true ? 5000 : 30000) });
  } catch (error) {
    if (config.optional === true) {
      await postJobEvent(ctx, 'optional_fill_skipped', `Skipped optional field: ${safeMatcherLabel(config)} was not visible.`, {
        matcher: safeMatcherLabel(config)
      });
      return;
    }
    throw error;
  }
  await locator.fill(String(value), { timeout: safeTimeout(config.timeout, 30000) });
  await postJobEvent(ctx, 'fill_field', 'Filled visible field.', {
    value_ref: valueRefs.length === 1 ? valueRefs[0] : null,
    value_refs: valueRefs.length > 1 ? valueRefs : null,
    matcher: safeMatcherLabel(config),
    sensitive
  });
}

async function clickConfiguredElement(ctx, page, config) {
  const locator = await locatorFromConfig(page, config);
  await locator.waitFor({ state: 'visible', timeout: safeTimeout(config.timeout, 30000) });
  const submitLike = await isSubmitLikeClick(locator);
  if (submitLike) {
    await pauseForUser(ctx, page, 'This click appears to submit, sign in, create, verify, or confirm an action. Complete that step manually in the visible browser, then continue.', 'submit_click_blocked');
    await postJobEvent(ctx, 'click_skipped_for_manual_submit', 'Submit-like click was left for manual user action.');
    return;
  }
  await locator.click({ timeout: safeTimeout(config.timeout, 30000) });
  await postJobEvent(ctx, 'click', 'Clicked configured visible element.', { matcher: safeMatcherLabel(config) });
}

async function captureUserApprovedScreenshot(ctx, page, config) {
  if (!ctx.allowScreenshots) {
    await postJobEvent(ctx, 'screenshot_skipped', 'Screenshot step skipped because screenshots are disabled in GS Agent settings.');
    return;
  }
  const choice = await showMessage(ctx.ownerWindow, {
    type: 'warning',
    buttons: ['Capture Browser Screenshot', 'Skip Screenshot'],
    defaultId: 1,
    cancelId: 1,
    message: 'Screenshot requested',
    detail: 'Only continue if the visible browser does not show passwords, OTP codes, private tabs, or other sensitive information.'
  });
  if (choice.response !== 0) {
    await postJobEvent(ctx, 'screenshot_skipped', 'User skipped screenshot capture.');
    return;
  }
  const image = await page.screenshot({ type: 'jpeg', quality: 55, fullPage: false });
  const response = await apiFetch(ctx, '/api/companion/snapshots', {
    method: 'POST',
    body: {
      image_base64: image.toString('base64'),
      mime_type: 'image/jpeg',
      content_type: 'image/jpeg',
      client_instance_id: ctx.job.client_instance_id || null,
      account_id: ctx.job.account_id || null,
      window_title: await page.title().catch(() => config.window_title || 'GS Browser Automator')
    }
  });
  await postJobEvent(ctx, 'screenshot_uploaded', 'User-approved browser screenshot uploaded.', {
    snapshot_id: response.snapshot && response.snapshot.id ? response.snapshot.id : null
  });
}

async function pauseIfManualCheckDetected(ctx, page) {
  const detected = await detectManualCheck(page);
  if (!detected) return;
  await pauseForUser(
    ctx,
    page,
    `Manual verification or security check detected (${detected}). Complete it manually in the visible browser. GS Browser Automator will not solve or bypass it.`,
    'manual_check_detected'
  );
}

async function pauseForUser(ctx, page, message, reason) {
  await postJobStatus(ctx, 'waiting_for_user', message, { reason });
  await postJobEvent(ctx, 'waiting_for_user', message, { reason, url_host: safePageHost(page) });
  emitProgress(ctx, 'waiting_for_user', message);
  const choice = await showMessage(ctx.ownerWindow, {
    type: 'warning',
    buttons: ['Continue After Manual Step', 'Stop Job'],
    defaultId: 0,
    cancelId: 1,
    message: 'Manual action required',
    detail: `${message}\n\nDo not use GS Browser Automator to bypass CAPTCHA, 2FA, email verification, phone verification, or security checks.`
  });
  if (choice.response !== 0) throw new Error('User stopped job during manual pause.');
  await postJobStatus(ctx, 'running', 'User continued after manual step.', { reason });
  await postJobEvent(ctx, 'manual_continue', 'User continued after manual step.', { reason });
  emitProgress(ctx, 'running', 'User continued after manual step.');
}

async function confirmSensitiveFill(ctx, valueRef) {
  const requiresExplicit = /otp/i.test(valueRef) || /password|bank_pin|recovery/i.test(valueRef);
  if (!requiresExplicit) return;
  const choice = await showMessage(ctx.ownerWindow, {
    type: 'question',
    buttons: ['Fill This Field', 'Stop Job'],
    defaultId: 0,
    cancelId: 1,
    message: 'Sensitive field fill requested',
    detail: `The workflow is about to fill ${safeFieldLabel(valueRef)} into the visible browser. The value will not be written to logs.`
  });
  if (choice.response !== 0) throw new Error('User declined sensitive field fill.');
}

async function ensureAutomationPage(ctx) {
  const requiredProxyKey = proxyKeyFromPayload(ctx);
  if (automationBrowser && requiredProxyKey !== automationProxyKey) {
    await closeAutomationBrowser();
  }
  if (!automationBrowser || !automationBrowser.isConnected()) {
    const launched = await launchVisibleBrowser(ctx);
    automationBrowser = launched.browser;
    automationProxyKey = launched.proxyKey || '';
    automationContext = await automationBrowser.newContext({
      viewport: null,
      acceptDownloads: false
    });
    automationPage = await automationContext.newPage();
    automationBrowser.on('disconnected', () => {
      automationBrowser = null;
      automationContext = null;
      automationPage = null;
      automationProxyKey = '';
    });
    await postJobEvent(ctx, 'browser_opened', 'Visible Chromium browser opened.');
  }
  if (!automationPage || automationPage.isClosed()) automationPage = await automationContext.newPage();
  await automationPage.bringToFront().catch(() => {});
  return automationPage;
}

async function launchVisibleBrowser(ctx) {
  const proxyOptions = await proxyLaunchOptions(ctx);
  const launchOptions = {
    headless: false,
    args: ['--start-maximized'],
    ...(proxyOptions ? { proxy: proxyOptions.proxy } : {})
  };
  if (proxyOptions) {
    await postJobEvent(ctx, 'browser_proxy_enabled', 'Visible browser will launch with the selected proxy.', {
      proxy_id: ctx.job.proxy_id || (ctx.payload.proxy && ctx.payload.proxy.id) || null,
      proxy_type: proxyOptions.proxyType
    });
  }
  const attempts = [
    { label: 'Playwright Chromium', options: launchOptions },
    { label: 'Microsoft Edge', options: { ...launchOptions, channel: 'msedge' } },
    { label: 'Google Chrome', options: { ...launchOptions, channel: 'chrome' } }
  ];
  const errors = [];
  for (const attempt of attempts) {
    try {
      const browser = await chromium.launch(attempt.options);
      await postJobEvent(ctx, 'browser_runtime_selected', `Visible browser runtime selected: ${attempt.label}.`, { runtime: attempt.label });
      return { browser, runtime: attempt.label, proxyKey: proxyOptions ? proxyOptions.proxyKey : '' };
    } catch (error) {
      errors.push(`${attempt.label}: ${error.message.split('\n')[0]}`);
    }
  }
  throw new Error(`No usable browser runtime found. Install the Browser Runtime from Downloads or install Microsoft Edge/Chrome. ${errors.join(' | ')}`);
}

async function proxyLaunchOptions(ctx) {
  const proxy = ctx.payload.proxy || {};
  if (!proxy.credentials_url) return null;
  const data = await apiFetch(ctx, proxy.credentials_url, { method: 'GET' });
  const type = String(data.proxy_type || 'HTTP').toLowerCase();
  const scheme = type.includes('socks') ? 'socks5' : 'http';
  const host = String(data.host || '').trim();
  const port = Number(data.port);
  if (!host || !port) throw new Error('Selected proxy is missing host or port.');
  const config = {
    server: `${scheme}://${host}:${port}`
  };
  if (data.username) config.username = String(data.username);
  if (data.password) config.password = String(data.password);
  return {
    proxy: config,
    proxyType: data.proxy_type || 'HTTP',
    proxyKey: `${scheme}:${data.id || ''}:${host}:${port}`
  };
}

function proxyKeyFromPayload(ctx) {
  const proxy = ctx.payload && ctx.payload.proxy;
  if (!proxy) return '';
  return `${proxy.id || ''}:${proxy.endpoint || ''}:${proxy.credentials_url || ''}`;
}

async function locatorFromConfig(page, config = {}) {
  const selector = String(config.selector || '').trim();
  if (selector) return page.locator(selector).first();

  const matcher = String(config.matcher || config.label || config.placeholder || '').trim();
  const terms = matcher.split(',').map(item => item.trim()).filter(Boolean);
  for (const term of terms) {
    const common = commonFieldLocator(page, term);
    if (common && await common.count().catch(() => 0)) return common.first();
    const located = await firstExistingLocator([
      page.getByLabel(term, { exact: false }),
      page.getByPlaceholder(term, { exact: false }),
      page.getByRole('textbox', { name: term, exact: false }),
      page.locator(fieldSelectorForTerm(term))
    ]);
    if (located) return located;
  }

  if (/password/i.test(matcher)) return page.locator('input[type="password"]').first();
  if (/email/i.test(matcher)) return page.locator('input[type="email"], input[name*="email" i], input[id*="email" i]').first();
  throw new Error('Step needs a selector or matcher that resolves to a visible field.');
}

function commonFieldLocator(page, term) {
  if (/password|passcode/i.test(term)) {
    return page.locator('input[type="password"], input[name*="password" i], input[id*="password" i], input[autocomplete*="password" i]');
  }
  if (/email|mail/i.test(term)) {
    return page.locator('input[type="email"], input[name*="email" i], input[id*="email" i], input[autocomplete*="email" i]');
  }
  if (/user|login|account/i.test(term)) {
    return page.locator('input[name*="user" i], input[id*="user" i], input[name*="login" i], input[id*="login" i], input[autocomplete*="username" i], input[type="text"]');
  }
  return null;
}

async function firstExistingLocator(locators) {
  for (const locator of locators) {
    try {
      if (await locator.count()) return locator.first();
    } catch (_) {}
  }
  return null;
}

function fieldSelectorForTerm(term) {
  const safe = cssAttributeValue(term.toLowerCase());
  return [
    `input[name*="${safe}" i]`,
    `input[id*="${safe}" i]`,
    `input[autocomplete*="${safe}" i]`,
    `textarea[name*="${safe}" i]`,
    `textarea[id*="${safe}" i]`
  ].join(', ');
}

async function resolveStepValue(ctx, config) {
  if (config.static_text !== undefined && config.static_text !== null) return String(config.static_text);
  const valueRefs = configuredValueRefs(config);
  if (!valueRefs.length) return '';
  if (!ctx.payload.account || !ctx.payload.account.field_values_url) throw new Error('This job does not include an account field endpoint.');
  for (const valueRef of valueRefs) {
    if (!valueRef.startsWith('account.')) throw new Error(`Unsupported value reference: ${valueRef}`);
    const field = valueRef.replace(/^account\./, '');
    const path = ctx.payload.account.field_values_url.replace(':field', encodeURIComponent(field));
    const data = await apiFetch(ctx, path, { method: 'GET' });
    if (data.value !== undefined && data.value !== null && data.value !== '') return data.value;
  }
  return '';
}

function configuredValueRefs(config = {}) {
  const refs = [];
  if (Array.isArray(config.value_refs)) refs.push(...config.value_refs);
  if (config.value_ref) refs.push(config.value_ref);
  return refs.map(item => String(item || '').trim()).filter(Boolean);
}

function configuredValueLabel(valueRefs) {
  return valueRefs.length > 1 ? valueRefs.join(' or ') : valueRefs[0] || '';
}

async function detectManualCheck(page) {
  try {
    const title = await page.title().catch(() => '');
    const url = page.url();
    const body = await page.locator('body').innerText({ timeout: 1200 }).catch(() => '');
    const text = `${title}\n${url}\n${body.slice(0, 8000)}`;
    const match = manualCheckPatterns.find(([, pattern]) => pattern.test(text));
    return match ? match[0] : null;
  } catch (_) {
    return null;
  }
}

async function isSubmitLikeClick(locator) {
  try {
    const meta = await locator.evaluate(element => ({
      tag: element.tagName,
      type: element.getAttribute('type') || '',
      role: element.getAttribute('role') || '',
      text: element.innerText || element.getAttribute('value') || element.getAttribute('aria-label') || element.getAttribute('name') || ''
    }));
    const combined = `${meta.tag} ${meta.type} ${meta.role} ${meta.text}`.toLowerCase();
    return /submit|sign in|log in|login|create account|register|continue|verify|confirm|authorize|pay|checkout/.test(combined);
  } catch (_) {
    return true;
  }
}

function normalizeRequest(request, emit, ownerWindow) {
  const job = request && request.job ? request.job : {};
  const payload = job.payload || {};
  const baseUrl = normalizeWebsiteUrl(request && request.baseUrl ? request.baseUrl : '');
  const token = String(request && request.token ? request.token : '').trim();
  if (!baseUrl) throw new Error('Website URL is required.');
  if (!token) throw new Error('Device token is required.');
  if (!job.id) throw new Error('A current job is required.');
  return {
    job,
    payload,
    baseUrl,
    token,
    allowScreenshots: Boolean(request && request.allowScreenshots),
    emit,
    ownerWindow
  };
}

function normalizeWebsiteUrl(value) {
  let raw = String(value || '').trim();
  if (!raw) return '';
  if (!/^https?:\/\//i.test(raw)) {
    const local = /^localhost(?::|\/|$)|^127\.|^\[::1\]/i.test(raw);
    raw = `${local ? 'http' : 'https'}://${raw}`;
  }
  try {
    const url = new URL(raw);
    if (url.hostname.toLowerCase() === 'gsaccountmanager.com') {
      url.hostname = 'www.gsaccountmanager.com';
    }
    return url.origin.replace(/\/+$/, '');
  } catch (_) {
    return raw.replace(/\/+$/, '');
  }
}

function normalizeSteps(job) {
  const payload = job.payload || {};
  if (Array.isArray(payload.steps)) return payload.steps;
  if (job.job_type === 'open_browser' && payload.url) {
    return [{ order: 1, type: 'open_url', label: 'Open browser', config: { url: payload.url } }];
  }
  if (job.job_type === 'fill_visible_fields' && Array.isArray(payload.fields)) {
    return payload.fields.map((field, index) => ({
      order: index + 1,
      type: 'fill_field',
      label: field.label || field.value_ref || `Field ${index + 1}`,
      config: field
    }));
  }
  return [];
}

function safeHttpUrl(url) {
  const parsed = new URL(String(url || '').trim());
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http:// and https:// URLs are supported.');
  return parsed.toString();
}

function safeTimeout(value, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return fallback;
  return Math.min(Math.max(number, 1000), 120000);
}

function isSensitiveReference(valueRef) {
  return /password|otp|bank_pin|recovery/i.test(String(valueRef || ''));
}

function safeFieldLabel(valueRef) {
  return String(valueRef || 'sensitive field').replace(/^account\./, 'account.').replace(/_/g, ' ');
}

function safeMatcherLabel(config) {
  if (config.selector) return 'selector';
  if (config.matcher) return String(config.matcher).slice(0, 120);
  return 'configured element';
}

function safePageHost(page) {
  try {
    return new URL(page.url()).hostname;
  } catch (_) {
    return null;
  }
}

function cssAttributeValue(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').slice(0, 80);
}

async function apiFetch(ctx, path, options = {}) {
  const url = path.startsWith('http') ? path : `${ctx.baseUrl}${path}`;
  const headers = {
    Authorization: `Bearer ${ctx.token}`,
    ...(options.body ? { 'Content-Type': 'application/json' } : {})
  };
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  let data = {};
  try { data = await response.json(); } catch (_) {}
  if (!response.ok) throw new Error(data.error || `Request failed with ${response.status}`);
  return data;
}

async function postJobStatus(ctx, status, message, result = {}) {
  return apiFetch(ctx, `/api/companion/jobs/${ctx.job.id}/status`, {
    method: 'POST',
    body: {
      status,
      message,
      result: safeAutomationResult(result),
      metadata: safeAutomationResult(result)
    }
  });
}

async function postJobEvent(ctx, eventType, message, metadata = {}) {
  return apiFetch(ctx, `/api/companion/jobs/${ctx.job.id}/events`, {
    method: 'POST',
    body: {
      event_type: eventType,
      message,
      metadata: safeAutomationResult(metadata)
    }
  }).catch(() => null);
}

function safeAutomationResult(value) {
  if (Array.isArray(value)) return value.map(item => safeAutomationResult(item));
  if (!value || typeof value !== 'object') return value;
  const clean = {};
  for (const [key, item] of Object.entries(value)) {
    clean[key] = /password|secret|token|cookie|session|otp|value/i.test(key) ? '[redacted]' : safeAutomationResult(item);
  }
  return clean;
}

function emitProgress(ctx, type, message) {
  ctx.emit({
    type,
    job_id: ctx.job.id,
    message,
    at: new Date().toISOString()
  });
}

function showMessage(ownerWindow, options) {
  return ownerWindow ? dialog.showMessageBox(ownerWindow, options) : dialog.showMessageBox(options);
}

module.exports = {
  runBrowserAutomationJob,
  closeAutomationBrowser,
  browserJobTypes
};
