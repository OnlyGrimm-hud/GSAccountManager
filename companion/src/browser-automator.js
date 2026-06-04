const { dialog } = require('electron');
const { chromium } = require('playwright');

let automationBrowser = null;
let automationContext = null;
let automationPage = null;

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
      await postJobEvent(ctx, 'proxy_notice', 'Proxy details are shown on the website. Local browser proxy launch is not enabled in this build.', {
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
  const locator = await locatorFromConfig(page, config);
  const valueRef = String(config.value_ref || '').trim();
  if (/otp_secret/i.test(valueRef)) {
    throw new Error('Filling raw OTP secrets is not allowed. Use account.otp_code with explicit user confirmation.');
  }
  const value = await resolveStepValue(ctx, config);
  if (value === undefined || value === null || value === '') {
    throw new Error(`No value available for ${valueRef || 'configured field'}.`);
  }
  if (isSensitiveReference(valueRef) || config.sensitive === true) {
    await confirmSensitiveFill(ctx, valueRef || 'sensitive field');
  }
  await locator.waitFor({ state: 'visible', timeout: safeTimeout(config.timeout, 30000) });
  await locator.fill(String(value), { timeout: safeTimeout(config.timeout, 30000) });
  await postJobEvent(ctx, 'fill_field', 'Filled visible field.', {
    value_ref: valueRef || null,
    matcher: safeMatcherLabel(config),
    sensitive: isSensitiveReference(valueRef) || config.sensitive === true
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
    await postJobEvent(ctx, 'screenshot_skipped', 'Screenshot step skipped because screenshots are disabled in Local App settings.');
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
      window_title: await page.title().catch(() => config.window_title || 'Automation Browser')
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
    `Manual verification or security check detected (${detected}). Complete it manually in the visible browser. The Local App will not solve or bypass it.`,
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
    detail: `${message}\n\nDo not use GS Local App to bypass CAPTCHA, 2FA, email verification, phone verification, or security checks.`
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
  if (!automationBrowser || !automationBrowser.isConnected()) {
    const launched = await launchVisibleBrowser(ctx);
    automationBrowser = launched.browser;
    automationContext = await automationBrowser.newContext({
      viewport: null,
      acceptDownloads: false
    });
    automationPage = await automationContext.newPage();
    automationBrowser.on('disconnected', () => {
      automationBrowser = null;
      automationContext = null;
      automationPage = null;
    });
    await postJobEvent(ctx, 'browser_opened', 'Visible Chromium browser opened.');
  }
  if (!automationPage || automationPage.isClosed()) automationPage = await automationContext.newPage();
  await automationPage.bringToFront().catch(() => {});
  return automationPage;
}

async function launchVisibleBrowser(ctx) {
  const launchOptions = {
    headless: false,
    args: ['--start-maximized']
  };
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
      return { browser, runtime: attempt.label };
    } catch (error) {
      errors.push(`${attempt.label}: ${error.message.split('\n')[0]}`);
    }
  }
  throw new Error(`No usable browser runtime found. Install the Browser Runtime from Downloads or install Microsoft Edge/Chrome. ${errors.join(' | ')}`);
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
  const valueRef = String(config.value_ref || '').trim();
  if (!valueRef) return '';
  if (!valueRef.startsWith('account.')) throw new Error(`Unsupported value reference: ${valueRef}`);
  if (!ctx.payload.account || !ctx.payload.account.field_values_url) throw new Error('This job does not include an account field endpoint.');
  const field = valueRef.replace(/^account\./, '');
  const path = ctx.payload.account.field_values_url.replace(':field', encodeURIComponent(field));
  const data = await apiFetch(ctx, path, { method: 'GET' });
  return data.value || '';
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
  const baseUrl = String(request && request.baseUrl ? request.baseUrl : '').replace(/\/+$/, '');
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
