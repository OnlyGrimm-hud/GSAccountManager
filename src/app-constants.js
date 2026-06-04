const accountTypes = ['legacy', 'jagex', 'email_only', 'other', 'unknown'];
const accountStatuses = [
  'available', 'pending', 'in_progress', 'completed', 'upgraded', 'skipped', 'blocked',
  'needs_review', 'exported', 'archived', 'banned_temp', 'banned_perm', 'locked', 'invalid', 'unknown'
];
const credentialStatuses = ['missing', 'partial', 'ready', 'needs_review'];
const workflowStatuses = ['pending', 'in_progress', 'complete', 'skipped', 'blocked', 'needs_review'];
const proxyTypes = ['HTTP', 'SOCKS5'];
const proxyStatuses = ['unchecked', 'working', 'failed', 'banned', 'unknown', 'untested', 'online', 'works', 'blocked', 'review'];
const userRoles = ['user', 'staff', 'admin'];
const subscriptionStatuses = ['inactive', 'active', 'trial', 'expired', 'banned'];
const activeSubscriptionStatuses = ['active', 'trial'];
const exportFormats = [
  'legacy_user_pass', 'legacy_user_pass_pin', 'legacy_user_pass_pin_otp',
  'legacy_user_pass_otp', 'jagex_email_pass', 'login_email_pass_proxy',
  'jagex_email_pass_otp', 'full_account_export', 'safe_csv',
  'username_password', 'username_password_otp', 'username_password_bank_pin_otp',
  'username_password_bank_pin', 'username_password_recovery',
  'email_password', 'email_password_recovery', 'jagex_email_password',
  'legacy_to_jagex', 'full', 'custom'
];
const workflowModes = ['manual'];
const workflowTypes = ['login_fill', 'email_upgrade', 'account_creation_fill', 'generic_form_fill', 'custom'];
const workflowDefinitionStatuses = ['draft', 'active', 'archived'];
const workflowRunStatuses = ['queued', 'running', 'paused', 'waiting_for_user', 'completed', 'failed', 'cancelled'];
const workflowStepTypes = [
  'open_url', 'wait_for_selector', 'fill_field', 'click', 'pause_for_user',
  'wait_for_user_continue', 'mark_complete', 'fail', 'screenshot', 'note'
];
const companionJobStatuses = ['queued', 'accepted', 'running', 'paused', 'waiting_for_user', 'completed', 'failed', 'cancelled'];
const companionJobTypes = [
  'workflow_run', 'run_workflow', 'launch_client', 'stop_client', 'detect_clients', 'request_snapshot',
  'open_browser', 'fill_visible_fields', 'pause_workflow', 'resume_workflow', 'cancel_workflow'
];
const clientTypes = ['runelite', 'jagex_launcher', 'official_client', 'dreambot', 'custom'];
const clientInstanceStatuses = ['pending', 'detected', 'launching', 'running', 'scanning', 'stopped', 'crashed', 'unknown'];
const clientStates = ['active', 'idle', 'offline', 'unknown', 'error'];
const wealthSources = ['manual', 'companion_reported', 'client_reported', 'unknown'];
const paymentMethods = ['LTC', 'BTC', 'ETH', 'manual_admin_activation'];
const downloadStatuses = ['coming_soon', 'available', 'hidden'];
const downloadCategories = ['local_app', 'browser_runtime', 'client_tool', 'guide'];

module.exports = {
  accountTypes,
  accountStatuses,
  credentialStatuses,
  workflowStatuses,
  proxyTypes,
  proxyStatuses,
  userRoles,
  subscriptionStatuses,
  activeSubscriptionStatuses,
  exportFormats,
  workflowModes,
  workflowTypes,
  workflowDefinitionStatuses,
  workflowRunStatuses,
  workflowStepTypes,
  companionJobStatuses,
  companionJobTypes,
  clientTypes,
  clientInstanceStatuses,
  clientStates,
  wealthSources,
  paymentMethods,
  downloadStatuses,
  downloadCategories
};
