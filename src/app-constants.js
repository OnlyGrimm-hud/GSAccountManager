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
  'jagex_email_pass_otp', 'full_account_export', 'safe_csv'
];
const workflowModes = ['manual'];
const paymentMethods = ['LTC', 'BTC', 'ETH', 'manual_admin_activation'];

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
  paymentMethods
};
