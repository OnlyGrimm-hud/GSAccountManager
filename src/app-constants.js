const accountTypes = ['legacy', 'jagex', 'unknown'];
const accountStatuses = ['pending', 'in_progress', 'upgraded', 'skipped', 'blocked', 'needs_review', 'exported', 'archived'];
const credentialStatuses = ['missing', 'partial', 'ready', 'needs_review'];
const workflowStatuses = ['pending', 'in_progress', 'complete', 'skipped', 'blocked', 'needs_review'];
const proxyTypes = ['HTTP', 'SOCKS5'];
const proxyStatuses = ['untested', 'online', 'works', 'blocked', 'review'];

module.exports = {
  accountTypes,
  accountStatuses,
  credentialStatuses,
  workflowStatuses,
  proxyTypes,
  proxyStatuses
};
