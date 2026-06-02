function parseAccountImport(text, delimiter = ':', options = {}) {
  if (typeof delimiter === 'object') {
    options = delimiter;
    delimiter = options.delimiter || ':';
  }
  const accountType = String(options.account_type || options.accountType || 'legacy').toLowerCase();
  return String(text || '').split(/\r?\n/).map((line, index) => {
    const raw = line.trim();
    const parts = raw ? raw.split(delimiter).map(part => part.trim()) : [];
    const row = {
      line: index + 1,
      raw: line,
      username: parts[0] || '',
      password: parts[1] || '',
      bank_pin: '',
      otp_secret: '',
      recovery_email: '',
      recovery_email_password: '',
      notes: '',
      extra_fields: [],
      valid: false,
      error: ''
    };

    if (!raw) return null;
    if (parts.length < 2) {
      row.error = 'Expected at least username/email and password';
      return row;
    }

    const extras = parts.slice(2);
    if (accountType === 'jagex') {
      row.recovery_email = extras[0] || '';
      row.recovery_email_password = extras[1] || '';
      row.otp_secret = extras[2] || '';
      row.notes = extras.slice(3).filter(Boolean).join(' ');
      row.extra_fields = extras.slice(3);
    } else {
      if (extras.length === 1) {
        row.otp_secret = extras[0] || '';
      }
      if (extras.length >= 2) {
        const thirdLooksLikePin = /^\d{3,8}$/.test(extras[0] || '');
        if (thirdLooksLikePin) {
          row.bank_pin = extras[0] || '';
          row.otp_secret = extras[1] || '';
          row.notes = extras.slice(2).filter(Boolean).join(' ');
          row.extra_fields = extras.slice(2);
        } else {
          row.otp_secret = extras[0] || '';
          row.notes = extras.slice(1).filter(Boolean).join(' ');
          row.extra_fields = extras.slice(1);
        }
      }
    }

    row.valid = Boolean(row.username && row.password);
    if (!row.valid) row.error = 'Username and password are required';
    return row;
  }).filter(Boolean);
}

function parseProxyLine(line, delimiter = ':', defaults = {}) {
  const raw = String(line || '').trim();
  if (!raw) return null;
  const result = {
    raw,
    proxy_type: defaults.proxy_type || defaults.proxyType || 'HTTP',
    host: '',
    port: '',
    username: '',
    password: '',
    category: defaults.category || '',
    valid: false,
    error: ''
  };

  try {
    if (/^https?:\/\//i.test(raw)) {
      const url = new URL(raw);
      result.proxy_type = 'HTTP';
      result.host = url.hostname;
      result.port = url.port;
      result.username = decodeURIComponent(url.username || '');
      result.password = decodeURIComponent(url.password || '');
    } else {
      const parts = raw.split(delimiter);
      if (parts.length === 2 || parts.length === 4) {
        [result.host, result.port, result.username = '', result.password = ''] = parts;
      } else {
        result.error = 'Expected host:port or host:port:user:pass';
      }
    }
  } catch (error) {
    result.error = 'Invalid proxy URL';
  }

  result.valid = Boolean(result.host && Number(result.port) > 0 && Number(result.port) < 65536);
  if (!result.valid && !result.error) result.error = 'Host and valid port are required';
  return result;
}

function parseProxyImport(text, delimiter = ':', defaults = {}) {
  if (typeof delimiter === 'object') {
    defaults = delimiter;
    delimiter = defaults.delimiter || ':';
  }
  return String(text || '').split(/\r?\n/).map(line => parseProxyLine(line, delimiter, defaults)).filter(Boolean);
}

module.exports = { parseAccountImport, parseProxyLine, parseProxyImport };
