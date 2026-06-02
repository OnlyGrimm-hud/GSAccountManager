function parseAccountImport(text, delimiter = ':') {
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
      notes: '',
      valid: false,
      error: ''
    };

    if (!raw) return null;
    if (parts.length < 2 || parts.length > 4) {
      row.error = 'Expected 2 to 4 fields';
      return row;
    }

    if (parts.length === 3) {
      row.otp_secret = parts[2] || '';
    }

    if (parts.length === 4) {
      const thirdLooksLikePin = /^\d{3,8}$/.test(parts[2] || '');
      if (thirdLooksLikePin) {
        row.bank_pin = parts[2] || '';
        row.otp_secret = parts[3] || '';
      } else {
        row.otp_secret = parts[2] || '';
        row.notes = parts[3] || '';
      }
    }

    row.valid = Boolean(row.username && row.password);
    if (!row.valid) row.error = 'Username and password are required';
    return row;
  }).filter(Boolean);
}

function parseProxyLine(line) {
  const raw = String(line || '').trim();
  if (!raw) return null;
  const result = {
    raw,
    proxy_type: 'HTTP',
    host: '',
    port: '',
    username: '',
    password: '',
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
      const parts = raw.split(':');
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

function parseProxyImport(text) {
  return String(text || '').split(/\r?\n/).map(parseProxyLine).filter(Boolean);
}

module.exports = { parseAccountImport, parseProxyLine, parseProxyImport };
