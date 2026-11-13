// APNs from a Worker: WebCrypto ES256 provider token + fetch. A deployed
// Worker's subrequests negotiate HTTP/2 with APNs (local workerd cannot).
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const text64 = value => b64url(new TextEncoder().encode(JSON.stringify(value)));

export async function webProviderToken({ keyId, teamId, privateKey, now = Date.now() }) {
  if (!/^[A-Z0-9]{10}$/.test(keyId ?? '') || !/^[A-Z0-9]{10}$/.test(teamId ?? '')) {
    throw new Error('Invalid APNs key/team identifier');
  }
  const pem = String(privateKey).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const message = `${text64({ alg: 'ES256', kid: keyId })}.${text64({ iss: teamId, iat: Math.floor(now / 1000) })}`;
  // WebCrypto ECDSA already returns IEEE P1363 (r||s), as JWS requires.
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(message));
  return `${message}.${b64url(signature)}`;
}

const origins = ['https://api.sandbox.push.apple.com', 'https://api.push.apple.com'];

export async function fetchSend(request, { fetchFn = fetch, timeoutMs = 10000 } = {}) {
  if (!origins.includes(request.origin)) throw new Error('Non-APNs destination refused');
  const headers = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (!name.startsWith(':')) headers[name] = value; // HTTP/2 pseudo-headers
  }
  const response = await fetchFn(request.origin + request.headers[':path'], {
    method: request.headers[':method'] ?? 'POST', headers, body: request.body,
    // Workers only accept 'follow' | 'manual'; APNs never redirects, so a 3xx is refused.
    redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
  });
  if (response.status >= 300 && response.status < 400) throw new Error('Unexpected APNs redirect');
  const raw = (await response.text()).slice(0, 4096);
  let reason;
  try { reason = JSON.parse(raw).reason; } catch { /* empty success body */ }
  const status = response.status;
  return {
    accepted: status === 200, status,
    reason: typeof reason === 'string' && /^[A-Za-z]{1,80}$/.test(reason) ? reason : undefined,
    invalidateDevice: status === 410,
    retryable: status === 429 || status >= 500,
  };
}
