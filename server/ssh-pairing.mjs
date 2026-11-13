// Short-lived SSH onboarding mailboxes. Tokens authorize transport only.
// Clients authenticate messages with a secret NEVER sent to this service.
import { createHash, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';

const token = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{22}$/.test(value);
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = (status, code) => { throw Object.assign(new Error(code), { status, code }); };
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export function createSshPairingTable(relay) {
  relay.db.exec(`CREATE TABLE IF NOT EXISTS ssh_pair_sessions (
    id TEXT PRIMARY KEY, host_hash TEXT NOT NULL, phone_hash TEXT NOT NULL,
    mode TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
    hello TEXT, key_request TEXT, receipt TEXT, acknowledgement TEXT);
    CREATE INDEX IF NOT EXISTS ssh_pair_expiry ON ssh_pair_sessions(expires);`);
}

export function handleSshPairing(relay, method, path, auth, body) {
  if (!path.startsWith('/v1/ssh-pair/')) return undefined;
  if (!body || typeof body !== 'object' || Array.isArray(body) || !validId(body.id)) fail(400, 'invalid_ssh_pair');
  const now = relay.now();
  relay.run('DELETE FROM ssh_pair_sessions WHERE expires <= ?', now);
  if (path === '/v1/ssh-pair/create' && method === 'POST') {
    if (Object.keys(body).some(k => !['id', 'hostHash', 'phoneHash', 'mode'].includes(k)) || !['qr', 'command'].includes(body.mode) ||
        !/^[a-f0-9]{64}$/.test(body.hostHash ?? '') || !/^[a-f0-9]{64}$/.test(body.phoneHash ?? '') || body.hostHash === body.phoneHash) fail(400, 'invalid_ssh_pair');
    const existing = relay.get('SELECT * FROM ssh_pair_sessions WHERE id=?', body.id);
    if (existing) {
      if (!equal(existing.host_hash, body.hostHash) || !equal(existing.phone_hash, body.phoneHash) || existing.mode !== body.mode) fail(409, 'ssh_pair_exists');
      return { schema: 1, id: body.id, expires: existing.expires };
    }
    if (relay.get('SELECT count(*) n FROM ssh_pair_sessions').n >= 200 || relay.get('SELECT count(*) n FROM ssh_pair_sessions WHERE created>?', now - 60000).n >= 20) fail(429, 'ssh_pair_capacity');
    const expires = now + 300000;
    relay.run(`INSERT INTO ssh_pair_sessions
      (id,host_hash,phone_hash,mode,created,expires,hello,key_request,receipt,acknowledgement)
      VALUES (?,?,?,?,?,?,NULL,NULL,NULL,NULL)`, body.id, body.hostHash, body.phoneHash, body.mode, now, expires);
    return { schema: 1, id: body.id, expires };
  }
  const role = path === '/v1/ssh-pair/host' ? 'host' : path === '/v1/ssh-pair/phone' ? 'phone' : null;
  if (!role || method !== 'POST' || !token(auth) || Object.keys(body).some(k => !['id', 'kind', 'message'].includes(k))) fail(400, 'invalid_ssh_pair');
  const session = relay.get('SELECT * FROM ssh_pair_sessions WHERE id=? AND expires>?', body.id, now);
  if (!session || !equal(session[`${role}_hash`], digest(auth))) fail(401, 'invalid_ssh_pair');
  if (body.kind !== undefined || body.message !== undefined) {
    const kinds = role === 'host' ? { hello: 'hello', receipt: 'receipt' } : { key: 'key_request', acknowledgement: 'acknowledgement' };
    const column = typeof body.kind === 'string' && Object.hasOwn(kinds, body.kind) ? kinds[body.kind] : null;
    const message = body.message;
    if (!column || !message || typeof message !== 'object' || Array.isArray(message) || Object.keys(message).some(k => !['payload', 'mac', 'proof'].includes(k)) ||
        typeof message.payload !== 'string' || !/^[A-Za-z0-9_-]{1,1400}$/.test(message.payload) || !token(message.mac) ||
        (message.proof !== undefined && !/^[A-Za-z0-9_-]{86}$/.test(message.proof))) fail(400, 'invalid_ssh_pair_message');
    const encoded = JSON.stringify({ payload: message.payload, mac: message.mac, ...(message.proof === undefined ? {} : { proof: message.proof }) });
    if (session[column] !== null && session[column] !== encoded) fail(409, 'ssh_pair_candidate_locked');
    if (session[column] === null) relay.run(`UPDATE ssh_pair_sessions SET ${column}=? WHERE id=? AND ${column} IS NULL`, encoded, body.id);
  }
  const fresh = relay.get('SELECT * FROM ssh_pair_sessions WHERE id=?', body.id);
  return { schema: 1, id: body.id, mode: fresh.mode, expires: fresh.expires,
    hello: fresh.hello ? JSON.parse(fresh.hello) : null,
    key: fresh.key_request ? JSON.parse(fresh.key_request) : null,
    receipt: fresh.receipt ? JSON.parse(fresh.receipt) : null,
    acknowledgement: fresh.acknowledgement ? JSON.parse(fresh.acknowledgement) : null };
}
