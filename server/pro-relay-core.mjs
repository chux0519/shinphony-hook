// Staged, fail-closed relay. Runtime rollout requires Apple credentials + roots,
// coordinated app protocol/body limits, backup and migration acceptance.
import { createHash, randomBytes } from 'node:crypto';
import { activityTicket } from './live-activity.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const secret = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const deny = (code, status = 403) => { throw Object.assign(new Error(code), { code, status }); };
// Free tier (2026-11 pricing): devices without a purchase proof get agent
// push + Live Activity at 10 events per minute; Pro keeps the base 60.
export const FREE_EVENTS_PER_MINUTE = 10;
const isFree = binding => binding?.tier === 'free';

// Pro / free-tier authorization over any relay base (Node or Worker).
export const withPro = Base => class ProRelay extends Base {
  constructor({ verification, purchaseEnvironment, publicRegistration = false, allowReviewSandbox = false, freeTier = false, ...options }) {
    if (!verification) throw new Error('Apple verification required');
    const expected = purchaseEnvironment ?? ({ sandbox: 'Sandbox', production: 'Production' }[options.environment ?? 'sandbox']);
    if (!['Sandbox', 'Production'].includes(expected)) throw new Error('Invalid purchase environment');
    super(options);
    this.purchaseEnvironment = expected;
    if (allowReviewSandbox && (expected !== 'Production' || options.environment !== 'production')) {
      throw new Error('Review sandbox requires explicit production APNs and purchase policy');
    }
    this.publicRegistration = publicRegistration;
    this.freeTier = freeTier;
    this.allowReviewSandbox = allowReviewSandbox;
    this.verification = verification;
    this.verificationWindow = -1;
    this.verificationCount = 0;
    this.db.exec(`CREATE TABLE IF NOT EXISTS entitlements (
      device TEXT PRIMARY KEY, binding TEXT NOT NULL);`);
    this.run('DELETE FROM entitlements WHERE device NOT IN (SELECT id FROM devices)');
    const deliver = this.deliver;
    this.deliver = async input => {
      await this.authorize(input.device.id);
      // Device deletion, revocation, token rotation can overtake Apple I/O.
      const current = this.get(`SELECT d.token FROM devices d JOIN hosts h ON h.device=d.id
        WHERE d.id=? AND d.active=1 AND h.key=? AND h.active=1`, input.device.id, input.event.host_key);
      if (!current || current.token !== input.device.token) return { retryable: true };
      return deliver(input);
    };
  }
  accepts(environment) {
    return environment === this.purchaseEnvironment || (this.allowReviewSandbox && environment === 'Sandbox');
  }
  budget() {
    const window = Math.floor(this.now() / 60000);
    if (window !== this.verificationWindow) { this.verificationWindow = window; this.verificationCount = 0; }
    if (++this.verificationCount > 60) deny('verification_rate_limit', 429);
  }
  async authorize(deviceId) {
    const saved = this.get('SELECT binding FROM entitlements WHERE device=?', deviceId);
    if (!saved) deny('pro_required');
    const parsed = JSON.parse(saved.binding);
    if (isFree(parsed)) {
      if (!this.freeTier) deny('pro_required');
      return parsed;
    }
    this.budget();
    let binding;
    try {
      const stored = parsed;
      if (!this.accepts(stored.environment)) deny('pro_required');
      binding = await this.verification.revalidate(stored);
      if (!this.accepts(binding.environment) || binding.environment !== stored.environment) deny('pro_required');
    }
    catch (error) {
      if (error.code === 'pro_required' && this.freeTier) {
        // Refund / lapsed proof: fall back to the free tier, keep the device.
        const free = { tier: 'free', environment: this.purchaseEnvironment };
        this.run('UPDATE entitlements SET binding=? WHERE device=?', JSON.stringify(free), deviceId);
        return free;
      }
      if (error.code === 'pro_required') {
        this.run('UPDATE devices SET active=0 WHERE id=?', deviceId);
        this.run("UPDATE events SET state='revoked' WHERE device=? AND state='queued'", deviceId);
        this.run('DELETE FROM pairs WHERE device=?', deviceId);
        this.run('DELETE FROM live_activities WHERE device=?', deviceId);
      }
      throw error;
    }
    const current = this.get('SELECT binding FROM entitlements WHERE device=?', deviceId);
    if (!current || current.binding !== saved.binding || !this.get('SELECT id FROM devices WHERE id=? AND active=1', deviceId)) {
      deny('authorization_changed', 409);
    }
    return binding;
  }
  async handle(method, path, auth, body = {}) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) deny('invalid_fields', 400);
    if ((method === 'POST' && path === '/v1/register') || (method === 'PUT' && path === '/v1/device')) {
      const { purchaseProof, ...request } = body;
      const allowed = method === 'POST' ? ['ownerToken', 'invite', 'deviceToken'] : ['deviceToken'];
      if (Object.keys(request).some(key => !allowed.includes(key)) ||
          typeof request.deviceToken !== 'string' || !/^[a-f0-9]{64,512}$/i.test(request.deviceToken) || request.deviceToken.length % 2) {
        deny('invalid_registration', 400);
      }
      // Authenticate the invitation/owner BEFORE spending Apple/network work.
      if (method === 'POST') {
        if (!secret(request.ownerToken) || (!this.publicRegistration && !secret(request.invite))) deny('invalid_registration', 400);
        const existing = this.get('SELECT id FROM devices WHERE owner=?', hash(request.ownerToken));
        if (!this.publicRegistration && !existing && !this.get('SELECT key FROM invites WHERE key=? AND expires>?', hash(request.invite), this.now())) {
          deny('invalid_invite', 401);
        }
      } else { this.owner(auth); }
      let binding;
      if (this.freeTier && (purchaseProof === undefined || purchaseProof === null || purchaseProof === '')) {
        binding = { tier: 'free', environment: this.purchaseEnvironment };
      } else {
        this.budget();
        binding = await this.verification.verify(purchaseProof);
        if (!this.accepts(binding.environment)) {
          deny('pro_required');
        }
      }
      // Do not allow an existing device identity to switch purchase environment.
      const existingDevice = method === 'POST'
        ? this.get('SELECT id FROM devices WHERE owner=?', hash(request.ownerToken)) : this.owner(auth);
      const old = existingDevice && this.get('SELECT binding FROM entitlements WHERE device=?', existingDevice.id);
      if (old && JSON.parse(old.binding).environment !== binding.environment) deny('environment_mismatch', 409);
      if (method === 'POST' && this.publicRegistration && !existingDevice) {
        // Fixed upper bounds, rechecked after Apple I/O. Do not let one replayed
        // proof fill the entire service. These are relay safety limits, not a
        // desktop license policy. Cleanup is always available.
        if (this.get('SELECT count(*) n FROM devices').n >= 1000) deny('capacity', 503);
        const matching = isFree(binding) ? 0 : this.get(`SELECT count(*) n FROM entitlements
          WHERE json_extract(binding, '$.originalTransactionId')=?
          AND json_extract(binding, '$.environment')=?`, binding.originalTransactionId, binding.environment).n;
        if (matching >= 10) deny('device_limit', 429);
        if (binding.environment === 'Sandbox' && this.allowReviewSandbox &&
            this.get("SELECT count(*) n FROM entitlements WHERE json_extract(binding, '$.environment')='Sandbox'").n >= 100) deny('capacity', 503);
        const id = randomBytes(32).toString('base64url');
        this.db.transaction(() => {
          this.run('INSERT INTO devices (id, owner, token, active, environment) VALUES (?, ?, ?, 1, ?)', id, hash(request.ownerToken), request.deviceToken, this.environment);
          this.run('INSERT INTO entitlements VALUES (?,?)', id, JSON.stringify(binding));
        });
        return { ownerToken: request.ownerToken, environment: this.environment };
      }
      // An idempotent public registration still uses the base conflict checks;
      // its existing owner is sufficient and no invitation is consumed.
      if (method === 'POST' && this.publicRegistration) request.invite = 'x'.repeat(43);
      // No await between mutation and binding. Crash/write failure leaves an
      // unbound device (fail closed), recoverable by authenticated PUT + proof.
      const result = super.handle(method, path, auth, request);
      const device = this.owner(method === 'POST' ? result.ownerToken : auth);
      this.run('INSERT INTO entitlements VALUES (?,?) ON CONFLICT(device) DO UPDATE SET binding=excluded.binding', device.id, JSON.stringify(binding));
      return result;
    }
    if (path === '/v1/device' && method === 'DELETE') {
      const device = this.owner(auth);
      const result = super.handle(method, path, auth, body);
      this.run('DELETE FROM entitlements WHERE device=?', device.id);
      return result;
    }
    // Cleanup is never gated on Pro or Apple availability.
    if (path === '/v1/live-activity' && method === 'POST') {
      await this.authorize(this.owner(auth).id);
    } else if (path === '/v1/live-activity/auto' && method === 'PUT' && (body.enabled === true || body.startToken !== undefined)) {
      // Turning auto-start off stays available without Pro.
      await this.authorize(this.owner(auth).id);
    } else if (path === '/v1/live-activity/token' && method === 'PUT') {
      await this.authorize(activityTicket(this, auth).device);
      // handleActivity revalidates the scoped ticket after the Apple await.
    }
    if (path === '/v1/hosts/revoke' && method === 'POST') return super.handle(method, path, auth, body);
    if (path === '/v1/pair' && method === 'POST') {
      await this.authorize(this.owner(auth).id);
    } else if (path === '/v1/pair/exchange' && method === 'POST') {
      if (!secret(body.pairingCode)) deny('invalid_pair', 400);
      const pair = this.get('SELECT device FROM pairs WHERE code=? AND expires>?', hash(body.pairingCode), this.now());
      if (!pair) deny('invalid_pair', 401);
      await this.authorize(pair.device);
    } else if (path === '/v1/events' && method === 'POST') {
      if (!secret(auth)) deny('unauthorized', 401);
      const host = this.get('SELECT device FROM hosts WHERE key=? AND active=1', hash(auth));
      if (!host) deny('unauthorized', 401);
      // Queue acceptance is not delivery authorization. Keep the host hook fast;
      // dispatch ALWAYS queries Apple before APNs and fails closed on refund.
      const entitlement = this.get('SELECT binding FROM entitlements WHERE device=?', host.device);
      if (!entitlement) deny('pro_required');
      if (isFree(JSON.parse(entitlement.binding))) {
        if (!this.freeTier) deny('pro_required');
        const recent = this.get('SELECT count(*) n FROM events WHERE device=? AND created>?', host.device, this.now() - 60000).n;
        if (recent >= FREE_EVENTS_PER_MINUTE) deny('rate_limit', 429);
      }
    }
    return super.handle(method, path, auth, body);
  }
};
