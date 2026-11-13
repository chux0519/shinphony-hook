// Relay logic shared by the Node server (relay.mjs) and the Cloudflare Worker
// (worker/). No filesystem, HTTP server or SQLite driver here.
import { createHash, randomBytes } from 'node:crypto';
import { createSshPairingTable, handleSshPairing } from './ssh-pairing.mjs';
import { notificationRequest, providerToken } from './apns-core.mjs';
import { taskContext } from './task-context.mjs';
import { agentDetails, detailFields } from './agent-event.mjs';
import { createActivityTable, handleActivity, liveActivityRequest, startActivityRequest, maybeAutoStart, recordSession, aggregate, RUNNING_TTL } from './live-activity.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('base64url');
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const validToken = value => typeof value === 'string' && /^[a-f0-9]{64,512}$/i.test(value) && value.length % 2 === 0;
const fail = (status, code) => { throw Object.assign(new Error(code), { status, code }); };
function fields(body, names) {
  if (!body || typeof body !== 'object' || Array.isArray(body) ||
      Object.keys(body).some(key => !names.includes(key))) fail(400, 'invalid_fields');
}

export class Relay {
  // `db`: { exec(sql), prepare(sql) -> { get, all, run }, transaction(fn), close() }.
  // Node uses node:sqlite (relay.mjs); the Cloudflare Worker uses a Durable
  // Object's SQLite (worker/). Schema and logic are shared.
  constructor({ db, now = Date.now, deliver, environment = 'sandbox' }) {
    if (!['sandbox', 'production'].includes(environment)) throw new Error('Invalid environment');
    if (!db) throw new Error('Database adapter required');
    this.now = now;
    this.deliver = deliver;
    this.environment = environment;
    this.db = db;
    this.db.exec(`CREATE TABLE IF NOT EXISTS invites (key TEXT PRIMARY KEY, expires INTEGER);
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY, owner TEXT UNIQUE, token TEXT, active INTEGER, environment TEXT);
      CREATE TABLE IF NOT EXISTS pairs (
        code TEXT PRIMARY KEY, device TEXT, host TEXT, expires INTEGER);
      CREATE TABLE IF NOT EXISTS hosts (
        key TEXT PRIMARY KEY, device TEXT, host TEXT, active INTEGER,
        UNIQUE(device, host));
      CREATE TABLE IF NOT EXISTS events (
        host_key TEXT, event_id TEXT, device TEXT, host TEXT, status TEXT,
        created INTEGER, expires INTEGER, due INTEGER, attempts INTEGER,
        state TEXT, PRIMARY KEY(host_key, event_id));
      CREATE INDEX IF NOT EXISTS events_due ON events(state, due);
      CREATE INDEX IF NOT EXISTS events_device_time ON events(device, created);
      CREATE INDEX IF NOT EXISTS events_created ON events(created);
      CREATE INDEX IF NOT EXISTS events_host_time ON events(host_key, created);`);
    const columns = this.db.columns('events');
    for (const [name, type] of [['apns_status', 'INTEGER'], ['apns_reason', 'TEXT'], ['context_json', 'TEXT'], ['details_json', 'TEXT'], ['live_only', 'INTEGER'], ['start_json', 'TEXT']]) {
      if (!columns.includes(name)) this.db.exec(`ALTER TABLE events ADD COLUMN ${name} ${type}`);
    }
    this.lastClean = -Infinity;
    createActivityTable(this);
    createSshPairingTable(this);
  }
  close() { this.db.close(); }
  get(sql, ...args) { return this.db.prepare(sql).get(...args); }
  run(sql, ...args) { return this.db.prepare(sql).run(...args); }
  clean(force = false) {
    const now = this.now();
    if (!force && now - this.lastClean < 60000) return;
    this.lastClean = now;
    this.run('DELETE FROM ssh_pair_sessions WHERE expires <= ?', now);
    this.run('DELETE FROM invites WHERE expires <= ?', now);
    this.run('DELETE FROM pairs WHERE expires <= ?', now);
    this.run('DELETE FROM live_activities WHERE expires <= ?', now);
    this.run("UPDATE events SET state='expired' WHERE state='queued' AND expires <= ?", now);
    this.run("UPDATE events SET context_json=NULL, details_json=NULL, start_json=NULL WHERE state!='queued' AND (context_json IS NOT NULL OR details_json IS NOT NULL OR start_json IS NOT NULL)");
    this.run('DELETE FROM events WHERE created < ?', now - 86400000);
    this.run('DELETE FROM session_states WHERE updated < ?', now - RUNNING_TTL * 3);
  }
  invite() {
    this.clean();
    if (this.get('SELECT count(*) n FROM invites').n >= 100) fail(429, 'invite_capacity');
    const invite = secret();
    this.run('INSERT INTO invites VALUES (?, ?)', hash(invite), this.now() + 3600000);
    return { invite, expiresIn: 3600 };
  }
  owner(auth) {
    if (typeof auth !== 'string' || auth.length !== 43) fail(401, 'unauthorized');
    const device = this.get('SELECT * FROM devices WHERE owner = ?', hash(auth));
    if (!device) fail(401, 'unauthorized');
    return device;
  }
  handle(method, path, auth, body = {}) {
    const now = this.now();
    if (method === 'GET' && path === '/health') return { ok: true };
    this.clean();
    const sshPairing = handleSshPairing(this, method, path, auth, body);
    if (sshPairing !== undefined) return sshPairing;
    if (path === '/v1/live-activity' || path === '/v1/live-activity/token' || path === '/v1/live-activity/auto') {
      return handleActivity(this, method, path, auth, body);
    }
    if (method === 'POST' && path === '/v1/register') {
      fields(body, ['invite', 'deviceToken', 'ownerToken']);
      if (!validToken(body.deviceToken) || typeof body.invite !== 'string' || body.invite.length !== 43) fail(400, 'invalid_registration');
      if (body.ownerToken !== undefined && (typeof body.ownerToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.ownerToken))) fail(400, 'invalid_registration');
      // New clients persist a CSPRNG owner credential before the first request.
      // Retry can recover a committed registration without consuming another invite.
      if (body.ownerToken) {
        const existing = this.get('SELECT token FROM devices WHERE owner=?', hash(body.ownerToken));
        if (existing) {
          if (existing.token !== body.deviceToken) fail(409, 'registration_conflict');
          return { ownerToken: body.ownerToken, environment: this.environment };
        }
      }
      if (this.get('SELECT count(*) n FROM devices').n >= 1000) fail(503, 'capacity');
      if (!this.get('SELECT key FROM invites WHERE key=? AND expires>?', hash(body.invite), now)) fail(401, 'invalid_invite');
      const ownerToken = body.ownerToken ?? secret(), id = secret();
      this.db.transaction(() => {
        if (!this.run('DELETE FROM invites WHERE key=?', hash(body.invite)).changes) fail(401, 'invalid_invite');
        this.run('INSERT INTO devices (id, owner, token, active, environment) VALUES (?, ?, ?, 1, ?)', id, hash(ownerToken), body.deviceToken, this.environment);
      });
      return { ownerToken, environment: this.environment };
    }
    if (path === '/v1/device' && method === 'PUT') {
      const device = this.owner(auth);
      fields(body, ['deviceToken']);
      if (!validToken(body.deviceToken)) fail(400, 'invalid_device_token');
      this.run('UPDATE devices SET token=?, active=1 WHERE id=?', body.deviceToken, device.id);
      return { ok: true };
    }
    if (path === '/v1/device' && method === 'DELETE') {
      const device = this.owner(auth);
      this.db.transaction(() => {
        for (const table of ['events', 'hosts', 'pairs', 'live_activities', 'session_states']) this.run(`DELETE FROM ${table} WHERE device=?`, device.id);
        this.run('DELETE FROM devices WHERE id=?', device.id);
      });
      return { ok: true };
    }
    if (path === '/v1/pair' && method === 'POST') {
      const device = this.owner(auth);
      fields(body, ['hostId']);
      if (!validId(body.hostId)) fail(400, 'invalid_host_id');
      if (!device.active) fail(409, 'device_inactive');
      if (this.get('SELECT count(*) n FROM hosts WHERE device=?', device.id).n >= 20 &&
          !this.get('SELECT key FROM hosts WHERE device=? AND host=?', device.id, body.hostId)) fail(429, 'host_limit');
      if (this.get('SELECT count(*) n FROM pairs WHERE device=?', device.id).n >= 20) fail(429, 'pair_limit');
      const pairingCode = secret();
      this.run('INSERT INTO pairs VALUES (?, ?, ?, ?)', hash(pairingCode), device.id, body.hostId, now + 300000);
      return { pairingCode, expiresIn: 300 };
    }
    if (path === '/v1/pair/exchange' && method === 'POST') {
      fields(body, ['pairingCode']);
      if (typeof body.pairingCode !== 'string' || body.pairingCode.length !== 43) fail(400, 'invalid_pair');
      const key = hash(body.pairingCode);
      const pair = this.get('SELECT * FROM pairs WHERE code=? AND expires>?', key, now);
      if (!pair || !this.get('SELECT id FROM devices WHERE id=? AND active=1', pair.device)) fail(401, 'invalid_pair');
      // Recheck at exchange, not just code creation: several pending codes can race.
      if (this.get('SELECT count(*) n FROM hosts WHERE device=?', pair.device).n >= 20 &&
          !this.get('SELECT key FROM hosts WHERE device=? AND host=?', pair.device, pair.host)) fail(429, 'host_limit');
      const hostToken = secret();
      this.db.transaction(() => {
        if (!this.run('DELETE FROM pairs WHERE code=?', key).changes) fail(401, 'invalid_pair');
        // Re-pairing rotates the credential and cancels the old host's pending events.
        this.run("UPDATE events SET state='revoked' WHERE device=? AND host=? AND state='queued'", pair.device, pair.host);
        this.run('DELETE FROM live_activities WHERE device=? AND host=?', pair.device, pair.host);
        this.run('INSERT INTO hosts (key, device, host, active) VALUES (?, ?, ?, 1) ON CONFLICT(device,host) DO UPDATE SET key=excluded.key, active=1', hash(hostToken), pair.device, pair.host);
      });
      return { hostToken, hostId: pair.host };
    }
    if (path === '/v1/hosts/revoke' && method === 'POST') {
      const device = this.owner(auth);
      fields(body, ['hostId']);
      if (!validId(body.hostId)) fail(400, 'invalid_host_id');
      this.run('UPDATE hosts SET active=0 WHERE device=? AND host=?', device.id, body.hostId);
      this.run('DELETE FROM live_activities WHERE device=? AND host=?', device.id, body.hostId);
      this.run('DELETE FROM pairs WHERE device=? AND host=?', device.id, body.hostId);
      this.run('DELETE FROM session_states WHERE device=? AND host=?', device.id, body.hostId);
      this.run("UPDATE events SET state='revoked' WHERE device=? AND host=? AND state='queued'", device.id, body.hostId);
      return { ok: true };
    }
    if (path === '/v1/events' && method === 'POST') {
      fields(body, ['eventId', 'status', 'context', ...detailFields]);
      let context, details;
      try { context = taskContext(body.context); } catch { fail(400, 'invalid_context'); }
      try { details = agentDetails(body); } catch { fail(400, 'invalid_details'); }
      if (context && context.route !== body.eventId) fail(400, 'invalid_context');
      if (!validId(body.eventId) || !['completed', 'failed', 'attention'].includes(body.status)) fail(400, 'invalid_event');
      if (typeof auth !== 'string' || auth.length !== 43) fail(401, 'unauthorized');
      const hostKey = hash(auth);
      const host = this.get('SELECT h.* FROM hosts h JOIN devices d ON d.id=h.device WHERE h.key=? AND h.active=1 AND d.active=1', hostKey);
      if (!host) fail(401, 'unauthorized');
      const previous = this.get('SELECT status FROM events WHERE host_key=? AND event_id=?', hostKey, body.eventId);
      if (previous) {
        if (previous.status !== body.status) fail(409, 'event_conflict');
        return { accepted: true, duplicate: true };
      }
      // Moshi Pro: 60 agent events per minute, shared by the hosts of one device;
      // an hourly cap bounds a host that stays at that rate.
      if (this.get('SELECT count(*) n FROM events WHERE device=? AND created>?', host.device, now - 60000).n >= 60 ||
          this.get('SELECT count(*) n FROM events WHERE host_key=? AND created>?', hostKey, now - 3600000).n >= 600 ||
          this.get('SELECT count(*) n FROM events WHERE device=? AND created>?', host.device, now - 3600000).n >= 1200) fail(429, 'rate_limit');
      if (this.get('SELECT count(*) n FROM events').n >= 100000) fail(503, 'capacity');
      this.run("INSERT INTO events (host_key,event_id,device,host,status,created,expires,due,attempts,state,context_json,details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'queued', ?, ?)", hostKey, body.eventId, host.device, host.host, body.status, now, now + 300000, now, context ? JSON.stringify(context) : null, details ? JSON.stringify(details) : null);
      this.run('UPDATE live_activities SET latest_event_id=? WHERE device=? AND host=?', body.eventId, host.device, host.host);
      recordSession(this, host.device, host.host, details, body.status, now);
      maybeAutoStart(this, host.device, host.host, now);
      return { accepted: true, duplicate: false };
    }
    fail(404, 'not_found');
  }
  async tick() {
    if (this.busy) return;
    this.busy = true;
    try {
      this.clean();
      this.run("UPDATE events SET state='expired' WHERE state='queued' AND expires<=?", this.now());
      this.run("UPDATE events SET state='failed' WHERE state='queued' AND attempts>=3");
      const event = this.get("SELECT * FROM events WHERE state='queued' AND due<=? ORDER BY due LIMIT 1", this.now());
      if (!event) return;
      const device = this.get('SELECT d.* FROM devices d JOIN hosts h ON d.id=h.device WHERE h.key=? AND h.active=1 AND d.active=1', event.host_key);
      if (!device) {
        this.run("UPDATE events SET state='revoked' WHERE host_key=? AND event_id=?", event.host_key, event.event_id);
        return;
      }
      // ActivityKit timestamps have second precision. Keep successive updates
      // ordered without inventing future timestamps or running an idle poll.
      const previousActivity = this.get(`SELECT last_timestamp FROM live_activities
        WHERE device=? AND host=? AND latest_event_id=? AND expires>? AND token IS NOT NULL`,
      device.id, event.host, event.event_id, this.now());
      if (previousActivity?.last_timestamp >= Math.floor(this.now() / 1000)) {
        this.run('UPDATE events SET due=? WHERE host_key=? AND event_id=?',
          (previousActivity.last_timestamp + 1) * 1000, event.host_key, event.event_id);
        return;
      }
      // Persist before network; process restart waits instead of immediately flooding APNs.
      const attempts = event.attempts + 1;
      this.run('UPDATE events SET attempts=?, due=? WHERE host_key=? AND event_id=?', attempts, this.now() + 30000, event.host_key, event.event_id);
      let result;
      const activity = () => {
        const row = this.get(`SELECT * FROM live_activities
          WHERE device=? AND host=? AND latest_event_id=? AND expires>? AND token IS NOT NULL`,
        device.id, event.host, event.event_id, this.now());
        if (row) this.run('UPDATE live_activities SET last_timestamp=? WHERE device=? AND activity_id=?',
          Math.floor(this.now() / 1000), device.id, row.activity_id);
        return row;
      };
      const invalidateActivity = row => this.run('UPDATE live_activities SET token=NULL WHERE device=? AND activity_id=? AND token=?', device.id, row.activity_id, row.token);
      event.aggregate = aggregate(this, device.id, event.host, this.now());
      const startTokenRejected = row => this.run('UPDATE devices SET start_token=NULL WHERE id=? AND start_token=?', row.id, row.start_token);
      try { result = await this.deliver({ device, event, activity, invalidateActivity, startTokenRejected }); }
      catch { result = { retryable: true }; } // Timeout is ambiguous; delivery is not exactly-once.
      if (result.invalidateDevice || result.reason === 'BadDeviceToken' || result.reason === 'DeviceTokenNotForTopic') {
        // A token refresh while the APNs request was in flight must remain active.
        this.run('UPDATE devices SET active=0 WHERE id=? AND token=?', device.id, device.token);
      }
      const state = result.accepted ? 'accepted' : result.retryable && attempts < 3 && this.now() < event.expires ? 'queued' : 'failed';
      this.run("UPDATE events SET state=?, due=?, apns_status=?, apns_reason=? WHERE host_key=? AND event_id=? AND state='queued'", state,
        this.now() + 15000 * 2 ** attempts, Number.isInteger(result.status) ? result.status : null,
        /^[A-Za-z]{1,80}$/.test(result.reason ?? '') ? result.reason : null, event.host_key, event.event_id);
      if (state !== 'queued') this.run('UPDATE events SET context_json=NULL, details_json=NULL, start_json=NULL WHERE host_key=? AND event_id=?', event.host_key, event.event_id);
    } finally { this.busy = false; }
  }
}

// `token(config)` signs the APNs provider JWT (node:crypto or WebCrypto);
// `send(request)` performs the HTTP/2 POST (node:http2 or Worker fetch).
export function apnsDelivery(config, send, now = Date.now, token = providerToken) {
  let jwt, issued = 0;
  return async ({ device, event, activity, invalidateActivity, startTokenRejected }) => {
    if (!jwt || now() - issued >= 3000000) {
      jwt = await token({ ...config, now: now() }); issued = now();
    }
    let request = notificationRequest({ jwt, deviceToken: device.token, environment: device.environment,
      now: now(), event: { status: event.status, eventId: event.event_id, hostId: event.host,
        context: event.context_json ? JSON.parse(event.context_json) : undefined,
        details: event.details_json ? JSON.parse(event.details_json) : undefined } });
    // Preserve original event deadline across retries. A session's turn results
    // replace each other (Moshi keeps one row per session); others collapse
    // only pending duplicates.
    const details = event.details_json ? JSON.parse(event.details_json) : undefined;
    // Resolve AFTER any Pro verification await. Old retries cannot replace the
    // newest task, and a revoked/rotated activity cannot borrow a device token.
    const live = activity?.();
    if (event.live_only === 2) {
      // Push-to-start (iOS 17.2+): the system creates the activity; the app then
      // registers its update token with the one-time ticket in the attributes.
      if (!device.start_token || !event.start_json) return { accepted: true, status: 200 };
      const result = await send(startActivityRequest({ device, event, jwt, now: now() }));
      if (result.invalidateDevice || ['BadDeviceToken', 'DeviceTokenNotForTopic'].includes(result.reason)) {
        startTokenRejected?.(device);
      }
      // Never let the start token's verdict reach the ordinary device token.
      return { status: result.status, accepted: true };
    }
    if (event.live_only) {
      // Follow-time sync: Live Activity only, never an ordinary notification.
      if (!live) return { accepted: true, status: 200 };
      const result = await send(liveActivityRequest({ device, activity: live, event, jwt, now: now() }));
      if (result.invalidateDevice || ['BadDeviceToken', 'DeviceTokenNotForTopic'].includes(result.reason)) invalidateActivity?.(live);
      // The activity token's verdict (reason included) must not disable the device.
      return { status: result.status, accepted: true };
    }
    // A banner event on a host the phone already follows: the Live Activity
    // alerts (screen on, sound, island expands) and the ordinary push goes out
    // silent, for the inbox only. Two cards for one question was the bug.
    const banner = details ? details.visibility !== 'silent' : true;
    let alerted = false;
    if (live) {
      try {
        const result = await send(liveActivityRequest({ device, activity: live, event, jwt, now: now(), alert: banner }));
        if (result.invalidateDevice || ['BadDeviceToken', 'DeviceTokenNotForTopic'].includes(result.reason)) invalidateActivity?.(live);
        alerted = banner && result.accepted;
      } catch { /* Ordinary notification remains independent and available. */ }
    }
    if (alerted) {
      request = notificationRequest({ jwt, deviceToken: device.token, environment: device.environment,
        now: now(), event: { status: event.status, eventId: event.event_id, hostId: event.host,
          context: event.context_json ? JSON.parse(event.context_json) : undefined,
          details: { ...details, visibility: 'silent' } } });
    }
    request.headers['apns-expiration'] = String(Math.floor(event.expires / 1000));
    request.headers['apns-collapse-id'] = details?.session && details.category === 'task_complete'
      ? hash(`${event.host_key}:${details.session}:turn`) : hash(`${event.host_key}:${event.event_id}`);
    return send(request);
  };
}

