// One Durable Object per lane holds the whole relay (its SQLite is the relay
// database). Requests are serialised by the object, as the Node server's single
// process was; queued deliveries run from the object's alarm, not a timer.
import { DurableObject } from 'cloudflare:workers';
import { Buffer } from 'node:buffer';
import { Relay, apnsDelivery } from '../../server/relay-core.mjs';
import { withPro } from '../../server/pro-relay-core.mjs';
import { runtimePolicy } from '../../server/runtime-policy.mjs';
import { durableDatabase } from './do-database.mjs';
import { fetchSend, webProviderToken } from './apns-web.mjs';
import rootG2 from '../../server/certificates/AppleRootCA-G2.cer';
import rootG3 from '../../server/certificates/AppleRootCA-G3.cer';

const ProRelay = withPro(Relay);
const flag = value => value === '1' || value === 'true';

// The three lanes the Node server ran behind nginx (same URL prefixes).
export const LANES = {
  // Development lanes are invite-only; production registration is public.
  sandbox: { prefix: '', apns: 'sandbox', iap: 'sandbox', publicRegistration: false, reviewSandbox: false },
  testflight: { prefix: '/testflight', apns: 'production', iap: 'sandbox', publicRegistration: false, reviewSandbox: false },
  production: { prefix: '/production', apns: 'production', iap: 'production', publicRegistration: true, reviewSandbox: true },
};

// The Apple library (via jsrsasign) draws random numbers when it loads, which a
// Worker forbids at global scope: load it inside the object instead.
export async function relayFor(ctx, env, laneName) {
  const lane = LANES[laneName];
  if (!lane) throw new Error('Unknown lane');
  const { createAppleProVerifier, EnvironmentProVerification } = await import('../../server/pro-verification.mjs');
  // APNs keys can be limited to one environment: production lanes use APNS_PROD_*.
  const prod = lane.apns === 'production';
  const apns = { environment: lane.apns, teamId: env.APNS_TEAM_ID,
    keyId: prod ? env.APNS_PROD_KEY_ID : env.APNS_KEY_ID,
    privateKey: prod ? env.APNS_PROD_PRIVATE_KEY : env.APNS_PRIVATE_KEY };
  const apple = { environment: lane.iap };
  const policy = runtimePolicy(apns, apple);
  const verificationConfig = {
    environment: apple.environment, keyId: env.IAP_KEY_ID, issuerId: env.IAP_ISSUER_ID,
    privateKey: env.IAP_PRIVATE_KEY,
    rootCertificates: [Buffer.from(rootG2), Buffer.from(rootG3)],
  };
  const publicRegistration = lane.publicRegistration;
  const allowReviewSandbox = lane.reviewSandbox;
  if (allowReviewSandbox && (apple.environment !== 'production' || apns.environment !== 'production' || !publicRegistration)) {
    throw new Error('Review sandbox requires public production policy');
  }
  const production = createAppleProVerifier(verificationConfig);
  const verification = allowReviewSandbox ? new EnvironmentProVerification(production,
    createAppleProVerifier({ ...verificationConfig, environment: 'sandbox' })) : production;
  return new ProRelay({
    db: durableDatabase(ctx.storage), environment: apns.environment, verification,
    publicRegistration, allowReviewSandbox, freeTier: flag(env.FREE_TIER),
    purchaseEnvironment: policy.purchaseEnvironment,
    deliver: (delivery => async input => {
      try { return await delivery(input); }
      catch (error) {
        // Error class and message only (never tokens, keys or payloads).
        console.error('delivery failed', error?.name, String(error?.message ?? '').slice(0, 120));
        throw error;
      }
    })(apnsDelivery(apns, request => fetchSend(request), Date.now, webProviderToken)),
  });
}

export class RelayObject extends DurableObject {
  // One object per lane; the entry Worker names the lane (internal header,
  // never accepted from the internet) and the object remembers it for alarms.
  async ensure(laneName) {
    if (this.relay) return this.relay;
    const stored = this.ctx.storage.kv.get('lane');
    const lane = stored ?? laneName;
    if (!LANES[lane] || (laneName && stored && laneName !== stored)) throw new Error('Lane mismatch');
    if (!stored) this.ctx.storage.kv.put('lane', lane);
    this.relay = await relayFor(this.ctx, this.env, lane);
    return this.relay;
  }

  async fetch(request) {
    await this.ensure(request.headers.get('x-shinphony-lane'));
    const url = new URL(request.url);
    const reply = (status, data) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });
    // Global fixed-size guard, as the Node server had (never a per-IP map).
    const minute = Math.floor(Date.now() / 60000);
    if (minute !== this.window) { this.window = minute; this.requests = 0; }
    if (++this.requests > 600) return reply(429, { error: 'busy' });
    try {
      // Admin-only, reachable solely through the entry Worker's checked route.
      if (url.pathname === '/__invite' && request.headers.get('x-shinphony-admin') === '1') {
        return Response.json(this.relay.invite(), { headers: { 'Cache-Control': 'no-store' } });
      }
      // Read-only operations view: counts and the latest delivery results (no tokens).
      if (url.pathname === '/__status' && request.headers.get('x-shinphony-admin') === '1') {
        const count = table => this.relay.get(`SELECT count(*) n FROM ${table}`).n;
        return reply(200, {
          devices: count('devices'), hosts: count('hosts'), entitlements: count('entitlements'),
          events: this.relay.db.prepare(`SELECT state, apns_status, apns_reason, count(*) n FROM events
            GROUP BY state, apns_status, apns_reason`).all(),
        });
      }
      // Ops diagnostics (admin only): revalidate one stored Pro binding; error class + stack frames, never data.
      if (url.pathname === '/__probe-verify' && request.headers.get('x-shinphony-admin') === '1') {
        const row = this.relay.get("SELECT binding FROM entitlements WHERE json_extract(binding, '$.tier') IS NULL LIMIT 1");
        if (!row) return reply(200, { probe: 'no pro binding' });
        try {
          const result = await this.relay.verification.revalidate(JSON.parse(row.binding));
          return reply(200, { probe: 'ok', environment: result.environment });
        } catch (error) {
          return reply(200, { probe: 'failed', code: error.code, name: error.name,
            cause: error.cause ? String(error.cause.name) + ': ' + String(error.cause.message).slice(0, 160) : null,
            stack: error.cause ? String(error.cause.stack).split('\n').slice(0, 8).map(l => l.trim().slice(0, 140)) : null,
            causeKeys: error.cause ? Object.keys(error.cause).slice(0, 10) : null, httpStatus: error.cause?.httpStatusCode ?? error.cause?.status ?? null, apiError: error.cause?.apiError ?? null });
        }
      }
      // One-time migration from the Node relay's SQLite (tool/migrate-from-vps.py).
      if (url.pathname === '/__import' && request.headers.get('x-shinphony-admin') === '1') {
        let data;
        try { data = await request.json(); } catch { return reply(400, { error: 'invalid_json' }); }
        return reply(200, this.import(data));
      }
      let body = {};
      const raw = await request.text();
      try { if (raw) body = JSON.parse(raw); } catch { return reply(400, { error: 'invalid_json' }); }
      const authorization = request.headers.get('authorization');
      const auth = authorization?.startsWith('Bearer ') ? authorization.slice(7) : undefined;
      const result = await this.relay.handle(request.method, url.pathname, auth, body);
      if (url.pathname === '/v1/events' && !result.duplicate) await this.schedule();
      return reply(url.pathname === '/v1/events' ? 202 : 200, result);
    } catch (error) {
      // No exception details, tokens or payloads.
      return reply(error.status ?? 500, { error: error.code ?? 'internal_error' });
    }
  }

  // Rows keep their original column values (hashes, tokens, bindings). Only
  // the durable tables move; queued events and pairing codes are short-lived.
  import(data) {
    const tables = ['devices', 'hosts', 'entitlements', 'live_activities'];
    const counts = {};
    this.relay.db.transaction(() => {
      for (const table of tables) {
        const rows = data?.[table] ?? [];
        if (!Array.isArray(rows)) throw Object.assign(new Error('invalid_import'), { status: 400, code: 'invalid_import' });
        const columns = this.relay.db.columns(table);
        for (const row of rows) {
          const names = Object.keys(row);
          if (!names.length || names.some(n => !columns.includes(n))) {
            throw Object.assign(new Error('invalid_import'), { status: 400, code: 'invalid_import' });
          }
          this.relay.run(`INSERT OR REPLACE INTO ${table} (${names.join(',')}) VALUES (${names.map(() => '?').join(',')})`,
            ...names.map(n => row[n]));
        }
        counts[table] = this.relay.get(`SELECT count(*) n FROM ${table}`).n;
      }
    });
    return { imported: counts };
  }

  // Deliver due events one at a time, then wake again for the next due one.
  async alarm() {
    await this.ensure(null);
    try { await this.relay.tick(); } finally { await this.schedule(); }
  }

  async schedule() {
    const next = this.relay.get("SELECT min(due) due FROM events WHERE state='queued'");
    if (next?.due == null) return;
    const at = Math.max(Date.now() + 50, Math.min(next.due, Date.now() + 300000));
    const current = await this.ctx.storage.getAlarm();
    if (current == null || current > at) await this.ctx.storage.setAlarm(at);
  }
}
