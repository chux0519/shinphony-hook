// One explicitly followed host per device. Tokens are scoped to a single
// ActivityKit instance; a host credential can never register an activity.
import { createHash, randomBytes } from 'node:crypto';
import { clipText, displayText } from './display-text.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const fail = (status, code) => { throw Object.assign(new Error(code), { status, code }); };
const fields = (body, names) => {
  if (Object.keys(body).some(key => !names.includes(key))) fail(400, 'invalid_fields');
};
export function createActivityTable(relay) {
  relay.db.exec(`CREATE TABLE IF NOT EXISTS live_activities (
    device TEXT PRIMARY KEY, activity_id TEXT NOT NULL, host TEXT NOT NULL,
    registration_key TEXT UNIQUE NOT NULL, token TEXT, expires INTEGER NOT NULL,
    latest_event_id TEXT, last_timestamp INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS session_states (
      device TEXT NOT NULL, host TEXT NOT NULL, session TEXT NOT NULL,
      state TEXT NOT NULL, agent TEXT, project TEXT, updated INTEGER NOT NULL,
      PRIMARY KEY(device, host, session));`);
  // Push-to-start (iOS 17.2+): one start token per device; auto-start is opt-in per host.
  for (const [table, name, type] of [['devices', 'start_token', 'TEXT'], ['devices', 'activity_prefix', 'TEXT'],
    ['hosts', 'auto_activity', 'INTEGER'], ['hosts', 'host_name', 'TEXT'], ['hosts', 'last_auto_start', 'INTEGER'],
    ['hosts', 'host_ref', 'TEXT'], ['hosts', 'live_lines', 'INTEGER']]) {
    if (!relay.db.columns(table).includes(name)) relay.db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
}

// A started activity has this long to register its update token.
export const PENDING_START_TTL = 120000;
// At most one automatic start per device in this window (Apple budgets start pushes).
export const AUTO_START_INTERVAL = 5 * 60000;
const PENDING = 'pending-';
const prefixes = ['', '/testflight', '/production'];
const hostName = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 64 &&
  !/[\u0000-\u001f\u007f]/.test(value);

// Per-session state, no task text: only what the Live Activity needs to say
// "N tasks running" while several agents work on one host. A turn that never
// reports back stops counting after RUNNING_TTL.
export const RUNNING_TTL = 2 * 3600000;
const sessionState = (category, status) =>
  ['task_started', 'tool_running', 'tool_finished'].includes(category) ? 'running'
    : ['approval_required', 'question'].includes(category) || status === 'attention' ? 'attention'
    : category === 'session_started' ? 'idle'
    : category === 'session_ended' ? null : 'done';

export function recordSession(relay, device, host, details, status, now) {
  if (!details?.session) return;
  const state = sessionState(details.category, status);
  if (state === null) {
    relay.run('DELETE FROM session_states WHERE device=? AND host=? AND session=?', device, host, details.session);
    return;
  }
  relay.run(`INSERT INTO session_states VALUES (?,?,?,?,?,?,?) ON CONFLICT(device,host,session)
    DO UPDATE SET state=excluded.state, agent=excluded.agent, project=excluded.project, updated=excluded.updated`,
  device, host, details.session, state, details.agent ?? '', details.project ?? '', now);
}

export function aggregate(relay, device, host, now) {
  const rows = relay.db.prepare(`SELECT state, agent, project FROM session_states
    WHERE device=? AND host=? AND updated>? AND state IN ('running','attention') ORDER BY updated DESC`)
    .all(device, host, now - RUNNING_TTL);
  return { running: rows.filter(r => r.state === 'running'), attention: rows.filter(r => r.state === 'attention') };
}

const agentName = agent => ({ codex: 'Codex', claude: 'Claude Code', dsh: 'DSH' })[agent] || 'A task';

// Follow-time sync: the current state as one Live-Activity-only event.
export function queueActivitySync(relay, device, host, now) {
  const agg = aggregate(relay, device, host, now);
  const lead = agg.attention[0] ?? agg.running[0];
  if (!lead) return null;
  const row = relay.get('SELECT key, host_ref, live_lines FROM hosts WHERE device=? AND host=? AND active=1', device, host);
  if (!row?.key) return null;
  const eventId = 'sync-' + randomBytes(12).toString('hex');
  const details = { category: agg.attention.length ? 'approval_required' : 'task_started', agent: lead.agent,
    project: lead.project, visibility: 'silent' };
  relay.run(`INSERT INTO events (host_key,event_id,device,host,status,created,expires,due,attempts,state,context_json,details_json,host_ref,live_lines,live_only)
    VALUES (?,?,?,?,?,?,?,?,0,'queued',NULL,?,?,?,1)`, row.key, eventId, device, host,
  agg.attention.length ? 'attention' : 'completed', now, now + 300000, now, JSON.stringify(details), row.host_ref ?? null, row.live_lines ?? 0);
  relay.run('UPDATE live_activities SET latest_event_id=? WHERE device=? AND host=?', eventId, device, host);
  return eventId;
}
// A task started (or needs an answer) on an auto host and the device shows no
// Live Activity: queue a push-to-start. The ticket travels only in the APNs
// payload's attributes; the relay keeps its hash.
export function maybeAutoStart(relay, device, host, now) {
  const row = relay.get(`SELECT h.key, h.host_name, h.last_auto_start, h.host_ref, h.live_lines, d.start_token, d.activity_prefix FROM hosts h
    JOIN devices d ON d.id=h.device WHERE h.device=? AND h.host=? AND h.active=1 AND d.active=1 AND h.auto_activity=1`, device, host);
  if (!row?.start_token || !hostName(row.host_name)) return null;
  if (now - (row.last_auto_start ?? 0) < AUTO_START_INTERVAL) return null;
  if (relay.get('SELECT 1 FROM live_activities WHERE device=? AND expires>?', device, now)) return null;
  const agg = aggregate(relay, device, host, now);
  const lead = agg.attention[0] ?? agg.running[0];
  if (!lead) return null;
  const ticket = randomBytes(32).toString('base64url');
  const eventId = 'start-' + randomBytes(12).toString('hex');
  relay.run(`INSERT INTO live_activities (device,activity_id,host,registration_key,expires,latest_event_id)
    VALUES (?,?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET activity_id=excluded.activity_id, host=excluded.host,
    registration_key=excluded.registration_key, token=NULL, expires=excluded.expires,
    latest_event_id=excluded.latest_event_id, last_timestamp=0`,
  device, PENDING + randomBytes(12).toString('hex'), host, hash(ticket), now + PENDING_START_TTL, eventId);
  const details = { category: agg.attention.length ? 'approval_required' : 'task_started', agent: lead.agent,
    project: lead.project, visibility: 'silent' };
  relay.run(`INSERT INTO events (host_key,event_id,device,host,status,created,expires,due,attempts,state,context_json,details_json,host_ref,live_lines,live_only,start_json)
    VALUES (?,?,?,?,?,?,?,?,0,'queued',NULL,?,?,?,2,?)`, row.key, eventId, device, host,
  agg.attention.length ? 'attention' : 'completed', now, now + PENDING_START_TTL, now, JSON.stringify(details),
  row.host_ref ?? null, row.live_lines ?? 0,
  JSON.stringify({ hostId: host, hostName: row.host_name, ticket, prefix: row.activity_prefix ?? '' }));
  relay.run('UPDATE hosts SET last_auto_start=? WHERE device=? AND host=?', now, device, host);
  return eventId;
}

export function activityTicket(relay, auth) {
  if (typeof auth !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(auth)) fail(401, 'unauthorized');
  const row = relay.get(`SELECT a.* FROM live_activities a JOIN devices d ON d.id=a.device
    JOIN hosts h ON h.device=a.device AND h.host=a.host
    WHERE a.registration_key=? AND a.expires>? AND d.active=1 AND h.active=1`, hash(auth), relay.now());
  if (!row) fail(401, 'unauthorized');
  return row;
}
export function handleActivity(relay, method, path, auth, body) {
  if (path === '/v1/live-activity' && method === 'POST') {
    fields(body, ['hostId', 'activityId']);
    if (!id(body.hostId) || !id(body.activityId)) fail(400, 'invalid_activity');
    const device = relay.owner(auth);
    if (!device.active || !relay.get('SELECT key FROM hosts WHERE device=? AND host=? AND active=1', device.id, body.hostId)) fail(409, 'host_not_paired');
    const token = randomBytes(32).toString('base64url');
    relay.run(`INSERT INTO live_activities (device,activity_id,host,registration_key,expires)
      VALUES (?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET activity_id=excluded.activity_id,
      host=excluded.host,registration_key=excluded.registration_key,token=NULL,
      expires=excluded.expires,latest_event_id=NULL,last_timestamp=0`,
    device.id, body.activityId, body.hostId, hash(token), relay.now() + 8 * 3600000);
    return { registrationToken: token };
  }
  if (path === '/v1/live-activity/auto' && method === 'PUT') {
    fields(body, ['hostId', 'enabled', 'hostName', 'startToken', 'prefix']);
    const device = relay.owner(auth);
    if (!device.active) fail(409, 'device_inactive');
    if (body.startToken !== undefined) {
      if (typeof body.startToken !== 'string' || !/^[a-f0-9]{64,512}$/i.test(body.startToken) || body.startToken.length % 2) fail(400, 'invalid_start_token');
      if (body.prefix !== undefined && !prefixes.includes(body.prefix)) fail(400, 'invalid_prefix');
      relay.run('UPDATE devices SET start_token=?, activity_prefix=? WHERE id=?', body.startToken, body.prefix ?? '', device.id);
    }
    if (body.hostId !== undefined) {
      if (!id(body.hostId) || typeof body.enabled !== 'boolean') fail(400, 'invalid_auto');
      if (!relay.get('SELECT key FROM hosts WHERE device=? AND host=? AND active=1', device.id, body.hostId)) fail(409, 'host_not_paired');
      if (body.enabled && !hostName(body.hostName)) fail(400, 'invalid_host_name');
      if (body.enabled && !body.startToken && !relay.get('SELECT start_token FROM devices WHERE id=?', device.id)?.start_token) fail(409, 'start_token_required');
      relay.run('UPDATE hosts SET auto_activity=?, host_name=CASE WHEN ? THEN ? ELSE host_name END WHERE device=? AND host=?',
        body.enabled ? 1 : 0, body.enabled ? 1 : 0, body.hostName ?? null, device.id, body.hostId);
      // Turning it on while a task already runs shows the activity now.
      if (body.enabled) maybeAutoStart(relay, device.id, body.hostId, relay.now());
    }
    return { ok: true };
  }
  if (path === '/v1/live-activity/token' && method === 'PUT') {
    fields(body, ['activityId', 'pushToken']);
    const row = activityTicket(relay, auth);
    // A pushed start learns its system-assigned ID only on the device.
    const started = row.activity_id.startsWith(PENDING);
    if (!started && row.activity_id !== body.activityId) fail(409, 'activity_changed');
    if (started && !id(body.activityId)) fail(400, 'invalid_activity');
    if (typeof body.pushToken !== 'string' || !/^[a-f0-9]{64,512}$/i.test(body.pushToken) || body.pushToken.length % 2) fail(400, 'invalid_activity_token');
    if (started) {
      relay.run('UPDATE live_activities SET activity_id=?, expires=? WHERE registration_key=?',
        body.activityId, relay.now() + 8 * 3600000, row.registration_key);
    }
    relay.run('UPDATE live_activities SET token=? WHERE registration_key=?', body.pushToken, row.registration_key);
    // Tasks that started before Follow show as running at once, not after
    // their next event.
    queueActivitySync(relay, row.device, row.host, relay.now());
    return { ok: true };
  }
  if (path === '/v1/live-activity' && method === 'DELETE') {
    fields(body, ['activityId']);
    if (!id(body.activityId)) fail(400, 'invalid_activity');
    // The activity's own ticket may end it too: the app reports a dismissed
    // activity without the owner credential, so auto-start can show it again.
    const scoped = typeof auth === 'string' && /^[A-Za-z0-9_-]{43}$/.test(auth) &&
      relay.get('SELECT device FROM live_activities WHERE registration_key=? AND activity_id=?', hash(auth), body.activityId);
    if (scoped) {
      relay.run('DELETE FROM live_activities WHERE device=? AND activity_id=?', scoped.device, body.activityId);
      return { ok: true };
    }
    const device = relay.owner(auth);
    relay.run('DELETE FROM live_activities WHERE device=? AND activity_id=?', device.id, body.activityId);
    return { ok: true };
  }
  fail(404, 'not_found');
}

// The state a widget shows, without any text. The plaintext activity and the
// private one share it, so both agree on working / attention / done.
const baseState = (category, status) => ['task_started', 'tool_running'].includes(category) ? 'working'
  : ['session_started', 'tool_finished'].includes(category) ? 'waiting'
  : category === 'session_ended' ? 'ended' : status;

export function activityState(event, agg = event.aggregate) {
  const details = event.details_json ? JSON.parse(event.details_json) : {};
  const state = baseState(details.category, event.status);
  const running = agg?.running?.length ?? 0, attention = agg?.attention?.length ?? 0;
  if (state !== 'attention' && attention > 0) return 'attention';
  if (state !== 'attention' && running > 0) return 'working';
  return state;
}

// A private Live Activity: only the state, when this event happened and the
// opaque hostRef. The widget resolves the host's name from its own App Group,
// so no title and no terminal lines ever reach the relay. `status`/`updatedAt`
// are the names the current widget decodes; `state`/`startedAt` are the same
// values under the plan's names.
export function privateActivityContent(event, timestamp, agg = event.aggregate) {
  const created = Number(event.created);
  const state = activityState(event, agg);
  return { status: state, state, hostRef: event.host_ref,
    startedAt: Math.floor((created > 0 ? created : timestamp * 1000) / 1000), updatedAt: timestamp };
}

export function activityContent(event, timestamp, agg = event.aggregate) {
  // Sealed pairing without the plaintext-lines opt-in: nothing readable.
  if (event.host_ref && event.live_lines !== 1) return privateActivityContent(event, timestamp, agg);
  const details = event.details_json ? JSON.parse(event.details_json) : {};
  const context = event.context_json ? JSON.parse(event.context_json) : undefined;
  const category = details.category;
  let status = baseState(category, event.status);
  let title = displayText(details.title || context?.title || '');
  let summary = displayText(context?.preview || details.body || '');
  if (category === 'question' && details.body) {
    // Keep the hook's "1. label" lines: the widget turns them into answer
    // buttons. displayText would flatten them to "A B".
    summary = details.body.split('\n').slice(0, 9).map(line => {
      const m = line.match(/^(\d{1,2})\. (.*)$/);
      return m ? `${m[1]}. ${displayText(m[2])}` : displayText(line);
    }).filter(Boolean).join('\n');
  }
  // The conversation a helper belongs to, and the helper's own name. Both are
  // additive optional fields: widgets that predate them ignore them. A helper
  // without a live parent keeps its own title as the conversation.
  const parent = clipText(context?.parentTitle, 120);
  const conversation = parent || title;
  const helper = parent ? clipText(context?.session, 80) : '';
  // One island for the whole host: someone waiting for an answer comes first,
  // then any task still running; "done"/"waiting" only when everything stopped.
  const running = agg?.running?.length ?? 0, attention = agg?.attention?.length ?? 0;
  if (status !== 'attention' && attention > 0) {
    status = 'attention';
    title = `${agentName(agg.attention[0].agent)} needs you`;
  } else if (status !== 'attention' && running > 0) {
    if (status !== 'working') {
      const what = title || summary;
      summary = what && status !== 'waiting' && status !== 'ended' ? displayText(`Finished: ${what}`) : '';
      title = running === 1 ? `${agentName(agg.running[0].agent)} still running` : `${running} tasks running`;
    } else if (running > 1) {
      title = `${running} tasks running`;
    }
    status = 'working';
  }
  // Opted-in plaintext preview: the terminal lines this pairing allows, for a
  // widget that shows them as a list. Legacy plaintext hosts keep their look.
  const lines = event.host_ref && event.live_lines === 1 && context?.preview
    ? context.preview.split('\n').map(line => line.trim()).filter(Boolean).slice(0, 6) : [];
  // Additive: older widgets ignore category and still understand status.
  return { status, ...(category ? { category } : {}), agent: details.agent ?? (context ? 'codex' : ''),
    title, summary, project: details.project || context?.session || '',
    ...(conversation ? { conversation } : {}), ...(helper ? { helper } : {}),
    updatedAt: timestamp, eventId: event.event_id,
    // Additive: the widget resolves the host's name from its App Group.
    ...(event.host_ref ? { hostRef: event.host_ref } : {}),
    ...(lines.length ? { lines } : {}),
    // JSON string keeps the native Codable schema stable across context versions.
    contextJSON: context ? JSON.stringify(context) : '' };
}

export function startActivityRequest({ device, event, jwt, now }) {
  const timestamp = Math.floor(now / 1000);
  const start = JSON.parse(event.start_json);
  const state = activityContent(event, timestamp);
  const body = JSON.stringify({ aps: { timestamp, event: 'start', 'content-state': state,
    'attributes-type': 'TaskActivityAttributes',
    attributes: { hostId: start.hostId, hostName: start.hostName, ticket: start.ticket, prefix: start.prefix },
    alert: { title: start.hostName, body: state.title || 'A task is running' }, 'stale-date': timestamp + 600 } });
  if (Buffer.byteLength(body) > 4096) throw new Error('Activity too large');
  return {
    origin: device.environment === 'sandbox' ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com',
    headers: { ':method': 'POST', ':path': `/3/device/${device.start_token}`,
      authorization: `bearer ${jwt}`, 'apns-topic': 'net.potafree.shinphony.push-type.liveactivity',
      'apns-push-type': 'liveactivity', 'apns-priority': '10',
      'apns-expiration': String(Math.floor(event.expires / 1000)), 'content-type': 'application/json' }, body,
  };
}

export function liveActivityRequest({ device, activity, event, jwt, now, alert = false }) {
  const timestamp = Math.floor(now / 1000);
  const state = activityContent(event, timestamp);
  const body = JSON.stringify({ aps: { timestamp, event: 'update', 'content-state': state, 'stale-date': timestamp + 600,
    // Instead of a separate banner: lights the screen and expands the island.
    ...(alert ? { alert: { title: state.title || 'Shinphony', body: state.summary || state.title || '', sound: 'default' } } : {}) } });
  if (Buffer.byteLength(body) > 4096) throw new Error('Activity too large');
  return {
    origin: device.environment === 'sandbox' ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com',
    headers: { ':method': 'POST', ':path': `/3/device/${activity.token}`,
      authorization: `bearer ${jwt}`, 'apns-topic': 'net.potafree.shinphony.push-type.liveactivity',
      // Follow-time sync goes out at once (5 may be held, and a late push older
      // than the app's own "Following" update is dropped: stuck on Waiting).
      'apns-push-type': 'liveactivity', 'apns-priority': event.live_only || alert ? '10' : '5',
      'apns-expiration': String(Math.floor(Math.min(activity.expires, event.expires) / 1000)),
      'apns-collapse-id': hash(activity.activity_id), 'content-type': 'application/json' }, body,
  };
}
