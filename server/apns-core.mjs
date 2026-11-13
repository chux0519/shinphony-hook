// APNs payloads and the node:crypto provider token (shared). Transport: apns.mjs.
import { createPrivateKey, sign } from 'node:crypto';
import { taskContext } from './task-context.mjs';
import { clipText } from './display-text.mjs';
import { agentDetails, agents, e2ePayload } from './agent-event.mjs';

const topic = 'net.potafree.shinphony';
const states = {
  completed: 'Task completed',
  failed: 'Task failed',
  attention: 'Task needs your attention',
};
// One short word for a subtitle line, next to a conversation title.
const shortStates = { completed: 'Done', failed: 'Failed', attention: 'Needs you' };

// Private notifications: the only text the relay can write, by category. The
// Notification Service Extension replaces it with the sealed content on the
// phone; when it cannot, this is what the user sees.
export const e2eAlerts = { finished: 'Task finished', attention: 'Needs your attention', failed: 'Task failed' };
export function e2eAlert(category, status) {
  if (['approval_required', 'question'].includes(category) || status === 'attention') return e2eAlerts.attention;
  if (category === 'error' || status === 'failed') return e2eAlerts.failed;
  return e2eAlerts.finished;
}

export function providerToken({ keyId, teamId, privateKey, now = Date.now() }) {
  if (!/^[A-Z0-9]{10}$/.test(keyId ?? '') || !/^[A-Z0-9]{10}$/.test(teamId ?? '')) {
    throw new Error('Invalid APNs key/team identifier');
  }
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('APNs requires a P-256 private key');
  }
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const message = `${encode({ alg: 'ES256', kid: keyId })}.${encode({ iss: teamId, iat: Math.floor(now / 1000) })}`;
  return `${message}.${sign('sha256', Buffer.from(message), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

export function notificationRequest({ deviceToken, environment, event, jwt, now = Date.now() }) {
  if (!['sandbox', 'production'].includes(environment)) throw new Error('Explicit APNs environment required');
  if (!/^[a-f0-9]{64,512}$/i.test(deviceToken ?? '') || deviceToken.length % 2) throw new Error('Invalid device token');
  if (!jwt) throw new Error('Provider token required');
  if (!event || !Object.hasOwn(states, event.status)) throw new Error('Invalid task status');
  for (const field of ['eventId', 'hostId']) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(event[field] ?? '')) throw new Error(`Invalid ${field}`);
  }
  const context = taskContext(event.context);
  const details = event.details ? agentDetails(event.details) : undefined;
  // A sealed event: the relay only knows the category, hostRef and envelope.
  const sealed = event.e2e !== undefined
    ? e2ePayload({ category: details?.category, e2e: event.e2e, hostRef: event.hostRef, silent: event.silent, liveLines: event.liveLines })
    : undefined;
  const silent = sealed ? sealed.silent : details?.visibility === 'silent';
  const shinphony = { version: details && !sealed ? 2 : 1, eventId: event.eventId, hostId: event.hostId, status: event.status,
    ...(context ? { context } : {}), ...(details && !sealed ? { details } : {}) };
  let aps;
  if (sealed) {
    // Generic text, `mutable-content` so the NSE can open the envelope, and the
    // envelope itself at the top level. Never the plaintext details.
    aps = silent
      ? { 'content-available': 1 }
      : { alert: { title: 'Shinphony', body: e2eAlert(details?.category, event.status) },
        sound: 'default', 'mutable-content': 1, 'thread-id': sealed.hostRef };
  } else if (silent) {
    // Inbox-only update (Moshi's silent push): no banner, sound or badge.
    aps = { 'content-available': 1 };
  } else if (context) {
    // A helper names the conversation it belongs to in the title and keeps its
    // own name plus the status in the subtitle. Without a parent nothing
    // changes. Both fields are sanitised and capped like every other excerpt.
    const conversation = clipText(context.parentTitle, 120);
    const helper = clipText(context.session, 80);
    const status = shortStates[event.status];
    aps = { alert: {
      title: conversation || `${context.session} · Codex`,
      subtitle: conversation ? (helper ? `${helper} · ${status}` : status) : context.title,
      body: states[event.status] + (context.preview ? `\n${context.preview}` : '') },
    sound: 'default', 'thread-id': `${event.hostId}:${context.thread}` };
  } else if (details) {
    // Moshi: the reply excerpt is the title, the prompt excerpt the body.
    const label = [details.project, agents[details.agent]].filter(Boolean).join(' · ');
    aps = { alert: { title: details.title ?? states[event.status], ...(label ? { subtitle: label } : {}),
      body: details.body ?? states[event.status] }, sound: 'default',
    ...(details.session ? { 'thread-id': `${event.hostId}:${details.session}` } : {}) };
  } else {
    aps = { alert: { title: 'Shinphony', body: states[event.status] }, sound: 'default' };
  }
  const body = JSON.stringify({ aps, shinphony, ...(sealed ? { e2e: sealed.e2e, hostRef: sealed.hostRef } : {}) });
  if (Buffer.byteLength(body) > 4096) throw new Error('Notification payload too large');
  return {
    origin: environment === 'sandbox' ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com',
    headers: {
      ':method': 'POST', ':path': `/3/device/${deviceToken}`,
      authorization: `bearer ${jwt}`, 'apns-topic': topic,
      'apns-push-type': silent ? 'background' : 'alert', 'apns-priority': silent ? '5' : '10',
      'apns-expiration': String(Math.floor(now / 1000) + 300),
      'content-type': 'application/json',
    }, body,
  };
}

