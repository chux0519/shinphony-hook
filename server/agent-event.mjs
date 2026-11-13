// Optional v2 agent-event details (Moshi-style inbox categories). Bounded like
// Moshi's: up to 80 characters of the reply as title, 200 of the prompt as
// body, plus project/agent/session labels. Never paths, commands or PIDs.
export const categories = ['approval_required', 'question', 'task_complete', 'error',
  'session_started', 'session_ended', 'task_started', 'tool_running', 'tool_finished'];
export const agents = { codex: 'Codex', claude: 'Claude Code', dsh: 'DSH' };
export const detailFields = ['category', 'agent', 'session', 'title', 'body', 'project', 'visibility'];

const unsafe = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]/u;
function text(value, chars, { multiline = false } = {}) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || [...value].length > chars || Buffer.byteLength(value) > chars * 4 ||
      unsafe.test(value) || (!multiline && /[\n\t]/.test(value)) || value.split('\n').length > 6) throw new Error('invalid_details');
  return value.trim() || undefined;
}

export function agentDetails(body) {
  if (!detailFields.some(key => body[key] !== undefined)) return undefined;
  const d = {
    category: body.category, agent: body.agent, session: body.session,
    title: text(body.title, 80), body: text(body.body, 200, { multiline: true }),
    project: text(body.project, 64), visibility: body.visibility ?? 'banner',
  };
  if ((d.category !== undefined && !categories.includes(d.category)) ||
      (d.agent !== undefined && !Object.hasOwn(agents, d.agent)) ||
      (d.session !== undefined && !/^[a-f0-9]{32}$/.test(d.session)) ||
      !['banner', 'silent'].includes(d.visibility)) throw new Error('invalid_details');
  return Object.fromEntries(Object.entries(d).filter(([, v]) => v !== undefined));
}

// Private notifications (plan: Crypto). The relay never sees the text: it
// receives the category, an opaque hostRef and a sealed envelope that it only
// passes through to APNs. The envelope is bounded so one event stays one push.
export const e2eMaxEnvelope = 2800;
const e2eKeys = ['v', 'epk', 'n', 'ct'];
const base64url = /^[A-Za-z0-9_-]+$/;
// A pairing's Live Activity choice: true means today's plaintext title and
// terminal lines travel for the Live Activity only. Notifications stay sealed.
export const e2ePayload = body => {
  if (body.e2e === undefined && body.hostRef === undefined && body.silent === undefined && body.liveLines === undefined) return undefined;
  if (body.category === undefined) throw new Error('invalid_details');
  if (body.e2e === undefined || body.hostRef === undefined) throw new Error('invalid_e2e');
  if (typeof body.hostRef !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(body.hostRef)) throw new Error('invalid_host_ref');
  for (const flag of ['silent', 'liveLines']) {
    if (body[flag] !== undefined && typeof body[flag] !== 'boolean') throw new Error('invalid_e2e');
  }
  const e2e = body.e2e;
  if (!e2e || typeof e2e !== 'object' || Array.isArray(e2e) || Object.keys(e2e).some(key => !e2eKeys.includes(key)) ||
      e2e.v !== 1 || e2eKeys.slice(1).some(key => typeof e2e[key] !== 'string' || e2e[key].length > 4096 || !base64url.test(e2e[key]))) {
    throw new Error('invalid_e2e');
  }
  const epk = Buffer.from(e2e.epk, 'base64url'), nonce = Buffer.from(e2e.n, 'base64url'), sealed = Buffer.from(e2e.ct, 'base64url');
  if (epk.length !== 32 || nonce.length !== 12 || sealed.length < 17 || sealed.length > 2064) throw new Error('invalid_e2e');
  if (Buffer.byteLength(JSON.stringify(e2e)) > e2eMaxEnvelope) throw new Error('e2e_too_large');
  return { e2e, hostRef: body.hostRef, silent: body.silent === true, liveLines: body.liveLines === true };
};
