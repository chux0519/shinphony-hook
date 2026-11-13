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
