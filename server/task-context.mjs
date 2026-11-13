// Bounded, versioned projection. Local socket paths, PIDs and commands are never
// accepted by the public relay. Task context includes bounded terminal text.
// parent/parentTitle/space name the hc conversation a helper belongs to; they
// are optional, so a helper without a live parent projects as it always did.
const optional = new Set(['preview', 'parentTitle', 'space']);
export function taskContext(value) {
  if (value === undefined || value === null) return undefined;
  const keys = ['version', 'agent', 'thread', 'title', 'multiplexer', 'session', 'window', 'preview', 'route', 'binary',
    'parent', 'parentTitle', 'space'];
  if (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.includes(k)) ||
      value.version !== 1 || value.agent !== 'codex' || !['tmux', 'hc'].includes(value.multiplexer)) throw new Error('invalid_context');
  for (const key of ['thread', 'route']) if (!/^[A-Za-z0-9_-]{1,64}$/.test(value[key] ?? '')) throw new Error('invalid_context');
  if (value.parent !== undefined && !/^t[0-9a-z]{1,32}$/.test(value.parent)) throw new Error('invalid_context');
  if (!/^[a-f0-9]{64}$/.test(value.binary ?? '')) throw new Error('invalid_context');
  for (const [key, limit] of [['title',120],['session',80],['window',80],['preview',700],['parentTitle',120],['space',80]]) {
    const text = value[key];
    if (text === undefined && optional.has(key)) continue;
    if (typeof text !== 'string' || Buffer.byteLength(text) > limit ||
        /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(text) ||
        (key !== 'preview' && /[\n\t]/.test(text)) || (key === 'preview' && text.split('\n').length > 6)) throw new Error('invalid_context');
  }
  return Object.fromEntries(keys.filter(k => value[k] !== undefined).map(k => [k,value[k]]));
}
