// Edge entry for notify.potafree.net: picks the lane from the URL prefix (as
// nginx did), applies the same body limits, and forwards to that lane's relay
// object with the prefix removed.
import { LANES, RelayObject } from './relay-object.mjs';
export { RelayObject };

const limits = path => path === '/v1/register' || path === '/v1/device' ? 32768
  : path === '/v1/events' ? 4096 : 2048;

function route(pathname) {
  for (const [name, lane] of Object.entries(LANES)) {
    if (!lane.prefix) continue;
    if (pathname === lane.prefix + '/health' || pathname.startsWith(lane.prefix + '/v1/')) {
      return { lane: name, path: pathname.slice(lane.prefix.length) };
    }
  }
  if (pathname === '/health' || pathname.startsWith('/v1/')) return { lane: 'sandbox', path: pathname };
  return null;
}

async function same(a, b) {
  const [x, y] = await Promise.all([a, b].map(v => crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))));
  return crypto.subtle.timingSafeEqual(x, y);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // One-time invites for the invite-only lanes (was `pro-server.mjs --invite`).
    const admin = url.pathname.match(/^\/admin\/(sandbox|testflight|production)\/(invite|import|status|probe-verify)$/);
    if (admin) {
      const auth = request.headers.get('authorization') ?? '';
      if (request.method !== 'POST' || !env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 32 ||
          !(await same(auth, `Bearer ${env.ADMIN_TOKEN}`))) {
        return Response.json({ error: 'unauthorized' }, { status: 401 });
      }
      const stub = env.RELAY.get(env.RELAY.idFromName(admin[1]));
      const body = admin[2] === 'import' ? await request.text() : undefined;
      if (body && body.length > 20_000_000) return Response.json({ error: 'body_too_large' }, { status: 413 });
      return stub.fetch(new Request(`https://relay/__${admin[2]}`, { method: 'POST', body,
        headers: { 'x-shinphony-lane': admin[1], 'x-shinphony-admin': '1' } }));
    }
    const target = route(url.pathname);
    if (!target) return Response.json({ error: 'not_found' }, { status: 404 });
    const limit = limits(target.path);
    if (Number(request.headers.get('content-length') ?? 0) > limit) {
      return Response.json({ error: 'body_too_large' }, { status: 413 });
    }
    const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer();
    if (body && body.byteLength > limit) return Response.json({ error: 'body_too_large' }, { status: 413 });
    const headers = new Headers();
    for (const name of ['authorization', 'content-type']) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
    headers.set('x-shinphony-lane', target.lane);
    const stub = env.RELAY.get(env.RELAY.idFromName(target.lane));
    return stub.fetch(new Request('https://relay' + target.path, { method: request.method, headers, body }));
  },
};
