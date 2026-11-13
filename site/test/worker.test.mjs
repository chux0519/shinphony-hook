import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSite, createHashCache, DEFAULT_DOWNLOAD_BASE, DEFAULT_METADATA_BASE, PRODUCT_URL } from '../src/index.mjs';
import { PINNED_ROOT } from '../src/pinned-root.mjs';

const TEMPLATE = readFileSync(new URL('../pair.sh.tmpl', import.meta.url), 'utf8');
const FIXTURES = new URL('./fixtures/release-2026111201/', import.meta.url);
const fixture = (name) => new Uint8Array(readFileSync(new URL(name, FIXTURES)));
const RELEASED = Date.UTC(2026, 10, 12, 7, 0, 0);
const LINUX_ARM64 = '7efa42eae8d70cdfa00d8f2d4d4a9c5f2f176dbc239de3135ad550c0ad44cfb9';

// A fake upstream that serves the published metadata set, with per-role
// overrides so failures can be injected.
function upstream({ files = {}, status = {}, size = {} } = {}) {
  const calls = [];
  const served = {
    timestamp: fixture('timestamp.json'),
    snapshot: fixture('snapshot.json'),
    targets: fixture('targets.json'),
    ...files,
  };
  const fetchImpl = async (url) => {
    calls.push(url);
    const role = url.slice(url.lastIndexOf('/') + 1).replace(/\.json$/, '');
    if (status[role]) return new Response('upstream failure', { status: status[role] });
    let body = served[role];
    if (size[role]) body = new Uint8Array(size[role]).fill(0x20);
    if (!body) return new Response('missing', { status: 404 });
    return new Response(body, { status: 200 });
  };
  return { calls, fetchImpl };
}

function site(overrides = {}) {
  const { calls, fetchImpl } = upstream(overrides.upstream);
  const handled = createSite({
    root: PINNED_ROOT,
    template: TEMPLATE,
    fetchImpl,
    now: overrides.now ?? (() => RELEASED),
    ...overrides.site,
  });
  return { calls, fetch: handled };
}

const request = (path, method = 'GET') => new Request(`https://shinphony.app${path}`, { method });

function shellSyntaxOk(script) {
  const file = join(mkdtempSync(join(tmpdir(), 'pair-script-')), 'pair.sh');
  writeFileSync(file, script);
  execFileSync('sh', ['-n', file], { stdio: 'pipe' });
}

test('/pair serves the filled bootstrap script with verified hashes', async () => {
  const { fetch, calls } = site();
  const res = await fetch(request('/pair'));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.text();
  assert.ok(body.includes(LINUX_ARM64));
  assert.ok(body.includes('2026111201'));
  assert.ok(body.includes(`downloads=${DEFAULT_DOWNLOAD_BASE}`));
  assert.equal(body.includes('@@'), false);
  assert.deepEqual(calls, [
    `${DEFAULT_METADATA_BASE}/timestamp.json`,
    `${DEFAULT_METADATA_BASE}/snapshot.json`,
    `${DEFAULT_METADATA_BASE}/targets.json`,
  ]);
  shellSyntaxOk(body);
});

// The advertised command is `curl -fsSL`, which throws away a 4xx/5xx body, so
// the fallback is served as 200 and flagged with a header instead.
const refused = async (res) => {
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-shinphony-setup'), 'unavailable');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.text();
  assert.ok(body.includes('temporarily unavailable'));
  assert.ok(!body.includes(LINUX_ARM64));
  assert.ok(!/curl|wget/.test(body));
  shellSyntaxOk(body);
  return body;
};

test('/pair serves an echo-only refusal when signatures break', async () => {
  const tampered = JSON.parse(new TextDecoder().decode(fixture('targets.json')));
  tampered.signatures[0].sig = tampered.signatures[0].sig.replace(/^./, (c) => (c === '0' ? '1' : '0'));
  const { fetch } = site({ upstream: { files: { targets: new Uint8Array(Buffer.from(JSON.stringify(tampered))) } } });
  await refused(await fetch(request('/pair')));
});

test('/pair refuses expired metadata, broken upstreams and oversized bodies', async () => {
  await refused(await site({ now: Date.UTC(2027, 0, 1) }).fetch(request('/pair')));

  for (const role of ['timestamp', 'snapshot', 'targets']) {
    await refused(await site({ upstream: { status: { [role]: 500 } } }).fetch(request('/pair')));
  }
  await refused(await site({ upstream: { status: { timestamp: 302 } } }).fetch(request('/pair')));
  await refused(await site({ upstream: { size: { targets: 300 * 1024 } } }).fetch(request('/pair')));
  await refused(await site({ upstream: { files: { targets: null } } }).fetch(request('/pair')));
});

test('verified hashes are cached for five minutes and shared by concurrent requests', async () => {
  let now = RELEASED;
  const { calls, fetch } = site({ now: () => now });
  assert.equal((await fetch(request('/pair'))).status, 200);
  assert.equal((await fetch(request('/pair'))).status, 200);
  assert.equal(calls.length, 3);

  now += 5 * 60 * 1000 - 1;
  assert.equal((await fetch(request('/pair'))).status, 200);
  assert.equal(calls.length, 3);

  now += 2; // past the cache window
  assert.equal((await fetch(request('/pair'))).status, 200);
  assert.equal(calls.length, 6);

  const concurrent = site();
  const [a, b] = await Promise.all([concurrent.fetch(request('/pair')), concurrent.fetch(request('/pair'))]);
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  assert.equal(concurrent.calls.length, 3);
});

test('a failed load is not cached', async () => {
  let fail = true;
  let requests = 0;
  const { fetchImpl } = upstream();
  const fetch = createSite({
    root: PINNED_ROOT,
    template: TEMPLATE,
    fetchImpl: async (url) => {
      requests += 1;
      return fail && url.endsWith('targets.json') ? new Response('down', { status: 503 }) : fetchImpl(url);
    },
    now: () => RELEASED,
  });
  const first = await fetch(request('/pair'));
  assert.equal(first.headers.get('x-shinphony-setup'), 'unavailable');
  assert.equal(requests, 3, 'timestamp, snapshot and the failing targets fetch');
  fail = false;
  assert.equal((await fetch(request('/pair'))).status, 200, 'a verified set is served as soon as the upstream recovers');
  assert.equal(requests, 6, 'both metadata sets were fetched again');
});

test('the root redirect and unknown paths', async () => {
  const { fetch, calls } = site();
  const root = await fetch(request('/'));
  assert.equal(root.status, 302);
  assert.equal(root.headers.get('location'), PRODUCT_URL);
  assert.equal(root.headers.get('cache-control'), 'no-store');

  for (const path of ['/other', '/pair/x', '/pair/', '/PAIR', '/favicon.ico']) {
    const res = await fetch(request(path));
    assert.equal(res.status, 404, path);
    assert.equal(res.headers.get('cache-control'), 'no-store');
  }
  const post = await fetch(request('/pair', 'POST'));
  assert.equal(post.status, 404);
  assert.equal(calls.length, 0, 'no metadata is fetched for other paths');
});

test('HEAD works without a body', async () => {
  const { fetch } = site();
  const pair = await fetch(request('/pair', 'HEAD'));
  assert.equal(pair.status, 200);
  assert.equal(await pair.text(), '');
  const root = await fetch(request('/', 'HEAD'));
  assert.equal(root.status, 302);
  assert.equal(root.headers.get('location'), PRODUCT_URL);
});

test('the download base can be overridden for local testing only', async () => {
  const local = site({ site: { downloadBase: 'http://127.0.0.1:8788' } });
  const res = await local.fetch(request('/pair'));
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes('downloads=http://127.0.0.1:8788'));

  const invalid = site({ site: { downloadBase: 'http://example.com' } });
  await refused(await invalid.fetch(request('/pair')));

  const customBase = site({ site: { metadataBase: 'https://pair-test.example/stable/metadata' } });
  assert.equal((await customBase.fetch(request('/pair'))).status, 200);
  assert.ok(customBase.calls[0].startsWith('https://pair-test.example/stable/metadata/'));
});

test('a site without a pinned root or template refuses to be constructed', () => {
  assert.throws(() => createSite({ template: TEMPLATE }), /pinned root required/);
  assert.throws(() => createSite({ root: PINNED_ROOT }), /pair template required/);
});

test('the hash cache exposes its last verified entry', async () => {
  const { fetchImpl } = upstream();
  const cache = createHashCache({ root: PINNED_ROOT, fetchImpl, now: () => RELEASED, metadataBase: DEFAULT_METADATA_BASE });
  assert.equal(cache.peek(), null);
  const value = await cache.get();
  assert.equal(value.sequence, 2026111201);
  assert.equal(cache.peek().sequence, 2026111201);
  assert.equal(value.expiresAt, RELEASED + 5 * 60 * 1000);
  assert.deepEqual(value.targets['linux-arm64'], {
    sha256: LINUX_ARM64,
    length: 15401122,
  });
});