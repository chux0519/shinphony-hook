import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createSite } from '../src/index.mjs';
import { PINNED_ROOT } from '../src/pinned-root.mjs';
import { renderHookPage, unavailableHookPage, releaseDate } from '../src/hook-page.mjs';

const TEMPLATE = readFileSync(new URL('../pair.sh.tmpl', import.meta.url), 'utf8');
const FIXTURES = new URL('./fixtures/release-2026111201/', import.meta.url);
const fixture = (name) => new Uint8Array(readFileSync(new URL(name, FIXTURES)));
const RELEASED = Date.UTC(2026, 10, 12, 7, 0, 0);
const SEQUENCE = 2026111201;
const LINUX_ARM64 = '7efa42eae8d70cdfa00d8f2d4d4a9c5f2f176dbc239de3135ad550c0ad44cfb9';

function upstream({ status = {} } = {}) {
  const served = {
    timestamp: fixture('timestamp.json'),
    snapshot: fixture('snapshot.json'),
    targets: fixture('targets.json'),
  };
  return async (url) => {
    const role = url.slice(url.lastIndexOf('/') + 1).replace(/\.json$/, '');
    if (status[role]) return new Response('upstream failure', { status: status[role] });
    return new Response(served[role], { status: 200 });
  };
}

function site(overrides = {}) {
  return createSite({
    root: PINNED_ROOT,
    template: TEMPLATE,
    fetchImpl: upstream(overrides.upstream),
    now: overrides.now ?? (() => RELEASED),
    ...overrides.site,
  });
}

const request = (path, method = 'GET') => new Request(`https://shinphony.app${path}`, { method });

test('/hook renders the signed release and verification commands', async () => {
  const res = await site()(request('/hook'));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.text();
  assert.ok(body.includes(`<strong>${SEQUENCE}</strong>`));
  assert.ok(body.includes('2026-11-12'));
  assert.ok(body.includes(LINUX_ARM64));
  assert.ok(body.includes('shasum -a 256 ~/.shinphony-agent/shinphony-hook-*'));
  assert.ok(body.includes(`tool/verify_reproducible.sh ${SEQUENCE}`));
  assert.ok(body.includes('windows-arm64'), 'every platform is listed');
  assert.equal(body.includes('<script'), false, 'no JavaScript');
  assert.equal(body.includes('Source code:'), false, 'the source link is hidden until SOURCE_URL is set');
});

test('/hook shows the source link only for an https SOURCE_URL', async () => {
  const shown = await site({ site: { sourceUrl: 'https://github.com/example/shinphony-hook' } })(request('/hook'));
  assert.ok((await shown.text()).includes('href="https://github.com/example/shinphony-hook"'));

  const hidden = await site({ site: { sourceUrl: 'javascript:alert(1)' } })(request('/hook'));
  assert.equal((await hidden.text()).includes('Source code:'), false);
});

test('/hook never shows hashes when metadata cannot be verified', async () => {
  for (const failure of [
    { now: Date.UTC(2027, 0, 1) },
    { upstream: { status: { timestamp: 500 } } },
    { upstream: { status: { snapshot: 404 } } },
    { upstream: { status: { targets: 503 } } },
  ]) {
    const res = await site(failure)(request('/hook'));
    assert.equal(res.status, 503);
    const body = await res.text();
    assert.ok(body.includes('temporarily unavailable'));
    assert.equal(body.includes(LINUX_ARM64), false);
    assert.equal(body.includes('<script'), false);
    assert.equal(body.includes('shasum'), false);
  }
});

test('/hook supports HEAD and rejects other methods', async () => {
  const head = await site()(request('/hook', 'HEAD'));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert.equal((await site()(request('/hook', 'POST'))).status, 404);
});

test('the hook renderer refuses incomplete target sets', () => {
  const targets = { 'linux-arm64': { sha256: LINUX_ARM64, length: 1 } };
  assert.throws(() => renderHookPage({ sequence: SEQUENCE, targets }), /target_hash_invalid/);
  assert.throws(() => renderHookPage({ sequence: SEQUENCE }), /targets_missing/);
  assert.equal(unavailableHookPage().includes('<script'), false);
});

test('the release date comes from the sequence digits', () => {
  assert.equal(releaseDate(2026111201), '2026-11-12');
  assert.equal(releaseDate(2026130101), '');
  assert.equal(releaseDate(0), '');
});