// https://shinphony.app — the router for the one-line setup (/pair) and the
// release page (/hook).
//
// GET /pair  -> bootstrap script with the current verified release hashes
// GET /hook  -> plain HTML release page (sequence, date, signed hashes, verify)
// GET /      -> 302 to the Shinphony product page
// everything else -> 404
//
// Verified hashes are cached in the isolate for at most five minutes. When the
// signed metadata cannot be verified the Worker answers 200 with a script that
// only prints a message and the `x-shinphony-setup: unavailable` header (a 4xx
// body would be swallowed by the `curl -fsSL` in the advertised command);
// unverified hashes are never served.

import { verifyEd25519 } from './ed25519.mjs';
import { MetadataError, MAX_METADATA_BYTES, RELEASE_PLATFORMS, verifyMetadata } from './tuf.mjs';
import { renderPairScript, unavailableScript } from './pair-script.mjs';
import { renderHookPage, unavailableHookPage } from './hook-page.mjs';

export const DEFAULT_METADATA_BASE = 'https://downloads.potafree.net/agent/stable/metadata';
export const DEFAULT_DOWNLOAD_BASE = 'https://downloads.potafree.net';
export const PRODUCT_URL = 'https://potafree.net/shinphony';
export const HASH_CACHE_MS = 5 * 60 * 1000;

const METADATA_ROLES = ['timestamp', 'snapshot', 'targets'];
const FETCH_TIMEOUT_MS = 5000;

function response(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...headers,
    },
  });
}

function html(body, status) {
  return response(body, status, { 'content-type': 'text/html; charset=utf-8' });
}

function text(body, status, headers = {}) {
  return response(body, status, { 'content-type': 'text/plain; charset=utf-8', ...headers });
}

async function fetchMetadata(fetchImpl, base, role) {
  const url = `${base}/${role}.json`;
  let res;
  try {
    res = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (error) {
    throw new MetadataError(role + '_unreachable');
  }
  if (!res || res.status !== 200) throw new MetadataError(role + '_status');
  const declared = Number(res.headers?.get?.('content-length') ?? '');
  if (Number.isFinite(declared) && declared > MAX_METADATA_BYTES) throw new MetadataError(role + '_size');
  let body;
  try {
    body = new Uint8Array(await res.arrayBuffer());
  } catch {
    throw new MetadataError(role + '_read');
  }
  if (body.length === 0 || body.length > MAX_METADATA_BYTES) throw new MetadataError(role + '_size');
  return body;
}

// One verified hash set per Worker configuration, refreshed at most every five
// minutes. Concurrent requests share one upstream load.
export function createHashCache({ root, fetchImpl, now, metadataBase, verify = verifyEd25519 }) {
  let entry = null;
  let inflight = null;

  async function load() {
    const files = {};
    for (const role of METADATA_ROLES) files[role] = await fetchMetadata(fetchImpl, metadataBase, role);
    return verifyMetadata({ root, ...files, now: now(), verify, platforms: RELEASE_PLATFORMS });
  }

  return {
    async get() {
      if (entry && now() < entry.expiresAt) return entry;
      if (!inflight) {
        inflight = load()
          .then((value) => {
            const cached = { ...value, expiresAt: now() + HASH_CACHE_MS };
            entry = cached;
            return cached;
          })
          .finally(() => {
            inflight = null;
          });
      }
      return inflight;
    },
    peek() {
      return entry;
    },
  };
}

export function createSite(options) {
  const {
    root,
    template,
    fetchImpl = (...args) => globalThis.fetch(...args),
    now = () => Date.now(),
    metadataBase = DEFAULT_METADATA_BASE,
    downloadBase = DEFAULT_DOWNLOAD_BASE,
    sourceUrl = '',
    verify = verifyEd25519,
  } = options ?? {};
  if (!root) throw new Error('pinned root required');
  if (typeof template !== 'string' || template.length === 0) throw new Error('pair template required');

  const cache = createHashCache({ root, fetchImpl, now, metadataBase, verify });

  return async function handle(request) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const head = method === 'HEAD';

    if (url.pathname === '/') {
      if (method !== 'GET' && !head) return text('Not found\n', 404);
      return response(null, 302, { location: PRODUCT_URL });
    }

    if (url.pathname === '/hook') {
      if (method !== 'GET' && !head) return text('Not found\n', 404);
      let body;
      try {
        const verified = await cache.get();
        body = renderHookPage(verified, { sourceUrl });
      } catch (error) {
        const code = error instanceof MetadataError ? error.code : error?.message;
        console.error('hook: refusing to show unverified hashes:', code);
        return html(head ? null : unavailableHookPage(), 503);
      }
      return html(head ? null : body, 200);
    }

    if (url.pathname === '/pair') {
      if (method !== 'GET' && !head) return text('Not found\n', 404);
      let body;
      try {
        const verified = await cache.get();
        body = renderPairScript(template, verified, downloadBase);
      } catch (error) {
        const code = error instanceof MetadataError ? error.code : error?.message;
        console.error('pair: refusing to serve unverified hashes:', code);
        const fallback = head ? null : unavailableScript();
        return text(fallback, 200, { 'x-shinphony-setup': 'unavailable' });
      }
      return text(head ? null : body, 200, { 'cache-control': 'no-store' });
    }

    return text('Not found\n', 404);
  };
}