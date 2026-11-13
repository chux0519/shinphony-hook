import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  MetadataError,
  canonicalJson,
  parseEnvelope,
  parseExpiry,
  verifyMetadata,
} from '../src/tuf.mjs';
import { verifyEd25519 } from '../src/ed25519.mjs';
import { PINNED_ROOT } from '../src/pinned-root.mjs';

const FIXTURES = new URL('./fixtures/release-2026111201/', import.meta.url);
const fixture = (name) => new Uint8Array(readFileSync(new URL(name, FIXTURES)));
const RELEASED = Date.UTC(2026, 10, 12, 7, 0, 0);

// What release 2026111201 published (public values, also asserted by the
// release tool): the Worker must serve exactly these hashes.
const PUBLISHED = {
  'darwin-amd64': ['7d9003794d26c201b723eb267bb2282696e3fb86316e789496e2642bf593f020', 16347376],
  'darwin-arm64': ['0013152038b13adc1404c8fb9471c3c579e237f7c8f2ecfb1d1b414e00617e24', 15590834],
  'linux-amd64': ['ad4dcac8763f7173ce4bf3ab76956570068fa15349257688d6237296756cbbc9', 16220322],
  'linux-arm64': ['7efa42eae8d70cdfa00d8f2d4d4a9c5f2f176dbc239de3135ad550c0ad44cfb9', 15401122],
};

function publishedSet() {
  return {
    root: PINNED_ROOT,
    timestamp: fixture('timestamp.json'),
    snapshot: fixture('snapshot.json'),
    targets: fixture('targets.json'),
    now: RELEASED,
    verify: verifyEd25519,
  };
}

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof MetadataError, `expected MetadataError, got ${error?.name}: ${error?.message}`);
    assert.equal(error.code, code);
    return true;
  });
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const encoder = new TextEncoder();

async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicHex = hex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  return { privateKey: pair.privateKey, publicHex };
}

async function sign(key, signed) {
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, encoder.encode(canonicalJson(signed)));
  return hex(new Uint8Array(signature));
}

// A complete synthetic set signed by freshly generated keys. The pinned root
// stays untouched: this only exercises the verifier's own rules.
async function syntheticSet({ mutate } = {}) {
  const [rootKey, timestampKey, snapshotKey, targetsKey] = await Promise.all([newKey(), newKey(), newKey(), newKey()]);
  const keyEntry = (key) => ({ keytype: 'ed25519', scheme: 'ed25519', keyval: { public: key.publicHex } });
  const rootSigned = {
    _type: 'root',
    consistent_snapshot: true,
    expires: '2027-10-23T08:19:37.333271Z',
    keys: { kroot: keyEntry(rootKey), ktimestamp: keyEntry(timestampKey), ksnapshot: keyEntry(snapshotKey), ktargets: keyEntry(targetsKey) },
    roles: {
      root: { keyids: ['kroot'], threshold: 1 },
      timestamp: { keyids: ['ktimestamp'], threshold: 1 },
      snapshot: { keyids: ['ksnapshot'], threshold: 1 },
      targets: { keyids: ['ktargets'], threshold: 1 },
    },
    spec_version: '1.0.31',
    version: 1,
  };
  const targets = {};
  for (const [index, platform] of ['darwin-amd64', 'darwin-arm64', 'linux-amd64', 'linux-arm64'].entries()) {
    targets['agent/' + platform] = {
      custom: { apiVersion: 2, platform, sequence: 2026111201 },
      hashes: { sha256: String(index + 1).padStart(2, '0').repeat(32) },
      length: 1000 + index,
    };
  }
  const targetsSigned = { _type: 'targets', expires: '2026-12-12T06:48:26.75447397Z', spec_version: '1.0.31', targets, version: 41 };
  const targetsBytes = encoder.encode(JSON.stringify({ signatures: [{ keyid: 'ktargets', sig: await sign(targetsKey, targetsSigned) }], signed: targetsSigned }));
  const snapshotSigned = {
    _type: 'snapshot',
    expires: '2026-12-12T06:48:26.75447397Z',
    meta: { 'targets.json': { version: targetsSigned.version, length: targetsBytes.length, hashes: { sha256: hex(new Uint8Array(await crypto.subtle.digest('SHA-256', targetsBytes))) } } },
    spec_version: '1.0.31',
    version: 41,
  };
  const snapshotBytes = encoder.encode(JSON.stringify({ signatures: [{ keyid: 'ksnapshot', sig: await sign(snapshotKey, snapshotSigned) }], signed: snapshotSigned }));
  const timestampSigned = {
    _type: 'timestamp',
    expires: '2026-12-12T06:48:26.75447397Z',
    meta: { 'snapshot.json': { version: snapshotSigned.version, length: snapshotBytes.length, hashes: { sha256: hex(new Uint8Array(await crypto.subtle.digest('SHA-256', snapshotBytes))) } } },
    spec_version: '1.0.31',
    version: 41,
  };
  const timestampBytes = encoder.encode(JSON.stringify({ signatures: [{ keyid: 'ktimestamp', sig: await sign(timestampKey, timestampSigned) }], signed: timestampSigned }));
  const rootEnvelope = { signatures: [{ keyid: 'kroot', sig: await sign(rootKey, rootSigned) }], signed: rootSigned };

  const set = { root: rootEnvelope, timestamp: timestampBytes, snapshot: snapshotBytes, targets: targetsBytes, now: RELEASED, verify: verifyEd25519 };
  if (mutate) await mutate(set, { rootSigned, timestampSigned, snapshotSigned, targetsSigned, keys: { rootKey, timestampKey, snapshotKey, targetsKey } });
  return set;
}

test('canonical JSON sorts keys, keeps integers and rejects the rest', () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'x'] }), '{"a":[true,null,"x"],"b":1}');
  assert.equal(canonicalJson({ 'agent/a': { hashes: { sha256: 'ab' }, length: 2 } }), '{"agent/a":{"hashes":{"sha256":"ab"},"length":2}}');
  assert.throws(() => canonicalJson({ n: 1.5 }), MetadataError);
  assert.equal(canonicalJson('quote"and\\slash'), '"quote\\"and\\\\slash"');
});

test('expiry parsing handles go-tuf nanosecond fractions and offsets', () => {
  assert.equal(parseExpiry('2026-12-12T06:48:26.75447397Z'), Date.UTC(2026, 11, 12, 6, 48, 26, 754));
  assert.equal(parseExpiry('2026-12-12T06:48:26Z'), Date.UTC(2026, 11, 12, 6, 48, 26));
  assert.equal(parseExpiry('2026-12-12T08:48:26+02:00'), Date.UTC(2026, 11, 12, 6, 48, 26));
  for (const bad of [undefined, '', '2026-12-12', '06:48:26Z', '2026-13-12T06:48:26Z']) {
    assert.throws(() => parseExpiry(bad), MetadataError, String(bad));
  }
});

test('the pinned root is the Hook root and verifies the published release', async () => {
  const deployed = JSON.parse(readFileSync(new URL('../../deploy/root.json', import.meta.url), 'utf8'));
  assert.deepEqual(PINNED_ROOT, deployed);
  assert.equal(PINNED_ROOT.signed.roles.targets.keyids.length, 1);

  const result = await verifyMetadata(publishedSet());
  assert.equal(result.sequence, 2026111201);
  assert.deepEqual(Object.keys(result.targets).sort(), Object.keys(PUBLISHED).sort());
  for (const [platform, [sha256, length]] of Object.entries(PUBLISHED)) {
    assert.deepEqual(result.targets[platform], { sha256, length });
  }
});

test('expired metadata is rejected before any hash is returned', async () => {
  // Root expires 2027-10-23, timestamp/snapshot/targets 2026-12-12.
  await rejects(verifyMetadata({ ...publishedSet(), now: Date.UTC(2027, 0, 1) }), 'timestamp_expired');
  await rejects(verifyMetadata({ ...publishedSet(), now: Date.UTC(2030, 0, 1) }), 'root_expired');
});

test('tampered signatures, bodies and lengths are rejected', async () => {
  const timestamp = fixture('timestamp.json');
  const signatures = JSON.parse(new TextDecoder().decode(timestamp));
  signatures.signatures[0].sig = signatures.signatures[0].sig.replace(/^./, (c) => (c === '0' ? '1' : '0'));
  await rejects(
    verifyMetadata({ ...publishedSet(), timestamp: encoder.encode(JSON.stringify(signatures)) }),
    'timestamp_signature',
  );

  // The snapshot pins the targets bytes, so a changed signed value is a hash
  // mismatch before the signature is even consulted.
  const targets = JSON.parse(new TextDecoder().decode(fixture('targets.json')));
  const platform = Object.keys(targets.signed.targets)[0];
  targets.signed.targets[platform].hashes.sha256 = 'f'.repeat(64);
  await rejects(
    verifyMetadata({ ...publishedSet(), targets: encoder.encode(JSON.stringify(targets)) }),
    'targets_hash',
  );

  // (Targets bytes are pinned by the snapshot, so any change to them, including
  // their signatures, is reported as a hash mismatch. Signature rejection with
  // intact hashes is covered by the timestamp case above and the synthetic set.)

  // Whitespace leaves the signature valid but breaks the declared length/hash.
  const snapshot = fixture('snapshot.json');
  const padded = new Uint8Array(snapshot.length + 1);
  padded.set(snapshot);
  padded[snapshot.length] = 0x20;
  await rejects(verifyMetadata({ ...publishedSet(), snapshot: padded }), 'snapshot_length');

  const truncated = fixture('targets.json').slice(0, 100);
  await rejects(verifyMetadata({ ...publishedSet(), targets: truncated }), 'targets_length');

  await rejects(verifyMetadata({ ...publishedSet(), timestamp: encoder.encode('not json') }), 'timestamp_json');
  await rejects(
    verifyMetadata({
      ...publishedSet(),
      timestamp: encoder.encode(JSON.stringify({ ...JSON.parse(new TextDecoder().decode(fixture('timestamp.json'))), extra: 1 })),
    }),
    'timestamp_envelope',
  );
});

test('synthetic signed metadata round-trips through the verifier', async () => {
  const set = await syntheticSet();
  const result = await verifyMetadata(set);
  assert.equal(result.sequence, 41);
  assert.equal(result.targets['linux-arm64'].length, 1003);
  assert.equal(result.targets['darwin-arm64'].sha256, '02'.repeat(32));
});

test('valid signatures are not enough: versions, hashes and targets must agree', async () => {
  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          // Re-sign a snapshot whose declared targets hash is wrong.
          const snapshot = JSON.parse(new TextDecoder().decode(set.snapshot));
          snapshot.signed.meta['targets.json'].hashes.sha256 = 'e'.repeat(64);
          snapshot.signatures = [{ keyid: 'ksnapshot', sig: await sign(ctx.keys.snapshotKey, snapshot.signed) }];
          set.snapshot = encoder.encode(JSON.stringify(snapshot));
          // Keep the timestamp's own snapshot hash correct after the rewrite.
          const timestamp = JSON.parse(new TextDecoder().decode(set.timestamp));
          timestamp.signed.meta['snapshot.json'].length = set.snapshot.length;
          timestamp.signed.meta['snapshot.json'].hashes.sha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', set.snapshot)));
          timestamp.signatures = [{ keyid: 'ktimestamp', sig: await sign(ctx.keys.timestampKey, timestamp.signed) }];
          set.timestamp = encoder.encode(JSON.stringify(timestamp));
        },
      }),
    ),
    'targets_hash',
  );

  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          const timestamp = JSON.parse(new TextDecoder().decode(set.timestamp));
          timestamp.signed.meta['snapshot.json'].version = 40; // lagging snapshot
          timestamp.signatures = [{ keyid: 'ktimestamp', sig: await sign(ctx.keys.timestampKey, timestamp.signed) }];
          set.timestamp = encoder.encode(JSON.stringify(timestamp));
        },
      }),
    ),
    'snapshot_version',
  );

  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          const targets = JSON.parse(new TextDecoder().decode(set.targets));
          delete targets.signed.targets['agent/linux-arm64'];
          targets.signatures = [{ keyid: 'ktargets', sig: await sign(ctx.keys.targetsKey, targets.signed) }];
          set.targets = encoder.encode(JSON.stringify(targets));
          const snapshot = JSON.parse(new TextDecoder().decode(set.snapshot));
          snapshot.signed.meta['targets.json'].length = set.targets.length;
          snapshot.signed.meta['targets.json'].hashes.sha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', set.targets)));
          snapshot.signatures = [{ keyid: 'ksnapshot', sig: await sign(ctx.keys.snapshotKey, snapshot.signed) }];
          set.snapshot = encoder.encode(JSON.stringify(snapshot));
          const timestamp = JSON.parse(new TextDecoder().decode(set.timestamp));
          timestamp.signed.meta['snapshot.json'].length = set.snapshot.length;
          timestamp.signed.meta['snapshot.json'].hashes.sha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', set.snapshot)));
          timestamp.signatures = [{ keyid: 'ktimestamp', sig: await sign(ctx.keys.timestampKey, timestamp.signed) }];
          set.timestamp = encoder.encode(JSON.stringify(timestamp));
        },
      }),
    ),
    'target_missing',
  );

  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          const targets = JSON.parse(new TextDecoder().decode(set.targets));
          targets.signed.targets['agent/linux-arm64'].custom.platform = 'linux-amd64';
          targets.signatures = [{ keyid: 'ktargets', sig: await sign(ctx.keys.targetsKey, targets.signed) }];
          set.targets = encoder.encode(JSON.stringify(targets));
          const snapshot = JSON.parse(new TextDecoder().decode(set.snapshot));
          snapshot.signed.meta['targets.json'].length = set.targets.length;
          snapshot.signed.meta['targets.json'].hashes.sha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', set.targets)));
          snapshot.signatures = [{ keyid: 'ksnapshot', sig: await sign(ctx.keys.snapshotKey, snapshot.signed) }];
          set.snapshot = encoder.encode(JSON.stringify(snapshot));
          const timestamp = JSON.parse(new TextDecoder().decode(set.timestamp));
          timestamp.signed.meta['snapshot.json'].length = set.snapshot.length;
          timestamp.signed.meta['snapshot.json'].hashes.sha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', set.snapshot)));
          timestamp.signatures = [{ keyid: 'ktimestamp', sig: await sign(ctx.keys.timestampKey, timestamp.signed) }];
          set.timestamp = encoder.encode(JSON.stringify(timestamp));
        },
      }),
    ),
    'target_custom',
  );
});

// The root role must stay self-signed after a role change.
async function resignRoot(set, ctx) {
  set.root = { signatures: [{ keyid: 'kroot', sig: await sign(ctx.keys.rootKey, ctx.rootSigned) }], signed: ctx.rootSigned };
}

test('role thresholds and unknown keys are enforced', async () => {
  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          ctx.rootSigned.roles.timestamp = { keyids: ['ktimestamp'], threshold: 2 };
          await resignRoot(set, ctx);
        },
      }),
    ),
    'timestamp_threshold',
  );

  // Two keys, threshold two, only one signature: refused.
  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          ctx.rootSigned.roles.timestamp = { keyids: ['ktimestamp', 'ksnapshot'], threshold: 2 };
          await resignRoot(set, ctx);
        },
      }),
    ),
    'timestamp_signature',
  );

  // A listed keyid with a signature made by another key does not count.
  await rejects(
    verifyMetadata(
      await syntheticSet({
        mutate: async (set, ctx) => {
          const timestamp = JSON.parse(new TextDecoder().decode(set.timestamp));
          timestamp.signatures = [{ keyid: 'ktimestamp', sig: await sign(ctx.keys.targetsKey, timestamp.signed) }];
          set.timestamp = encoder.encode(JSON.stringify(timestamp));
        },
      }),
    ),
    'timestamp_signature',
  );
});

test('an unparsable envelope or missing verifier fails closed', async () => {
  assert.throws(() => parseEnvelope(encoder.encode('[]'), 'timestamp'), MetadataError);
  await rejects(verifyMetadata({ ...publishedSet(), verify: undefined }), 'verifier_missing');
  await rejects(
    verifyMetadata({ ...publishedSet(), now: Number.NaN }),
    'now_invalid',
  );
});

test('Ed25519 helper rejects wrong key or signature sizes', async () => {
  const key = await newKey();
  const signature = await sign(key, { hello: 'world' });
  const message = encoder.encode(canonicalJson({ hello: 'world' }));
  assert.equal(await verifyEd25519(key.publicHex, message, signature), true);
  assert.equal(await verifyEd25519(key.publicHex, encoder.encode('{"hello":"there"}'), signature), false);
  assert.equal(await verifyEd25519(key.publicHex.slice(2), message, signature), false);
  assert.equal(await verifyEd25519(key.publicHex, message, signature.slice(2)), false);
  assert.equal(await verifyEd25519('zz'.repeat(32), message, signature), false);
  assert.equal(await verifyEd25519(key.publicHex, message, signature, null), false);
});