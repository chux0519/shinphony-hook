// Verification of Shinphony's signed release metadata (TUF) for the /pair Worker.
//
// This is the reader side of the same pinned root the Hook ships in
// deploy/root.json: signatures over the canonical JSON of each role's `signed`
// object, role thresholds from the root, expiry on every role, and the
// snapshot/targets hashes and versions the signed metadata declares. Nothing
// from the network is trusted before these checks pass.

export class MetadataError extends Error {
  constructor(code) {
    super(code);
    this.name = 'MetadataError';
    this.code = code;
  }
}

export const MAX_METADATA_BYTES = 256 * 1024;

// The four platforms the bootstrap script can install (Windows uses the
// phone-pinned command instead).
export const SCRIPT_PLATFORMS = ['darwin-arm64', 'darwin-amd64', 'linux-arm64', 'linux-amd64'];

// The six platforms a release ships. /hook lists all of them; verified metadata
// always covers the full set so a partial release cannot reach either page.
export const RELEASE_PLATFORMS = [...SCRIPT_PLATFORMS, 'windows-arm64', 'windows-amd64'];

const ENVELOPE_KEYS = new Set(['signatures', 'signed']);
const HASH_RE = /^[a-f0-9]{64}$/;

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function bytesOf(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new MetadataError('metadata_not_bytes');
}

// TUF canonical JSON: object keys sorted, no insignificant whitespace, integers
// only. The release tool signs with go-tuf's encoder, whose output matches this
// for the ASCII fields these roles contain (checked against a real release
// fixture in the Worker tests).
export function canonicalJson(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new MetadataError('metadata_non_integer');
      return String(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
      const keys = Object.keys(value).sort();
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
    }
    default:
      throw new MetadataError('metadata_unsupported_value');
  }
}

// Accepts raw metadata bytes (what the network returns) or an already parsed
// envelope (the pinned root, which is bundled as JSON).
export function parseEnvelope(source, role) {
  let envelope;
  if (source instanceof Uint8Array || source instanceof ArrayBuffer) {
    const raw = bytesOf(source);
    if (raw.length === 0 || raw.length > MAX_METADATA_BYTES) throw new MetadataError(role + '_size');
    try {
      envelope = JSON.parse(new TextDecoder().decode(raw));
    } catch {
      throw new MetadataError(role + '_json');
    }
  } else if (isObject(source)) {
    envelope = source;
  } else {
    throw new MetadataError(role + '_envelope');
  }
  if (!isObject(envelope) || !isObject(envelope.signed) || !Array.isArray(envelope.signatures)) {
    throw new MetadataError(role + '_envelope');
  }
  for (const key of Object.keys(envelope)) {
    if (!ENVELOPE_KEYS.has(key)) throw new MetadataError(role + '_envelope');
  }
  return { signed: envelope.signed, signatures: envelope.signatures };
}

// Expiry strings are RFC 3339 with optional fractional seconds (go-tuf writes
// up to nanosecond precision). Parsed by hand so every runtime agrees.
export function parseExpiry(value) {
  if (typeof value !== 'string') throw new MetadataError('expiry_missing');
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!m) throw new MetadataError('expiry_invalid');
  const [, y, mo, d, h, mi, s, frac, zone] = m;
  if (+mo < 1 || +mo > 12 || +d < 1 || +d > 31 || +h > 23 || +mi > 59 || +s > 60) {
    throw new MetadataError('expiry_invalid');
  }
  let millis = Date.UTC(+y, +mo - 1, +d, +h, +mi, +s, frac ? +frac.slice(0, 3).padEnd(3, '0') : 0);
  if (zone !== 'Z') {
    const sign = zone[0] === '-' ? -1 : 1;
    millis -= sign * (+zone.slice(1, 3) * 60 + +zone.slice(4, 6)) * 60 * 1000;
  }
  if (!Number.isFinite(millis)) throw new MetadataError('expiry_invalid');
  return millis;
}

function assertFresh(signed, role, now) {
  if (parseExpiry(signed.expires) <= now) throw new MetadataError(role + '_expired');
}

function assertType(signed, role) {
  if (signed._type !== role) throw new MetadataError(role + '_type');
}

async function assertSignedBy(envelope, keys, role, roleName, now, verify) {
  if (!isObject(role) || !Array.isArray(role.keyids) || role.keyids.length === 0) throw new MetadataError(roleName + '_role');
  if (!Number.isSafeInteger(role.threshold) || role.threshold < 1 || role.threshold > role.keyids.length) {
    throw new MetadataError(roleName + '_threshold');
  }
  const message = new TextEncoder().encode(canonicalJson(envelope.signed));
  const valid = new Set();
  for (const signature of envelope.signatures) {
    if (!isObject(signature) || typeof signature.keyid !== 'string' || typeof signature.sig !== 'string') {
      throw new MetadataError(roleName + '_signature');
    }
    if (valid.has(signature.keyid) || !role.keyids.includes(signature.keyid)) continue;
    const key = keys[signature.keyid];
    if (!isObject(key) || key.keytype !== 'ed25519' || key.scheme !== 'ed25519' || !isObject(key.keyval)) continue;
    if (await verify(key.keyval.public, message, signature.sig)) valid.add(signature.keyid);
  }
  if (valid.size < role.threshold) throw new MetadataError(roleName + '_signature');
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytesOf(bytes));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function assertMeta(meta, role) {
  if (!isObject(meta)) throw new MetadataError(role + '_meta');
  if (!Number.isSafeInteger(meta.version) || meta.version <= 0) throw new MetadataError(role + '_version');
  if (!Number.isSafeInteger(meta.length) || meta.length <= 0 || meta.length > MAX_METADATA_BYTES) {
    throw new MetadataError(role + '_length');
  }
  if (!isObject(meta.hashes) || typeof meta.hashes.sha256 !== 'string' || !HASH_RE.test(meta.hashes.sha256)) {
    throw new MetadataError(role + '_hash');
  }
  return meta;
}

async function assertMetaBytes(raw, meta, name) {
  if (bytesOf(raw).length !== meta.length) throw new MetadataError(name + '_length');
  if ((await sha256Hex(raw)) !== meta.hashes.sha256) throw new MetadataError(name + '_hash');
}

// Verifies a full metadata set and returns { sequence, targets } where targets
// maps a platform to { sha256, length }.
export async function verifyMetadata({ root, timestamp, snapshot, targets, now, verify, platforms = SCRIPT_PLATFORMS }) {
  if (typeof now !== 'number' || !Number.isFinite(now)) throw new MetadataError('now_invalid');
  if (typeof verify !== 'function') throw new MetadataError('verifier_missing');

  const rootEnv = parseEnvelope(root, 'root');
  assertType(rootEnv.signed, 'root');
  assertFresh(rootEnv.signed, 'root', now);
  if (!isObject(rootEnv.signed.keys) || !isObject(rootEnv.signed.roles)) throw new MetadataError('root_roles');
  await assertSignedBy(rootEnv, rootEnv.signed.keys, rootEnv.signed.roles.root, 'root', now, verify);

  const timestampEnv = parseEnvelope(timestamp, 'timestamp');
  assertType(timestampEnv.signed, 'timestamp');
  assertFresh(timestampEnv.signed, 'timestamp', now);
  await assertSignedBy(timestampEnv, rootEnv.signed.keys, rootEnv.signed.roles.timestamp, 'timestamp', now, verify);
  if (!isObject(timestampEnv.signed.meta)) throw new MetadataError('timestamp_meta');
  const snapshotMeta = assertMeta(timestampEnv.signed.meta['snapshot.json'], 'snapshot');
  await assertMetaBytes(snapshot, snapshotMeta, 'snapshot');

  const snapshotEnv = parseEnvelope(snapshot, 'snapshot');
  assertType(snapshotEnv.signed, 'snapshot');
  assertFresh(snapshotEnv.signed, 'snapshot', now);
  if (snapshotEnv.signed.version !== snapshotMeta.version) throw new MetadataError('snapshot_version');
  await assertSignedBy(snapshotEnv, rootEnv.signed.keys, rootEnv.signed.roles.snapshot, 'snapshot', now, verify);
  if (!isObject(snapshotEnv.signed.meta)) throw new MetadataError('snapshot_meta');
  // go-tuf publishes the unversioned name even with consistent snapshots; accept
  // the versioned name too so a stricter release layout keeps working.
  const targetsEntry =
    snapshotEnv.signed.meta['targets.json'] ?? snapshotEnv.signed.meta[`${snapshotMeta.version}.targets.json`];
  const targetsMeta = assertMeta(targetsEntry, 'targets');
  await assertMetaBytes(targets, targetsMeta, 'targets');

  const targetsEnv = parseEnvelope(targets, 'targets');
  assertType(targetsEnv.signed, 'targets');
  assertFresh(targetsEnv.signed, 'targets', now);
  if (targetsEnv.signed.version !== targetsMeta.version) throw new MetadataError('targets_version');
  await assertSignedBy(targetsEnv, rootEnv.signed.keys, rootEnv.signed.roles.targets, 'targets', now, verify);
  if (!isObject(targetsEnv.signed.targets)) throw new MetadataError('targets_list');

  const verified = {};
  for (const platform of platforms) {
    const target = targetsEnv.signed.targets['agent/' + platform];
    if (!isObject(target)) throw new MetadataError('target_missing');
    const sha256 = isObject(target.hashes) ? target.hashes.sha256 : undefined;
    if (typeof sha256 !== 'string' || !HASH_RE.test(sha256)) throw new MetadataError('target_hash');
    if (!Number.isSafeInteger(target.length) || target.length <= 0 || target.length > 64 * 1024 * 1024) {
      throw new MetadataError('target_length');
    }
    if (!isObject(target.custom) || target.custom.platform !== platform || target.custom.apiVersion !== 2) {
      throw new MetadataError('target_custom');
    }
    verified[platform] = { sha256, length: target.length };
  }
  return { sequence: targetsEnv.signed.version, targets: verified };
}