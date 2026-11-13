// Staged authorization component. Not yet wired into the public relay routes.
// Never trust hasPro, a decoded-but-unverified JWT, or an old pre-refund proof.
import { AppStoreServerAPIClient, SignedDataVerifier, Environment, Type } from '@apple/app-store-server-library';
import { createHash } from 'node:crypto';

const appleRootHashes = new Set([
  'c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050',
  '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179',
]);

const bundleId = 'net.potafree.shinphony';
const productId = 'shinphony.pro.lifetime';
const appAppleId = 6774558021;
const transactionId = value => typeof value === 'string' && /^[0-9]{1,32}$/.test(value);
const reject = (code, status = 403) => { throw Object.assign(new Error(code), { code, status }); };
const checkJws = value => {
  if (typeof value !== 'string' || value.length > 24000 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) reject('invalid_proof');
};

// Official client transport otherwise has no end-to-end timeout. Override only
// transport, keeping Apple's JWT creation, API schema validation and verifier.
export class BoundedAppleClient extends AppStoreServerAPIClient {
  async makeFetchRequest(path, query, method, body, headers) {
    if (!['https://api.storekit.apple.com', 'https://api.storekit-sandbox.apple.com'].includes(this.urlBase)) {
      reject('invalid_apple_origin', 500);
    }
    if (method !== 'GET' || !/^\/inApps\/v1\/transactions\/[0-9]{1,32}$/.test(path)) {
      reject('unsupported_apple_request', 500);
    }
    const response = await fetch(`${this.urlBase}${path}?${query}`, {
      // 'manual' (not 'error'): Cloudflare Workers reject 'error'. Apple never
      // redirects these requests, so any 3xx is refused below.
      method, headers, redirect: 'manual', signal: AbortSignal.timeout(10000),
    });
    if (response.status >= 300 && response.status < 400) reject('verification_unavailable', 503);
    const chunks = [];
    let size = 0;
    if (response.body) {
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 32768) reject('apple_response_too_large', 503);
        chunks.push(chunk);
      }
    }
    return new Response(Buffer.concat(chunks), { status: response.status });
  }
}

// Explicit dependency injection allows offline adversarial policy tests. Only
// createAppleProVerifier is for runtime construction; no mock/skip-verify flag.
export class ProVerification {
  constructor({ verifier, client, environment, now = Date.now }) {
    if (![Environment.SANDBOX, Environment.PRODUCTION].includes(environment)) {
      throw new Error('Real Apple environment required');
    }
    this.verifier = verifier;
    this.client = client;
    this.environment = environment;
    this.now = now;
    this.busy = false;
  }
  validate(transaction) {
    if (!transaction || transaction.bundleId !== bundleId ||
        transaction.productId !== productId || transaction.environment !== this.environment ||
        transaction.type !== Type.NON_CONSUMABLE ||
        !transactionId(transaction.transactionId) || !transactionId(transaction.originalTransactionId) ||
        !Number.isSafeInteger(transaction.signedDate) || transaction.signedDate <= 0 ||
        transaction.signedDate > this.now() + 60000 ||
        transaction.revocationDate != null || transaction.revocationReason != null ||
        transaction.expiresDate != null || transaction.isUpgraded === true) reject('pro_required');
    return transaction;
  }
  async exclusive(action) {
    // No unbounded request queue, retry, cache, background job or idle timer.
    if (this.busy) reject('verification_busy', 429);
    this.busy = true;
    try { return await action(); }
    catch (error) {
      if (['pro_required', 'invalid_proof', 'verification_busy'].includes(error.code)) throw error;
      // Never forward Apple's exception message, which can contain request data.
      // The cause stays server-side only (operator diagnostics), never in replies.
      throw Object.assign(new Error('verification_unavailable'), { code: 'verification_unavailable', status: 503, cause: error });
    } finally { this.busy = false; }
  }
  async current(id, originalId) {
    const response = await this.client.getTransactionInfo(id);
    checkJws(response.signedTransactionInfo);
    const current = this.validate(await this.verifier.verifyAndDecodeTransaction(response.signedTransactionInfo));
    if (current.transactionId !== id || current.originalTransactionId !== originalId) reject('pro_required');
    return { transactionId: id, originalTransactionId: originalId,
      environment: this.environment, checkedAt: this.now() };
  }
  verify(proof) {
    return this.exclusive(async () => {
      checkJws(proof);
      const transaction = this.validate(await this.verifier.verifyAndDecodeTransaction(proof));
      // A valid old JWS is insufficient: ask Apple for current refund/revoke state.
      return this.current(transaction.transactionId, transaction.originalTransactionId);
    });
  }
  revalidate(binding) {
    return this.exclusive(async () => {
      if (binding?.environment !== this.environment || !transactionId(binding?.transactionId) ||
          !transactionId(binding?.originalTransactionId)) reject('pro_required');
      return this.current(binding.transactionId, binding.originalTransactionId);
    });
  }
}

export function createAppleProVerifier({ rootCertificates, privateKey, keyId, issuerId, environment }) {
  const appleEnvironment = { sandbox: Environment.SANDBOX, production: Environment.PRODUCTION }[environment];
  if (!appleEnvironment || !Array.isArray(rootCertificates) || rootCertificates.length === 0 ||
      !privateKey || !keyId || !issuerId) throw new Error('Complete Apple verification configuration required');
  if (!rootCertificates.every(root => Buffer.isBuffer(root) &&
      appleRootHashes.has(createHash('sha256').update(root).digest('hex')))) {
    throw new Error('Only pinned official Apple root certificates accepted');
  }
  return new ProVerification({ environment: appleEnvironment,
    verifier: new SignedDataVerifier(rootCertificates, true, appleEnvironment, bundleId, appAppleId),
    client: new BoundedAppleClient(privateKey, keyId, issuerId, bundleId, appleEnvironment),
  });
}

// The untrusted hint selects ONE verifier, never authorizes a request. That
// verifier must validate Apple's signature, environment and current entitlement.
// No fallback after signature/network/refund errors. Sandbox stays explicitly
// labeled in every binding; it is never upgraded to a Production purchase.
export class EnvironmentProVerification {
  constructor(production, sandbox) { this.production = production; this.sandbox = sandbox; this.busy = false; }
  select(environment) {
    if (environment === Environment.PRODUCTION) return this.production;
    if (environment === Environment.SANDBOX) return this.sandbox;
    reject('pro_required');
  }
  async exclusive(operation) {
    if (this.busy) reject('verification_busy', 429);
    this.busy = true;
    try { return await operation(); } finally { this.busy = false; }
  }
  verify(proof) {
    return this.exclusive(async () => {
      checkJws(proof);
      let hint;
      try { hint = JSON.parse(Buffer.from(proof.split('.')[1], 'base64url').toString('utf8')).environment; }
      catch { reject('invalid_proof'); }
      const result = await this.select(hint).verify(proof);
      if (result.environment !== hint) reject('pro_required');
      return result;
    });
  }
  revalidate(binding) {
    return this.exclusive(async () => {
      const result = await this.select(binding?.environment).revalidate(binding);
      if (result.environment !== binding.environment) reject('pro_required');
      return result;
    });
  }
}
