// Ed25519 verification through WebCrypto. Cloudflare Workers expose the
// algorithm as "Ed25519"; older runtimes call it "NODE-ED25519". Both are
// signature checks against a raw 32-byte public key, so trying the second name
// only happens when the first is not implemented by the runtime.

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^a-f0-9]/i.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

const ALGORITHMS = ['Ed25519', 'NODE-ED25519'];

export async function verifyEd25519(publicKeyHex, message, signatureHex, subtle = globalThis.crypto?.subtle) {
  if (!subtle) return false;
  const publicKey = hexToBytes(publicKeyHex);
  const signature = hexToBytes(signatureHex);
  if (!publicKey || publicKey.length !== 32 || !signature || signature.length !== 64) return false;
  for (const algorithm of ALGORITHMS) {
    let key;
    try {
      key = await subtle.importKey('raw', publicKey, { name: algorithm }, false, ['verify']);
    } catch {
      continue; // Algorithm unknown to this runtime; try the next name.
    }
    try {
      return await subtle.verify({ name: algorithm }, key, signature, message);
    } catch {
      return false;
    }
  }
  return false;
}