// The Apple library calls node-fetch (for OCSP certificate checks). node-fetch
// needs node:http, which a Worker lacks: route it to the Worker's fetch, adding
// node-fetch's `timeout` option and `response.buffer()`.
import { Buffer } from 'node:buffer';

export default async function fetchShim(url, options = {}) {
  const { timeout, ...rest } = options;
  const response = await fetch(url, {
    ...rest, redirect: 'manual', signal: AbortSignal.timeout(timeout || 30000),
  });
  response.buffer = async () => Buffer.from(await response.arrayBuffer());
  return response;
}
export const Headers = globalThis.Headers;
export const Request = globalThis.Request;
export const Response = globalThis.Response;
