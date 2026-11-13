// Worker entry point for the shinphony-site Worker (shinphony.app).
//
// Only this module knows about the reviewed template, the pinned root and the
// Worker variables; the routing logic lives in index.mjs so the tests can run it
// without bundler-only imports. SOURCE_URL is the public source link shown on
// /hook; it stays hidden while unset or not an https URL.

import template from '../pair.sh.tmpl';
import { PINNED_ROOT } from './pinned-root.mjs';
import { createSite, DEFAULT_DOWNLOAD_BASE, DEFAULT_METADATA_BASE } from './index.mjs';

// The isolates keep one handler (and its hash cache) per configuration.
let site = null;
let siteKey = null;

function configuredSite(env) {
  const metadataBase = (env?.METADATA_BASE || DEFAULT_METADATA_BASE).replace(/\/+$/, '');
  const downloadBase = (env?.DOWNLOAD_BASE || DEFAULT_DOWNLOAD_BASE).replace(/\/+$/, '');
  const sourceUrl = (env?.SOURCE_URL || '').trim();
  const key = `${metadataBase}|${downloadBase}|${sourceUrl}`;
  if (!site || key !== siteKey) {
    site = createSite({ root: PINNED_ROOT, template, metadataBase, downloadBase, sourceUrl });
    siteKey = key;
  }
  return site;
}

export default {
  async fetch(request, env) {
    return configuredSite(env)(request);
  },
};