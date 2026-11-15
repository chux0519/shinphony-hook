// Fills the reviewed bootstrap template with the hashes of the current verified
// release. A script with any placeholder left, a malformed hash or a non-HTTPS
// download base is never served.

import { SCRIPT_PLATFORMS } from './tuf.mjs';

const PLACEHOLDER = /@@[A-Z0-9_]+@@/g;
const HASH_RE = /^[a-f0-9]{64}$/;

const HASH_FIELDS = {
  'darwin-arm64': '@@DARWIN_ARM64@@',
  'darwin-amd64': '@@DARWIN_AMD64@@',
  'linux-arm64': '@@LINUX_ARM64@@',
  'linux-amd64': '@@LINUX_AMD64@@',
};

// The Windows hashes used by the PowerShell templates (/ssh.ps1, /pair.ps1).
export const WINDOWS_HASH_FIELDS = {
  'windows-amd64': '@@WINDOWS_AMD64@@',
  'windows-arm64': '@@WINDOWS_ARM64@@',
};

export function isAllowedDownloadBase(base) {
  if (typeof base !== 'string' || base.length === 0) return false;
  if (/\s/.test(base)) return false;
  if (base === 'https://downloads.potafree.net') return true;
  if (/^https:\/\/[a-z0-9.-]+(:\d{1,5})?$/.test(base)) return true;
  // Loopback HTTP exists for local testing of the installer only.
  return /^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(base);
}

// renderWindowsScript is the same fill-and-verify discipline for a PowerShell
// template: every placeholder replaced, every hash well-formed, nothing served
// from an unverified release.
export function renderWindowsScript(template, { sequence, targets }, downloadBase, hashFields = WINDOWS_HASH_FIELDS) {
  if (typeof template !== 'string' || template.length === 0) throw new Error('template_missing');
  if (!Number.isSafeInteger(sequence) || sequence <= 0) throw new Error('sequence_invalid');
  if (!isAllowedDownloadBase(downloadBase)) throw new Error('download_base_invalid');

  let script = template
    .split('@@SEQUENCE@@')
    .join(String(sequence))
    .split('@@DOWNLOAD_BASE@@')
    .join(downloadBase);

  for (const [platform, placeholder] of Object.entries(hashFields)) {
    const target = targets?.[platform];
    if (!target || typeof target.sha256 !== 'string' || !HASH_RE.test(target.sha256)) {
      throw new Error('target_hash_invalid');
    }
    if (!script.includes(placeholder)) throw new Error('template_placeholder_missing');
    script = script.split(placeholder).join(target.sha256);
  }

  const leftover = script.match(PLACEHOLDER);
  if (leftover) throw new Error('template_placeholder_left');
  return script;
}

export function renderPairScript(template, { sequence, targets }, downloadBase) {
  if (typeof template !== 'string' || template.length === 0) throw new Error('template_missing');
  if (!Number.isSafeInteger(sequence) || sequence <= 0) throw new Error('sequence_invalid');
  if (!isAllowedDownloadBase(downloadBase)) throw new Error('download_base_invalid');

  let script = template
    .split('@@SEQUENCE@@')
    .join(String(sequence))
    .split('@@DOWNLOAD_BASE@@')
    .join(downloadBase);

  for (const platform of SCRIPT_PLATFORMS) {
    const target = targets?.[platform];
    if (!target || typeof target.sha256 !== 'string' || !HASH_RE.test(target.sha256)) {
      throw new Error('target_hash_invalid');
    }
    const placeholder = HASH_FIELDS[platform];
    if (!script.includes(placeholder)) throw new Error('template_placeholder_missing');
    script = script.split(placeholder).join(target.sha256);
  }

  const leftover = script.match(PLACEHOLDER);
  if (leftover) throw new Error('template_placeholder_left');
  return script;
}

// Served as the body with status 200 and the `x-shinphony-setup: unavailable`
// header when signed metadata cannot be verified. The advertised command is
// `curl -fsSL`, which discards a 4xx/5xx body, so a 503 would leave the user
// with only curl's error line; 200 lets this message reach them. Echo only: it
// must never run anything or imply that something was installed.
export function unavailableScript() {
  return [
    '#!/bin/sh',
    '# Shinphony setup is temporarily unavailable. Nothing was installed.',
    "echo 'Shinphony setup is temporarily unavailable. Nothing was installed. Try again in a minute.' >&2",
    'exit 1',
    '',
  ].join('\n');
}

export const UNSUPPORTED_PLATFORM_TEXT =
  'Shinphony setup supports macOS and Linux. On Windows, run this in PowerShell: irm https://shinphony.app/pair.ps1 | iex';