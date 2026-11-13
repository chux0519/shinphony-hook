import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isAllowedDownloadBase, renderPairScript, unavailableScript } from '../src/pair-script.mjs';

const TEMPLATE = readFileSync(new URL('../pair.sh.tmpl', import.meta.url), 'utf8');

const TARGETS = {
  'darwin-arm64': { sha256: '11'.repeat(32), length: 1 },
  'darwin-amd64': { sha256: '22'.repeat(32), length: 1 },
  'linux-arm64': { sha256: '33'.repeat(32), length: 1 },
  'linux-amd64': { sha256: '44'.repeat(32), length: 1 },
};
const VERIFIED = { sequence: 2026111201, targets: TARGETS };
const BASE = 'https://downloads.potafree.net';

test('the served script is fully filled and stays under the size limit', () => {
  const script = renderPairScript(TEMPLATE, VERIFIED, BASE);
  assert.match(script, /^#!\/bin\/sh\n/);
  for (const [platform, target] of Object.entries(TARGETS)) assert.ok(script.includes(target.sha256), platform);
  assert.ok(script.includes('2026111201'));
  assert.ok(script.includes(BASE));
  assert.equal(script.includes('@@'), false);
  assert.ok(Buffer.byteLength(script) < 8 * 1024, `script is ${Buffer.byteLength(script)} bytes`);
  for (const line of ['Run this as your normal user, without sudo.', '~/.shinphony-agent', 'exec "$binary" pair </dev/tty >/dev/tty']) {
    assert.ok(script.includes(line), line);
  }
});

test('a placeholder left in the template is refused', () => {
  assert.throws(() => renderPairScript(TEMPLATE + '\n@@EXTRA@@\n', VERIFIED, BASE), /template_placeholder_left/);
  assert.throws(
    () => renderPairScript(TEMPLATE.replace('@@LINUX_ARM64@@', 'aaa'), VERIFIED, BASE),
    /template_placeholder_missing/,
  );
  assert.throws(() => renderPairScript('no placeholders at all\n', VERIFIED, BASE), /template_placeholder_missing/);
});

test('missing or malformed hashes are refused', () => {
  for (const broken of [
    { ...VERIFIED, targets: { ...TARGETS, 'linux-amd64': undefined } },
    { ...VERIFIED, targets: { ...TARGETS, 'linux-amd64': { sha256: 'nothex', length: 1 } } },
    { ...VERIFIED, targets: { ...TARGETS, 'linux-amd64': { sha256: 'AB'.repeat(32), length: 1 } } },
  ]) {
    assert.throws(() => renderPairScript(TEMPLATE, broken, BASE), /target_hash_invalid/);
  }
  assert.throws(() => renderPairScript(TEMPLATE, { ...VERIFIED, sequence: 0 }, BASE), /sequence_invalid/);
  assert.throws(() => renderPairScript(TEMPLATE, { ...VERIFIED, sequence: 1.5 }, BASE), /sequence_invalid/);
});

test('only HTTPS and loopback downloads are allowed', () => {
  for (const good of [BASE, 'https://pair-test.example', 'https://127.0.0.1:8788', 'http://127.0.0.1:8788', 'http://localhost:9000']) {
    assert.equal(isAllowedDownloadBase(good), true, good);
    assert.ok(renderPairScript(TEMPLATE, VERIFIED, good).includes(`downloads=${good}`), good);
  }
  for (const bad of [
    'http://downloads.potafree.net',
    'http://example.com',
    'ftp://downloads.potafree.net',
    'https://downloads.potafree.net/path',
    'https://downloads.potafree.net ',
    '',
    null,
  ]) {
    assert.equal(isAllowedDownloadBase(bad), false, String(bad));
    assert.throws(() => renderPairScript(TEMPLATE, VERIFIED, bad), /download_base_invalid/);
  }
});

test('the unavailable script only prints and exits', () => {
  const script = unavailableScript();
  const lines = script.trimEnd().split('\n');
  assert.equal(lines[0], '#!/bin/sh');
  const commands = lines.filter((line) => line && !line.startsWith('#') && !line.startsWith('#!/'));
  assert.equal(commands.length, 2, script);
  assert.ok(commands[0].startsWith('echo '));
  assert.equal(commands[1], 'exit 1');
  assert.ok(!commandWordOutsideEcho(script));
});

// Guards against an accidental `curl | sh` payload in the failure script.
function commandWordOutsideEcho(script) {
  return script
    .split('\n')
    .filter((line) => !line.startsWith('#') && !line.startsWith('echo '))
    .some((line) => /(curl|wget|sh -c|eval|exec|rm |mv |cp |mkdir)/.test(line));
}