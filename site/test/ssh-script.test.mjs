import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderWindowsScript } from '../src/pair-script.mjs';
import { renderPairPs1, renderSSHPs1, unavailablePairPs1, unavailableSSHPs1 } from '../src/ps1.mjs';

const TEMPLATE = readFileSync(new URL('../ssh.ps1.tmpl', import.meta.url), 'utf8');

const TARGETS = {
  'darwin-arm64': { sha256: '11'.repeat(32), length: 1 },
  'darwin-amd64': { sha256: '22'.repeat(32), length: 1 },
  'linux-arm64': { sha256: '33'.repeat(32), length: 1 },
  'linux-amd64': { sha256: '44'.repeat(32), length: 1 },
  'windows-amd64': { sha256: '55'.repeat(32), length: 1 },
  'windows-arm64': { sha256: '66'.repeat(32), length: 1 },
};
const VERIFIED = { sequence: 2026111201, targets: TARGETS };
const BASE = 'https://downloads.potafree.net';

test('the served ssh script is fully filled with both Windows hashes', () => {
  const script = renderSSHPs1(TEMPLATE, VERIFIED, BASE);
  assert.ok(script.includes('$windowsAmd64 = \'' + TARGETS['windows-amd64'].sha256 + '\''));
  assert.ok(script.includes('$windowsArm64 = \'' + TARGETS['windows-arm64'].sha256 + '\''));
  assert.ok(script.includes(`$downloads = '${BASE}'`));
  assert.ok(script.includes('2026111201'));
  assert.equal(script.includes('@@'), false);
  assert.ok(Buffer.byteLength(script) < 16 * 1024, `script is ${Buffer.byteLength(script)} bytes`);
  for (const line of [
    'windows-sshd status',
    'windows-sshd enable',
    '-Verb RunAs',
    'Get-FileHash',
    'OpenSSH Server is $state ($start). Firewall: $firewall.',
  ]) {
    assert.ok(script.includes(line), line);
  }
});

test('a placeholder left in the template is refused', () => {
  assert.throws(() => renderWindowsScript(TEMPLATE + '\n# @@EXTRA@@\n', VERIFIED, BASE), /template_placeholder_left/);
  assert.throws(
    () => renderWindowsScript(TEMPLATE.replace('@@WINDOWS_ARM64@@', 'aaa'), VERIFIED, BASE),
    /template_placeholder_missing/,
  );
});

test('missing or malformed Windows hashes are refused', () => {
  for (const broken of [
    { ...VERIFIED, targets: { ...TARGETS, 'windows-amd64': undefined } },
    { ...VERIFIED, targets: { ...TARGETS, 'windows-arm64': { sha256: 'nothex', length: 1 } } },
    { ...VERIFIED, targets: { ...TARGETS, 'windows-amd64': { sha256: 'AB'.repeat(32), length: 1 } } },
  ]) {
    assert.throws(() => renderSSHPs1(TEMPLATE, broken, BASE), /target_hash_invalid/);
  }
  assert.throws(() => renderSSHPs1(TEMPLATE, { ...VERIFIED, sequence: 0 }, BASE), /sequence_invalid/);
  for (const bad of ['http://downloads.potafree.net', 'ftp://example.com', 'https://example.com/path']) {
    assert.throws(() => renderSSHPs1(TEMPLATE, VERIFIED, bad), /download_base_invalid/);
  }
});

test('the unavailable ssh script only prints, and closes nothing', () => {
  const script = unavailableSSHPs1();
  assert.ok(script.includes('temporarily unavailable'));
  assert.equal(/^\s*exit\b/m.test(script), false);
  assert.equal(script.includes('Invoke-WebRequest'), false);
  assert.equal(script.includes('windows-sshd'), false);
  assert.equal(script.includes('@@'), false);
});
const PAIR_TEMPLATE = readFileSync(new URL('../pair.ps1.tmpl', import.meta.url), 'utf8');

test('the served pair script installs the helper and pairs', () => {
  const script = renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE);
  assert.ok(script.includes('$windowsAmd64 = \'' + TARGETS['windows-amd64'].sha256 + '\''));
  assert.equal(script.includes('@@'), false);
  assert.ok(Buffer.byteLength(script) < 16 * 1024, `script is ${Buffer.byteLength(script)} bytes`);
  for (const line of [
    'Get-FileHash',
    'windows-sshd status',
    'windows-sshd enable',
    '-Verb RunAs',
    'Shinphony needs administrator permission to turn on OpenSSH Server and add your key.',
    "& $binary pair",
    'Continue? [Y/n]',
  ]) {
    assert.ok(script.includes(line), line);
  }
});

test('the pair script only asks for administrator permission when it is needed', () => {
  const script = renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE);
  // The elevation branch is guarded by the status, so an account whose sshd is
  // running and whose key file is its own pairs in the same console.
  assert.ok(script.includes('$needsAdmin = $status.isAdmin -or (-not $status.running)'));
  assert.ok(script.includes('& $binary pair'));
});

test('bad metadata refuses the pair script too', () => {
  assert.throws(() => renderPairPs1(PAIR_TEMPLATE, { ...VERIFIED, targets: {} }, BASE), /target_hash_invalid/);
  assert.throws(() => renderPairPs1(PAIR_TEMPLATE + '\n# @@EXTRA@@\n', VERIFIED, BASE), /template_placeholder_left/);
  assert.ok(unavailablePairPs1().includes('temporarily unavailable'));
  assert.equal(unavailablePairPs1().includes('windows-sshd'), false);
  assert.equal(/^\s*exit\b/m.test(unavailablePairPs1()), false);
});

// These scripts are run with `irm ... | iex` inside the user's own PowerShell
// window: `exit` would close it, and a temp .ps1 would leave a file in %TEMP%
// between writing and elevation.
test('the setup scripts never exit the user window and never write a temp script', () => {
  for (const [name, script] of [
    ['ssh.ps1', renderSSHPs1(TEMPLATE, VERIFIED, BASE)],
    ['pair.ps1', renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE)],
  ]) {
    // A statement that starts with `exit`; the comments mention the word.
    assert.equal(/^\s*exit\b/m.test(script), false, `${name} must not call exit`);
    assert.equal(script.includes('-.ps1'), false, `${name} must not name a temp script`);
    assert.equal(script.includes('Set-Content'), false, `${name} must not write a temp script`);
    assert.equal(script.includes('Join-Path ([System.IO.Path]::GetTempPath()) (' + "'" + 'shinphony-' + "'" + ' +'), false, `${name} must not create a temp script path`);
    assert.ok(script.includes('shinphony_setup_stopped: '), `${name} must use the Stop-Setup marker`);
    assert.ok(script.includes('-EncodedCommand'), `${name} must pass the elevated command as -EncodedCommand`);
    assert.ok(script.trimEnd().endsWith('}'), `${name} must end with the top-level catch`);
  }
});
