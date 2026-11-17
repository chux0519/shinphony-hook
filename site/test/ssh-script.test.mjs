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
    'windows-sshd prepare-keys',
    '-Verb RunAs',
    'Shinphony needs administrator permission to turn on OpenSSH Server.',
    '$needsAdmin = (-not $status.running)',
    'Continue? [Y/n]',
  ]) {
    assert.ok(script.includes(line), line);
  }
  // Pairing runs exactly once, in the user's own window: the elevated block
  // never holds the QR.
  assert.equal(script.split('& $binary pair').length - 1, 1, 'pair runs once');
  assert.equal(script.includes('keys install'), false, 'the script never writes a key itself');
});

test('the pair script elevates only the setup steps', () => {
  const script = renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE);
  const start = script.indexOf('$command = @"');
  const end = script.indexOf('"@', start + 1);
  assert.ok(start > 0 && end > start, 'the elevated command is one here-string');
  const elevated = script.slice(start, end);
  // Enabling sshd and preparing the administrator key file need administrator
  // rights; the pairing itself does not and stays in the normal window.
  assert.ok(elevated.includes('windows-sshd enable'), 'the elevated window enables sshd');
  assert.ok(elevated.includes('windows-sshd prepare-keys'), 'the elevated window prepares the key file');
  assert.equal(elevated.includes('& $binary pair'), false, 'the elevated window never pairs');
  assert.equal(elevated.includes('keys install'), false, 'the elevated window installs no key');
  assert.ok(elevated.includes("if ('$prepare' -eq 'true')"), 'the elevated window prepares keys only for this account');
  assert.ok(elevated.includes('-ne \'$sid\''), 'the elevated window checks the account');
  // The elevated window only appends to the log the normal window created.
  assert.equal(elevated.includes('New-Item'), false, 'the elevated window creates no file');
  assert.ok(elevated.includes('*>> `$log'), 'the elevated window appends to the log');
});

test('the pair script only asks for administrator permission when it is needed', () => {
  const script = renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE);
  // The elevation branch is guarded by the status, so an account whose sshd is
  // running and whose firewall rule is enabled pairs in the same console.
  assert.ok(script.includes('$needsAdmin = (-not $status.running)'));
  assert.ok(script.includes('if ($needsAdmin) {'));
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

// The bug this guards against: `Set-Acl` and `SetOwner` from a non-elevated
// window fail with SeSecurityPrivilege and can leave the helper folder owned by
// Administrators, which made every later run fail the same way.
test('the setup scripts fix access rules only and never change the owner', () => {
  for (const [name, script] of [
    ['ssh.ps1', renderSSHPs1(TEMPLATE, VERIFIED, BASE)],
    ['pair.ps1', renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE)],
  ]) {
    assert.equal(script.includes('Set-Acl'), false, `${name} must not use Set-Acl`);
    assert.equal(script.includes('SetOwner'), false, `${name} must never set an owner`);
    assert.ok(script.includes("Get-FolderAcl $dir 'Access'"), `${name} reads the access section only`);
    assert.ok(script.includes("Get-FolderAcl $dir 'Owner'"), `${name} reads the owner separately`);
    assert.ok(script.includes('Set-FolderAcl $dir $acl') && script.includes('FileSystemAclExtensions'), `${name} writes the access section back`);
    // An unexpected owner is one sentence with the exact repair command.
    assert.ok(script.includes('belongs to another account'), `${name} explains a foreign owner`);
    assert.ok(script.includes('icacls "'), `${name} names icacls`);
    assert.ok(script.includes('/setowner "'), `${name} names /setowner`);
    assert.ok(script.includes('/T /C'), `${name} repairs the folder tree`);
    assert.ok(script.includes('then run this command again'), `${name} says to rerun`);
  }
});

// TF 160: an elevated administrator process creates .shinphony-agent owned by
// BUILTIN\Administrators, not by the user, and the scripts then refused the
// folder as "another account" on the next run. For an administrator account that
// owner is the same trust boundary, and the helper hands it back to the user; a
// standard user's folder must still be its own, and neither script elevates to
// change an owner.
test('the setup scripts accept Administrators as the owner on an administrator account', () => {
  for (const [name, script] of [
    ['ssh.ps1', renderSSHPs1(TEMPLATE, VERIFIED, BASE)],
    ['pair.ps1', renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE)],
  ]) {
    assert.ok(script.includes("@($me.Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' })"), `${name} reads administrator membership from the token`);
    assert.ok(script.includes("$isAdmin -and $owner.Value -eq 'S-1-5-32-544'"), `${name} accepts Administrators for an administrator`);
    assert.ok(script.includes('$owner.Value -ne $me.User.Value'), `${name} still requires this account's own SID otherwise`);
    // The decision stays in the owner check: no icacls run, no second elevation.
    assert.equal(/icacls[^\n]*\|\s*(iex|Invoke)/.test(script), false, `${name} never runs icacls`);
    assert.equal(script.split('-Verb RunAs').length - 1, 1, `${name} keeps one elevation`);
  }
});

// The elevated window writes a log the normal window prints, and the log file
// itself is created before elevation so it stays owned by the user.
test('the elevated window keeps its errors and logs them for the normal window', () => {
  for (const [name, script] of [
    ['ssh.ps1', renderSSHPs1(TEMPLATE, VERIFIED, BASE)],
    ['pair.ps1', renderPairPs1(PAIR_TEMPLATE, VERIFIED, BASE)],
  ]) {
    assert.ok(script.includes("('shinphony-elevated-' + [System.Guid]::NewGuid().ToString('N') + '.log')"), `${name} names the log`);
    assert.ok(script.includes('New-Item -ItemType File -Path $log'), `${name} creates the log before elevation`);
    assert.ok(script.includes("Read-Host 'Press Enter to close this window.'"), `${name} keeps the elevated window open`);
    assert.ok(script.includes('shinphony_elevated=failed'), `${name} marks a failed elevated step`);
    assert.ok(script.includes('What the administrator window reported:'), `${name} prints the log`);
    assert.ok(script.includes('Remove-Item -LiteralPath $log'), `${name} removes the log`);
  }
});
