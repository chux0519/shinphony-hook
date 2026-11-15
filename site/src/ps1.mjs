// The PowerShell setup scripts served by the site: /ssh.ps1 turns on Windows'
// OpenSSH Server, /pair.ps1 installs the helper and starts pairing.
//
// Both templates are filled with the hashes of the current verified release by
// the same renderer as /pair: every placeholder replaced, every hash
// well-formed, and a download base that is HTTPS or loopback only. When signed
// metadata cannot be verified the Worker answers 200 with a script that only
// prints a message and the `x-shinphony-setup: unavailable` header, because
// `irm` throws on a 4xx/5xx body and would hide the reason. Neither script calls
// `exit`: they run inside the user's own window through `irm ... | iex`.

import { renderWindowsScript } from './pair-script.mjs';

export function renderSSHPs1(template, verified, downloadBase) {
  return renderWindowsScript(template, verified, downloadBase);
}

export function renderPairPs1(template, verified, downloadBase) {
  return renderWindowsScript(template, verified, downloadBase);
}

export function unavailableSSHPs1() {
  return [
    '# Shinphony setup is temporarily unavailable. Nothing was installed.',
    "Write-Host 'Shinphony setup is temporarily unavailable. Nothing was installed. Try again in a minute.' -ForegroundColor Red",
    '',
  ].join('\n');
}

export function unavailablePairPs1() {
  return unavailableSSHPs1();
}
