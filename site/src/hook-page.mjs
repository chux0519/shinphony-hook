// https://shinphony.app/hook — the public release and verification page.
//
// Plain HTML with no JavaScript, built from the same signed TUF metadata the
// /pair script uses. It lists the current sequence, its release date and the
// signed sha256 of every platform, plus the commands needed to check an
// installed binary or rebuild it. When metadata cannot be verified the page
// says so and shows no hashes at all.

const HASH_RE = /^[a-f0-9]{64}$/;
const HTTPS_URL_RE = /^https:\/\/[^\s"'<>]+$/;

const PLATFORMS = [
  ['darwin-arm64', 'macOS Apple silicon'],
  ['darwin-amd64', 'macOS Intel'],
  ['linux-arm64', 'Linux arm64'],
  ['linux-amd64', 'Linux x86_64'],
  ['windows-arm64', 'Windows arm64'],
  ['windows-amd64', 'Windows x86_64'],
];

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// Sequences are YYYYMMDDNN; the date comes from the sequence itself, so the
// page needs no extra metadata field.
export function releaseDate(sequence) {
  if (!Number.isSafeInteger(sequence) || sequence <= 0) return '';
  const text = String(sequence).padStart(10, '0');
  const year = text.slice(0, 4);
  const month = text.slice(4, 6);
  const day = text.slice(6, 8);
  if (Number(month) < 1 || Number(month) > 12 || Number(day) < 1 || Number(day) > 31) return '';
  return `${year}-${month}-${day}`;
}

function page(title, body) {
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(title)}</title>`,
    '<style>',
    'body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#111}',
    'h1{font-size:1.5rem}table{border-collapse:collapse;width:100%;margin:1rem 0}',
    'th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ddd;vertical-align:top}',
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem;word-break:break-all}',
    'pre{background:#f6f6f6;padding:.8rem;overflow-x:auto}',
    '.muted{color:#555}',
    '</style>',
    '</head>',
    '<body>',
    body,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

export function renderHookPage({ sequence, targets }, { sourceUrl = '' } = {}) {
  if (!Number.isSafeInteger(sequence) || sequence <= 0) throw new Error('sequence_invalid');
  if (!targets || typeof targets !== 'object') throw new Error('targets_missing');

  const rows = [];
  for (const [platform, label] of PLATFORMS) {
    const target = targets[platform];
    if (!target || typeof target.sha256 !== 'string' || !HASH_RE.test(target.sha256)) {
      throw new Error('target_hash_invalid');
    }
    rows.push(
      `<tr><td>${escapeHtml(label)}<br><span class="muted"><code>${escapeHtml(platform)}</code></span></td>` +
        `<td><code>${escapeHtml(target.sha256)}</code></td></tr>`,
    );
  }

  const date = releaseDate(sequence);
  const source =
    typeof sourceUrl === 'string' && HTTPS_URL_RE.test(sourceUrl)
      ? `<p>Source code: <a href="${escapeHtml(sourceUrl)}" rel="noopener">${escapeHtml(sourceUrl)}</a></p>`
      : '';

  const body = [
    '<h1>Shinphony Hook releases</h1>',
    `<p>Current stable release <strong>${escapeHtml(String(sequence))}</strong>` +
      (date ? ` (<time datetime="${date}">${date}</time>)` : '') +
      '.</p>',
    '<p>These hashes come from the release metadata signed by Shinphony and are re-verified by the Hook before it installs or updates. Windows binaries are installed by the Shinphony app; macOS and Linux use the one-line setup.</p>',
    '<table>',
    '<thead><tr><th>Platform</th><th>Signed SHA-256</th></tr></thead>',
    '<tbody>',
    ...rows,
    '</tbody>',
    '</table>',
    '<h2>Check an installed binary</h2>',
    '<pre><code>shasum -a 256 ~/.shinphony-agent/shinphony-hook-*</code></pre>',
    '<p class="muted">On Linux, <code>sha256sum</code> accepts the same arguments. Compare the output with the row above.</p>',
    '<h2>Reproduce the build</h2>',
    '<p>From a checkout of the public source, build all six targets with a clean Go cache and compare them with the signed hashes:</p>',
    `<pre><code>tool/verify_reproducible.sh ${escapeHtml(String(sequence))}</code></pre>`,
    source,
    '<p class="muted">See <code>docs/verify.md</code> in the source for details, and <code>SECURITY.md</code> to report a problem.</p>',
  ].join('\n');

  return page('Shinphony Hook releases', body);
}

export function unavailableHookPage() {
  return page(
    'Shinphony Hook releases',
    [
      '<h1>Shinphony Hook releases</h1>',
      '<p>Release information is temporarily unavailable.</p>',
      '<p class="muted">The signed release metadata could not be verified just now. No hashes are shown until it can be. Try again in a minute.</p>',
    ].join('\n'),
  );
}