// Display projection only. Do not rewrite stored events, commands or routing
// context. Bounded input and conservative Markdown handling keep this cheap.
export function displayText(value) {
  if (typeof value !== 'string') return '';
  const source = [...value].slice(0, 4096).join('');
  let prefix = '\uE000';
  while (source.includes(prefix)) prefix += '\uE000';
  const protectedText = [];
  const protect = text => `${prefix}${protectedText.push(text) - 1}\uE001`;
  let fence;
  const lines = source.split(/\r?\n/).map(line => {
    const marker = line.match(/^\s{0,3}(`{3,}|~{3,})(.*)$/);
    if (fence) {
      if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length && !marker[2].trim()) {
        fence = undefined;
        return '';
      }
      return protect(line);
    }
    if (marker) { fence = marker[1]; return ''; }
    let text = line
      .replace(/\\([\\`*_{}\[\]()#+.!>~-])/g, (_, literal) => protect(literal))
      .replace(/(`+)([^`]+?)\1/g, (_, _ticks, code) => protect(code))
      .replace(/^\s{0,3}(?:#{1,6}\s+|(?:>\s*)+)/, '')
      .replace(/^\s{0,3}[-+*]\s+(?:\[[ xX]\]\s+)?/, '')
      .replace(/^\s{0,3}\d+[.)]\s+/, '')
      .replace(/!?\[([^\]\n]+)\]\(([^\s()]+)\)/g, (_, label, url) => label === url ? label : `${label} (${url})`)
      .replace(/(?<![\p{L}\p{N}_/])\*\*(?![*/.\s])(\S(?:.*?\S)?)\*\*(?![*/])/gu, '$1')
      // Hook excerpts may be cut at 80 characters before the closing marker.
      // Do not treat globstar paths or exponentiation as emphasis.
      .replace(/(^|\s)\*\*(?=[\p{L}\p{N}"“‘])/gu, '$1')
      .replace(/~~(\S(?:.*?\S)?)~~/g, '$1')
      .replace(/(^|[\s([{])__(\S(?:.*?\S)?)__(?=$|[\s\p{P}])/gu, '$1$2')
      .replace(/(^|[\s([{])\*([^*\s](?:[^*]*?[^*\s])?)\*(?=$|[\s\p{P}])/gu, '$1$2')
      .replace(/(^|[\s([{])_([^_\s](?:[^_]*?[^_\s])?)_(?=$|[\s\p{P}])/gu, '$1$2');
    return text;
  });
  let result = lines.join(' ').replace(/\s+/g, ' ').trim();
  for (let i = 0; i < protectedText.length; i++) result = result.replaceAll(`${prefix}${i}\uE001`, () => protectedText[i]);
  return result;
}

// Display text for a titled field (alert title, subtitle line, Live Activity
// conversation). Sanitising comes first so a cap never splits Markdown syntax,
// then the cap counts characters, not UTF-16 units or bytes.
export function clipText(value, limit = 4096) {
  const text = displayText(value);
  const chars = [...text];
  return chars.length > limit ? chars.slice(0, limit).join('') : text;
}
