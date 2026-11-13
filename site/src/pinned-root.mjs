// The one pinned trust root, shared with the Hook. The Worker bundles these
// exact bytes; the tests assert they still match deploy/root.json.
import root from '../../deploy/root.json' with { type: 'json' };

export const PINNED_ROOT = root;