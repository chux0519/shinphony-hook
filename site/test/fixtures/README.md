# Worker test fixtures

`release-2026111201/` is the real, public TUF metadata set that release
2026111201 of the Hook publishes at
`https://downloads.potafree.net/agent/stable/metadata/` (fetched 2026-11-12,
byte for byte). It contains no secrets: only signatures and public hashes.

It is committed so the Worker's verifier is tested against what go-tuf actually
produces (canonical JSON, nanosecond expiry, `custom` target fields) instead of
only against fixtures the tests sign themselves. The tests use a fixed clock
(`2026-11-12`), so they do not start failing when the metadata expires.

To refresh after a release (only when a newer set is worth testing):

```sh
base=https://downloads.potafree.net/agent/stable/metadata
d=site/test/fixtures/release-<sequence>
mkdir -p "$d"
for f in timestamp snapshot targets; do curl -fsS "$base/$f.json" -o "$d/$f.json"; done
```

Then update `PUBLISHED` in `test/tuf.test.mjs` and the `RELEASED` date.
