# Shinphony push relay on Cloudflare Workers

Replaces the Node relay on the RackNerd VPS (`server/`), with the same routes, limits and
logic (`server/relay-core.mjs`, `server/pro-relay-core.mjs` are shared). One Worker serves
`notify.potafree.net`; each lane (`/`, `/testflight`, `/production`) is one Durable Object
whose SQLite holds that lane's relay. Deliveries run from the object's alarm.

| Lane | Prefix | APNs | Purchases | Registration |
| --- | --- | --- | --- | --- |
| sandbox | `/` | sandbox | Sandbox | invite only |
| testflight | `/testflight` | production | Sandbox | invite only |
| production | `/production` | production | Production (+ review Sandbox) | public |

`FREE_TIER=1`: devices without a purchase proof, 10 events per minute (Pro 60).

## Secrets (`wrangler secret put NAME`)

`APNS_TEAM_ID`; sandbox APNs key `APNS_KEY_ID`, `APNS_PRIVATE_KEY` (the .p8 text); production APNs key `APNS_PROD_KEY_ID`, `APNS_PROD_PRIVATE_KEY`; `IAP_KEY_ID`,
`IAP_ISSUER_ID`, `IAP_PRIVATE_KEY`, `ADMIN_TOKEN` (≥ 32 characters, for invites/import).
Local `wrangler dev` reads `.dev.vars` (git-ignored; throwaway keys are fine — APNs itself
only works from a deployed Worker, which negotiates HTTP/2).

## Admin

- Invite (invite-only lanes): `POST /admin/<lane>/invite` with `Authorization: Bearer $ADMIN_TOKEN`.
- Migration from the VPS: `tool/migrate_from_vps.py` (read-only on the VPS; dry run without `--apply`).

## Cutover (2026-11)

1. `npm ci && npx wrangler deploy`; set the secrets; check `https://<workers route>/production/health`.
2. Migrate with `tool/migrate_from_vps.py --apply`; counts must match.
3. Point `notify.potafree.net` at the Worker (custom domain); the VPS keeps running.
4. Keep the VPS 3 days as fallback, then stop the three `shinphony-push*` units.
