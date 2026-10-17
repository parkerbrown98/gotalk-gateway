# Accounts and logistics

Phase 0 checklist for everything that needs a person, a payment method or a legal decision. These cannot be done
from the repository; the Phase 0 exit criteria ("the Apple/Google accounts exist") depend on them.

Never commit credentials. Provider keys go in the secrets store described in Phase 8; for local development use
untracked files or environment variables.

| Item | Owner | Status | Notes |
|---|---|---|---|
| Apple Developer Program membership (organization or individual) | Publisher | ⬜ | Needed for the app ID, the push entitlement and TestFlight. Organization enrollment needs a D-U-N-S number and takes longer. |
| App ID / bundle ID with Push Notifications capability | Publisher | ⬜ | Also create the App ID for the Notification Service Extension target (`<bundle id>.NotificationService`) and a keychain access group shared with it. |
| APNs authentication key (`.p8`), Key ID, Team ID | Publisher | ⬜ | One key serves sandbox and production and does not expire, but Apple allows few active keys per team. Keep the `.p8` out of the repo. |
| Firebase project and Android app (package name) | Publisher | ⬜ | Enable the Firebase Cloud Messaging API (v1). Upload the APNs key to Firebase only if the app uses FCM on iOS; this design sends to APNs directly. |
| FCM service account for the gateway | Publisher | ⬜ | Create a dedicated service account with only the role needed to send messages (`Firebase Cloud Messaging API Admin` at the narrowest scope that works). The Android client uses `google-services.json`; the gateway uses the service account JSON. |
| VAPID key pair (P-256) per app | Publisher | ⬜ | Generate once. The public key goes in discovery; the private key stays with the gateway. Rotating it invalidates every browser subscription, so treat it as long lived. |
| Domain for the gateway and its status page | Publisher | ⬜ | Decide the host (for example `push.<publisher domain>`) and which registrar and DNS provider hold it. Examples in this repo use `push.example`. |
| Name and trademark of the official gateway | Publisher | ⬜ | Run a trademark search, decide what "official" means, and draft the trademark policy for Phase 11. |
| Production hosting: Postgres, Redis, Kubernetes | Publisher | ⬜ | Needed for Phase 9. Not blocking for Phase 0. |
| Support and abuse contact mailbox, `security.txt` | Publisher | ⬜ | Referenced by `SECURITY.md` in Phase 8 and by the discovery document. |

## Proposed decisions to confirm

- **Direct APNs, not APNs via FCM.** Fewer moving parts, and the encrypted body passes through one provider.
- **One Firebase project and one APNs key per app**, so a white-label app (Phase 10) never shares credentials with the
  official one.
- **One VAPID key per app**, because browser subscriptions are bound to the key.
- **Iterate on a staging setup first**: a separate Firebase project and the Apple sandbox environment, with the
  production accounts used only at the Milestone A review.

## Licensing

Decided in this repository:

- Code is licensed **AGPL-3.0-only**, in [LICENSE](../LICENSE), so that a modified hosted gateway has to publish its
  changes. The protocol documents and the OpenAPI file are part of the same repository and carry the same license; the
  conformance suite planned for Phase 11 will be dual-licensed or permissively licensed if third-party implementers
  need it, to be decided then.
- Contributions use the **Developer Certificate of Origin** (`Signed-off-by`), described in
  [CONTRIBUTING.md](../CONTRIBUTING.md). A DCO was chosen over a CLA because it adds no paperwork for contributors and
  does not transfer copyright. The consequence is that relicensing later (for example to sell a non-AGPL commercial
  license) would need agreement from every contributor. If that option matters, switch to a CLA **before** accepting
  the first external contribution.
- `gotalk-server` is licensed **AGPL-3.0** (see its `LICENSE`) and `gotalk-client` is licensed **MIT**. The
  client is MIT because it ships through app stores, where copyleft licensing is awkward for outside
  contributions; it only talks to the server over the public API.
