# Threat model

Part of the [gateway protocol](protocol.md). Scope: the push gateway, its protocol, and the data that crosses it.
Phase 8 must map every mitigation below to a test or a documented control.

## On this page

- [Assets](#assets)
- [Actors and trust](#actors-and-trust)
- [What the gateway can and cannot see](#what-the-gateway-can-and-cannot-see)
- [Threats and mitigations](#threats-and-mitigations)
- [Residual risks](#residual-risks)
- [Out of scope](#out-of-scope)

## Assets

| Asset | Why it matters |
|---|---|
| Notification content | Messages and forum text. Must not be readable by the gateway or providers. |
| Device private keys | Decrypt content. Never leave the device. |
| Platform tokens and web endpoints | Whoever has one can push to the device through the provider, if they also hold the app's provider credentials. |
| Provider credentials (APNs key, FCM service account, VAPID keys) | Compromise lets an attacker push to every installed app. Gateway-only. |
| Instance private keys | Authenticate pushes as one instance. |
| Subscription secrets | Authenticate a client's refresh and delete calls. |
| Gateway availability and quota | Free capacity is shared; abuse costs money and harms deliverability. |
| User attention | Spam or spoofed notifications on real devices. |

## Actors and trust

| Actor | Trust |
|---|---|
| Gateway operator | Trusted with metadata and credentials, **not** with content. A compromise is modeled below. |
| Instance operator | Trusted only to speak for its own users on its own origin. |
| Client app | Trusted by its user. Unauthenticated toward the gateway at registration. |
| Providers (Apple, Google, browser vendors) | See ciphertext and metadata, can drop or delay pushes, and can see device tokens. |
| Network attacker | Controls the path between any two parties. TLS is required on every hop. |

## What the gateway can and cannot see

| The gateway **can** see | The gateway **cannot** see |
|---|---|
| Instance origin, contact email, keys and software version | Notification title, body, sender, place, channel or topic names |
| Platform token or web endpoint, platform, app, APNs environment | Device private keys, device public keys, `auth` secrets |
| Which instance pushes to which subscription, when, and how often | Which user or account on the instance a subscription belongs to |
| Encrypted body size (padded) and the urgency, TTL and collapse key | Content of the encrypted body |
| `notification_id` and the instance origin in `id_only` mode | Anything about the recipient beyond the subscription |
| Client IP addresses at registration and refresh | |

The collapse key is a metadata hint chosen by the instance. Instances should derive it from a hash of the
conversation, never from content or names. Providers additionally see the device token and the encrypted body, and
can see message timing.

The gateway stores the encrypted body only in its delivery queue: until the push is delivered, plus a minute, or for
`delivery.dead_letter_retention` (default 24 hours) when its retries run out. The delivery log keeps IDs, status,
attempts, latency and the provider's short failure reason for 72 hours, never the body.

## Threats and mitigations

Format: threat, then what stops it or limits it. "Test" names where Phase 2 to 8 should prove it.

### Rogue instance

An instance operator abuses the gateway or the users registered for it.

| Threat | Mitigation |
|---|---|
| Pushes to devices registered for other instances | Every subscription is bound to one origin. A signed push whose key belongs to another instance gets `subscription_not_found`. *Test: cross-instance push and push-status reads are rejected (`TestPushCrossInstance`); cross-instance delete is rejected (`TestDeviceCrossInstanceMisuse`).* |
| Spam to its own subscribers | Per-instance daily quota, per-device hourly cap, urgency and TTL limits, automatic temporary blocks and a manual blocklist with a visible reason. |
| Impersonating another app or sender in the notification text | The client composes the notification from structured fields and always shows the instance name; the undecrypted fallback is gateway-controlled text. |
| Registering as someone else's origin | Domain verification through the origin's own well-known document. Squatted pending registrations never verify and expire. A recovery key for someone else's verified origin can only call `verify`, so it reveals nothing about the instance. *Test: `TestRecovery`, `TestPrune`.* |
| Using the gateway as a request forger (SSRF through verification) | Fetch rules: HTTPS, public addresses only, checked at connect, no redirects, size and time limits, per-IP and per-origin rate limits. *Test: private-range and redirect cases (`internal/wellknown`).* |
| Learning device identity | The instance never gets a token or endpoint, only a subscription ID it was given by the device. A fresh key pair per subscription prevents cross-instance linking by key. |

### Rogue client

| Threat | Mitigation |
|---|---|
| Mass-registering fake devices to exhaust quotas or storage | Per-IP (IPv6 per /64) and per-token registration limits, short unrefreshed expiry, attestation on the official gateway (Phase 8). Registration is only possible for verified, active instances. *Test: `TestDeviceRateLimits`, `TestDeviceRegistrationNeedsActiveInstance`.* |
| Registering someone else's token for a rogue instance, to spam that person | Needs the victim's platform token, which providers treat as secret. With a token, a rogue instance can only push what the rogue operator writes, within the same quotas and with the instance name shown. |
| Registering for a real instance to read someone else's notifications | Content is encrypted to a key the registrant controls and shares with the instance. An attacker gets only what the instance would send to the attacker's own account. |
| Taking over another device's subscription by re-registering its token | Needs the token. The previous secret is invalidated, so a rightful owner who still holds the token can reclaim it. |
| Probing which subscriptions exist | Missing, unauthorized and foreign subscriptions return the same `404`. IDs are 128-bit and secrets 256-bit random values. *Test: `TestDeviceCrossInstanceMisuse`.* |
| Using the gateway as a request forger (SSRF through a Web Push endpoint) | Endpoints must be https on port 443 at a known push service (`devices.web_push_hosts`), checked at registration and again before each delivery. Deliveries connect only to public addresses on port 443, checked after DNS resolution on every connection, with no redirects and no proxies. The request is a fixed-shape `POST` whose body the instance chose but whose headers the gateway sets. *Test: `TestWebEndpoints`, `TestConnectionsOnlyGoToPublicAddresses`, `TestRedirectsAreNotFollowed`, `TestRefusedBeforeSending`.* |

### Stolen instance key

| Threat | Mitigation |
|---|---|
| Attacker pushes as the instance | Limited to that instance's subscriptions and quota. The attacker does not hold the devices' `auth` secrets, so they cannot form valid payloads, but garbage pushes still reach devices as fallback alerts and cost quota. |
| Silent long-term use | Recovery through domain control: re-registering the origin with a new key advertised in the well-known document revokes every other key (see protocol). Operators get contact-email notices on key changes and anomalies. Gateway operators can block an instance immediately. |
| Replay of captured requests | Timestamp window, per-key nonce cache, host binding in the signature. *Test: `TestSignatureRejections`, `TestReplicasShareNoncesThroughRedis`.* |

If the attacker also has the instance's database they hold `p256dh` and `auth` for the subscriptions, and can
forge convincing content to those devices until the subscriptions are rotated. They cannot read past pushes
(they would need the device private key).

### Stolen device token or endpoint

| Threat | Mitigation |
|---|---|
| Registering the token with a rogue origin | See rogue client. The token alone does not let an attacker push: pushes go through the app's credentials, which only the gateway holds. |
| Pushing to the token directly | Not possible without the app's APNs, FCM or VAPID credentials. |
| Silently deleting the legitimate subscription | Deletion needs the subscription secret or the bound instance's signature. |

### Stolen subscription secret

An attacker who has it can refresh, change the token for, or delete that one subscription. They cannot push.
Re-registering with the real token (see above) rotates the secret. The secret is never given to the instance.

### Gateway compromise

| Threat | Mitigation |
|---|---|
| Reading notification content | Not possible: content is encrypted end to end between instance and device. The attacker sees ciphertext and metadata. |
| Pushing arbitrary notifications through provider credentials | **Possible.** Mitigated only by the fallback being generic and clients rendering from decrypted fields: a forged push has no valid ciphertext, so clients show the fallback or drop it. Credentials are stored encrypted, rotated per a runbook, and scoped to push only (no other Firebase or Apple permissions). |
| Redirecting a subscription to a different instance | The attacker could re-bind records, but content still goes to a device whose key the new instance does not have; the device would drop or fall back. |
| Stealing instance public keys | They are public. |
| Dumping the device table | Exposes platform tokens and instance bindings (metadata). Tokens are only useful with provider credentials, which are separate. Subscription secrets are stored hashed. |

### Provider compromise or malice

Providers can read ciphertext metadata, delay, drop or replay pushes and see the device token. They cannot read
content. Clients de-duplicate on `notification_id` and never assume delivery.

### Replay and spam in general

| Threat | Mitigation |
|---|---|
| Request replay | Nonce cache keyed by key ID, 600 second retention against a 300 second window. |
| Clock skew abuse | Window is symmetric ±300 seconds; `Date` is returned on `stale_timestamp` for debugging. |
| Provider replay of an old push | Client de-duplication on `notification_id`; TTL bounds how long a provider holds a push. |
| Instance retries causing duplicate pushes | `Idempotency-Key` replays the original response for 24 hours. *Test: `TestPushIdempotency`.* |
| A late dead-token report killing a refreshed subscription | Marking a subscription gone is a compare-and-set on the token the push was sent to. *Test: `TestDeliverIgnoresDeadTokenReportForReplacedToken`.* |
| Resource exhaustion | Body size limits, a 100 entry batch limit, per-instance and per-IP rate limits, a bounded queue per instance, and request timeouts. |
| Slow verification fetches used for amplification | 5 second timeout, one fetch per pending registration and per 24 hour verification, global concurrency cap. |
| Enumeration of instances | `GET /v1/instances/{id}` requires a signature from that instance; discovery is the only public instance-independent data. |

## Residual risks

- **Metadata is visible** to the gateway and to providers: which instance pushes to which device, and when.
  Operators who cannot accept this run their own gateway.
- **Gateway compromise can send fallback alerts** to every device. Content stays safe, but a user may see a
  generic "New notification" they did not expect.
- **A user who adds a malicious instance** accepts that its operator can push to them. They can disable pushes per
  instance or remove it, which deletes the subscription.
- **Providers can censor or delay** delivery.
- **Registration is unauthenticated** by design (a device cannot prove it is logged in to an instance), so quotas,
  attestation and the blocklist carry the abuse load.
- **Single-node gateways without Redis** accept a replay within the skew window after a restart.

## Out of scope

- Compromise of the user's device or the instance server itself (an instance operator can read content they
  host).
- Browser or mobile-OS vulnerabilities in notification rendering.
- Denial of service against Apple, Google or browser push services.
