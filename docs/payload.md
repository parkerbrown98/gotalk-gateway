# Push payload format

Part of the [gateway protocol](protocol.md). Defines what the instance encrypts, what the gateway forwards,
size limits, and how each provider carries it.

## On this page

- [Design](#design)
- [Device keys](#device-keys)
- [Encrypted mode](#encrypted-mode)
- [Plaintext schema](#plaintext-schema)
- [id_only mode](#id_only-mode)
- [Size limits](#size-limits)
- [Provider mapping](#provider-mapping)
- [Client handling](#client-handling)
- [Open items](#open-items)

## Design

- One encryption scheme everywhere: **RFC 8291 Message Encryption for Web Push**, content coding `aes128gcm`
  (RFC 8188). Browsers decrypt it natively; the iOS extension and the Android service implement the same
  decryption with platform crypto.
- The instance encrypts, the gateway forwards bytes it cannot read, and the provider sees ciphertext plus
  metadata. Only the device holds the private key.
- Two modes: `encrypted` (default) and `id_only` (fallback, nothing but IDs leave the instance).
- The gateway sets all cleartext display text itself, so an instance cannot choose what an undecrypted
  notification says.

## Device keys

For each subscription the client generates:

- a P-256 key pair; the private key never leaves the device (and the iOS extension's keychain group), and
- a random 16-byte `auth` secret.

The client sends the instance the **uncompressed public key** (65 bytes, base64url, called `p256dh`) and `auth`
(16 bytes, base64url). The gateway never receives either. A fresh key pair for every account on every instance stops
two instances from correlating a device by its public key. Accounts on the same instance share the device's
subscription, and the device tries each of its keys for that subscription (see
[protocol.md](protocol.md#device-registration)).

**Web is the exception.** A browser creates the key pair and `auth` itself as part of the `PushSubscription`.
`pushManager.subscribe()` exposes `p256dh` and `auth` through `getKey()`, and the client sends them to the
instance exactly like native clients do. A browser has one subscription per service worker, so the same keys
(and endpoint) back every instance's gateway registration; the `instance` and `user_id` fields in the plaintext
tell the service worker which account a push belongs to.

## Encrypted mode

The instance builds the body as defined in RFC 8291 §3 and RFC 8188:

```
salt (16) | rs (4, big-endian uint32) | idlen (1) | keyid (idlen) | ciphertext
```

- `rs` is `4096`. The body always has a single record. `keyid` is the instance's ephemeral public key
  (`idlen = 65`), per RFC 8291.
- The plaintext is padded with zero bytes after the `0x02` delimiter (RFC 8188 §2). Instances pad the JSON to a
  multiple of 256 bytes, but never past the 2,048 byte limit, to blunt length leakage.
- The result is base64url-encoded and sent as `payload` in the push request.

The gateway does not parse the body; it only checks that the decoded length is ≤ 2,200 bytes and ≥ 103 bytes
(the smallest valid body). Conformance tests use the RFC 8291 Appendix A vector for the encryption itself.

## Plaintext schema

The plaintext is a UTF-8 JSON object of at most 2,048 bytes including padding.

```json
{
  "v": 1,
  "instance": "https://forum.example",
  "user_id": "usr_01JD…",
  "notification_id": "ntf_01JD…",
  "type": "mention",
  "title": "Alice in #general",
  "body": "@bob are you free for the call?",
  "thread_id": "chn_01JD…",
  "category": "mentions",
  "badge": 3,
  "created_at": "2026-10-17T16:46:00Z",
  "target": {
    "place_id": "plc_01JD…",
    "channel_id": "chn_01JD…",
    "message_id": "msg_01JD…"
  }
}
```

| Field | Required | Description |
|---|---|---|
| `v` | yes | Payload version. `1`. Clients ignore payloads with a higher version and show the fallback. |
| `instance` | yes | The instance origin. Lets web and multi-account clients route the push. |
| `user_id` | yes | The recipient's user ID on the instance. |
| `notification_id` | yes | The instance's notification ID. Clients de-duplicate on it. |
| `type` | yes | The notification type: `mention`, `reply`, `topic_reply`, `direct_message`, `reaction`, `moderation`, or a future value. Unknown types use the generic category. |
| `title` | yes | Short title. Clients prepend or append the instance name (see [Client handling](#client-handling)). |
| `body` | no | Body text, truncated by the instance to fit. |
| `thread_id` | no | Grouping key for the notification stack (maps to iOS `threadIdentifier` and the Android group). |
| `category` | no | Notification category for per-category channels and settings. Defaults to `type`. |
| `badge` | no | New app badge count for this account. |
| `created_at` | no | When the notification was created on the instance. |
| `target` | no | IDs the client needs to deep link: any of `place_id`, `board_id`, `topic_id`, `channel_id`, `conversation_id`, `message_id`, `post_id`. Unknown keys are ignored. |

New optional fields can be added without bumping `v`; a change that breaks existing readers bumps it.

## id_only mode

The instance sends no payload; the gateway builds a cleartext envelope instead:

```json
{ "v": 1, "instance": "https://forum.example", "notification_id": "ntf_01JD…" }
```

The client (iOS extension, Android service or service worker) fetches the notification from the instance with
its stored credentials and builds the notification itself. Use it when:

- the device cannot decrypt in the background in time (the extension has about 30 seconds and a small memory
  budget), or
- the operator prefers that no notification text, even encrypted, passes through the gateway and providers.

The gateway and providers see the instance origin and notification ID in `id_only` mode; they see only the
subscription (and so the instance) in `encrypted` mode. Both are metadata, not content. A device records the
mode it supports at registration with the instance, not with the gateway; the gateway treats both modes alike.

## Size limits

| Limit | Value | Why |
|---|---|---|
| Plaintext (padded) | 2,048 bytes | Leaves room for base64 and provider overhead on the strictest platform. |
| Encrypted body | 2,200 bytes | 86 byte header + 2,048 + 1 delimiter + 16 byte tag = 2,151, plus slack. |
| Base64url body | 2,934 characters | What APNs and FCM carry in a JSON field. |
| APNs payload | 4,096 bytes | Provider hard limit. Envelope plus `aps` is about 3,100 bytes, so about 1 KB of headroom. |
| FCM data payload | 4,096 bytes | Provider hard limit, similar headroom. |
| Web Push body | 4,096 bytes | Push services guarantee at least 4,096 bytes of ciphertext (RFC 8030 §7.2). The Web Push body is raw binary, so there is more than 1.8 KB of headroom. |

The gateway rejects a larger `payload` with `413 payload_too_large`. Instances that need more text truncate the
body or switch to `id_only`; they never split a notification into several pushes.

## Provider mapping

**APNs** (HTTP/2, token auth, `apns-topic` = the app's bundle ID):

```json
{
  "aps": {
    "alert": { "loc-key": "GT_NEW_NOTIFICATION" },
    "mutable-content": 1,
    "sound": "default"
  },
  "gt": { "v": 1, "sub": "sub_3kP…", "mode": "encrypted", "body": "<base64url body>" }
}
```

Headers: `apns-push-type: alert`, `apns-priority` from urgency (10, 5 or 1), `apns-expiration` from TTL (the
acceptance time plus TTL, or `0` for a TTL of 0), `apns-collapse-id` from `collapse_key`. Every push is a visible
alert with `mutable-content`, including low-urgency ones: background (`content-available`) pushes do not run the
Notification Service Extension, and iOS throttles them, so the gateway does not send them. For `id_only`, `gt` is `{ "v": 1, "sub": "...", "mode": "id_only",
"instance": "...", "notification_id": "..." }`. The app bundle ships the localized string `GT_NEW_NOTIFICATION`
("New notification"). It is the only text the user sees if the extension fails or the payload cannot be decrypted.
Badge counts come from the decrypted payload, set by the extension.

**FCM v1** (data-only, so the app always runs its handler):

```json
{
  "message": {
    "token": "<fcm token>",
    "data": { "gt_v": "1", "gt_sub": "sub_3kP…", "gt_mode": "encrypted", "gt_body": "<base64url body>" },
    "android": { "priority": "HIGH", "ttl": "3600s", "collapse_key": "c_4f9a1b" }
  }
}
```

FCM data values are strings, so `gt_v` is a string. Collapsed messages replace each other on FCM's servers. For
`id_only`, `data` is `{ "gt_v": "1", "gt_sub": "...", "gt_mode": "id_only", "gt_instance": "...",
"gt_notification_id": "..." }`. `android.ttl` is the time left of the push's TTL when it is sent, so retries do not
extend it.

**Web Push** (RFC 8030, VAPID per RFC 8292):

```
POST {endpoint}
Authorization: vapid t=<JWT>, k=<the app's VAPID public key>
Content-Type: application/octet-stream
Content-Encoding: aes128gcm
TTL: 3600
Urgency: high
Topic: c_4f9a1b

<the decoded payload bytes>
```

The body is the instance's RFC 8291 body exactly as decoded from `payload`; browsers decrypt it natively. `TTL` is
the time left of the push's TTL when it is sent (so retries do not extend it), `Urgency` is the push's urgency
(`low`, `normal` or `high`), and `Topic` is `collapse_key`, omitted without one. The VAPID JWT is ES256-signed with
the app's VAPID private key, with `aud` set to the endpoint's origin, `exp` 12 hours ahead and `sub` the operator
contact (`web.vapid.subject`). The gateway reuses a token per push service until an hour before it expires.

The push service answers `201 Created`. `404` and `410` mean the browser unsubscribed or the subscription
expired, and the gateway marks the subscription `gone`. `429` and `5xx` are retried with backoff, honoring
`Retry-After`. `401` and `403` (the VAPID token was refused) are retried too, since a bad key affects every
subscription and is fixed by the operator. Other `4xx`, including `413`, are `provider_rejected`.

The gateway refuses `mode: id_only` for web subscriptions (`invalid_request`): a browser decrypts
every push it receives, so an unencrypted body is useless there. A web client that wants the ID-only behavior has
the instance send `mode: encrypted` with a plaintext of only `v`, `instance`, `user_id` and `notification_id`.
[web-push.md](web-push.md) covers browser support and its quirks.

## Client handling

- **iOS Notification Service Extension:** find the key by `gt.sub`, decrypt, set title, body, thread, badge and
  deep link. On any failure, fall back to `id_only` fetch within the extension limit, then to the generic alert.
- **Android messaging service:** same flow, then post to the notification channel for `category`.
- **Web service worker:** `event.data.json()` is already decrypted by the browser. Route by `instance` and
  `user_id`.
- **Always show the instance name** in the notification (for example as the subtitle or a title suffix), and show
  only what the client renders from the structured fields. An instance never controls the full notification text,
  so a malicious instance cannot pass itself off as another app or sender.
- **De-duplicate** on `notification_id`; providers can deliver twice.
- **Suppress** the notification when the app is foregrounded and connected to the realtime gateway.

## Open items

- **iOS extension prototype.** The plan's Phase 0 risk calls for a Notification Service Extension that
  decrypts an RFC 8291 body inside its time and memory limits before this format is frozen. It needs a device and
  Apple credentials and has not been done; the envelope is **draft** until it has.
- **`id_only` on the web.** The rule above (encrypted minimal plaintext instead of `id_only`) is the working
  decision; confirm it in the prototype.
