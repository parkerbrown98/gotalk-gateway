# Gotalk Push Gateway Protocol

Protocol version: **v1** (draft, Phase 0). Machine-readable contract: [openapi.yaml](openapi.yaml).
Related: [payload.md](payload.md) · [threat-model.md](threat-model.md) · [gateway-plan.md](gateway-plan.md).

Key words MUST, SHOULD and MAY are used as in RFC 2119.

## On this page

- [Roles](#roles)
- [Conventions](#conventions)
- [Discovery and versioning](#discovery-and-versioning)
- [Instance registration](#instance-registration)
- [Request signing](#request-signing)
- [Device registration](#device-registration)
- [Push requests](#push-requests)
- [Errors](#errors)
- [Rate limits](#rate-limits)
- [Integration points in the server and client](#integration-points-in-the-server-and-client)
- [Appendix A: signing test vector](#appendix-a-signing-test-vector)

## Roles

| Role | Description |
|---|---|
| **Gateway** | Holds the app's APNs, FCM and VAPID credentials. Forwards opaque payloads to push providers. |
| **Instance** | A `gotalk-server`. Identified by its **origin** (`https://host[:port]`). Authenticates to the gateway with an Ed25519 key. |
| **Client** | A Gotalk app install. Registers a platform token for one instance and one account. Authenticates later requests with a per-subscription secret. |
| **Provider** | APNs, FCM or a browser push service. |

Trust summary (details in [threat-model.md](threat-model.md)): the gateway never sees notification content,
a subscription only works for the instance it was registered for, and an instance can only push to
subscriptions bound to its own origin.

## Conventions

- All endpoints live under `/v1` on the gateway's base URL. Request and response bodies are UTF-8 JSON
  (`Content-Type: application/json`); errors use `application/problem+json` ([Errors](#errors)).
- Binary values (keys, signatures, ciphertext, nonces, digests) are **base64url without padding** (RFC 4648 §5).
- Timestamps in bodies are RFC 3339 UTC. Timestamps in signing headers are Unix seconds.
- IDs are opaque, URL-safe strings with a type prefix: `inst_…` instances, `key_…` instance keys, `sub_…`
  subscriptions and `push_…` pushes (apps use short slugs such as `gotalk`). Callers MUST NOT parse them.
- Unknown JSON fields in requests are rejected with `invalid_request` (typos should not pass silently).
  Unknown fields in **responses** MUST be ignored by callers so that the gateway can add fields within a
  version.
- Origins are normalized before use: lowercase scheme and host, no path, query, fragment or trailing slash,
  default port omitted. Only `https` is accepted unless the gateway runs in development mode.
- Request bodies are limited to 64 KiB (single push: 16 KiB, batch: 1 MiB). Larger requests fail with `413`.

## Discovery and versioning

`GET /.well-known/gotalk-gateway` and `GET /v1/gateway` return the same document. Both are unauthenticated and
cacheable (`Cache-Control: public, max-age=300`).

```json
{
  "software": "gotalk-gateway",
  "name": "Gotalk Push Gateway",
  "version": "0.1.0",
  "api_versions": ["v1"],
  "api_base_url": "https://push.example/v1",
  "platforms": ["ios", "android", "web"],
  "apps": [
    {
      "id": "gotalk",
      "name": "Gotalk",
      "platforms": {
        "ios": { "bundle_id": "app.example.gotalk" },
        "android": { "package_name": "app.example.gotalk" },
        "web": { "vapid_public_key": "BEl62iUY…" }
      },
      "attestation_required": false
    }
  ],
  "limits": {
    "max_plaintext_bytes": 2048,
    "max_encrypted_body_bytes": 2200,
    "max_batch_size": 100,
    "max_ttl_seconds": 2419200,
    "subscription_expiry_days": 60
  },
  "terms_url": "https://push.example/terms",
  "privacy_url": "https://push.example/privacy"
}
```

- `apps` is the app registry. A device registration for an unlisted `app_id` is refused with `unknown_app`.
- The web VAPID public key is per app because a browser push subscription is bound to the key it was created with.
- `attestation_required` is reserved for Phase 8 and is `false` in v1 drafts.

**Versioning.**

- The major version is in the path (`/v1`). Within a major version the gateway only makes additive changes:
  new optional request fields, new response fields, new error codes, new enum values for responses.
  Callers MUST tolerate them.
- A breaking change ships as `/v2` alongside `/v1`. The gateway announces the end of an old version with
  `Deprecation` and `Sunset` headers (RFC 9745 / RFC 8594) at least 6 months before removal.
- `api_versions` in discovery is the list of majors the gateway serves. Callers choose the highest version they
  support. The encrypted payload has its own version field ([payload.md](payload.md)).

**How a client finds a gateway.** The instance advertises it in `GET /api/v1/instance`
(`push.gateway_url`). The client fetches `{gateway_url}/.well-known/gotalk-gateway` and only registers when the
chosen app and platform are listed. A client MUST NOT register with a gateway the instance did not advertise,
except one the user configured themselves for a custom build.

## Instance registration

An instance registers its origin and an Ed25519 public key, then proves it controls the origin.

### Register

`POST /v1/instances` (unauthenticated, rate limited per IP)

```json
{
  "origin": "https://forum.example",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "contact_email": "ops@forum.example",
  "software": "gotalk",
  "software_version": "1.4.0"
}
```

`201 Created`:

```json
{
  "instance_id": "inst_7Hq2…",
  "key_id": "key_9fKd…",
  "status": "pending",
  "verification": {
    "well_known_url": "https://forum.example/.well-known/gotalk-instance",
    "expires_at": "2026-10-18T16:46:00Z"
  }
}
```

`contact_email` is used only for abuse and key-expiry notices. `software` and `software_version` are informational.

### Domain verification

The gateway verifies domain control by fetching `https://{origin}/.well-known/gotalk-instance`. The instance MUST
list its key in a `push` object:

```json
{
  "software": "gotalk",
  "instance_url": "https://forum.example",
  "push": {
    "keys": [
      { "alg": "Ed25519", "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg" }
    ]
  }
}
```

A key becomes `active` only when the fetched document lists exactly that public key. Verification runs when the
instance calls `POST /v1/instances/{instance_id}/verify` (signed with the pending key) and again every 24 hours
while the instance is active or suspended.

- An explicit `verify` activates every advertised pending key and succeeds when the signing key is then active and
  every active key is advertised. Otherwise it fails with `422 verification_failed` and a `detail` that names the
  failed check. Explicit failures never count towards suspension, so nobody can suspend an instance by calling
  `verify` during an outage of its origin. Only the scheduled 24-hour verification counts.

- The origin's well-known document is the root of trust: whoever controls the origin controls the instance.
- Pending registrations expire after 24 hours. Several pending registrations may exist for one origin. Only a key
  that the origin actually advertises can be verified, so squatting an origin gains nothing.
- A verified origin has one `instance_id`. Registering the same origin again with a new key starts **recovery**:
  when the new key is verified, the gateway activates it and revokes every other key of that instance. The
  `instance_id` and its subscriptions are kept. This is the path for a stolen or lost key.
  - The registration response returns the existing `instance_id` and status.
  - A recovery key expires 24 hours after registration if it is not verified.
  - A recovery key can only call `verify` until then, so registering someone else's origin reveals nothing about
    their instance.
  - The gateway keeps the 3 newest pending recovery keys per instance. Recovery keys do not count towards the
    3-key limit, and the instance cannot revoke them (`404 key_not_found`). Otherwise whoever holds a stolen
    key could cancel the owner's recovery.
- Repeating a registration with the same origin and key returns the same pending registration.
- An active key that is no longer advertised fails re-verification. After 3 consecutive failures (72 hours) the
  instance becomes `suspended` and pushes fail with `instance_not_verified` until the key reappears. Existing
  subscriptions are kept.

Fetch rules (SSRF guard): HTTPS only; port 443 unless the gateway config allows others; the resolved address MUST
be public (no loopback, private, link-local or metadata ranges, checked after DNS resolution and again on
connect); no redirects; 5 second timeout; response limited to 64 KiB; `Content-Type: application/json`.

### Instance lifecycle

| Status | Meaning |
|---|---|
| `pending` | Registered, not yet verified. Can only call `verify` and `GET /v1/instances/{id}`. Deleted after 24 hours. |
| `active` | Verified. May push. |
| `suspended` | Verification lapsed. Pushes are refused with `instance_not_verified`. |
| `blocked` | Blocked by the gateway operator. Pushes are refused with `instance_blocked`; `reason` is returned. |

Other endpoints (all signed by an active key unless noted). A pending rotation key may call `GET` and `verify`;
a pending recovery key may only call `verify`; other calls with a pending key fail with `instance_not_verified`.

| Endpoint | Purpose |
|---|---|
| `GET /v1/instances/{instance_id}` | Status, keys, usage and limits. Allowed while `pending` or `suspended`. |
| `POST /v1/instances/{instance_id}/verify` | Re-run domain verification now. Any live key of the instance, including pending keys. |
| `POST /v1/instances/{instance_id}/keys` | Add a key (key rotation). The new key must be advertised in the well-known document before it is activated. |
| `DELETE /v1/instances/{instance_id}/keys/{key_id}` | Revoke a key. The last active key cannot be revoked (`409 conflict`); deregister instead. Revoking a revoked key succeeds; a key of another instance is `404 key_not_found`. |
| `DELETE /v1/instances/{instance_id}` | Deregister: deletes the instance and **all** its subscriptions. |

**Rotation without downtime.** Add the new key, publish it in the well-known document next to the old one, wait
for `status: active` on the new key, switch the instance to sign with it, then revoke the old key and remove
it from the well-known document. At most 3 keys are active or pending per instance.

## Request signing

Every instance request except `POST /v1/instances` uses an Ed25519 signature over a canonical string. The
gateway rejects requests with missing or malformed signing headers with `invalid_signature`.

Headers:

| Header | Value |
|---|---|
| `Gotalk-Key-Id` | The `key_…` ID of the signing key. |
| `Gotalk-Timestamp` | Unix seconds when the request was signed. |
| `Gotalk-Nonce` | 16 to 32 random bytes, base64url. Unique per request. |
| `Content-Digest` | `sha-256=:<standard base64>:` of the body (RFC 9530). Required when there is a body; for an empty body the digest of the empty string is used in the signing string and the header may be omitted. |
| `Gotalk-Signature` | base64url Ed25519 signature of the signing string. |

Signing string, joined with a single `\n` and **no trailing newline**:

```
GOTALK-SIG-V1
{METHOD}
{HOST}
{PATH_AND_QUERY}
{TIMESTAMP}
{NONCE}
{KEY_ID}
{BODY_SHA256_BASE64URL}
```

- `METHOD` is upper case. `HOST` is the gateway's `Host` header value in lower case. `PATH_AND_QUERY` is the
  request target exactly as sent (path, then `?` and the raw query when there is one).
- A gateway with a configured public URL verifies against that URL's host, so a reverse proxy in front of it may
  rewrite `Host`. A proxy must not rewrite the path or query.
- `BODY_SHA256_BASE64URL` is the unpadded base64url SHA-256 of the raw body bytes.
- Binding the host stops a request signed for one gateway from being replayed to another. The `GOTALK-SIG-V1`
  prefix is the domain separator and the signature version.

Gateway checks, in order, and the error returned for each failure:

1. Headers present and well formed: `invalid_signature`.
2. Key exists, is not revoked, and has not expired (a pending registration or recovery key after 24 hours):
   `unknown_key`.
3. `|now − timestamp| ≤ 300` seconds: `stale_timestamp`.
4. `Content-Digest`, when present, matches the body, and `BODY_SHA256` is computed from the body, not the header:
   `invalid_signature`.
5. Ed25519 signature verifies: `invalid_signature`.
6. `(key_id, nonce)` has not been seen within the last 600 seconds. The nonce is recorded only after the
   signature verifies: `replayed_nonce`.
7. The instance status allows the operation:
   - `instance_blocked` (with the operator's reason) when the instance is blocked or its origin is on the
     gateway's blocklist.
   - `instance_not_verified` when the instance or key is pending for an operation that needs an active key.
   - `instance_not_found` when the path names another instance.
8. Rate limits and quotas ([Rate limits](#rate-limits)).

Nonce records are kept for twice the skew window (600 s). Single-node deployments without Redis keep them in
memory, so a restart can briefly accept a replay inside the skew window; the 5 minute window bounds that exposure.

[Appendix A](#appendix-a-signing-test-vector) has a test vector.

## Device registration

A device registration binds one platform token to one `(app, instance origin)` pair. **A client registers one
subscription per instance and token**, and uses a fresh key pair for each account on that instance (see
[payload.md](payload.md)). The
gateway never receives the device keys: the client gives them to the instance, and the instance encrypts to them.

Device endpoints are called by clients and are unauthenticated at creation (a device cannot prove it is logged
in to an instance). Later calls use the subscription secret.

**Several accounts on one instance.** iOS and Android give an app install one token, and a browser gives a
service worker one endpoint, so several accounts that a device holds on the same instance share one
subscription: registering the same token again returns the same `subscription_id` and rotates the secret (see
below).

- The client keeps one secret per (instance, token) and registers once.
- It still generates a key pair per account and gives each account's keys to the instance under that shared
  `subscription_id`.
- On receipt, the device tries the keys it holds for the subscription; the `aes128gcm` tag tells it which one
  fits. The plaintext's `user_id` then routes the notification.

### Register

`POST /v1/devices` (rate limited per IP and per token)

iOS:

```json
{
  "app_id": "gotalk",
  "instance_origin": "https://forum.example",
  "platform": "ios",
  "token": "9f2c…64 or more hex characters",
  "apns_environment": "production"
}
```

Android:

```json
{
  "app_id": "gotalk",
  "instance_origin": "https://forum.example",
  "platform": "android",
  "token": "fcm-registration-token"
}
```

Web:

```json
{
  "app_id": "gotalk",
  "instance_origin": "https://forum.example",
  "platform": "web",
  "endpoint": "https://fcm.googleapis.com/fcm/send/…"
}
```

`201 Created`:

```json
{
  "subscription_id": "sub_3kP…",
  "subscription_secret": "gtsec_…",
  "expires_at": "2026-12-16T16:46:00Z"
}
```

Rules:

- `instance_origin` must belong to an instance with status `active` (`instance_not_verified` otherwise,
  `instance_not_found` if the origin is unknown). A device cannot be registered "ahead of time".
- `app_id` must be in the discovery `apps` list with the requested platform: `422 unknown_app` otherwise. A
  blocked instance or blocklisted origin returns `403 instance_blocked`.
- Validation: iOS tokens are hex, 64 to 200 characters (stored in lower case). Android tokens are 100 to 4096
  characters of the FCM token alphabet (`A-Z a-z 0-9 _ - . :`). Web endpoints are `https` URLs on port 443, at most
  2048 characters, whose host is public. The gateway rejects endpoints it will not send to: by default only the
  browser push services (FCM, Mozilla, Apple, Windows) and their subdomains are accepted, and the operator can
  change that list. Failures return `422 invalid_token`, and `errors` names the field (`token` or `endpoint`).
- Malformed requests return `invalid_request`: `400` for a body that is not one JSON object, and `422` with field
  `errors` for missing, unknown or mismatched fields (for example `endpoint` on iOS). The optional `attestation`
  object is reserved for Phase 8 and ignored.
- `apns_environment` is `production` or `sandbox` (iOS only, default `production`).
- Registering the same `(app, instance origin, platform, token or endpoint)` again returns the **same**
  `subscription_id` with a **new** `subscription_secret`; the old secret stops working. Platform tokens are
  secret to the device, so holding one proves control of it.
- `subscription_secret` is shown once. The gateway stores only a hash. The client keeps it in secure storage
  and sends it as `Authorization: Bearer <secret>` for later calls. It is **not** given to the instance.
- The client then sends `subscription_id` to the instance together with its device public key material.
  The instance never sees the platform token or endpoint.
- `expires_at` moves forward every time the subscription is refreshed. Subscriptions not refreshed within
  `subscription_expiry_days` (default 60) are deleted. Clients refresh at least every 14 days, on every app
  start after 7 days, and whenever the platform token changes.

### Refresh and delete

| Endpoint | Auth | Purpose |
|---|---|---|
| `PUT /v1/devices/{subscription_id}` | Subscription secret | Replace the token or endpoint (`token` for iOS and Android, `endpoint` for web; iOS may also change `apns_environment`). `app_id` and `instance_origin` cannot change. Always extends `expires_at`. An empty body `{}` only extends expiry. Response: `{"subscription_id", "expires_at"}`. Moving to a token another subscription of the same app and instance already uses returns `409 conflict`; register that token instead. |
| `DELETE /v1/devices/{subscription_id}` | Subscription secret **or** instance signature | Delete the subscription, including one whose status is `gone` (`204`). An instance may only delete subscriptions bound to its own instance. |

An unknown subscription, a wrong secret, and a subscription bound to another instance all return the same
`404 subscription_not_found` so that existence cannot be probed. As a consequence, a repeated `DELETE` returns
`404`; callers SHOULD treat `404` from `DELETE` as success. A missing or non-`Bearer` `Authorization` header
returns `401 unauthorized`. A request that carries any `Gotalk-*` signing header is always authenticated as an
instance and never falls back to the secret.

### Dead tokens

When a provider reports an unregistered or invalid token (APNs `410`/`BadDeviceToken`, FCM `UNREGISTERED`,
Web Push `404`/`410`), the gateway marks the subscription `gone`, unless the client replaced the token (or APNs environment) after the
push was sent, in which case the stale rejection is ignored. The instance learns about it from:

- the next push to that subscription, which fails with `410 subscription_gone`, and
- `GET /v1/pushes/{push_id}`, whose `status` is `gone` when the failing push was already accepted.

The instance MUST delete its own record of a `gone` subscription. A client re-registering the same token, or
replacing the token with `PUT`, reactivates the subscription; a refresh that keeps the token does not. The
gateway deletes `gone` subscriptions after 7 days.

## Push requests

All push endpoints are signed by the instance.

### Single push

`POST /v1/push`

```json
{
  "subscription_id": "sub_3kP…",
  "mode": "encrypted",
  "notification_id": "ntf_01JD…",
  "payload": "<base64url RFC 8291 body>",
  "urgency": "high",
  "ttl": 3600,
  "collapse_key": "c_4f9a1b"
}
```

| Field | Required | Description |
|---|---|---|
| `subscription_id` | yes | Target. Must be bound to the signing instance. |
| `mode` | yes | `encrypted` or `id_only`. See [payload.md](payload.md). |
| `notification_id` | yes | The instance's notification ID, 1 to 64 characters of `[A-Za-z0-9._:-]`. In `id_only` mode it is delivered to the device; in `encrypted` mode it is only used for correlation and the delivery log. |
| `payload` | `encrypted` only | The encrypted body. Max 2,200 bytes after decoding. Forbidden in `id_only` mode. |
| `urgency` | no | `low`, `normal` (default) or `high`. |
| `ttl` | no | Seconds the provider should hold the push for an offline device. 0 to 2,419,200 (28 days). Default 86,400. `0` means "deliver now or drop". |
| `collapse_key` | no | 1 to 32 characters of `[A-Za-z0-9_-]`. A new push with the same key replaces an undelivered older one for the same device. |

Semantics:

- **Urgency** maps to APNs priority (`high` 10, `normal` 5, `low` 1), FCM `android.priority` (`high` →
  `HIGH`, the others → `NORMAL`) and the Web Push `Urgency` header (`high`, `normal`, `low`). Use `high` only
  for things a person expects immediately: direct messages and mentions.
- **TTL** maps to `apns-expiration` (now + ttl), FCM `android.ttl` and the Web Push `TTL` header.
- **Collapse key** maps to `apns-collapse-id`, FCM `collapse_key` and the Web Push `Topic` header. The 32
  character limit is the Web Push `Topic` limit, the strictest of the three. Instances SHOULD derive it from
  the conversation or topic (for example a truncated hash) and never from content. FCM limits a device to 4
  distinct collapse keys at a time; the gateway documents this but does not enforce it.
- `mode: id_only` is refused for web subscriptions with `invalid_request`; see [payload.md](payload.md#provider-mapping).
- The gateway never modifies, truncates or inspects `payload`.

Response `202 Accepted`:

```json
{
  "push_id": "push_5Qm…",
  "subscription_id": "sub_3kP…",
  "status": "queued"
}
```

`202` means the push passed validation and is queued. It does not mean the device received it.

Failures before queueing use an HTTP error ([Errors](#errors)): `404 subscription_not_found`,
`410 subscription_gone`, `413 payload_too_large`, `422 invalid_request`, `429 rate_limited` or `quota_exceeded`.

**Idempotency.** An instance MAY send `Idempotency-Key` (1 to 64 characters). A repeat of the same key from the
same instance within 24 hours returns the original response with `Idempotency-Replayed: true` instead of queueing
a second push. Without the header, retries can duplicate; clients de-duplicate by notification ID.

### Batch push

`POST /v1/push/batch`: `{"pushes": [ <single push>, … ]}` with 1 to 100 entries. Each entry has its own payload
because every device has its own key. The response is always `202` when the batch itself is valid, with one
result per entry, in order:

```json
{
  "results": [
    { "index": 0, "status": "queued", "push_id": "push_5Qm…", "subscription_id": "sub_3kP…" },
    { "index": 1, "status": "rejected", "subscription_id": "sub_8xL…",
      "error": { "code": "subscription_gone", "message": "The device token is no longer valid." } }
  ]
}
```

A malformed envelope (not valid JSON, more than 100 entries, bad signature) fails the whole request with the
usual error. Per-entry validation failures are reported in `results` and do not stop other entries. Rate limits
count each entry. When the instance's quota runs out mid-batch, remaining entries are rejected with
`quota_exceeded` and `status` is `rejected`.

### Push status

`GET /v1/pushes/{push_id}` returns the delivery-log entry of a push sent by the calling instance (404 otherwise).
Entries are kept for 72 hours and contain no content.

```json
{
  "push_id": "push_5Qm…",
  "subscription_id": "sub_3kP…",
  "notification_id": "ntf_01JD…",
  "status": "sent",
  "attempts": 1,
  "created_at": "2026-10-17T16:46:00Z",
  "updated_at": "2026-10-17T16:46:01Z",
  "error": null
}
```

| `status` | Meaning |
|---|---|
| `queued` | Waiting for a worker or a retry. |
| `sent` | The provider accepted the push. This is the strongest guarantee any provider gives. |
| `failed` | Delivery failed permanently. `error.code` says why. |
| `expired` | The TTL ran out before the provider accepted it. |
| `gone` | The provider said the token is dead; the subscription is now `gone`. |

Delivery to providers retries transient failures (provider `5xx`, throttling, timeouts) with exponential backoff
and jitter (1 s base, factor 2, up to 5 attempts or the TTL, whichever is first). `Retry-After` from a provider is
honored.

## Errors

Errors use RFC 9457 `application/problem+json` with an extra `code`:

```json
{
  "type": "https://gotalk.app/problems/replayed-nonce",
  "title": "Request replayed",
  "status": 401,
  "code": "replayed_nonce",
  "detail": "This nonce was already used for this key.",
  "request_id": "req_01JD…"
}
```

`code` is the stable, machine-readable value; `title` and `detail` are for humans. Callers branch on `code`.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 / 422 | Malformed JSON, unknown field or failed validation. `errors` lists field problems. |
| `invalid_signature` | 401 | Missing or malformed signing headers, digest mismatch or bad signature. |
| `unknown_key` | 401 | The key does not exist or was revoked. |
| `stale_timestamp` | 401 | Timestamp outside ±300 seconds. Response includes `Date`; instances should check their clock. |
| `replayed_nonce` | 401 | Nonce already used within 600 seconds. |
| `unauthorized` | 401 | Missing or wrong subscription secret on a device endpoint that is not enumeration-sensitive. |
| `instance_not_verified` | 403 | Instance is `pending` or `suspended`. |
| `instance_blocked` | 403 | Instance is blocked, or its origin or the client address is on the gateway's blocklist. `detail` carries the operator's reason. |
| `unknown_app` | 422 | `app_id` is not served by this gateway, or not for this platform. |
| `invalid_token` | 422 | Platform token or endpoint fails validation. |
| `verification_failed` | 422 | Domain verification failed. `detail` names the check. |
| `instance_not_found` | 404 | No instance with that origin or ID. |
| `subscription_not_found` | 404 | Unknown subscription, wrong secret, or bound to another instance. |
| `push_not_found` | 404 | Unknown push, or not sent by this instance. |
| `key_not_found` | 404 | The key ID is not a key of the calling instance. |
| `not_found` | 404 | No endpoint at this path. |
| `method_not_allowed` | 405 | The endpoint does not support this method. |
| `conflict` | 409 | The operation conflicts with current state (for example revoking the last key). |
| `subscription_gone` | 410 | The provider rejected the token. Delete the subscription. |
| `payload_too_large` | 413 | Request body or `payload` over the limit. |
| `unsupported_media_type` | 415 | Body is not `application/json`. |
| `rate_limited` | 429 | Rate limit hit. `Retry-After` is set. |
| `quota_exceeded` | 429 | Daily or plan quota used up. `Retry-After` is set to the reset. |
| `provider_unavailable` | 503 | The gateway could not enqueue (queue or database down). Retry with backoff. |
| `internal_error` | 500 | Unexpected failure. `request_id` helps the operator. |

Failures reported on a push's `error.code` after the fact are limited to: `subscription_gone`,
`provider_rejected` (permanent provider refusal such as an invalid payload or a mismatched topic),
`provider_unavailable` and `internal_error`.

Security-sensitive responses do not reveal more than needed: unknown key and wrong key signature are
distinguishable only where the caller already holds the key ID; device endpoints use `subscription_not_found`
for all three of missing, unauthorized and foreign.

## Rate limits

Limits are per instance (signed endpoints) or per IP (unsigned endpoints). Defaults for the official gateway;
the actual values are in discovery `limits` and on the instance resource.

| Scope | Default |
|---|---|
| `POST /v1/instances` | 5 per hour per IP (IPv6 clients are counted per /64) |
| `POST /v1/instances/{id}/verify` | 12 per hour per signing key (each one fetches the origin) |
| `POST /v1/devices` | 60 per hour per IP (IPv6 per /64), 10 per hour per token |
| `PUT /v1/devices/{id}` | 60 per hour per subscription (counted after the secret is checked), and the per-token limit when the token changes |
| Signed requests | 1,200 per minute per instance |
| Pushes (entries) | 50,000 per day per instance (free tier; plans change this in Phase 10) |
| Pushes per device | 120 per hour per subscription |

Responses to rate-limited endpoints carry `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`
(Unix seconds). `429` responses add `Retry-After` (seconds).

## Integration points in the server and client

Reviewed against the [backend plan](https://github.com/parkerbrown98/gotalk-server/blob/main/docs/backend-plan.md)
and [client plan](https://github.com/parkerbrown98/gotalk-client/blob/main/docs/client-plan.md). What each side
must add, which feeds Phases 6 and 7:

**`gotalk-server`**

- `/.well-known/gotalk-instance` gains the `push.keys` array shown above. It currently returns `software`,
  `version`, `instance_url`, `api_base_url`, `api_versions`, `instance_info_url` and `gateway_url`. The last one
  is the realtime WebSocket gateway, unrelated to this service; the new field is named `push` to avoid the clash.
- `GET /api/v1/instance` advertises `push: { enabled, gateway_url }`.
- `PushSubscription` stores `subscription_id`, the user, the platform and the device key material
  (`p256dh` public key and `auth` secret). It does not store the platform token.
- Endpoints for a client to add, list and remove its subscriptions. Removing one SHOULD also call
  `DELETE /v1/devices/{id}` on the gateway.
- A signed gateway client, an RFC 8291 encryptor, and a job that turns notifications into pushes.
- Notification types that become pushes follow the server's notification types (`mention`, `reply`,
  `topic_reply`, `direct_message`, …) and its per-category preferences and mute rules.

**`gotalk-client`**

- Generates one P-256 keypair and one 16-byte auth secret per subscription, keeps the private key in secure
  storage, and shares the private key with the iOS Notification Service Extension through a keychain access
  group and with the Android messaging service through encrypted storage.
- Calls `POST /v1/devices`, then registers the result with the instance. On sign-out or instance removal it
  deletes both.
- Treats the gateway as untrusted for content and the instance as untrusted for identity: the notification
  title always carries the instance name, so an instance cannot impersonate another sender.

## Appendix A: signing test vector

Seed (32 bytes, `00 01 02 … 1f`): `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`
Public key: `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`

Request: `POST https://push.example/v1/push`, key ID `key_example`, timestamp `1760719200`, nonce
`AAECAwQFBgcICQoLDA0ODw`, body (no trailing newline):

```
{"subscription_id":"sub_example","mode":"id_only","notification_id":"n_1"}
```

Body SHA-256 (base64url): `SAUX3kZI6oRsw2ZIemu0vm_ENHcqIi_nr3Mtwf_zBvo`

Signing string:

```
GOTALK-SIG-V1
POST
push.example
/v1/push
1760719200
AAECAwQFBgcICQoLDA0ODw
key_example
SAUX3kZI6oRsw2ZIemu0vm_ENHcqIi_nr3Mtwf_zBvo
```

`Gotalk-Signature`:

```
3-vRa4hvPv4thLZdk2BO6zN_MPuYP8x9sYVISDDvaA7eyStJU6eE_R3-lJsYlZ2Y8IpNzlOPgwEJ8kAPpba2Aw
```

(The vector was generated with Go's `crypto/ed25519`; Ed25519 signatures are deterministic.)
