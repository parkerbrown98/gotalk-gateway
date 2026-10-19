# Gotalk — Gateway Plan

This document lays out the phases for `gotalk-gateway`, the push notification gateway for Gotalk. It is the
third plan alongside
[backend-plan.md](https://github.com/parkerbrown98/gotalk-server/blob/main/docs/backend-plan.md) and
[client-plan.md](https://github.com/parkerbrown98/gotalk-client/blob/main/docs/client-plan.md). The server and
client plans both defer push on purpose: the backend plan lists push notifications as not yet built, and the
client plan's Phase 9 is blocked on a "small Gotalk-operated push gateway (APNs/FCM)". This project unblocks both.

## Why a gateway exists

Any Gotalk client can connect to any Gotalk instance, and operators run their own servers. Mobile push does not
fit that model without help:

- APNs and FCM only accept pushes signed with credentials tied to the **app's bundle ID / Firebase project**.
  Those credentials belong to whoever publishes the app. An instance operator does not have the official app's
  credentials, and the official app's credentials must never be given to thousands of operators.
- So instances send pushes to a **gateway** operated by the app publisher, and the gateway forwards them to
  APNs/FCM/Web Push. This is the same model as Matrix push gateways (Sygnal) and Mastodon's push proxies.

The gateway is also the product's main sustainable revenue lever: a free, generous tier for every instance, and
paid capacity for large ones. It never withholds a feature. A self-hoster who wants no dependency on the
official gateway can run their own gateway with their own app builds. The protocol and the code are open for that
reason.

## Goals and non-goals

**Goals**

- Reliable, low-latency delivery of instance-originated notifications to iOS, Android and web clients.
- Minimal trust: the gateway cannot read notification content, and it cannot push to a device on behalf of an
  instance the device did not register for.
- Open protocol and open-source implementation that anyone can run, with the official deployment as one
  instance of it.
- Cheap to operate: stateless service, Postgres plus Redis, no per-message cost beyond compute.

**Non-goals**

- Not a message store or a chat relay. It keeps no notification content and no history beyond a short delivery
  log.
- Not a federation or inter-instance transport.
- No email, SMS or digest delivery. Those stay in `gotalk-server`.
- No end-to-end-encrypted chat. Payload encryption here only protects push content in transit through the gateway.

## Architecture (decided)

```
 gotalk-client ──(1) register device ───────────────► gotalk-gateway ──► APNs / FCM / Web Push
      │                                                  ▲  (4) forward
      │ (2) send subscription_id + device keys           │
      ▼                                                  │ (3) signed push request
 gotalk-server (instance) ───────────────────────────────┘
```

1. The client gets a platform token (APNs / FCM / Web Push subscription) and registers it with the gateway **for
   one specific instance origin**. The gateway returns an opaque `subscription_id` and a `subscription_secret`.
2. The client generates a **device keypair** per subscription and gives the instance the `subscription_id` and the
   device's **public** key material. The gateway never receives the keys, and the instance never sees the raw
   APNs/FCM token.
3. When a notification should be pushed, the instance **encrypts the payload to the device's key** and sends it
   to the gateway in a request **signed with the instance's registered key**.
4. The gateway checks the signature, the subscription's instance binding and the quotas, then forwards the opaque
   payload to the platform provider. It reports dead tokens back to the instance.

| Concern | Choice | Why |
|---|---|---|
| Language and layout | Go, same toolchain and layout conventions as `gotalk-server` | One skill set, `cmd/` plus `internal/`, single static binary and distroless image. |
| HTTP and OpenAPI | `chi` plus `huma` | Same as the server; the gateway protocol is published as OpenAPI 3.1. |
| Database | PostgreSQL via `pgx`, `sqlc` queries, `goose` migrations | Durable registry of instances, devices, usage and the delivery log. |
| Cache, rate limits, nonces | Redis (`go-redis`) | Request nonce replay protection, token buckets, short-lived delivery state. A single-node mode without Redis is supported for self-hosters. |
| Queue | `river` (Postgres-backed) | Retries, scheduling and backoff for provider calls with no extra infrastructure. |
| APNs | Small in-repo HTTP/2 client (stdlib `net/http`, `golang-jwt` for token auth) | Token-based auth with a `.p8` key; avoids a heavy dependency, like the server's LiveKit client. |
| FCM | HTTP v1 API with a service-account OAuth2 token (`golang.org/x/oauth2/google`) | The legacy API is gone; v1 is the only supported path. |
| Web Push | VAPID signing and forwarding of an already-encrypted RFC 8291 body | The instance does the encryption, so the gateway needs only VAPID. |
| Payload encryption | RFC 8291 (`aes128gcm`) on every platform | One encryption scheme, one instance-side encryptor, and Web Push is natively compatible. |
| Request signing | Ed25519 signature over method, path, timestamp, nonce and body hash | Small, fast and easy to implement in any language. |
| Observability | `log/slog`, `prometheus/client_golang`, OpenTelemetry | Same as the server. |
| Testing | stdlib `testing`, `testify`, `testcontainers-go`, fake APNs/FCM servers | Provider behavior is exercised against local fakes in CI. |
| Deployment | Docker image, Helm chart, Kustomize | Matches how the server ships. |

### Decisions worth recording

- **Instance identity is the instance origin**, matching the client's instance ID. The gateway verifies domain
  control with a challenge on the instance's `/.well-known/gotalk-instance` before issuing credentials.
- **A subscription is bound to one instance origin.** A malicious instance can only reach devices whose
  owners registered those devices for it.
- **Encrypted payload by default, ID-only fallback.** The default payload is encrypted content. A device that
  cannot decrypt in the background (or an operator who prefers it) can use an `id_only` mode, where the push
  carries only the instance and notification ID and the client fetches the content.
- **The gateway is multi-app.** An "app" is a bundle ID / package name plus provider credentials. The official app
  is one app, and white-label builds or a self-hoster's custom builds are others.
- **Device keys go to the instance only.** Settled in Phase 0: the gateway needs no key to forward ciphertext, so it
  never receives one. Each subscription (one account on one instance) has its own keypair so instances cannot
  correlate a device by its public key.
- **Honest privacy boundary.** The gateway sees metadata (which instance, which device token, when, how big). It
  never sees content, and it keeps no content.

## Cross-repo dependencies

The gateway cannot deliver anything until the server and client speak to it. The work is tracked here so the
phases below are not blocked on surprises.

| Repo | Needed | Phase |
|---|---|---|
| `gotalk-server` | Push subscription endpoints (`PushSubscription` entity from backend plan section 8), a gateway client, a job that turns notifications into pushes, notification preferences, wizard and settings for gateway URL and credentials | 6 |
| `gotalk-client` | Notification permission flow, device keypair, gateway registration, iOS Notification Service Extension, Android channels, web service worker, deep links, per-instance settings | 7 |

## Phases

Status key: ⬜ not started · 🟨 in progress · ✅ done.

### Phase 0 — Protocol and decisions 🟨

No service code. Settle the design before it is expensive to change.

Status: the written deliverables below are drafted and in the repo. Still open: the people-only items (accounts,
trademark, domain), the iOS extension prototype, and the review. See the checklist after the list.

- **Protocol spec** (`docs/protocol.md`): instance registration, device registration, push request and
  response, error codes, `well-known` discovery and versioning.
- **Threat model** (`docs/threat-model.md`): rogue instance, rogue client, stolen instance key, stolen device
  token, gateway compromise, replay and spam. State what the gateway can and cannot see.
- **OpenAPI skeleton** for every endpoint, reviewed against the server and client plans.
- **Payload format**: the encrypted envelope, the `id_only` variant, maximum sizes (4 KB for APNs and Web
  Push, with headroom), urgency, TTL and collapse key semantics.
- **Accounts and logistics**: Apple Developer Program push key, Firebase project, VAPID keypair, domain, and the
  name and trademark of the official gateway.
- **Licensing**: AGPL-3.0 for the gateway, matching the server strategy, plus a DCO or CLA before accepting
  contributions.

Done when the protocol, threat model and OpenAPI are reviewed and the Apple/Google accounts exist.

Deliverables:

- ✅ Protocol spec: [protocol.md](protocol.md)
- ✅ Payload format: [payload.md](payload.md)
- ✅ Threat model: [threat-model.md](threat-model.md)
- ✅ OpenAPI skeleton: [openapi.yaml](openapi.yaml) (passes `openapi-spec-validator`; cross-checked against the
  server and client plans in the protocol's "Integration points" section)
- ✅ Licensing: [LICENSE](../LICENSE) (AGPL-3.0) and a DCO in [CONTRIBUTING.md](../CONTRIBUTING.md)
- ⬜ Accounts and logistics: checklist and proposed decisions in
  [accounts-and-logistics.md](accounts-and-logistics.md); needs the publisher to create the accounts and choose the
  name and domain
- ⬜ iOS Notification Service Extension prototype that decrypts an RFC 8291 body (the risk table's Phase 0 item); the
  envelope stays draft until it passes
- ⬜ Review of the protocol, threat model and OpenAPI

### Phase 1 — Foundation ✅

- Repository scaffold: `cmd/gotalk-gateway`, `internal/` packages, `Dockerfile`, `docker-compose.yml`,
  `config.example.yaml`, `sqlc.yaml`, `Makefile`.
- Layered configuration (defaults, file, environment variables, flags) and structured logging.
- PostgreSQL schema v1 with migrations: `apps`, `instances`, `instance_keys`, `devices`, `usage_counters`,
  `delivery_log`, `blocklist`.
- Health and readiness endpoints, `/metrics`, graceful shutdown.
- `GET /.well-known/gotalk-gateway` and `GET /v1/gateway`: name, version, supported API versions, supported
  platforms, limits and the gateway's public keys.
- CI: build, vet, `golangci-lint`, tests with containers, Docker build, OpenAPI diff check.
- The repo is public from this phase.

Done when `docker compose up` yields a running gateway that passes health checks and serves discovery.

Deliverables:

- ✅ Scaffold and `Makefile` (see [development.md](development.md)). The `river` queue and OpenTelemetry tracing are
  not added yet, because nothing in this phase uses them. Phase 4 adds the queue.
- ✅ Configuration ([configuration.md](configuration.md)): defaults, YAML file, `GOTALK_GATEWAY_*` (with `_FILE`
  secrets), and `--set`/shorthand flags, all validated at startup. Structured logging with `log/slog`.
- ✅ Schema v1 in [00001_schema_v1.sql](../internal/database/migrations/00001_schema_v1.sql), applied by goose under
  an advisory lock. Constraints are tested against PostgreSQL. Apps are declared in config and synced into
  `apps` at startup. Apps that are removed are disabled, not deleted.
- ✅ `/healthz`, `/readyz` (database and Redis checks, `draining` during shutdown, no error details on the public
  endpoint), `/metrics` (optionally on its own listener), `SIGTERM` handling with a configurable drain delay.
- ✅ Discovery on both paths, matching the protocol document. The gateway's public keys are the per-app VAPID keys
  in `apps[].platforms.web`. Errors use `application/problem+json` with protocol codes and request IDs.
  `not_found` and `method_not_allowed` were added to the error table for unknown routes.
- ✅ CI ([ci.yml](../.github/workflows/ci.yml)): vet, golangci-lint, `sqlc diff`, tests with `-race` and
  testcontainers, contract validation, an oasdiff breaking-change check on pull requests, a test that keeps the
  implementation in step with [openapi.yaml](openapi.yaml), a `docker compose up` smoke test, and a multi-arch
  image pushed to GHCR.
- ✅ The repository is public on GitHub, and CI passes on `main`.

### Phase 2 — Instance registration and request authentication ✅

- `POST /v1/instances`: an instance registers its origin, Ed25519 public key and operator contact.
- Domain verification: the gateway fetches `/.well-known/gotalk-instance` and checks that it advertises the
  registered key (or a one-time challenge token), then marks the instance `verified`.
- Signed-request middleware: timestamp skew window, nonce replay cache, body-hash check and key lookup.
- Key rotation: a second key can be added before the old one is revoked, so rotation causes no downtime.
- Per-instance and per-IP rate limiting with `X-RateLimit-*` headers, and a blocklist for abusive instances.
- Instance deregistration and deletion of all its subscriptions.

Done when an instance can register, verify and make authenticated calls, and replayed, stale and
mis-signed requests are rejected in tests.

Deliverables:

- ✅ `POST /v1/instances` with origin normalization (IDN, default ports, https only unless in development mode),
  key and contact validation, and idempotent repeats. Implemented in
  [instances.go](../internal/instances/instances.go).
- ✅ Domain verification through `/.well-known/gotalk-instance` (the protocol settled on the advertised key, so
  there is no separate challenge token). The SSRF-guarded fetcher in
  [wellknown.go](../internal/wellknown/wellknown.go):
  - checks the resolved address on every connection, which covers DNS rebinding;
  - allows only configured ports;
  - follows no redirects and uses no proxies;
  - enforces a 5 second timeout, a 64 KiB size limit and the JSON content type;
  - caps concurrent fetches.

  Scheduled re-verification runs every 24 hours, with replicas claiming disjoint batches. Three scheduled failures
  suspend an instance. Explicit `verify` failures never count, so nobody can trigger a suspension.
- ✅ Signed-request middleware ([auth.go](../internal/api/auth.go)) that applies the protocol's checks in order:
  - well-formed headers;
  - a live key;
  - the ±300 s timestamp window (a stale timestamp returns `Date`);
  - `Content-Digest`;
  - the Ed25519 signature over the public host;
  - the nonce, stored in Redis or memory for 600 s and recorded only after the signature verifies;
  - the instance status and permissions;
  - the rate limits.

  [signing](../internal/signing/signing.go) is tested against the Appendix A vector.
- ✅ Key rotation (at most 3 active or pending keys; the last active key cannot be revoked). Recovery by
  re-registering a verified origin: the new key is activated once it is advertised, and all other keys are
  revoked. Pending recovery keys may only call `verify`, expire after 24 hours, and are capped at 3.
- ✅ Rate limits with `X-RateLimit-*` and `Retry-After`, in Redis or memory, configurable: registration per IP,
  signed requests per instance, and verification per signing key. A blocklist of origins, domains and client
  networks is cached in memory. Operators block and unblock instances with a reason shown to the instance
  (`gotalk-gateway instances …` and `blocklist …`).
- ✅ Deregistration deletes the instance with its keys, subscriptions, usage and delivery log. Expired pending
  registrations and recovery keys are pruned.
- ✅ Tests against PostgreSQL and Redis containers cover:
  - the lifecycle, rotation and recovery;
  - stale, replayed, mis-signed, tampered and wrong-host requests;
  - cross-instance access;
  - the blocklist, rate limits, scheduled suspension and pruning;
  - nonces shared between replicas.

  An end-to-end test (`make e2e`, also in CI) runs the same flow against the built container. The contract
  gained `key_not_found` and the additional error responses (no breaking changes).

### Phase 3 — Device subscriptions ✅

- `POST /v1/devices`: register a platform token for one instance origin and one app. Returns `subscription_id` and
  `subscription_secret`. Device keys are not sent to the gateway.
- `PUT /v1/devices/{id}` (token refresh) and `DELETE /v1/devices/{id}`, both authenticated by the secret.
- App registry: list the apps the gateway serves and refuse registrations for unknown apps.
- Validation: token format per platform, key format, size limits and per-IP registration rate limits.
- Token invalidation: when a provider reports a dead token, the subscription is marked `gone` and the instance
  is told on its next push.
- Expiry: subscriptions not refreshed within a configurable period are pruned.

Done when a client can register, refresh and delete a subscription, and cross-instance misuse is covered by
tests.

Deliverables:

- ✅ `POST /v1/devices` for iOS, Android and web. Registration needs an active instance. Repeating a registration
  keeps the subscription ID and rotates the secret. Secrets are 256-bit `gtsec_…` values stored as SHA-256 and
  never cached (`Cache-Control: no-store`). Implemented in [devices.go](../internal/devices/devices.go).
- ✅ `PUT` (extend, or replace the token, endpoint or APNs environment) and `DELETE` with the secret. `DELETE` also
  accepts the bound instance's signature. A request with signing headers never falls back to the secret.
- ✅ The app registry from Phase 1 refuses unknown apps and platforms with `unknown_app`.
- ✅ Validation per platform: APNs hex (normalized to lower case), the FCM alphabet and length, and https Web Push
  endpoints on public hosts. Endpoints are limited by default to the browser push services
  (`devices.web_push_hosts`). Requests are parsed strictly, with field errors. "Key format" needs no gateway
  check: Phase 0 settled that device keys never reach the gateway.
- ✅ Rate limits per IP (IPv6 per /64), per token, and per subscription for updates, counted only after the secret
  is checked so a third party cannot burn a subscription's budget.
- ✅ Dead tokens: `MarkGone`, ready for the Phase 4 providers. It is a compare-and-set on the token and APNs
  environment the push was sent to, so a late rejection of a replaced token cannot kill the new one; Phase 4 jobs
  must carry the token hash and environment they read. Registering again or replacing the token
  reactivates the subscription. `gone` subscriptions are deleted after 7 days, and unrefreshed ones after
  `gateway.subscription_expiry_days`; both are pruned in batches every 10 minutes. Telling the instance on its
  next push (`410 subscription_gone`) belongs to the Phase 4 push endpoint.
- ✅ Tests against PostgreSQL cover:
  - the lifecycle on every platform;
  - validation;
  - instance states;
  - cross-instance misuse (another instance's signature, another subscription's secret, token collisions,
    cascade on deregistration);
  - auth errors, dead tokens, pruning and rate limits.

  The end-to-end test registers and manages devices against the container.
- ✅ Fixed a Phase 2 documentation bug: huma ignored path parameters declared on embedded structs, so two key
  endpoints were missing `instance_id` in the generated spec. A test now checks every path parameter, and CI
  validates the generated spec.
- 🟨 Protocol clarifications for review:
  - Several accounts on one instance share a device's subscription; each account keeps its own key pair.
  - A repeated `DELETE` returns `404`, which callers treat as success, because unknown, foreign and
    wrong-secret subscriptions must look the same.

### Phase 4 — Delivery pipeline and mobile providers ✅

- `POST /v1/push` and `POST /v1/push/batch` (up to 100 targets): signed by the instance, validated against
  subscription ownership, answered with `202` and per-target results.
- A queue-backed worker pool with retries, exponential backoff, jitter and dead-lettering.
- **FCM v1** and **APNs** providers: priority and urgency mapping, TTL, collapse keys, `mutable-content` and
  background pushes for the iOS extension, and badge counts.
- Provider error mapping: unregistered, invalid, throttled and server errors become the same gateway error codes.
- Connection management: pooled HTTP/2 to APNs, token refresh for APNs JWTs and FCM OAuth tokens.
- A delivery log that stores IDs, status and latency only (no content), with a short retention period.
- Provider fakes and end-to-end tests that cover retry, backoff and the dead-token path.

Done when a signed push request reaches a fake APNs and FCM and the failure paths behave as specified.

Deliverables:

- ✅ `POST /v1/push` (16 KiB body) and `POST /v1/push/batch` (1 MiB, 1 to 100 entries) in
  [push.go](../internal/api/push.go), signed by an active key of an *active* instance (a suspended instance can still
  manage keys, but gets `instance_not_verified` here). Entries are parsed strictly and one by one, so a batch reports
  each bad entry in its result:
  - ownership: another instance's subscription is `404 subscription_not_found`, exactly like a missing one;
  - `410 subscription_gone`, `413 payload_too_large` (over 2,200 decoded bytes), `422 invalid_request` with field
    errors, and `id_only` refused for web;
  - `503 provider_unavailable` when the gateway has no credentials for the subscription's app and platform, which
    is how web subscriptions were answered until Phase 5.
- ✅ `GET /v1/pushes/{push_id}`: the delivery-log entry (status, attempts, timestamps, and `error` with the
  provider's short reason once final). Another instance's push is `404 push_not_found`.
- ✅ `Idempotency-Key`: the `202` response is kept for 24 hours per instance and replayed with
  `Idempotency-Replayed: true`. Reusing a key for another request is `422`. A rejected single push is not
  remembered. Concurrent duplicates queue once.
- ✅ Queue: [river](https://riverqueue.com) on PostgreSQL. The delivery-log rows, the jobs and the usage counters
  are written in one transaction, so a `202` push is always queued. River's schema is migrated by
  `database.Migrate` under an advisory lock. Urgency maps to job priority. `delivery.workers` (default 50) sets the
  worker pool per replica; `0` makes an API-only replica. Shutdown lets in-flight deliveries finish.
- ✅ Retries ([worker.go](../internal/push/worker.go)) follow the protocol: up to 5 attempts, a 1 s base doubled each
  time with equal jitter, the provider's `Retry-After` honored, and never past the TTL (a TTL of 0 gets exactly one
  attempt). Retries are river snoozes counted in the delivery log, so a throttling provider cannot stretch them.
  Out of attempts, a push is dead-lettered: `failed` with `provider_unavailable`, and its job is kept `cancelled`,
  with every error, for `delivery.dead_letter_retention` (24 h). Unexpected errors (a database outage) use river's
  own retries and end as `failed`/`internal_error`.
- ✅ Each attempt reads the subscription's current token. A dead-token report uses Phase 3's compare-and-set
  `MarkGone`; when the client replaced the token meanwhile, the report is ignored and the push is retried at once
  with the new token. Deleted or already gone subscriptions finish without a provider call.
- ✅ APNs ([apns.go](../internal/providers/apns/apns.go)): HTTP/2 only, pooled with ping health checks, ES256 provider
  tokens (`golang-jwt`) reused for 50 minutes and replaced when APNs reports them expired, per-subscription
  production or sandbox endpoint. The payload and headers are those of [payload.md](payload.md): an alert with
  `mutable-content` and the `GT_NEW_NOTIFICATION` fallback, priority 10/5/1, `apns-expiration`, `apns-collapse-id`.
- ✅ FCM ([fcm.go](../internal/providers/fcm/fcm.go)): HTTP v1 with a service account's OAuth token
  (`golang.org/x/oauth2/google`), cached until shortly before expiry and replaced when FCM refuses it; a data-only
  message with `HIGH`/`NORMAL` priority, the remaining TTL and `collapse_key`.
- ✅ Error mapping to three outcomes: *gone* (APNs `410`, `BadDeviceToken`, `DeviceTokenNotForTopic`; FCM
  `UNREGISTERED`, `SENDER_ID_MISMATCH`, an invalid `message.token`), *rejected* (other `4xx`, reported as
  `provider_rejected` and never retried) and *retry* (`429`, `5xx`, timeouts, and the gateway's own credentials
  being refused).
- ✅ Provider credentials in the app config (`ios.apns`, `android.fcm`, with `*_file` variants for mounted secrets),
  validated at startup and never written to the database; see [configuration.md](configuration.md#apps).
- ✅ Delivery log: IDs, status, attempts, latency and the provider's short reason, never content, pruned after 72
  hours with the idempotency keys. Completed queue jobs, which hold the ciphertext, are deleted after a minute.
  Usage counters record accepted, rejected, sent and failed pushes per UTC day, as shown on the instance resource.
- ✅ Metrics: `gotalk_gateway_push_accepted_total`, `push_rejected_total{code}`, `push_finished_total{status}`,
  `push_delivery_latency_seconds`, `push_dead_lettered_total`, `provider_requests_total{provider,result}` and
  `provider_request_duration_seconds{provider}`.
- ✅ Tests:
  - provider clients against the fakes in [providertest](../internal/providers/providertest/providertest.go), which
    verify the JWT and OAuth assertion signatures (payloads, headers, token refresh, error mapping);
  - every worker branch, deterministically (backoff bounds, `Retry-After`, exhaustion, expiry, TTL 0, dead tokens,
    a stale dead-token report, rejections, removed subscriptions, deleted instances);
  - the API through the real queue to the fakes: delivery, retries, dead-lettering, dead tokens on APNs and FCM,
    validation, cross-instance misuse, batches and idempotency.

  The end-to-end test (`make e2e`, also in CI) runs the container against fake APNs and FCM servers with
  throwaway keys from `internal/e2e/gen`, covering delivery, a retry and the dead-token path.
- Not in this phase: push quotas (50,000 per day per instance, 120 per hour per subscription, and counting each
  batch entry against the signed-request limit) stay with the other quotas in Phase 8. Milestone A is unmetered.
- 🟨 Protocol clarifications for review: `503 provider_unavailable` for platforms without credentials; idempotency
  rules (per instance and request, `202` only); the delivery error semantics in "Push status"; the FCM `id_only`
  data keys; and no background (`content-available`) pushes, since they do not run the Notification Service
  Extension. Badge counts stay in the encrypted payload, set by the extension.

### Phase 5 — Web Push ✅

- Web Push forwarding: VAPID signing and delivery of the instance-encrypted RFC 8291 body to the browser's push
  service endpoint.
- Browser subscription registration (the endpoint only; `p256dh` and `auth` go to the instance) through the same
  device API.
- Handling of `410 Gone` and `404`, and `TTL`, `Urgency` and `Topic` header mapping.
- Documentation of the browser quirks (iOS home-screen PWA requirements, permission prompts).

Done when a registered browser subscription receives a push through the gateway in an end-to-end test.

Deliverables:

- ✅ Web Push provider ([webpush.go](../internal/providers/webpush/webpush.go)): `POST {endpoint}` with the decoded
  `payload` byte for byte, `Content-Encoding: aes128gcm`, `TTL` (the time left, so retries do not extend it),
  `Urgency` and `Topic` from `collapse_key`. VAPID (RFC 8292) ES256 tokens with `aud` set to the push service's
  origin, a 12-hour `exp` and the operator's `sub`, cached per push service, replaced an hour before expiry and
  re-signed when a service refuses one.
- ✅ Credentials in the app config: `web.vapid.private_key` or `private_key_file` (the base64url scalar that
  web-push tools print, or PEM) and `web.vapid.subject` (`mailto:` or `https:`). The gateway refuses to start when
  the key does not match `web.vapid_public_key`, so discovery always advertises the key pushes are signed with.
- ✅ Browser registration needed no new endpoint: Phase 3 already registers the endpoint alone, and `p256dh` and
  `auth` go only to the instance.
- ✅ Error mapping: `404`, `410` (and Apple's `Unregistered`, `ExpiredToken`, `BadDeviceToken`) mark the
  subscription `gone` through the Phase 3 compare-and-set; `429` and `5xx` are retried with `Retry-After`; `401` and
  `403` (VAPID refused) are retried like the other providers' credential errors; other `4xx`, including `413`,
  are `provider_rejected`. The reason the instance sees is the status or Apple's short reason, never the
  endpoint or its host.
- ✅ SSRF guard for endpoints, which come from browsers: the `devices.web_push_hosts` policy is checked at
  registration and again before each delivery, connections go only to public addresses on port 443 (checked
  after DNS resolution on every connection), and redirects and proxies are never followed. A blocked endpoint
  is `provider_rejected` without a request. `devices.web_push_allow_insecure` relaxes this for local fakes only,
  and the startup warning lists it with the other development settings.
- ✅ Documentation: [web-push.md](web-push.md) (VAPID key generation and rotation, the client flow, browser
  support including Safari's Home Screen requirement on iOS, Brave's opt-in, and permission prompt rules), the Web
  Push mapping in [payload.md](payload.md#provider-mapping), configuration, and a threat-model row for SSRF through
  endpoints.
- ✅ Tests:
  - a fake push service in [providertest](../internal/providers/providertest/webpush.go) that verifies the VAPID
    token (signature, `aud`, `exp` within 24 hours, `sub`), the headers and the 4 KB limit, and decrypts each push
    with the subscription's keys like a browser. Its RFC 8291 encryptor and decryptor pass the RFC's Appendix A
    vector;
  - the provider against that fake over HTTP/2 and TLS at real push service URLs: header mapping, the token
    cache per audience, renewal and re-signing, every error class, the policy re-check, the address guard and
    redirects;
  - the API through the real queue: a browser decrypts what the instance encrypted, throttling is retried,
    `413` is rejected, `404` and `410` make the subscription `gone` and a new endpoint reactivates it, and an app
    without VAPID credentials still gets `503 provider_unavailable`.

  The end-to-end test (`make e2e`, also in CI) plays a browser: it reads the VAPID key from discovery, subscribes
  at a fake push service, registers the endpoint, and receives and decrypts a push from the container, then
  unsubscribes and sees `gone`.
- 🟨 Protocol clarifications for review: a Web Push endpoint outside the policy, or resolving to a non-public
  address, fails as `provider_rejected` rather than marking the subscription `gone`, because an operator's policy
  change should not delete subscriptions; and VAPID `401`/`403` are retried rather than treated as dead endpoints.

### Phase 6 — `gotalk-server` integration ⬜

Work happens in `gotalk-server`; the gateway's contract is the deliverable.

- `PushSubscription` entity and endpoints to add, list and remove a user's subscriptions. The server stores
  only the gateway `subscription_id` and the device public keys.
- A gateway client in `internal/` with the signed-request implementation and an RFC 8291 payload encryptor.
- Instance configuration: `push.gateway_url` (default: the official gateway), the instance key, enable/disable,
  and a section in the setup wizard and admin settings page. Pre-flight check that the gateway is reachable and
  the instance is verified.
- A background job that converts `NOTIFICATION_CREATE` events into pushes, honoring per-category preferences,
  mute settings, do-not-disturb, and collapse keys per conversation or topic.
- Handling of gateway responses: delete `gone` subscriptions, back off when throttled and surface gateway errors to
  operators in the admin UI and the audit log.
- Instance metadata: advertise `push` as a feature flag and the gateway's VAPID public key through
  `GET /api/v1/instance`.
- Docs and tests, including an integration test against a gateway container.

Done when a notification created on a test instance triggers a push request that a local gateway accepts.

### Phase 7 — `gotalk-client` integration ⬜

Work happens in `gotalk-client`.

- Permission flow and per-instance enable/disable in settings, plus per-category toggles.
- Device keypair generation and secure storage; registration with the gateway and with the instance; token
  refresh; unregister on sign-out and when an instance is removed.
- Android: notification channels per category, grouping and a handler that decrypts the payload.
- iOS: Notification Service Extension that decrypts the payload and falls back to the `id_only` fetch within the
  extension time limit; badge counts; Expo config plugin and EAS build setup for the extension target.
- Web: service worker for Web Push and a permission prompt that follows the browser's rules.
- Deep links from a notification to the right place, board, topic, channel or conversation.
- Suppress pushes while the app is in the foreground and connected to the realtime gateway.
- Tests on real devices for iOS and Android, since simulators do not cover push.

Done when a push for a mention on an iOS device, an Android device and a browser opens the right screen.

**Milestone A:** Phases 0–7 give working push end to end, free and unmetered, on a staging gateway.

### Phase 8 — Abuse, privacy and hardening ⬜

- **Device attestation:** App Attest on iOS and Play Integrity on Android, so only genuine app installs can
  register devices with the official gateway. Gateways serving custom builds can make this optional.
- **Quotas and abuse controls:** per-instance daily limits, per-device rate limits, payload-size caps,
  automatic temporary blocks for abuse, and an operator-visible reason for any block.
- **Privacy:** documented data inventory, retention limits, deletion on request, a privacy policy for the
  official gateway and a data processing agreement template.
- **Secrets:** encrypted storage of provider credentials and instance keys, a documented rotation procedure for
  APNs keys, FCM credentials and VAPID keys.
- **Security review:** dependency scanning, fuzzing of the request parser and payload handling, and an external
  review of the signing and subscription-binding logic before launch.
- **Responsible disclosure:** a `SECURITY.md` and a contact.

Done when the threat-model mitigations each map to a test or a documented control.

### Phase 9 — Production operations ⬜

- Deployment for the official gateway: Helm chart, at least two replicas in separate zones, managed Postgres and
  Redis, autoscaling on queue depth and latency, and zero-downtime migrations.
- Dashboards and alerts: delivery success rate, p95 latency, provider error rates, queue depth, token
  invalidation rate and certificate or key expiry.
- SLOs for the official gateway (for example, 99.9% availability and p95 end-to-end under 2 seconds), and a
  public status page.
- Runbooks: provider outage, APNs key rotation, a leaked instance key, abuse takedown and database restore.
- Load and soak tests, including a thundering herd where one large instance pushes to many devices.
- Backups and disaster recovery with a tested restore.

Done when a staged load test meets the SLOs and each alert has a runbook.

**Milestone B:** Phases 0–9 give a production-ready official gateway, still free. Ship it with the first public
mobile release.

### Phase 10 — Operator portal, plans and billing ⬜

The money phase. It never gates app features: plans change capacity and support, not what Gotalk can do.

- Operator accounts, and a portal that lists an operator's instances with verification status, key rotation,
  and usage (pushes sent, failures, active devices).
- Plan model: a generous free tier per instance, plus paid tiers with higher daily volume and priority support.
  Limits come from the plan, so quota enforcement from Phase 8 needs no new mechanism.
- Billing through Stripe (Checkout and the customer portal), webhooks for plan changes, invoices and dunning.
  Failed payment downgrades capacity to the free tier. It never cuts a free-tier instance off.
- Usage metering and exports, plus alerts to operators approaching their quota.
- **White-label apps:** a managed flow to register a custom app (bundle ID, FCM project, `.p8` key) with
  credentials stored encrypted, so organizations can ship their own branded builds against the hosted gateway.
- Tax, invoicing and terms of service for the official gateway.

Done when an instance can upgrade, exceed the free tier without errors, and downgrade cleanly.

### Phase 11 — Self-hosting the gateway and the open-source release ⬜

- Documentation: running your own gateway, creating your own APNs/FCM/VAPID credentials, building a custom client
  that points at it, and configuring `gotalk-server` to use it.
- A single-node mode (no Redis, no billing) and a config validator with pre-flight checks like the server's.
- Helm chart, Kustomize manifests and Compose files, signed release binaries and container images, and a
  changelog.
- A conformance test suite and a mock gateway in the repo, so third-party gateways and clients can verify protocol
  compatibility.
- `README`, `CONTRIBUTING`, `CODE_OF_CONDUCT`, issue templates, and the trademark policy that says what makes a
  gateway "official".
- A launch checklist: audit complete, SLOs met, status page live and support channel staffed.

Done when someone outside the project can stand up a gateway, ship a custom build and get pushes from their own
instance using only the docs.

### Phase 12 — Later ⬜

Valuable, but not needed to complete the project.

- **Incoming voice call ringing:** PushKit/CallKit on iOS and high-priority FCM on Android, once the client's
  voice phase calls for it. Apple's rules on VoIP pushes make this its own project.
- **UnifiedPush and ntfy** support for Android devices without Google services.
- **Multi-gateway fallback:** an instance lists more than one gateway, and a client registers with each.
- **Smart batching and digests:** merge bursts of notifications into one push.
- **Desktop notifications** through the gateway for a closed app, if native desktop notifications from the open
  app prove not to be enough.
- **Regional gateways** for data-residency requirements.

## Risks and open questions

| Risk | Mitigation |
|---|---|
| Decrypting RFC 8291 payloads inside an iOS Notification Service Extension is non-trivial and has tight time and memory limits | Prototype in Phase 0 and keep the `id_only` fallback. Build the extension before finalizing the envelope format. |
| Apple and Google policy changes (entitlements, rate limits, quotas) | Isolate providers behind one interface and track platform changes in the runbooks. |
| The gateway is a single point of failure for push on the official app | Multiple replicas, an SLO and status page, and the Phase 12 multi-gateway fallback. |
| Abuse of free registration (spam to real devices) | Instance-origin binding, domain verification, attestation, quotas and the blocklist. |
| Registration is unauthenticated by design (a device cannot prove it is logged in to an instance) | Subscriptions only work for the instance they were created for, and the user can delete them at any time. |
| Operator expectation that push works with no dependency on the publisher | Make the gateway URL configurable, publish the protocol and run a gateway in a couple of commands (Phase 11). |

## Summary

| Phase | Adds | Depends on |
|---|---|---|
| 0. Protocol and decisions | Protocol spec, threat model, OpenAPI, accounts, licensing | None |
| 1. Foundation | Scaffold, config, schema, CI, discovery | 0 |
| 2. Instance registration | Instance keys, domain verification, signed requests, rate limits | 1 |
| 3. Device subscriptions | Device registration, app registry, token invalidation | 2 |
| 4. Delivery pipeline | Push API, queue, APNs and FCM, delivery log | 3 |
| 5. Web Push | VAPID forwarding, browser subscriptions | 4 |
| 6. Server integration | Subscriptions API, gateway client, notification jobs, admin UX | 4 (and 5 for web) |
| 7. Client integration | Permissions, keys, registration, iOS extension, Android channels, deep links | 4, 6 |
| 8. Hardening | Attestation, quotas, privacy, secrets, security review | 7 |
| 9. Operations | Official deployment, SLOs, runbooks, load tests | 8 |
| 10. Portal and billing | Operator accounts, plans, Stripe, white-label apps | 9 |
| 11. Self-host and open-source release | Docs, packaging, conformance suite, trademark policy | 9 |
| 12. Later | Call ringing, UnifiedPush, multi-gateway, batching, regional gateways | 10, 11 |
