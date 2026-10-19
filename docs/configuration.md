# Configuration

The gateway reads configuration in layers. Each layer overrides the previous one:

1. Built-in defaults (the values in [config.example.yaml](../config.example.yaml)).
2. A YAML file passed with `--config FILE` or `GOTALK_GATEWAY_CONFIG`.
3. Environment variables.
4. Command-line flags: `--set KEY=VALUE` (repeatable) and the shorthands `--addr`, `--log-level` and
   `--log-format`.

The gateway validates the whole configuration at startup and lists every problem at once.

## Environment variables

Each key maps to `GOTALK_GATEWAY_<SECTION>_<KEY>` in upper case: `database.url` is
`GOTALK_GATEWAY_DATABASE_URL`, `server.public_url` is `GOTALK_GATEWAY_SERVER_PUBLIC_URL`.

- Add `_FILE` to read the value from a file, for Docker and Kubernetes secrets:
  `GOTALK_GATEWAY_DATABASE_URL_FILE=/run/secrets/db-url`.
- Empty variables are ignored, so Compose files can pass optional values through.
- `DATABASE_URL`, `REDIS_URL` and `PORT` are honored as fallbacks for platforms that set them. They only replace
  the built-in defaults: the config file and `GOTALK_GATEWAY_*` variables take precedence.
- List values (`server.trusted_proxies`) are comma-separated.
- Apps can only be declared in the config file.
- The PostgreSQL driver also reads the standard `PG*` variables, such as `PGPASSWORD`.

## Options

### `server`

| Key | Default | Description |
|---|---|---|
| `addr` | `:8090` | Listen address. |
| `public_url` | (derived) | External base URL, such as `https://push.example.com`. Discovery advertises `{public_url}/v1` as `api_base_url`. When empty, the URL comes from each request. Set this in production. |
| `trust_proxy` | `false` | Honor `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`, but only from `trusted_proxies`. Without `public_url`, discovery builds `api_base_url` from these headers and sends `Vary` on them. Set `public_url`, or make sure the proxy overwrites the headers rather than passing the client's values through. |
| `trusted_proxies` | loopback and private ranges | CIDRs of reverse proxies. |
| `drain_delay` | `0s` | After `SIGTERM`, keep serving for this long while `/readyz` reports `draining`, so load balancers stop routing here first. Use `5s` or more on Kubernetes. |
| `shutdown_timeout` | `20s` | How long in-flight requests get to finish after draining. |

### `database`

| Key | Default | Description |
|---|---|---|
| `url` | `postgres://gotalk:gotalk@localhost:5432/gotalk_gateway?sslmode=disable` | PostgreSQL connection string, as a URL or in keyword/value form. |
| `max_conns` | `20` | Connection pool size. |
| `auto_migrate` | `true` | Apply pending migrations at startup. Replicas take an advisory lock, so they can start at the same time. Set it to `false` to run `gotalk-gateway migrate` yourself. |
| `connect_timeout` | `30s` | How long startup waits for PostgreSQL and Redis to become reachable. |

### `redis`

| Key | Default | Description |
|---|---|---|
| `url` | (empty) | Redis URL, such as `redis://redis:6379/0`. When it is empty, the gateway runs in single-node mode and keeps nonces and rate limits in memory. Set it before running more than one replica. |

### `log`

| Key | Default | Description |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn` or `error`. Requests to health, readiness and metrics endpoints are logged at `debug`. |
| `format` | `json` | `json` or `text`. |

### `metrics`

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Serve Prometheus metrics at `/metrics`. |
| `addr` | (empty) | Serve `/metrics` on its own listener (for example `:9090`) instead of `server.addr`, which keeps it off the public port. |

Exported metrics include `gotalk_gateway_http_requests_total{method,route,status}`,
`gotalk_gateway_http_request_duration_seconds{method,route}`, `gotalk_gateway_http_requests_in_flight`,
`gotalk_gateway_build_info{version,goversion}`, and the standard Go and process collectors.

### `gateway`

| Key | Default | Description |
|---|---|---|
| `name` | `Gotalk Push Gateway` | Display name in discovery. |
| `terms_url` | (empty) | Terms of service URL, listed in discovery when set. |
| `privacy_url` | (empty) | Privacy policy URL, listed in discovery when set. |
| `subscription_expiry_days` | `60` | How long a device subscription lives without a refresh, from 14 to 365 days. |

### `instances`

Instance registration and domain verification. Leave these at their defaults in production.

| Key | Default | Description |
|---|---|---|
| `allow_http` | `false` | Accept `http://` origins. Development only: the origin's well-known document is the root of trust, and plain HTTP lets anyone on the network path forge it. |
| `allow_private_networks` | `false` | Let verification fetch loopback, private, link-local and other non-public addresses. Development only: otherwise anyone can use registration to probe the gateway's internal network. |
| `allowed_ports` | `[]` | Origin ports allowed besides the scheme's default (443), for example `[8443]`. Registration refuses other ports, and verification connects only to allowed ports. |

Verification fetches always refuse redirects and proxies. They time out after 5 seconds, are limited to 64 KiB of
`application/json`, and run at most 16 at a time. The address is checked on every connection, after DNS
resolution.

### `devices`

Device subscriptions. How long a subscription lives without a refresh is `gateway.subscription_expiry_days`.
Subscriptions that a provider reports as dead are kept for 7 days and then deleted. Both are pruned every
10 minutes.

| Key | Default | Description |
|---|---|---|
| `web_push_hosts` | FCM, Mozilla, Apple and Windows push services | Web Push endpoints must be on one of these hosts or a subdomain: `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `web.push.apple.com`, `notify.windows.com`. Set `[]` to accept any public host. Endpoints must use https on port 443 either way. The list is checked at registration and again before every delivery, so narrowing it also stops pushes to existing subscriptions (they fail with `provider_rejected`). |
| `web_push_allow_insecure` | `false` | **Development only.** Accepts and delivers to `http` endpoints on any port and host, including private networks, for a local fake push service. Never enable it in production: it lets anyone who can register a device make the gateway send requests into its own network. |

Web Push deliveries connect only to public addresses on port 443, checked after DNS resolution on every
connection, and never follow redirects or use proxies.

### `delivery`

Accepted pushes are queued in PostgreSQL ([river](https://riverqueue.com)) and delivered by workers on every replica
that has them. A push to a provider that fails transiently is retried up to 5 times, starting after about a second
and doubling each time with jitter, or until its TTL runs out. A provider's `Retry-After` is honored. A push whose
retries run out is dead-lettered: its status becomes `failed`, and its queue job stays `cancelled` (with every
attempt's error) for `dead_letter_retention`. Completed jobs are deleted after a minute, because they hold the
encrypted payload; the delivery log keeps IDs, status and latency for 72 hours.

| Key | Default | Description |
|---|---|---|
| `workers` | `50` | Pushes this replica delivers concurrently. `0` makes an API-only replica that queues pushes but does not deliver them; at least one replica must deliver. |
| `provider_timeout` | `10s` | Timeout of each request to APNs, FCM or a Web Push service (1s to 1m). |
| `dead_letter_retention` | `24h` | How long a push whose retries ran out stays in the queue for inspection (1m to 720h). |

On shutdown a replica stops taking new pushes from the queue and lets in-flight deliveries finish within
`server.shutdown_timeout`. Queued pushes wait for the next replica.

### `ratelimit`

Rates use `<limit>-<period>`, where the period is `S`, `M`, `H` or `D`. When `redis.url` is set, counters are shared
through Redis; otherwise each process keeps its own. Limited responses carry `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Reset`. A `429` also carries `Retry-After`.

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Turn every limit off with `false` (for example, behind your own rate limiter). |
| `registration` | `5-H` | `POST /v1/instances` per client IP (per /64 for IPv6). |
| `signed` | `1200-M` | Signed requests per instance. |
| `device_registration` | `60-H` | `POST /v1/devices` per client IP (per /64 for IPv6). |
| `device_token` | `10-H` | Registrations of one platform token or endpoint, and `PUT` switches to it. |
| `device_update` | `60-H` | `PUT /v1/devices/{id}` per subscription, counted only after the secret is checked. |
| `verification` | `12-H` | `POST /v1/instances/{id}/verify` per signing key. Each one fetches the origin. The limit is per key so that someone who registers a key for another origin cannot use up that origin owner's budget. |

## Operator commands

Blocks and instance changes are made with the CLI against the same database. Running gateways pick up blocklist
changes within 30 seconds, and instance blocks immediately.

```sh
gotalk-gateway instances list [--status pending|active|suspended|blocked] [--limit N]
gotalk-gateway instances show ID|ORIGIN
gotalk-gateway instances block ID|ORIGIN --reason "Shown to the instance operator."
gotalk-gateway instances unblock ID|ORIGIN        # re-verified within a minute
gotalk-gateway instances delete ID|ORIGIN --yes   # deletes its subscriptions too
gotalk-gateway blocklist list
gotalk-gateway blocklist add origin|domain|cidr VALUE --reason TEXT [--expires 72h]
gotalk-gateway blocklist remove origin|domain|cidr VALUE
```

How the blocklist kinds match:

- `origin` matches one origin exactly.
- `domain` matches a host and all its subdomains, which blocks registration and every signed request from
  matching instances.
- `cidr` matches client addresses on unsigned endpoints, such as registration.

In the container, run the commands as `docker compose exec gateway /gotalk-gateway …`.

### `apps`

The app registry: the bundle IDs, package names and VAPID public keys this gateway serves. Devices can only register
for listed apps. At startup the configured apps are written to the database. Apps that were removed from the file
are disabled, not deleted, because existing subscriptions refer to them. Configuring a disabled app again
re-enables it.

```yaml
apps:
  - id: gotalk                 # ^[a-z0-9][a-z0-9-]{0,31}$
    name: Gotalk
    ios:
      bundle_id: app.example.gotalk
    android:
      package_name: app.example.gotalk
    web:
      vapid_public_key: B…     # uncompressed P-256 public key, base64url without padding
```

Each app needs at least one platform.

**Provider credentials.** Without them, devices can still register, but pushes to them are refused with
`503 provider_unavailable`. Credentials are read at startup, never written to the database, and should be mounted as
secrets and referenced with the `*_file` settings.

```yaml
apps:
  - id: gotalk
    name: Gotalk
    ios:
      bundle_id: app.example.gotalk
      apns:
        team_id: ABCDE12345                      # Apple Developer team ID
        key_id: FGHIJ67890                       # ID of the APNs authentication key
        private_key_file: /run/secrets/apns.p8   # or private_key: the PEM contents
    android:
      package_name: app.example.gotalk
      fcm:
        service_account_file: /run/secrets/fcm.json   # or service_account: the JSON
        project_id: my-firebase-project               # optional; defaults to the key's project
    web:
      vapid_public_key: B…
      vapid:
        private_key_file: /run/secrets/vapid.key      # or private_key: the key itself
        subject: mailto:push-ops@example.com          # or an https: contact URL
```

| Key | Description |
|---|---|
| `ios.apns.team_id`, `ios.apns.key_id` | The 10-character team ID and key ID of an APNs authentication key (`.p8`). One key serves every app of the team, in both environments. |
| `ios.apns.private_key`, `ios.apns.private_key_file` | The `.p8` key. Set exactly one. The gateway signs a provider token with it and replaces the token every 50 minutes. |
| `ios.apns.production_url`, `ios.apns.sandbox_url` | Override Apple's endpoints, for testing against a fake. A subscription's `apns_environment` picks one. |
| `android.fcm.service_account`, `android.fcm.service_account_file` | A Google service account key (JSON) allowed to send with the FCM HTTP v1 API (the "Firebase Cloud Messaging API Admin" role, or `cloudmessaging.messages.create`). Set exactly one. |
| `android.fcm.project_id` | The Firebase project, when it differs from the key's `project_id`. |
| `android.fcm.endpoint` | Overrides `https://fcm.googleapis.com`, for testing against a fake. |
| `web.vapid.private_key`, `web.vapid.private_key_file` | The VAPID private key matching `web.vapid_public_key`: the 32-byte P-256 key in base64url, as `npx web-push generate-vapid-keys` prints it, or a PEM key (`openssl ecparam -name prime256v1 -genkey -noout`). Set exactly one. The gateway refuses to start when it does not match the public key. Browsers subscribe with the public key, so changing the pair invalidates every browser subscription of the app; see [web-push.md](web-push.md#vapid-keys). |
| `web.vapid.subject` | The VAPID `sub` claim: a `mailto:` or `https:` URL where push services can reach the gateway operator. Required with a private key; Apple's push service refuses tokens without it. |
