# Gotalk Push Gateway

The push notification gateway for [Gotalk](https://github.com/parkerbrown98/gotalk-server). Gotalk instances send
end-to-end encrypted notification payloads to the gateway, and the gateway forwards them to APNs, FCM and Web
Push. The gateway never sees notification content. [docs/gateway-plan.md](docs/gateway-plan.md) explains why it
exists, and [docs/protocol.md](docs/protocol.md) specifies the protocol.

**Status:** Phases 1 to 5 are done. The gateway serves discovery, health, readiness and metrics. Instances can
register, prove domain control, rotate and recover keys, and make Ed25519-signed requests. Clients can register,
refresh and delete device subscriptions. Instances can push to iOS (APNs), Android (FCM) and browsers (Web Push with
VAPID) through a PostgreSQL-backed queue with retries and dead-token handling.

## Quick start

```sh
docker compose up -d --wait
curl http://localhost:8090/.well-known/gotalk-gateway
```

This starts the gateway with PostgreSQL and Redis, using [config.example.yaml](config.example.yaml) (placeholder
app IDs and no provider credentials, so pushes are refused with `provider_unavailable` until you add your APNs, FCM
and VAPID credentials; see [docs/configuration.md](docs/configuration.md#apps)). Stop it with `docker compose down`.

To run from source against the Compose database: `docker compose up -d postgres redis`, then
`make run`. See [docs/development.md](docs/development.md).

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/gotalk-gateway`, `GET /v1/gateway` | Discovery document: name, version, API versions, platforms, apps (with VAPID public keys) and limits. Cacheable for 5 minutes. |
| `GET /healthz` | Liveness: the process is serving HTTP. |
| `GET /readyz` | Readiness: PostgreSQL (and Redis, when configured) answer, and the gateway is not shutting down. Returns `503` otherwise. |
| `GET /metrics` | Prometheus metrics. Can move to its own listener with `metrics.addr`. |
| `POST /v1/instances` | Register an instance origin and Ed25519 public key (or start key recovery). |
| `GET`, `DELETE /v1/instances/{id}` | Instance status, keys and usage; deregistration. Signed. |
| `POST /v1/instances/{id}/verify` | Fetch the origin's `/.well-known/gotalk-instance` and activate advertised keys. Signed. |
| `POST /v1/instances/{id}/keys`, `DELETE /v1/instances/{id}/keys/{key_id}` | Key rotation. Signed. |
| `POST /v1/devices` | Register an APNs or FCM token or a Web Push endpoint for one app and instance. Returns `subscription_id` and a `subscription_secret`. |
| `PUT`, `DELETE /v1/devices/{id}` | Refresh or replace the token, and delete. Authorized by the subscription secret (DELETE also by the instance's signature). |
| `POST /v1/push`, `POST /v1/push/batch` | Queue one push, or up to 100, for subscriptions bound to the instance. `202` with per-entry results; `Idempotency-Key` supported. Signed. |
| `GET /v1/pushes/{id}` | Delivery status of a push: queued, sent, failed, expired or gone. Kept 72 hours, no content. Signed. |
| `GET /v1/openapi.json`, `/v1/openapi.yaml` | OpenAPI 3.1 spec of the implemented endpoints. The full contract is [docs/openapi.yaml](docs/openapi.yaml). |

Errors use `application/problem+json` with a stable `code` ([docs/protocol.md](docs/protocol.md#errors)). Every
response has an `X-Request-Id`.

## Commands

```
gotalk-gateway [serve]          Run the gateway (default)
gotalk-gateway migrate          Apply database migrations
gotalk-gateway migrate status   Show the schema version
gotalk-gateway healthcheck      Exit 0 if the local gateway is healthy (container HEALTHCHECK)
gotalk-gateway openapi          Print the OpenAPI spec of the implemented endpoints
gotalk-gateway version          Print the version
gotalk-gateway instances …      List, show, block, unblock or delete instances
gotalk-gateway blocklist …      Block origins, domains or client networks
```

Every command accepts `--config FILE`, `--set KEY=VALUE` (repeatable), `--addr`, `--log-level` and `--log-format`.

## Configuration

Configuration is layered: built-in defaults, then a YAML file (`--config` or `GOTALK_GATEWAY_CONFIG`), then
`GOTALK_GATEWAY_*` environment variables, then flags. Apps are declared in the config file. See
[docs/configuration.md](docs/configuration.md) for every option.

## Documentation

[docs/](docs/README.md) has the plan, the protocol, the payload format, the threat model and the operator guides.

## License

[AGPL-3.0-only](LICENSE). Contributions are accepted under the DCO; see [CONTRIBUTING.md](CONTRIBUTING.md).
