# Gotalk Push Gateway

The push notification gateway for [Gotalk](https://github.com/parkerbrown98/gotalk-server). Gotalk instances send
end-to-end encrypted notification payloads to the gateway, and the gateway forwards them to APNs, FCM and Web
Push. The gateway never sees notification content. [docs/gateway-plan.md](docs/gateway-plan.md) explains why it
exists, and [docs/protocol.md](docs/protocol.md) specifies the protocol.

**Status:** Phase 1 (foundation) is done. The gateway runs, migrates its database, serves discovery, health,
readiness and metrics. Instance registration, device subscriptions and delivery come in Phases 2 to 5.

## Quick start

```sh
docker compose up -d --wait
curl http://localhost:8090/.well-known/gotalk-gateway
```

This starts the gateway with PostgreSQL and Redis, using [config.example.yaml](config.example.yaml) (placeholder
app IDs). Stop it with `docker compose down`.

To run from source against the Compose database: `docker compose up -d postgres redis`, then
`make run`. See [docs/development.md](docs/development.md).

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/gotalk-gateway`, `GET /v1/gateway` | Discovery document: name, version, API versions, platforms, apps (with VAPID public keys) and limits. Cacheable for 5 minutes. |
| `GET /healthz` | Liveness: the process is serving HTTP. |
| `GET /readyz` | Readiness: PostgreSQL (and Redis, when configured) answer, and the gateway is not shutting down. Returns `503` otherwise. |
| `GET /metrics` | Prometheus metrics. Can move to its own listener with `metrics.addr`. |
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
