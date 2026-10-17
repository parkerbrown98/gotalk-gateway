# Development

Requirements: Go (the version in `go.mod`) and Docker. For linting and code generation you also need
[golangci-lint](https://golangci-lint.run/) v2 and [sqlc](https://sqlc.dev/) 1.30.

## Layout

```
cmd/gotalk-gateway/     Entry point: serve, migrate, healthcheck, openapi, version
internal/api/           HTTP: router, middleware, problem errors, discovery, health, metrics
internal/apps/          App registry: config validation, sync to the database, cached listing
internal/config/        Layered configuration
internal/database/      PostgreSQL connection and embedded goose migrations
internal/database/migrations/  Schema (one file per version)
internal/ids/           Prefixed random IDs (inst_, key_, sub_, push_, req_)
internal/protocol/      Fixed protocol values: API versions, platforms, limits
internal/store/         sqlc-generated queries (do not edit; edit internal/store/queries/)
internal/testdb/        Test helper: a migrated database on a shared PostgreSQL container
scripts/smoke.sh        Smoke test for a running gateway
```

## Common tasks

`make help` lists every target.

| Task | Command |
|---|---|
| Run the stack in Docker | `make up`, then `make smoke` and `make logs`; stop it with `make down` |
| Run from source | `docker compose up -d postgres redis`, then `make run` |
| All tests (needs Docker) | `make test` |
| Tests without containers | `make test-unit` (runs `go test -short`; PostgreSQL tests are skipped) |
| Lint and format | `make lint`, `make fmt` |
| Regenerate queries | `make sqlc` after you change `internal/store/queries/` or a migration |
| Print the implemented API spec | `make openapi` |

`make run` uses the Compose database at `localhost:5432`. Publish its port by adding
`ports: ["5432:5432"]` to the `postgres` service in a `docker-compose.override.yml`, or point
`GOTALK_GATEWAY_DATABASE_URL` at another database.

## Database changes

Add a new numbered file in `internal/database/migrations/` with `-- +goose Up` and `-- +goose Down` sections. Never
edit a migration that has been released. Run `make sqlc` afterwards. CI fails if `internal/store` is out of date.

## API changes

[docs/openapi.yaml](openapi.yaml) is the published contract. Two checks keep the code and the contract in step:

- `TestOpenAPIMatchesContract` (in `internal/api`) compares the spec generated from the code with the contract.
  Every implemented operation must be in the contract with the same `operationId` and response schema. Schemas
  with the same name must have the same properties and required fields.
- On pull requests, CI runs [oasdiff](https://github.com/oasdiff/oasdiff) on `docs/openapi.yaml` against the base
  branch and fails on breaking changes. Adding response enum values is allowed, because the protocol makes it
  additive ([docs/oasdiff-levels.txt](oasdiff-levels.txt)).

When you implement an endpoint, update the contract and [protocol.md](protocol.md) in the same pull request (see
[CONTRIBUTING.md](../CONTRIBUTING.md)).

## CI

[.github/workflows/ci.yml](../.github/workflows/ci.yml) runs these jobs:

- `go vet` and golangci-lint.
- `sqlc diff`.
- Tests with `-race`, with PostgreSQL in containers.
- Validation of the OpenAPI contract and the breaking-change check.
- A `docker compose up` smoke test that includes graceful shutdown.
- A multi-arch image build, pushed to `ghcr.io/parkerbrown98/gotalk-gateway` from `main` and from tags.
