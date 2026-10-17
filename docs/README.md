# Documentation

Documentation for the Gotalk push gateway. Phase 0 (protocol and decisions) produced the design documents, and
Phase 1 (foundation) added the operator and developer guides.

| Document | Contents |
|---|---|
| [gateway-plan.md](gateway-plan.md) | Why the gateway exists, architecture, phases and risks |
| [protocol.md](protocol.md) | Discovery, instance registration, request signing, device registration, push requests, errors |
| [payload.md](payload.md) | Encrypted envelope, `id_only` mode, size limits, provider mapping |
| [openapi.yaml](openapi.yaml) | OpenAPI 3.1 contract for every endpoint |
| [threat-model.md](threat-model.md) | What the gateway can and cannot see, threats and mitigations |
| [accounts-and-logistics.md](accounts-and-logistics.md) | Provider accounts, domain, naming and licensing |
| [configuration.md](configuration.md) | Every configuration option, environment variables and the app registry |
| [development.md](development.md) | Repository layout, make targets, tests, database and API changes, CI |
