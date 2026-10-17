# Contributing

Gotalk Push Gateway is licensed under [AGPL-3.0-only](LICENSE). The project is in its design phase; see
[docs/gateway-plan.md](docs/gateway-plan.md) for what is being built and [docs/](docs/README.md) for the protocol.

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). By
signing off, you state that you wrote the contribution or have the right to submit it under the project's license.

Sign off every commit with `git commit -s`, which adds this line using your configured name and email:

```
Signed-off-by: Jane Developer <jane@example.com>
```

Pull requests with unsigned commits are not merged. There is no contributor license agreement, so you keep the
copyright in your contributions.

## Changing the protocol

The protocol is the product: instances, clients and third-party gateways depend on it.

- Update [docs/protocol.md](docs/protocol.md), [docs/payload.md](docs/payload.md) and
  [docs/openapi.yaml](docs/openapi.yaml) together in the same pull request.
- Within a major version, changes are additive only. Anything else needs a new major version.
- Changes that affect what the gateway or providers can see must update
  [docs/threat-model.md](docs/threat-model.md).

## Reporting security problems

Do not open a public issue. A `SECURITY.md` with a contact is added in Phase 8; until then, contact the maintainers
privately.
