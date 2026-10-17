-- Schema v1: the registry of apps, instances and devices, plus usage, the delivery log and the
-- blocklist. Behavior is specified in docs/protocol.md. No table stores notification content.

-- +goose Up

-- An app is a bundle ID / package name plus provider credentials. Apps are declared in the
-- gateway config and synced here at startup; apps removed from the config are disabled, not
-- deleted, because devices reference them.
CREATE TABLE apps (
    id                   text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    name                 text NOT NULL CHECK (name <> ''),
    ios_bundle_id        text,
    android_package_name text,
    -- Uncompressed P-256 point, base64url without padding.
    web_vapid_public_key text,
    attestation_required boolean NOT NULL DEFAULT false,
    enabled              boolean NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CHECK (ios_bundle_id IS NOT NULL OR android_package_name IS NOT NULL OR web_vapid_public_key IS NOT NULL)
);

-- An instance is a gotalk-server identified by its normalized origin.
CREATE TABLE instances (
    id                    text PRIMARY KEY,
    origin                text NOT NULL CHECK (origin ~ '^https?://[a-z0-9.-]+(:[0-9]{1,5})?$'),
    status                text NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'active', 'suspended', 'blocked')),
    contact_email         text NOT NULL,
    software              text,
    software_version      text,
    -- Shown to the operator when status is 'blocked'.
    blocked_reason        text,
    -- Consecutive failed re-verifications; 3 suspends an active instance.
    verification_failures integer NOT NULL DEFAULT 0 CHECK (verification_failures >= 0),
    -- Pending registrations expire 24 hours after creation.
    pending_expires_at    timestamptz,
    verified_at           timestamptz,
    last_verified_at      timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'blocked') = (blocked_reason IS NOT NULL)),
    CHECK ((status = 'pending') = (pending_expires_at IS NOT NULL))
);

-- A verified origin has exactly one instance; several pending registrations may coexist.
CREATE UNIQUE INDEX instances_origin_verified_key ON instances (origin) WHERE status <> 'pending';
CREATE INDEX instances_origin_idx ON instances (origin);
CREATE INDEX instances_pending_expires_idx ON instances (pending_expires_at) WHERE status = 'pending';

-- Ed25519 keys an instance signs requests with. At most 3 are pending or active at once
-- (enforced by the service).
CREATE TABLE instance_keys (
    id           text PRIMARY KEY,
    instance_id  text NOT NULL REFERENCES instances (id) ON DELETE CASCADE,
    public_key   bytea NOT NULL CHECK (octet_length(public_key) = 32),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
    activated_at timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX instance_keys_instance_public_key_key ON instance_keys (instance_id, public_key);

-- A device subscription binds one platform token to one (app, instance) pair. The gateway
-- never receives device keys, and stores only a hash of the subscription secret.
CREATE TABLE devices (
    id               text PRIMARY KEY,
    app_id           text NOT NULL REFERENCES apps (id),
    instance_id      text NOT NULL REFERENCES instances (id) ON DELETE CASCADE,
    platform         text NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
    -- APNs device token, FCM registration token, or Web Push endpoint URL.
    token            text NOT NULL CHECK (octet_length(token) BETWEEN 1 AND 4096),
    -- SHA-256 of token: tokens are too long for a btree uniqueness check.
    token_hash       bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    apns_environment text CHECK (apns_environment IN ('production', 'sandbox')),
    secret_hash      bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'gone')),
    expires_at       timestamptz NOT NULL,
    gone_at          timestamptz,
    last_push_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK ((platform = 'ios') = (apns_environment IS NOT NULL)),
    CHECK ((status = 'gone') = (gone_at IS NOT NULL))
);

CREATE UNIQUE INDEX devices_target_key ON devices (app_id, instance_id, platform, token_hash);
CREATE INDEX devices_instance_idx ON devices (instance_id);
CREATE INDEX devices_expires_idx ON devices (expires_at);
CREATE INDEX devices_gone_idx ON devices (gone_at) WHERE status = 'gone';

-- Daily per-instance counters (UTC days) for quotas and the operator view.
CREATE TABLE usage_counters (
    instance_id text NOT NULL REFERENCES instances (id) ON DELETE CASCADE,
    day         date NOT NULL,
    -- Push entries accepted (202) and rejected before queueing.
    accepted    bigint NOT NULL DEFAULT 0 CHECK (accepted >= 0),
    rejected    bigint NOT NULL DEFAULT 0 CHECK (rejected >= 0),
    -- Final delivery outcomes reported by providers.
    sent        bigint NOT NULL DEFAULT 0 CHECK (sent >= 0),
    failed      bigint NOT NULL DEFAULT 0 CHECK (failed >= 0),
    PRIMARY KEY (instance_id, day)
);

-- One row per accepted push: IDs, status and latency only, never content. Rows are pruned
-- after the retention period (72 hours by default).
CREATE TABLE delivery_log (
    id              text PRIMARY KEY,
    instance_id     text NOT NULL REFERENCES instances (id) ON DELETE CASCADE,
    -- No foreign key: an entry outlives a deleted subscription so the instance can still
    -- read its status.
    subscription_id text NOT NULL,
    notification_id text NOT NULL CHECK (notification_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'sent', 'failed', 'expired', 'gone')),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error_code      text,
    -- Time from acceptance to the provider's final answer.
    latency_ms      integer CHECK (latency_ms >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX delivery_log_created_idx ON delivery_log (created_at);
CREATE INDEX delivery_log_instance_created_idx ON delivery_log (instance_id, created_at);

-- Operator blocks on registration and use. 'origin' matches a normalized origin exactly,
-- 'domain' matches a host and its subdomains, 'cidr' matches client addresses.
CREATE TABLE blocklist (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('origin', 'domain', 'cidr')),
    value      text NOT NULL CHECK (value <> ''),
    reason     text NOT NULL CHECK (reason <> ''),
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

-- +goose Down

DROP TABLE blocklist;
DROP TABLE delivery_log;
DROP TABLE usage_counters;
DROP TABLE devices;
DROP TABLE instance_keys;
DROP TABLE instances;
DROP TABLE apps;
