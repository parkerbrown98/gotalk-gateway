-- Push delivery (Phase 4): failure details on the delivery log and Idempotency-Key replays.
-- The delivery queue is river's schema, which database.Migrate applies after these files.

-- +goose Up

ALTER TABLE delivery_log
    -- A short provider reason for the last failure, such as "APNs BadDeviceToken". Never content.
    ADD COLUMN error_detail text CHECK (octet_length(error_detail) <= 200),
    -- The codes a push can report after it was accepted (docs/protocol.md, "Errors").
    ADD CONSTRAINT delivery_log_error_code_check CHECK (error_code IS NULL OR error_code IN
        ('subscription_gone', 'provider_rejected', 'provider_unavailable', 'internal_error'));

-- The 202 response of a push request sent with an Idempotency-Key, replayed for 24 hours.
CREATE TABLE push_idempotency (
    instance_id text NOT NULL REFERENCES instances (id) ON DELETE CASCADE,
    key         text NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 64),
    -- SHA-256 of the request path and body: a key reused for another request is refused.
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    response    jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, key)
);

CREATE INDEX push_idempotency_created_idx ON push_idempotency (created_at);

-- +goose Down

DROP TABLE push_idempotency;
ALTER TABLE delivery_log
    DROP CONSTRAINT delivery_log_error_code_check,
    DROP COLUMN error_detail;
