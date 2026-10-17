-- Instance registration and request authentication (Phase 2).

-- +goose Up

ALTER TABLE instance_keys
    -- A recovery key was registered for an already verified origin. Verifying it proves
    -- domain control again and revokes every other key of the instance.
    ADD COLUMN recovery boolean NOT NULL DEFAULT false,
    -- Pending recovery keys expire 24 hours after registration.
    ADD COLUMN expires_at timestamptz,
    ADD CONSTRAINT instance_keys_expires_pending_check CHECK (expires_at IS NULL OR status = 'pending'),
    ADD CONSTRAINT instance_keys_recovery_pending_check CHECK (NOT recovery OR status = 'pending');

CREATE INDEX instance_keys_expires_idx ON instance_keys (expires_at) WHERE expires_at IS NOT NULL;

ALTER TABLE instances
    -- When the scheduled re-verification of an active or suspended instance is due. Replicas
    -- claim due rows by moving this forward.
    ADD COLUMN next_verification_at timestamptz,
    -- Why the last scheduled re-verification failed; shown as status_reason while suspended.
    ADD COLUMN last_verification_error text;

CREATE INDEX instances_next_verification_idx ON instances (next_verification_at)
    WHERE status IN ('active', 'suspended');

-- +goose Down

DROP INDEX instances_next_verification_idx;
ALTER TABLE instances DROP COLUMN last_verification_error, DROP COLUMN next_verification_at;
DROP INDEX instance_keys_expires_idx;
ALTER TABLE instance_keys
    DROP CONSTRAINT instance_keys_recovery_pending_check,
    DROP CONSTRAINT instance_keys_expires_pending_check,
    DROP COLUMN expires_at,
    DROP COLUMN recovery;
