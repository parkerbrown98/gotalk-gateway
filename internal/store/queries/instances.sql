-- name: GetInstance :one
SELECT * FROM instances WHERE id = $1;

-- name: LockInstance :one
SELECT * FROM instances WHERE id = $1 FOR UPDATE;

-- name: GetVerifiedInstanceByOrigin :one
SELECT * FROM instances WHERE origin = $1 AND status <> 'pending';

-- name: ListInstancesByOrigin :many
SELECT * FROM instances WHERE origin = $1 ORDER BY created_at, id;

-- name: ListInstances :many
SELECT * FROM instances
WHERE sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text
ORDER BY created_at, id
LIMIT @max_rows;

-- name: FindPendingRegistration :one
SELECT i.id AS instance_id, k.id AS key_id, i.pending_expires_at
FROM instances i
JOIN instance_keys k ON k.instance_id = i.id
WHERE i.origin = @origin AND i.status = 'pending' AND i.pending_expires_at > now() AND k.public_key = @public_key;

-- name: CreateInstance :exec
INSERT INTO instances (id, origin, contact_email, software, software_version, pending_expires_at)
VALUES (@id, @origin, @contact_email, @software, @software_version, @pending_expires_at);

-- name: ActivateInstance :exec
UPDATE instances
SET status = 'active', pending_expires_at = NULL, verified_at = now(), last_verified_at = now(),
    verification_failures = 0, last_verification_error = NULL, next_verification_at = @next_verification_at,
    updated_at = now()
WHERE id = @id AND status = 'pending';

-- name: RecordVerificationSuccess :exec
UPDATE instances
SET status = CASE WHEN status = 'suspended' THEN 'active' ELSE status END,
    last_verified_at = now(), verification_failures = 0, last_verification_error = NULL,
    next_verification_at = @next_verification_at, updated_at = now()
WHERE id = @id AND status IN ('active', 'suspended');

-- name: RecordVerificationFailure :one
UPDATE instances
SET verification_failures = verification_failures + 1,
    status = CASE WHEN status = 'active' AND verification_failures + 1 >= @max_failures::int THEN 'suspended' ELSE status END,
    last_verification_error = @last_verification_error, next_verification_at = @next_verification_at,
    updated_at = now()
WHERE id = @id AND status IN ('active', 'suspended')
RETURNING status, verification_failures;

-- name: ClaimDueVerifications :many
-- Moves next_verification_at forward by the lease so other replicas skip these rows while
-- this one verifies them.
UPDATE instances
SET next_verification_at = now() + make_interval(secs => @lease_seconds::int)
WHERE id IN (
    SELECT id FROM instances
    WHERE status IN ('active', 'suspended') AND next_verification_at <= now()
    ORDER BY next_verification_at
    LIMIT @batch
    FOR UPDATE SKIP LOCKED
)
RETURNING id;

-- name: DeleteInstance :execrows
DELETE FROM instances WHERE id = $1;

-- name: DeleteExpiredPendingInstances :execrows
DELETE FROM instances WHERE status = 'pending' AND pending_expires_at <= now();

-- name: BlockInstance :execrows
UPDATE instances
SET status = 'blocked', blocked_reason = @reason, updated_at = now()
WHERE id = @id AND status <> 'pending';

-- name: UnblockInstance :execrows
-- The instance is re-verified right away; it is suspended again if the origin no longer
-- advertises its keys.
UPDATE instances
SET status = 'active', blocked_reason = NULL, next_verification_at = now(), updated_at = now()
WHERE id = @id AND status = 'blocked';

-- name: InstanceUsageToday :one
SELECT
    coalesce((SELECT u.accepted FROM usage_counters u WHERE u.instance_id = @id AND u.day = (now() AT TIME ZONE 'UTC')::date), 0)::bigint AS pushes_accepted,
    coalesce((SELECT u.failed FROM usage_counters u WHERE u.instance_id = @id AND u.day = (now() AT TIME ZONE 'UTC')::date), 0)::bigint AS pushes_failed,
    (SELECT count(*) FROM devices d WHERE d.instance_id = @id AND d.status = 'active')::bigint AS active_subscriptions;
