-- name: GetPushTargets :many
-- The subscriptions a push request names, to check ownership and status before queueing.
SELECT id, instance_id, app_id, platform, status FROM devices WHERE id = ANY(@ids::text[]);

-- name: InsertDeliveryLog :copyfrom
INSERT INTO delivery_log (id, instance_id, subscription_id, notification_id) VALUES ($1, $2, $3, $4);

-- name: GetPush :one
SELECT * FROM delivery_log WHERE id = @id AND instance_id = @instance_id;

-- name: GetDeliveryState :one
SELECT status, attempts, error_code, error_detail FROM delivery_log WHERE id = $1;

-- name: RecordDeliveryAttempt :one
-- Counted before the provider call, so an attempt that crashes the worker still counts.
UPDATE delivery_log SET attempts = attempts + 1, updated_at = now()
WHERE id = @id AND status = 'queued'
RETURNING attempts;

-- name: RecordDeliveryRetry :exec
UPDATE delivery_log SET error_code = @error_code, error_detail = @error_detail, updated_at = now()
WHERE id = @id AND status = 'queued';

-- name: FinishDelivery :one
-- Records the final outcome once. The latency runs from acceptance to the provider's answer.
UPDATE delivery_log SET
    status       = @status,
    error_code   = sqlc.narg(error_code),
    error_detail = sqlc.narg(error_detail),
    latency_ms   = LEAST(floor(extract(epoch FROM now() - created_at) * 1000), 2147483647)::int,
    updated_at   = now()
WHERE id = @id AND status = 'queued'
RETURNING instance_id, latency_ms;

-- name: TouchDeviceLastPush :exec
UPDATE devices SET last_push_at = now() WHERE id = $1;

-- name: AddUsage :exec
INSERT INTO usage_counters AS u (instance_id, day, accepted, rejected, sent, failed)
VALUES (@instance_id, (now() AT TIME ZONE 'UTC')::date, @accepted, @rejected, @sent, @failed)
ON CONFLICT (instance_id, day) DO UPDATE SET
    accepted = u.accepted + EXCLUDED.accepted,
    rejected = u.rejected + EXCLUDED.rejected,
    sent     = u.sent + EXCLUDED.sent,
    failed   = u.failed + EXCLUDED.failed;

-- name: GetIdempotentResponse :one
SELECT fingerprint, response FROM push_idempotency
WHERE instance_id = @instance_id AND key = @key AND created_at > now() - interval '24 hours';

-- name: SaveIdempotentResponse :execrows
-- Affects no row when a live entry exists, which means a concurrent request with the same key
-- committed first.
INSERT INTO push_idempotency (instance_id, key, fingerprint, response)
VALUES (@instance_id, @key, @fingerprint, @response)
ON CONFLICT (instance_id, key) DO UPDATE SET
    fingerprint = EXCLUDED.fingerprint,
    response    = EXCLUDED.response,
    created_at  = now()
WHERE push_idempotency.created_at <= now() - interval '24 hours';

-- name: DeleteOldDeliveryLog :execrows
DELETE FROM delivery_log
WHERE id IN (
    SELECT l.id FROM delivery_log l
    WHERE l.created_at <= now() - make_interval(hours => @retention_hours::int)
    LIMIT @batch
);

-- name: DeleteOldIdempotencyKeys :execrows
DELETE FROM push_idempotency
WHERE (instance_id, key) IN (
    SELECT p.instance_id, p.key FROM push_idempotency p
    WHERE p.created_at <= now() - interval '24 hours'
    LIMIT @batch
);
