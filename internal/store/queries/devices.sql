-- name: GetDevice :one
SELECT * FROM devices WHERE id = $1;

-- name: UpsertDevice :one
-- Registering the same (app, instance, platform, token) again keeps the subscription ID,
-- rotates the secret, extends the expiry and reactivates a gone subscription.
INSERT INTO devices (id, app_id, instance_id, platform, token, token_hash, apns_environment, secret_hash, expires_at)
VALUES (@id, @app_id, @instance_id, @platform, @token, @token_hash, @apns_environment, @secret_hash, @expires_at)
ON CONFLICT (app_id, instance_id, platform, token_hash) DO UPDATE SET
    token            = EXCLUDED.token,
    apns_environment = EXCLUDED.apns_environment,
    secret_hash      = EXCLUDED.secret_hash,
    expires_at       = EXCLUDED.expires_at,
    status           = 'active',
    gone_at          = NULL,
    updated_at       = now()
RETURNING id;

-- name: ExtendDevice :one
UPDATE devices SET expires_at = @expires_at, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ReplaceDeviceToken :one
UPDATE devices
SET token = @token, token_hash = @token_hash, apns_environment = @apns_environment,
    status = 'active', gone_at = NULL, expires_at = @expires_at, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteDevice :execrows
DELETE FROM devices WHERE id = $1;

-- name: MarkDeviceGone :execrows
-- Compare-and-set on the token the provider rejected: if the subscription moved to another
-- token or APNs environment since the push was sent, the rejection is stale and ignored.
UPDATE devices SET status = 'gone', gone_at = now(), updated_at = now()
WHERE id = @id AND status = 'active' AND token_hash = @token_hash
  AND apns_environment IS NOT DISTINCT FROM sqlc.narg(apns_environment)::text;

-- name: DeleteExpiredDevices :execrows
-- Deletes up to @batch subscriptions that expired without a refresh, or that have been gone
-- for longer than the retention period.
DELETE FROM devices
WHERE id IN (
    SELECT d.id FROM devices d
    WHERE d.expires_at <= now()
       OR (d.status = 'gone' AND d.gone_at <= now() - make_interval(days => @gone_retention_days::int))
    LIMIT @batch
);
