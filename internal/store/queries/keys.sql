-- name: CreateKey :exec
INSERT INTO instance_keys (id, instance_id, public_key, recovery, expires_at)
VALUES (@id, @instance_id, @public_key, @recovery, @expires_at);

-- name: GetKeyForAuth :one
SELECT k.id, k.instance_id, k.public_key, k.status, k.recovery, k.expires_at,
       i.origin, i.status AS instance_status, i.blocked_reason, i.pending_expires_at
FROM instance_keys k
JOIN instances i ON i.id = k.instance_id
WHERE k.id = $1;

-- name: TouchKey :exec
UPDATE instance_keys SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: ListKeys :many
SELECT * FROM instance_keys WHERE instance_id = $1 ORDER BY created_at, id;

-- name: GetKeyByPublicKey :one
SELECT * FROM instance_keys WHERE instance_id = @instance_id AND public_key = @public_key;

-- name: CountLiveKeys :one
-- Active keys plus pending rotation keys; recovery keys do not count, so a stolen key cannot
-- fill the slots and block recovery.
SELECT count(*) FROM instance_keys
WHERE instance_id = $1 AND status IN ('pending', 'active') AND NOT recovery;

-- name: TrimRecoveryKeys :exec
-- Keeps only the newest @keep pending recovery keys of an instance.
DELETE FROM instance_keys
WHERE id IN (
    SELECT k.id FROM instance_keys k
    WHERE k.instance_id = @instance_id AND k.recovery AND k.status = 'pending'
    ORDER BY k.created_at DESC, k.id DESC
    OFFSET @keep
);

-- name: ActivateKey :exec
UPDATE instance_keys
SET status = 'active', activated_at = now(), expires_at = NULL, recovery = false
WHERE id = $1 AND status = 'pending';

-- name: RevokeOtherKeys :execrows
UPDATE instance_keys
SET status = 'revoked', revoked_at = now(), expires_at = NULL, recovery = false
WHERE instance_id = @instance_id AND id <> @keep_id AND status <> 'revoked';

-- name: RevokeKey :exec
UPDATE instance_keys
SET status = 'revoked', revoked_at = now(), expires_at = NULL, recovery = false
WHERE id = $1 AND status <> 'revoked';

-- name: DeleteExpiredPendingKeys :execrows
DELETE FROM instance_keys WHERE status = 'pending' AND expires_at <= now();
