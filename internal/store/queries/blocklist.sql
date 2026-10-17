-- name: ListActiveBlocklist :many
SELECT * FROM blocklist WHERE expires_at IS NULL OR expires_at > now() ORDER BY kind, value;

-- name: ListBlocklist :many
SELECT * FROM blocklist ORDER BY kind, value;

-- name: UpsertBlocklistEntry :one
INSERT INTO blocklist (kind, value, reason, expires_at)
VALUES (@kind, @value, @reason, @expires_at)
ON CONFLICT (kind, value) DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at
RETURNING *;

-- name: DeleteBlocklistEntry :execrows
DELETE FROM blocklist WHERE kind = @kind AND value = @value;

-- name: DeleteExpiredBlocklist :execrows
DELETE FROM blocklist WHERE expires_at <= now();
