-- name: UpsertApp :exec
INSERT INTO apps (id, name, ios_bundle_id, android_package_name, web_vapid_public_key)
VALUES (@id, @name, @ios_bundle_id, @android_package_name, @web_vapid_public_key)
ON CONFLICT (id) DO UPDATE SET
    name                 = EXCLUDED.name,
    ios_bundle_id        = EXCLUDED.ios_bundle_id,
    android_package_name = EXCLUDED.android_package_name,
    web_vapid_public_key = EXCLUDED.web_vapid_public_key,
    enabled              = true,
    updated_at           = now()
WHERE NOT apps.enabled
   OR (apps.name, apps.ios_bundle_id, apps.android_package_name, apps.web_vapid_public_key)
      IS DISTINCT FROM
      (EXCLUDED.name, EXCLUDED.ios_bundle_id, EXCLUDED.android_package_name, EXCLUDED.web_vapid_public_key);

-- name: DisableAppsExcept :execrows
UPDATE apps
SET enabled = false, updated_at = now()
WHERE enabled AND NOT (id = ANY (@keep::text[]));

-- name: ListEnabledApps :many
SELECT id, name, ios_bundle_id, android_package_name, web_vapid_public_key, attestation_required
FROM apps
WHERE enabled
ORDER BY id;
