package database_test

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/database"
	"github.com/parkerbrown98/gotalk-gateway/internal/testdb"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testdb.Terminate()
	os.Exit(code)
}

func TestRedactNeverLeaksPasswords(t *testing.T) {
	const secret = "hunter2-secret"
	asURL := url.URL{Scheme: "postgres", User: url.UserPassword("user", secret), Host: "db.example.com:6543", Path: "/app", RawQuery: "sslmode=require"}
	keyword := "host=db.example.com port=6543 user=user dbname=app " + "pass" + "word=" + secret

	for _, dsn := range []string{asURL.String(), keyword} {
		got := database.Redact(dsn)
		assert.Equal(t, "db.example.com:6543/app", got)
		assert.NotContains(t, got, secret)
	}
	assert.Equal(t, "<unparseable database URL>", database.Redact("postgres://%zz"))
}

func TestMigrateCreatesSchemaV1(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := database.Connect(ctx, testdb.URL(t), 5, 10*time.Second, log)
	require.NoError(t, err)
	defer pool.Close()

	st, err := database.Status(ctx, pool)
	require.NoError(t, err)
	assert.Equal(t, int64(0), st.Current)
	assert.GreaterOrEqual(t, st.Latest, int64(2))

	require.NoError(t, database.Migrate(ctx, pool, log))
	require.NoError(t, database.Migrate(ctx, pool, log), "migrating twice is a no-op")
	st, err = database.Status(ctx, pool)
	require.NoError(t, err)
	assert.Equal(t, st.Latest, st.Current)

	for _, table := range []string{"apps", "instances", "instance_keys", "devices", "usage_counters", "delivery_log", "blocklist"} {
		var exists bool
		require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass('public.' || $1) IS NOT NULL", table).Scan(&exists))
		assert.True(t, exists, table)
	}
}

func TestSchemaConstraints(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	hash := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

	require.NoError(t, exec(`INSERT INTO apps (id, name, ios_bundle_id) VALUES ('gotalk', 'Gotalk', 'app.example.gotalk')`))
	assert.Error(t, exec(`INSERT INTO apps (id, name) VALUES ('none', 'No platforms')`), "an app needs a platform")
	assert.Error(t, exec(`INSERT INTO apps (id, name, ios_bundle_id) VALUES ('Bad', 'x', 'a.b')`), "app id pattern")

	pending := `INSERT INTO instances (id, origin, contact_email, pending_expires_at) VALUES ($1, $2, 'ops@example.com', now() + interval '1 day')`
	require.NoError(t, exec(pending, "inst_a", "https://forum.example"))
	require.NoError(t, exec(pending, "inst_b", "https://forum.example"), "several pending registrations per origin")
	assert.Error(t, exec(pending, "inst_c", "https://Forum.example/path"), "origins are stored normalized")

	activate := `UPDATE instances SET status = 'active', pending_expires_at = NULL, verified_at = now() WHERE id = $1`
	require.NoError(t, exec(activate, "inst_a"))
	assert.Error(t, exec(activate, "inst_b"), "a verified origin has one instance")
	assert.Error(t, exec(`UPDATE instances SET status = 'blocked' WHERE id = 'inst_a'`), "blocking needs a reason")

	require.NoError(t, exec(`INSERT INTO instance_keys (id, instance_id, public_key) VALUES ('key_a', 'inst_a', $1)`, make([]byte, 32)))
	assert.Error(t, exec(`INSERT INTO instance_keys (id, instance_id, public_key) VALUES ('key_b', 'inst_a', $1)`, make([]byte, 31)))

	device := `INSERT INTO devices (id, app_id, instance_id, platform, token, token_hash, apns_environment, secret_hash, expires_at)
		VALUES ($1, 'gotalk', 'inst_a', $2, 'tok', $3, $4, $5, now() + interval '60 days')`
	require.NoError(t, exec(device, "sub_a", "ios", hash("tok"), "production", hash("secret")))
	assert.Error(t, exec(device, "sub_b", "ios", hash("tok"), "production", hash("secret2")), "one subscription per (app, instance, platform, token)")
	assert.Error(t, exec(device, "sub_c", "android", hash("tok2"), "production", hash("s")), "apns_environment is iOS-only")
	assert.Error(t, exec(device, "sub_d", "ios", hash("tok3"), nil, hash("s")), "iOS needs an APNs environment")

	require.NoError(t, exec(`INSERT INTO delivery_log (id, instance_id, subscription_id, notification_id) VALUES ('push_a', 'inst_a', 'sub_a', 'ntf_1')`))
	assert.Error(t, exec(`INSERT INTO delivery_log (id, instance_id, subscription_id, notification_id) VALUES ('push_b', 'inst_a', 'sub_a', 'bad id')`))
	require.NoError(t, exec(`INSERT INTO usage_counters (instance_id, day, accepted) VALUES ('inst_a', current_date, 1)`))
	require.NoError(t, exec(`INSERT INTO blocklist (kind, value, reason) VALUES ('domain', 'spam.example', 'spam')`))
	assert.Error(t, exec(`INSERT INTO blocklist (kind, value, reason) VALUES ('domain', 'spam.example', 'again')`))

	require.NoError(t, exec(`DELETE FROM instances WHERE id = 'inst_a'`))
	for _, table := range []string{"instance_keys", "devices", "delivery_log", "usage_counters"} {
		var n int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n))
		assert.Zero(t, n, "deleting an instance deletes its %s", table)
	}
}
