package apps

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/testdb"
)

const testVAPIDKey = "BExMJ__m8K0lZhFzYG_SNZhoRmRL6BbVOMd25fGlwCN2uGyylC_WegHE-InIhLxpzs3kl6KqUfAS6lMIoFdne2Y"

func TestMain(m *testing.M) {
	code := m.Run()
	testdb.Terminate()
	os.Exit(code)
}

func TestValidateVAPIDPublicKey(t *testing.T) {
	assert.NoError(t, ValidateVAPIDPublicKey(testVAPIDKey))
	assert.ErrorContains(t, ValidateVAPIDPublicKey(testVAPIDKey+"="), "base64url")
	assert.ErrorContains(t, ValidateVAPIDPublicKey("AAAA"), "65-byte")
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 0x04
	assert.ErrorContains(t, ValidateVAPIDPublicKey(base64.RawURLEncoding.EncodeToString(notOnCurve)), "curve")
}

func TestValidateVAPIDSubject(t *testing.T) {
	for _, ok := range []string{"mailto:ops@push.example", "https://push.example/contact"} {
		assert.NoError(t, ValidateVAPIDSubject(ok), ok)
	}
	for _, bad := range []string{"", "ops@push.example", "mailto:nobody", "http://push.example", "https://", "ftp://push.example"} {
		assert.Error(t, ValidateVAPIDSubject(bad), bad)
	}
}

func TestRegistrySyncAndList(t *testing.T) {
	ctx := context.Background()
	r := NewRegistry(testdb.Pool(t))
	r.ttl = 0

	full := App{ID: "gotalk", Name: "Gotalk", IOS: &IOS{BundleID: "app.example.gotalk"},
		Android: &Android{PackageName: "app.example.gotalk"}, Web: &Web{VAPIDPublicKey: testVAPIDKey}}
	droid := App{ID: "droid", Name: "Droid", Android: &Android{PackageName: "com.example.droid"}}

	disabled, err := r.Sync(ctx, []App{full, droid})
	require.NoError(t, err)
	assert.Zero(t, disabled)
	list, err := r.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, []App{droid, full}, list, "ordered by id")

	renamed := full
	renamed.Name = "Gotalk Beta"
	renamed.Web = nil
	disabled, err = r.Sync(ctx, []App{renamed})
	require.NoError(t, err)
	assert.Equal(t, int64(1), disabled, "apps removed from the config are disabled")
	list, err = r.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, []App{renamed}, list)

	_, err = r.Sync(ctx, []App{renamed, droid})
	require.NoError(t, err)
	list, err = r.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2, "a disabled app comes back when configured again")

	disabled, err = r.Sync(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), disabled)
	list, err = r.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestRegistryCachesAndServesStale(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	r := NewRegistry(pool)
	now := time.Now()
	r.now = func() time.Time { return now }

	app := App{ID: "droid", Name: "Droid", Android: &Android{PackageName: "com.example.droid"}}
	_, err := r.Sync(ctx, []App{app})
	require.NoError(t, err)
	list, err := r.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)

	_, err = pool.Exec(ctx, "UPDATE apps SET name = 'Changed'")
	require.NoError(t, err)
	list, _ = r.List(ctx)
	assert.Equal(t, "Droid", list[0].Name, "cached within the TTL")

	now = now.Add(time.Minute)
	list, _ = r.List(ctx)
	assert.Equal(t, "Changed", list[0].Name, "refreshed after the TTL")

	pool.Close()
	now = now.Add(time.Minute)
	list, err = r.List(ctx)
	require.NoError(t, err, "a database outage serves the last result")
	assert.Equal(t, "Changed", list[0].Name)

	_, err = NewRegistry(pool).List(ctx)
	assert.Error(t, err, "nothing cached yet")
}

// A database that accepts connections but never answers must not stall discovery.
func TestRegistryServesStaleWhenDatabaseHangs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
		}
	}()
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@"+ln.Addr().String()+"/db?sslmode=disable")
	require.NoError(t, err)
	defer pool.Close()

	r := NewRegistry(pool)
	r.timeout = 200 * time.Millisecond
	stale := []App{{ID: "droid", Name: "Droid", Android: &Android{PackageName: "com.example.droid"}}}
	r.cached = stale

	start := time.Now()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			list, err := r.List(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, stale, list)
		})
	}
	wg.Wait()
	assert.Less(t, time.Since(start), 2*time.Second, "callers share one bounded query")

	r.mu.Lock()
	backoff := r.validUntil
	r.mu.Unlock()
	assert.True(t, backoff.After(time.Now()), "a failed refresh backs off instead of retrying on every request")

	r = NewRegistry(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = r.List(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "with nothing cached, the caller's deadline still applies")
}
