// Package testdb gives tests an isolated, migrated PostgreSQL database on a shared
// container. Tests are skipped when no container runtime is available.
package testdb

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/parkerbrown98/gotalk-gateway/internal/database"
)

var (
	once      sync.Once
	container *tcpostgres.PostgresContainer
	adminURL  string
	startErr  error
	counter   atomic.Int64
)

// Terminate stops the shared container. Call it from TestMain after m.Run.
func Terminate() {
	if container != nil {
		_ = testcontainers.TerminateContainer(container)
	}
}

// URL creates an empty database and returns its connection string. Tests using it are
// skipped with -short or when no container runtime is available.
func URL(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in -short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)
	once.Do(func() {
		ctx := context.Background()
		container, startErr = tcpostgres.Run(ctx, "postgres:17-alpine",
			tcpostgres.WithDatabase("gotalk_gateway"),
			tcpostgres.WithUsername("gotalk"),
			tcpostgres.WithPassword("gotalk"),
			tcpostgres.BasicWaitStrategies(),
		)
		if startErr == nil {
			adminURL, startErr = container.ConnectionString(ctx, "sslmode=disable")
		}
	})
	require.NoError(t, startErr)

	ctx := context.Background()
	name := fmt.Sprintf("t_%d_%d", time.Now().UnixNano(), counter.Add(1))
	conn, err := pgx.Connect(ctx, adminURL)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	require.NoError(t, conn.Close(ctx))

	u, err := url.Parse(adminURL)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}

// Pool returns a pool on a fresh, fully migrated database, closed when the test ends.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := database.Connect(ctx, URL(t), 5, 10*time.Second, log)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, database.Migrate(ctx, pool, log))
	return pool
}
