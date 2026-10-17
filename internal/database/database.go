// Package database connects to PostgreSQL and applies embedded migrations.
package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Connect opens a pool and waits (up to timeout) for PostgreSQL to accept connections,
// which smooths over container start-up ordering in Compose and Kubernetes.
func Connect(ctx context.Context, databaseURL string, maxConns int32, timeout time.Duration, log *slog.Logger) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid database URL: %w", err)
	}
	cfg.MaxConns = maxConns

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	deadline := time.Now().Add(timeout)
	delay := 500 * time.Millisecond
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			pool.Close()
			return nil, fmt.Errorf("could not connect to PostgreSQL at %s: %w (is it running? set GOTALK_GATEWAY_DATABASE_URL)",
				Redact(databaseURL), err)
		}
		log.Warn("waiting for PostgreSQL", "target", Redact(databaseURL), "error", err.Error())
		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
		delay = min(delay*2, 5*time.Second)
	}
}

// Redact describes a connection string (URL or keyword/value form) without credentials,
// for logging.
func Redact(databaseURL string) string {
	cfg, err := pgconn.ParseConfig(databaseURL)
	if err != nil {
		return "<unparseable database URL>"
	}
	return fmt.Sprintf("%s:%d/%s", cfg.Host, cfg.Port, cfg.Database)
}

func newProvider(pool *pgxpool.Pool) (*goose.Provider, error) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	// The advisory lock lets several replicas boot simultaneously without racing migrations.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(pool), sub,
		goose.WithSessionLocker(locker))
}

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	p, err := newProvider(pool)
	if err != nil {
		return fmt.Errorf("preparing migrations: %w", err)
	}
	results, err := p.Up(ctx)
	if err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	for _, r := range results {
		log.Info("applied migration", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration.String())
	}
	return nil
}

type MigrationStatus struct {
	Current int64
	Latest  int64
}

// Status reports the schema version of the database and the newest one this build knows.
func Status(ctx context.Context, pool *pgxpool.Pool) (MigrationStatus, error) {
	p, err := newProvider(pool)
	if err != nil {
		return MigrationStatus{}, err
	}
	current, err := p.GetDBVersion(ctx)
	if err != nil {
		return MigrationStatus{}, err
	}
	sources := p.ListSources()
	var latest int64
	if len(sources) > 0 {
		latest = sources[len(sources)-1].Version
	}
	return MigrationStatus{Current: current, Latest: latest}, nil
}
