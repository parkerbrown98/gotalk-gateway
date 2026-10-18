package push

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/apns"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/fcm"
)

type QueueOptions struct {
	// Workers is how many pushes this process delivers at once; 0 only inserts.
	Workers int
	// DeadLetterRetention is how long given-up pushes stay in the queue for inspection.
	DeadLetterRetention time.Duration
	Logger              *slog.Logger
	// PollInterval overrides how often idle workers look for due retries (tests).
	PollInterval time.Duration
}

// NewQueue builds the river client that queues pushes and, with workers, delivers them.
// Completed jobs are deleted after a minute, since they hold the encrypted payload and the
// delivery log already records the outcome.
func NewQueue(pool *pgxpool.Pool, w *Worker, o QueueOptions) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	if err := river.AddWorkerSafely(workers, w); err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cfg := &river.Config{
		Workers:                     workers,
		Logger:                      log.With("component", "queue"),
		MaxAttempts:                 jobMaxAttempts,
		JobTimeout:                  w.Timeout(nil),
		RescueStuckJobsAfter:        w.Timeout(nil) + time.Minute,
		CompletedJobRetentionPeriod: time.Minute,
		CancelledJobRetentionPeriod: o.DeadLetterRetention,
		DiscardedJobRetentionPeriod: o.DeadLetterRetention,
		FetchPollInterval:           o.PollInterval,
	}
	if o.PollInterval > 0 {
		cfg.FetchCooldown = min(o.PollInterval, river.FetchCooldownDefault)
	}
	if o.Workers > 0 {
		cfg.Queues = map[string]river.QueueConfig{QueueName: {MaxWorkers: o.Workers}}
	}
	return river.NewClient(riverpgxv5.New(pool), cfg)
}

// BuildProviders creates the provider clients of every app platform with credentials.
func BuildProviders(list []apps.App) (*providers.Registry, error) {
	r := providers.NewRegistry()
	for _, a := range list {
		if a.IOS != nil && a.IOS.APNs != nil {
			c := a.IOS.APNs
			key, err := c.Key()
			if err != nil {
				return nil, fmt.Errorf("app %q: reading ios.apns.private_key_file: %w", a.ID, err)
			}
			client, err := apns.New(apns.Config{
				BundleID: a.IOS.BundleID, TeamID: c.TeamID, KeyID: c.KeyID, PrivateKey: key,
				ProductionURL: c.ProductionURL, SandboxURL: c.SandboxURL,
			})
			if err != nil {
				return nil, fmt.Errorf("app %q: %w", a.ID, err)
			}
			r.Set(a.ID, devices.IOS, client)
		}
		if a.Android != nil && a.Android.FCM != nil {
			c := a.Android.FCM
			sa, err := c.Credentials()
			if err != nil {
				return nil, fmt.Errorf("app %q: reading android.fcm.service_account_file: %w", a.ID, err)
			}
			client, err := fcm.New(fcm.Config{ServiceAccount: sa, ProjectID: c.ProjectID, Endpoint: c.Endpoint})
			if err != nil {
				return nil, fmt.Errorf("app %q: %w", a.ID, err)
			}
			r.Set(a.ID, devices.Android, client)
		}
	}
	return r, nil
}
