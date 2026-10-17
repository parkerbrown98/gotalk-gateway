// Package apps is the gateway's app registry. An app is a bundle ID / package name plus
// provider credentials; devices register for one app. Apps are declared in the config file,
// synced into the database at startup and listed in the discovery document.
package apps

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"

	"github.com/parkerbrown98/gotalk-gateway/internal/store"
)

type App struct {
	ID      string   `koanf:"id"`
	Name    string   `koanf:"name"`
	IOS     *IOS     `koanf:"ios"`
	Android *Android `koanf:"android"`
	Web     *Web     `koanf:"web"`
	// AttestationRequired is reserved for Phase 8 and always false for configured apps.
	AttestationRequired bool `koanf:"-"`
}

type IOS struct {
	BundleID string `koanf:"bundle_id"`
}

type Android struct {
	PackageName string `koanf:"package_name"`
}

type Web struct {
	// VAPIDPublicKey is the uncompressed P-256 public key, base64url without padding.
	VAPIDPublicKey string `koanf:"vapid_public_key"`
}

// Platforms lists the platforms the app is configured for, in protocol order.
func (a App) Platforms() []string {
	var out []string
	if a.IOS != nil {
		out = append(out, "ios")
	}
	if a.Android != nil {
		out = append(out, "android")
	}
	if a.Web != nil {
		out = append(out, "web")
	}
	return out
}

var (
	idPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	bundleIDPattern    = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	packageNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
)

// Validate reports every problem with a list of configured apps.
func Validate(list []App) []error {
	var errs []error
	add := func(i int, format string, args ...any) {
		errs = append(errs, fmt.Errorf("apps[%d]: "+format, append([]any{i}, args...)...))
	}
	seen := map[string]bool{}
	for i, a := range list {
		if !idPattern.MatchString(a.ID) {
			add(i, "id %q must match %s", a.ID, idPattern)
		} else if seen[a.ID] {
			add(i, "duplicate id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Name == "" {
			add(i, "name must not be empty")
		}
		if len(a.Platforms()) == 0 {
			add(i, "configure at least one of ios, android or web")
		}
		if a.IOS != nil && !bundleIDPattern.MatchString(a.IOS.BundleID) {
			add(i, "ios.bundle_id %q is not a valid bundle ID", a.IOS.BundleID)
		}
		if a.Android != nil && !packageNamePattern.MatchString(a.Android.PackageName) {
			add(i, "android.package_name %q is not a valid package name", a.Android.PackageName)
		}
		if a.Web != nil {
			if err := ValidateVAPIDPublicKey(a.Web.VAPIDPublicKey); err != nil {
				add(i, "web.vapid_public_key %v", err)
			}
		}
	}
	return errs
}

// ValidateVAPIDPublicKey checks that key is an unpadded base64url uncompressed P-256 point.
func ValidateVAPIDPublicKey(key string) error {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return errors.New("must be base64url without padding")
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		return errors.New("must be a 65-byte uncompressed P-256 public key")
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return errors.New("is not a point on the P-256 curve")
	}
	return nil
}

// Registry reads and writes the apps table. List results are cached briefly because
// discovery is unauthenticated and frequently requested.
type Registry struct {
	pool *pgxpool.Pool
	// ttl is how long a successful listing is served from the cache.
	ttl time.Duration
	// timeout bounds each database query, so a hung database cannot stall discovery.
	timeout time.Duration
	// errBackoff is how long a stale listing is served after a failed refresh before the
	// database is tried again.
	errBackoff time.Duration
	now        func() time.Time

	refresh    singleflight.Group
	mu         sync.Mutex
	cached     []App
	validUntil time.Time
}

func NewRegistry(pool *pgxpool.Pool) *Registry {
	return &Registry{pool: pool, ttl: 30 * time.Second, timeout: 2 * time.Second, errBackoff: 5 * time.Second, now: time.Now}
}

// Sync makes the database match the configured apps: each one is created or updated and
// enabled, and every other app is disabled. It returns the number of apps disabled.
func (r *Registry) Sync(ctx context.Context, list []App) (disabled int64, err error) {
	err = pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		keep := make([]string, 0, len(list))
		for _, a := range list {
			p := store.UpsertAppParams{ID: a.ID, Name: a.Name}
			if a.IOS != nil {
				p.IosBundleID = &a.IOS.BundleID
			}
			if a.Android != nil {
				p.AndroidPackageName = &a.Android.PackageName
			}
			if a.Web != nil {
				p.WebVapidPublicKey = &a.Web.VAPIDPublicKey
			}
			if err := q.UpsertApp(ctx, p); err != nil {
				return fmt.Errorf("saving app %q: %w", a.ID, err)
			}
			keep = append(keep, a.ID)
		}
		disabled, err = q.DisableAppsExcept(ctx, keep)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("syncing apps: %w", err)
	}
	r.mu.Lock()
	r.cached, r.validUntil = nil, time.Time{}
	r.mu.Unlock()
	return disabled, nil
}

// List returns the enabled apps. Concurrent callers share one database query, and no lock
// is held while it runs. When the database fails or hangs, the last successful result is
// served, however old, so discovery keeps working through a database outage.
func (r *Registry) List(ctx context.Context) ([]App, error) {
	r.mu.Lock()
	cached, fresh := r.cached, r.now().Before(r.validUntil)
	r.mu.Unlock()
	if cached != nil && fresh {
		return slices.Clone(cached), nil
	}

	ch := r.refresh.DoChan("apps", func() (any, error) { return r.load() })
	select {
	case res := <-ch:
		if res.Err != nil {
			if cached != nil {
				return slices.Clone(cached), nil
			}
			return nil, res.Err
		}
		return slices.Clone(res.Val.([]App)), nil
	case <-ctx.Done():
		if cached != nil {
			return slices.Clone(cached), nil
		}
		return nil, ctx.Err()
	}
}

// load queries the database and updates the cache. It does not use a caller's context:
// the query is shared, and one caller giving up must not fail it for the others.
func (r *Registry) load() ([]App, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	rows, err := store.New(r.pool).ListEnabledApps(ctx)
	if err != nil {
		r.mu.Lock()
		if r.cached != nil {
			r.validUntil = r.now().Add(r.errBackoff)
		}
		r.mu.Unlock()
		return nil, fmt.Errorf("listing apps: %w", err)
	}
	list := make([]App, 0, len(rows))
	for _, row := range rows {
		a := App{ID: row.ID, Name: row.Name, AttestationRequired: row.AttestationRequired}
		if row.IosBundleID != nil {
			a.IOS = &IOS{BundleID: *row.IosBundleID}
		}
		if row.AndroidPackageName != nil {
			a.Android = &Android{PackageName: *row.AndroidPackageName}
		}
		if row.WebVapidPublicKey != nil {
			a.Web = &Web{VAPIDPublicKey: *row.WebVapidPublicKey}
		}
		list = append(list, a)
	}
	r.mu.Lock()
	r.cached, r.validUntil = list, r.now().Add(r.ttl)
	r.mu.Unlock()
	return list, nil
}
