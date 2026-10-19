// Package apps is the gateway's app registry. An app is a bundle ID / package name plus
// provider credentials; devices register for one app. Apps are declared in the config file,
// synced into the database at startup and listed in the discovery document. Credentials
// stay in the config: they are never written to the database.
package apps

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
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
	// APNs holds the credentials pushes are sent with. Without them devices can register,
	// but pushes to them are refused with provider_unavailable.
	APNs *APNs `koanf:"apns"`
}

// APNs is token-based APNs authentication with a .p8 key.
type APNs struct {
	TeamID string `koanf:"team_id"`
	KeyID  string `koanf:"key_id"`
	// PrivateKey is the PEM contents of the .p8 key; PrivateKeyFile is a path to it. Set one.
	PrivateKey     string `koanf:"private_key"`
	PrivateKeyFile string `koanf:"private_key_file"`
	// ProductionURL and SandboxURL override Apple's endpoints (for testing against a fake).
	ProductionURL string `koanf:"production_url"`
	SandboxURL    string `koanf:"sandbox_url"`
}

// Key returns the .p8 key, reading it from PrivateKeyFile when that is set.
func (a *APNs) Key() ([]byte, error) {
	return inlineOrFile(a.PrivateKey, a.PrivateKeyFile)
}

type Android struct {
	PackageName string `koanf:"package_name"`
	// FCM holds the credentials pushes are sent with. Without them devices can register, but
	// pushes to them are refused with provider_unavailable.
	FCM *FCM `koanf:"fcm"`
}

// FCM is a Google service account key for the FCM HTTP v1 API.
type FCM struct {
	// ServiceAccount is the JSON key; ServiceAccountFile is a path to it. Set one.
	ServiceAccount     string `koanf:"service_account"`
	ServiceAccountFile string `koanf:"service_account_file"`
	// ProjectID overrides the project_id of the service account.
	ProjectID string `koanf:"project_id"`
	// Endpoint overrides https://fcm.googleapis.com (for testing against a fake).
	Endpoint string `koanf:"endpoint"`
}

// Credentials returns the service account key, reading it from ServiceAccountFile when that
// is set.
func (f *FCM) Credentials() ([]byte, error) {
	return inlineOrFile(f.ServiceAccount, f.ServiceAccountFile)
}

func inlineOrFile(inline, path string) ([]byte, error) {
	if path == "" {
		return []byte(inline), nil
	}
	// Reading an operator-supplied path is the point of the *_file settings.
	data, err := os.ReadFile(path) //nolint:gosec // path comes from trusted deployment config
	if err != nil {
		return nil, err
	}
	return data, nil
}

type Web struct {
	// VAPIDPublicKey is the uncompressed P-256 public key, base64url without padding.
	VAPIDPublicKey string `koanf:"vapid_public_key"`
	// VAPID holds the private key pushes are signed with. Without it browsers can register,
	// but pushes to them are refused with provider_unavailable.
	VAPID *VAPID `koanf:"vapid"`
}

// VAPID is the application server identity of RFC 8292.
type VAPID struct {
	// PrivateKey is the P-256 private key matching vapid_public_key: the 32-byte scalar in
	// base64url (as web-push tools print it) or a PEM key. PrivateKeyFile is a path to it.
	// Set one.
	PrivateKey     string `koanf:"private_key"`
	PrivateKeyFile string `koanf:"private_key_file"`
	// Subject is the operator contact push services may use: a mailto: or https: URL.
	Subject string `koanf:"subject"`
}

// Key returns the private key, reading it from PrivateKeyFile when that is set.
func (v *VAPID) Key() ([]byte, error) {
	return inlineOrFile(v.PrivateKey, v.PrivateKeyFile)
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
	appleIDPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	projectIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
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
		if a.IOS != nil && a.IOS.APNs != nil {
			c := a.IOS.APNs
			if !appleIDPattern.MatchString(c.TeamID) {
				add(i, "ios.apns.team_id %q must be the 10-character Apple team ID", c.TeamID)
			}
			if !appleIDPattern.MatchString(c.KeyID) {
				add(i, "ios.apns.key_id %q must be the 10-character ID of the .p8 key", c.KeyID)
			}
			if (c.PrivateKey == "") == (c.PrivateKeyFile == "") {
				add(i, "ios.apns needs exactly one of private_key or private_key_file")
			}
			for _, f := range []struct{ key, v string }{{"production_url", c.ProductionURL}, {"sandbox_url", c.SandboxURL}} {
				if f.v != "" && !absoluteURL(f.v) {
					add(i, "ios.apns.%s %q must be an absolute http(s) URL", f.key, f.v)
				}
			}
		}
		if a.Android != nil && !packageNamePattern.MatchString(a.Android.PackageName) {
			add(i, "android.package_name %q is not a valid package name", a.Android.PackageName)
		}
		if a.Android != nil && a.Android.FCM != nil {
			c := a.Android.FCM
			if (c.ServiceAccount == "") == (c.ServiceAccountFile == "") {
				add(i, "android.fcm needs exactly one of service_account or service_account_file")
			}
			if c.ProjectID != "" && !projectIDPattern.MatchString(c.ProjectID) {
				add(i, "android.fcm.project_id %q is not a valid Google Cloud project ID", c.ProjectID)
			}
			if c.Endpoint != "" && !absoluteURL(c.Endpoint) {
				add(i, "android.fcm.endpoint %q must be an absolute http(s) URL", c.Endpoint)
			}
		}
		if a.Web != nil {
			if err := ValidateVAPIDPublicKey(a.Web.VAPIDPublicKey); err != nil {
				add(i, "web.vapid_public_key %v", err)
			}
			if v := a.Web.VAPID; v != nil {
				if (v.PrivateKey == "") == (v.PrivateKeyFile == "") {
					add(i, "web.vapid needs exactly one of private_key or private_key_file")
				}
				if err := ValidateVAPIDSubject(v.Subject); err != nil {
					add(i, "web.vapid.subject %v", err)
				}
			}
		}
	}
	return errs
}

func absoluteURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.RawQuery == "" && u.Fragment == ""
}

// ValidateVAPIDSubject checks the VAPID sub claim: a mailto: or https: URL (RFC 8292 §2.1).
// Apple's push service refuses tokens without one.
func ValidateVAPIDSubject(sub string) error {
	u, err := url.Parse(sub)
	switch {
	case sub == "":
		return errors.New("must be set to a mailto: or https: contact URL")
	case err != nil:
		return fmt.Errorf("%q is not a URL", sub)
	case u.Scheme == "mailto" && strings.Contains(u.Opaque, "@"):
		return nil
	case u.Scheme == "https" && u.Host != "":
		return nil
	}
	return fmt.Errorf("%q must be a mailto: or https: URL", sub)
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
