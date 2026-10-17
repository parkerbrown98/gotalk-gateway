// Package blocklist holds operator blocks on origins, domains and client addresses. The
// active entries are cached in memory and refreshed periodically, so changes made with the
// CLI reach every replica within the refresh interval.
package blocklist

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parkerbrown98/gotalk-gateway/internal/store"
)

// Kinds of entries.
const (
	// KindOrigin matches a normalized origin exactly.
	KindOrigin = "origin"
	// KindDomain matches a host and all its subdomains.
	KindDomain = "domain"
	// KindCIDR matches client addresses.
	KindCIDR = "cidr"
)

// RefreshInterval is how often the cache reloads entries.
const RefreshInterval = 30 * time.Second

type Entry struct {
	Kind      string
	Value     string
	Reason    string
	ExpiresAt *time.Time
	prefix    netip.Prefix
}

type snapshot struct {
	origins map[string]*Entry
	domains map[string]*Entry
	cidrs   []*Entry
}

// Cache answers blocklist lookups from memory.
type Cache struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	now  func() time.Time
	snap atomic.Pointer[snapshot]
}

func NewCache(pool *pgxpool.Pool, log *slog.Logger) *Cache {
	c := &Cache{pool: pool, log: log, now: time.Now}
	c.snap.Store(&snapshot{})
	return c
}

// Refresh reloads the active entries.
func (c *Cache) Refresh(ctx context.Context) error {
	rows, err := store.New(c.pool).ListActiveBlocklist(ctx)
	if err != nil {
		return fmt.Errorf("loading blocklist: %w", err)
	}
	entries := make([]Entry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, Entry{Kind: r.Kind, Value: r.Value, Reason: r.Reason, ExpiresAt: r.ExpiresAt})
	}
	c.Set(entries)
	return nil
}

// Set replaces the cached entries. Tests use it directly.
func (c *Cache) Set(entries []Entry) {
	s := &snapshot{origins: map[string]*Entry{}, domains: map[string]*Entry{}}
	for i := range entries {
		e := &entries[i]
		switch e.Kind {
		case KindOrigin:
			s.origins[e.Value] = e
		case KindDomain:
			s.domains[e.Value] = e
		case KindCIDR:
			p, err := netip.ParsePrefix(e.Value)
			if err != nil {
				continue
			}
			e.prefix = p.Masked()
			s.cidrs = append(s.cidrs, e)
		}
	}
	c.snap.Store(s)
}

// Run refreshes the cache until ctx ends. Failures keep the previous entries.
func (c *Cache) Run(ctx context.Context) {
	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(ctx); err != nil && ctx.Err() == nil {
				c.log.Warn("refreshing blocklist", "error", err.Error())
			}
		}
	}
}

func (c *Cache) live(e *Entry) *Entry {
	if e == nil || (e.ExpiresAt != nil && !c.now().Before(*e.ExpiresAt)) {
		return nil
	}
	return e
}

// MatchOrigin returns the entry blocking a normalized origin, or nil.
func (c *Cache) MatchOrigin(origin string) *Entry {
	s := c.snap.Load()
	if e := c.live(s.origins[origin]); e != nil {
		return e
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	for {
		if e := c.live(s.domains[host]); e != nil {
			return e
		}
		_, parent, ok := strings.Cut(host, ".")
		if !ok {
			return nil
		}
		host = parent
	}
}

// MatchIP returns the entry blocking a client address, or nil.
func (c *Cache) MatchIP(ip string) *Entry {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	for _, e := range c.snap.Load().cidrs {
		if e.prefix.Contains(addr) && c.live(e) != nil {
			return e
		}
	}
	return nil
}

// NormalizeValue validates an entry value for kind and returns its canonical form.
// Origins must already be normalized; see instances.NormalizeOrigin.
func NormalizeValue(kind, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch kind {
	case KindOrigin:
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", errors.New("origin must look like https://host[:port]")
		}
		return strings.ToLower(strings.TrimRight(value, "/")), nil
	case KindDomain:
		v := strings.ToLower(strings.Trim(value, "."))
		if v == "" || strings.ContainsAny(v, "/:@ ") {
			return "", errors.New("domain must be a host name such as spam.example")
		}
		return v, nil
	case KindCIDR:
		if p, err := netip.ParsePrefix(value); err == nil {
			return p.Masked().String(), nil
		}
		if a, err := netip.ParseAddr(value); err == nil {
			return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String(), nil
		}
		return "", errors.New("cidr must be an address or prefix such as 203.0.113.0/24")
	default:
		return "", fmt.Errorf("kind must be %s, %s or %s", KindOrigin, KindDomain, KindCIDR)
	}
}
