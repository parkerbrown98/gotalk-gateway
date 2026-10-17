// Package ratelimit wraps ulule/limiter with named rules backed by Redis or memory.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
)

// Rule names.
const (
	// Registration limits POST /v1/instances per client IP.
	Registration = "registration"
	// Signed limits signed requests per instance.
	Signed = "signed"
	// Verification limits on-demand verification fetches per signing key.
	Verification = "verification"
)

type Result struct {
	Limit     int64
	Remaining int64
	Reset     time.Time
	Reached   bool
}

// Limited reports whether the result came from a configured rule.
func (r Result) Limited() bool { return r.Limit >= 0 }

type Limiter struct {
	rules   map[string]*limiter.Limiter
	backend string
}

// New builds a limiter. When rdb is nil an in-process memory store is used, which is
// correct for single-replica deployments only. Rules without a rate are never limited.
func New(rdb *redis.Client, rates map[string]string) (*Limiter, error) {
	var store limiter.Store
	backend := "memory"
	opts := limiter.StoreOptions{Prefix: "gotalk-gateway:ratelimit", CleanUpInterval: time.Minute}
	if rdb != nil {
		s, err := redisstore.NewStoreWithOptions(rdb, opts)
		if err != nil {
			return nil, fmt.Errorf("creating redis rate limit store: %w", err)
		}
		store, backend = s, "redis"
	} else {
		store = memory.NewStoreWithOptions(opts)
	}
	l := &Limiter{rules: map[string]*limiter.Limiter{}, backend: backend}
	for name, formatted := range rates {
		rate, err := limiter.NewRateFromFormatted(formatted)
		if err != nil {
			return nil, fmt.Errorf("invalid rate %q for %s: %w", formatted, name, err)
		}
		l.rules[name] = limiter.New(store, rate)
	}
	return l, nil
}

func (l *Limiter) Backend() string { return l.backend }

// Take consumes one request from rule for key.
func (l *Limiter) Take(ctx context.Context, rule, key string) (Result, error) {
	lim, ok := l.rules[rule]
	if !ok {
		return Result{Limit: -1}, nil
	}
	c, err := lim.Get(ctx, rule+":"+key)
	if err != nil {
		return Result{}, err
	}
	return Result{Limit: c.Limit, Remaining: c.Remaining, Reset: time.Unix(c.Reset, 0), Reached: c.Reached}, nil
}
