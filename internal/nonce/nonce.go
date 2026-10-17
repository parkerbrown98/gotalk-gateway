// Package nonce remembers request nonces so signed requests cannot be replayed. Redis
// shares them across replicas; the memory store is for single-node deployments, where a
// restart forgets nonces (the 5 minute timestamp window bounds that exposure).
package nonce

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store records nonces.
type Store interface {
	// Claim records key for ttl and reports whether it was new. A false result means the
	// nonce was already used.
	Claim(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// New returns a Redis store when rdb is set and a memory store otherwise.
func New(rdb *redis.Client) Store {
	if rdb != nil {
		return &Redis{rdb: rdb}
	}
	return NewMemory()
}

type Redis struct {
	rdb *redis.Client
}

func (r *Redis) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return r.rdb.SetNX(ctx, "gotalk-gateway:nonce:"+key, 1, ttl).Result()
}

// Memory keeps nonces in process memory and sweeps expired ones as it goes.
type Memory struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	nextSweep time.Time
	now       func() time.Time
}

func NewMemory() *Memory {
	return &Memory{seen: map[string]time.Time{}, now: time.Now}
}

func (m *Memory) Claim(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if now.After(m.nextSweep) {
		for k, exp := range m.seen {
			if !now.Before(exp) {
				delete(m.seen, k)
			}
		}
		m.nextSweep = now.Add(time.Minute)
	}
	if exp, ok := m.seen[key]; ok && now.Before(exp) {
		return false, nil
	}
	m.seen[key] = now.Add(ttl)
	return true, nil
}
