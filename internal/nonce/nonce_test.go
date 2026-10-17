package nonce

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryClaim(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }

	ok, err := m.Claim(ctx, "key_a:n1", 10*time.Minute)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, _ = m.Claim(ctx, "key_a:n1", 10*time.Minute)
	assert.False(t, ok, "replay within the TTL")
	ok, _ = m.Claim(ctx, "key_b:n1", 10*time.Minute)
	assert.True(t, ok, "nonces are per key")

	now = now.Add(11 * time.Minute)
	ok, _ = m.Claim(ctx, "key_a:n1", 10*time.Minute)
	assert.True(t, ok, "forgotten after the TTL")
	assert.Len(t, m.seen, 1, "expired nonces are swept")
}
