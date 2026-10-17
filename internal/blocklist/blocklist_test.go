package blocklist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatching(t *testing.T) {
	c := NewCache(nil, nil)
	past := time.Now().Add(-time.Hour)
	c.Set([]Entry{
		{Kind: KindOrigin, Value: "https://bad.example", Reason: "spam"},
		{Kind: KindDomain, Value: "evil.example", Reason: "abuse"},
		{Kind: KindDomain, Value: "old.example", Reason: "expired", ExpiresAt: &past},
		{Kind: KindCIDR, Value: "203.0.113.0/24", Reason: "botnet"},
	})

	assert.Equal(t, "spam", c.MatchOrigin("https://bad.example").Reason)
	assert.Nil(t, c.MatchOrigin("https://bad.example:8443"), "origins match exactly")
	assert.Equal(t, "abuse", c.MatchOrigin("https://evil.example").Reason)
	assert.Equal(t, "abuse", c.MatchOrigin("https://a.b.evil.example:8443").Reason, "subdomains match")
	assert.Nil(t, c.MatchOrigin("https://notevil.example"), "suffix matching is per label")
	assert.Nil(t, c.MatchOrigin("https://old.example"), "expired entries are ignored")

	assert.Equal(t, "botnet", c.MatchIP("203.0.113.9").Reason)
	assert.Equal(t, "botnet", c.MatchIP("::ffff:203.0.113.9").Reason, "IPv4-mapped addresses match")
	assert.Nil(t, c.MatchIP("198.51.100.1"))
	assert.Nil(t, c.MatchIP("garbage"))
}

func TestNormalizeValue(t *testing.T) {
	for _, tc := range []struct{ kind, in, want string }{
		{KindOrigin, "https://Forum.Example/", "https://forum.example"},
		{KindDomain, ".Spam.Example.", "spam.example"},
		{KindCIDR, "203.0.113.7/24", "203.0.113.0/24"},
		{KindCIDR, "203.0.113.7", "203.0.113.7/32"},
		{KindCIDR, "2001:db8::1", "2001:db8::1/128"},
	} {
		got, err := NormalizeValue(tc.kind, tc.in)
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got)
	}
	for _, tc := range []struct{ kind, in string }{
		{KindOrigin, "forum.example"}, {KindDomain, "https://x"}, {KindCIDR, "nope"}, {"ip", "1.2.3.4"},
	} {
		_, err := NormalizeValue(tc.kind, tc.in)
		assert.Error(t, err, tc.in)
	}
}
