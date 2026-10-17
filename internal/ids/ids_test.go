package ids

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMatchesProtocolPattern(t *testing.T) {
	// Patterns from docs/openapi.yaml.
	patterns := map[string]*regexp.Regexp{
		Instance:     regexp.MustCompile(`^inst_[A-Za-z0-9_-]{8,64}$`),
		Key:          regexp.MustCompile(`^key_[A-Za-z0-9_-]{8,64}$`),
		Subscription: regexp.MustCompile(`^sub_[A-Za-z0-9_-]{8,64}$`),
		Push:         regexp.MustCompile(`^push_[A-Za-z0-9_-]{8,64}$`),
	}
	for prefix, re := range patterns {
		id := New(prefix)
		assert.Regexp(t, re, id)
		assert.NotEqual(t, id, New(prefix))
	}
}
