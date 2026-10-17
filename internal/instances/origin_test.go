package instances

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://forum.example":         "https://forum.example",
		"HTTPS://Forum.Example/":        "https://forum.example",
		"https://forum.example:443":     "https://forum.example",
		"https://forum.example:8443":    "https://forum.example:8443",
		" https://forum.example. ":      "https://forum.example",
		"https://bücher.example":        "https://xn--bcher-kva.example",
		"https://203.0.113.7":           "https://203.0.113.7",
		"https://a-b.c-d.example:00443": "https://a-b.c-d.example",
	} {
		got, err := NormalizeOrigin(in, false)
		if assert.NoError(t, err, in) {
			assert.Equal(t, want, got, in)
		}
	}
	for _, in := range []string{
		"http://forum.example", "forum.example", "https://forum.example/forum", "https://forum.example?x",
		"https://forum.example#x", "https://u:p@forum.example", "https://[2001:db8::1]", "https://-x.example",
		"https://forum.example:0", "https://forum.example:99999", "https://exa mple.com", "ftp://forum.example",
		"https://" + string(make([]byte, 250)),
	} {
		_, err := NormalizeOrigin(in, false)
		assert.Error(t, err, in)
	}
	got, err := NormalizeOrigin("http://localhost:8080", true)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", got, "development mode accepts http")
	got, _ = NormalizeOrigin("http://forum.example:80", true)
	assert.Equal(t, "http://forum.example", got)
}
