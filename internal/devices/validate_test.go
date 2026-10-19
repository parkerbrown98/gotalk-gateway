package devices

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeToken(t *testing.T) {
	apns := strings.Repeat("ab", 32)
	got, err := NormalizeToken(IOS, strings.ToUpper(apns), WebPushPolicy{})
	require.NoError(t, err)
	assert.Equal(t, apns, got, "APNs tokens are stored in lower case")
	for _, bad := range []string{strings.Repeat("a", 63), strings.Repeat("a", 201), strings.Repeat("g", 64), ""} {
		_, err := NormalizeToken(IOS, bad, WebPushPolicy{})
		assert.Error(t, err, bad)
	}

	fcm := "dXk3:APA91b" + strings.Repeat("Ab_-9.", 20)
	got, err = NormalizeToken(Android, fcm, WebPushPolicy{})
	require.NoError(t, err)
	assert.Equal(t, fcm, got)
	for _, bad := range []string{fcm[:99], strings.Repeat("a", 4097), fcm + " ", fcm + "/"} {
		_, err := NormalizeToken(Android, bad, WebPushPolicy{})
		assert.Error(t, err)
	}

	_, err = NormalizeToken("windows", "x", WebPushPolicy{})
	assert.Error(t, err)
}

func TestWebEndpoints(t *testing.T) {
	hosts := DefaultWebPushHosts
	for _, ok := range []string{
		"https://fcm.googleapis.com/fcm/send/cJ3x:APA91b",
		"https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"https://web.push.apple.com/QGuQyavXutnMH",
		"https://wns2-par02p.notify.windows.com/w/?token=BQYAAA",
		"https://fcm.googleapis.com:443/fcm/send/x",
	} {
		got, err := NormalizeToken(Web, ok, WebPushPolicy{Hosts: hosts})
		require.NoError(t, err, ok)
		assert.Equal(t, ok, got, "endpoints are stored verbatim")
	}
	for bad, msg := range map[string]string{
		"http://fcm.googleapis.com/fcm/send/x":                    "https",
		"https://evil.example/push":                               "does not send to push service evil.example",
		"https://fcm.googleapis.com.evil.example/x":               "does not send",
		"https://notfcm.googleapis.com.example/x":                 "does not send",
		"https://user:pw@fcm.googleapis.com/x":                    "user info",
		"https://fcm.googleapis.com:8443/x":                       "port 443",
		"https://93.184.216.34/push":                              "does not send",
		"https://fcm.googleapis.com/" + strings.Repeat("x", 2048): "at most 2048",
		"not a url": "https URL",
	} {
		_, err := NormalizeToken(Web, bad, WebPushPolicy{Hosts: hosts})
		if assert.Error(t, err, bad) {
			assert.Contains(t, err.Error(), msg, bad)
		}
	}

	// Without an allowlist any public host works, but private targets never do.
	for _, ok := range []string{"https://push.example/x", "https://93.184.216.34/push"} {
		_, err := NormalizeToken(Web, ok, WebPushPolicy{})
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{
		"https://127.0.0.1/x", "https://10.0.0.1/x", "https://[::1]/x", "https://169.254.169.254/latest",
		"https://localhost/x", "https://push.localhost/x", "https://printer.local/x", "https://metadata.google.internal/x",
	} {
		_, err := NormalizeToken(Web, bad, WebPushPolicy{})
		assert.Error(t, err, bad)
	}
}

func TestWebEndpointsInsecure(t *testing.T) {
	dev := WebPushPolicy{Hosts: []string{"host.docker.internal", "127.0.0.1"}, AllowInsecure: true}
	for _, ok := range []string{"http://host.docker.internal:18083/push/x", "http://127.0.0.1:9000/push", "https://host.docker.internal/x"} {
		assert.NoError(t, dev.Check(ok), ok)
	}
	for _, bad := range []string{"http://evil.example/x", "ftp://host.docker.internal/x", "http://10.0.0.1/x"} {
		assert.Error(t, dev.Check(bad), bad)
	}
	assert.NoError(t, WebPushPolicy{AllowInsecure: true}.Check("http://localhost:8080/x"), "any host without an allowlist")
	assert.Error(t, WebPushPolicy{}.Check("http://localhost:8080/x"))
}
