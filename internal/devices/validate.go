package devices

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/parkerbrown98/gotalk-gateway/internal/wellknown"
)

// Platforms.
const (
	IOS     = "ios"
	Android = "android"
	Web     = "web"
)

// APNs environments.
const (
	APNsProduction = "production"
	APNsSandbox    = "sandbox"
)

// DefaultWebPushHosts are the browser push services the gateway delivers to by default.
// An endpoint host must equal one of them or be a subdomain of one.
var DefaultWebPushHosts = []string{
	"fcm.googleapis.com",                // Chrome, Samsung Internet, Opera, Brave
	"updates.push.services.mozilla.com", // Firefox
	"web.push.apple.com",                // Safari
	"notify.windows.com",                // Edge
}

const maxEndpointLength = 2048

var (
	apnsTokenPattern = regexp.MustCompile(`^[0-9a-fA-F]{64,200}$`)
	fcmTokenPattern  = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
)

// NormalizeToken validates a platform token or Web Push endpoint and returns the form the
// gateway stores. APNs tokens are case-insensitive hex and are stored in lower case.
func NormalizeToken(platform, token string, webPushHosts []string) (string, error) {
	switch platform {
	case IOS:
		if !apnsTokenPattern.MatchString(token) {
			return "", errors.New("an APNs device token is 64 to 200 hexadecimal characters")
		}
		return strings.ToLower(token), nil
	case Android:
		if len(token) < 100 || len(token) > 4096 || !fcmTokenPattern.MatchString(token) {
			return "", errors.New("an FCM registration token is 100 to 4096 characters of A-Z, a-z, 0-9, '_', '-', '.' and ':'")
		}
		return token, nil
	case Web:
		return token, validateEndpoint(token, webPushHosts)
	default:
		return "", fmt.Errorf("unknown platform %q", platform)
	}
}

// validateEndpoint accepts https Web Push endpoints on a public host (and, when
// webPushHosts is set, on a known push service). The endpoint is stored verbatim because
// push services treat it as opaque.
func validateEndpoint(endpoint string, webPushHosts []string) error {
	if len(endpoint) > maxEndpointLength {
		return fmt.Errorf("a Web Push endpoint is at most %d characters", maxEndpointLength)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return errors.New("a Web Push endpoint must be an https URL")
	}
	if u.User != nil || u.Fragment != "" {
		return errors.New("a Web Push endpoint must not contain user info or a fragment")
	}
	if p := u.Port(); p != "" && p != "443" {
		return errors.New("a Web Push endpoint must use port 443")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		if !wellknown.IsPublic(addr) || len(webPushHosts) > 0 {
			return errors.New("the gateway does not send to this push service")
		}
		return nil
	}
	if !strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") {
		return errors.New("the gateway does not send to this push service")
	}
	if len(webPushHosts) == 0 {
		return nil
	}
	for _, allowed := range webPushHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return nil
		}
	}
	return fmt.Errorf("the gateway does not send to push service %s", host)
}
