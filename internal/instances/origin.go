package instances

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// maxOriginLength matches the Origin schema in docs/openapi.yaml.
const maxOriginLength = 253

// NormalizeOrigin returns the canonical form of an instance origin: lower-case scheme and
// host, no path, query, fragment or trailing slash, and no default port
// (docs/protocol.md, "Conventions"). Only https is accepted unless allowHTTP is set.
func NormalizeOrigin(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", errors.New("must be an origin such as https://forum.example")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && (!allowHTTP || scheme != "http") {
		return "", errors.New("must use https")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("must not contain user info, a path, a query or a fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if strings.Contains(host, ":") {
		return "", errors.New("IPv6 address origins are not supported")
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || !validHost(ascii) {
		return "", errors.New("host is not a valid domain name")
	}
	origin := scheme + "://" + ascii
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("port is invalid")
		}
		if defaultPort := (scheme == "https" && n == 443) || (scheme == "http" && n == 80); !defaultPort {
			origin += ":" + strconv.Itoa(n)
		}
	}
	if len(origin) > maxOriginLength {
		return "", errors.New("is too long")
	}
	return origin, nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
