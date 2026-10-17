// Package signing implements GOTALK-SIG-V1, the Ed25519 request signature instances use to
// authenticate to the gateway (docs/protocol.md, "Request signing").
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Header names.
const (
	HeaderKeyID         = "Gotalk-Key-Id"
	HeaderTimestamp     = "Gotalk-Timestamp"
	HeaderNonce         = "Gotalk-Nonce"
	HeaderSignature     = "Gotalk-Signature"
	HeaderContentDigest = "Content-Digest"
)

const (
	// Prefix is the domain separator and signature version.
	Prefix = "GOTALK-SIG-V1"
	// MaxSkew is how far a request timestamp may be from the gateway's clock.
	MaxSkew = 300 * time.Second
	// NonceTTL is how long nonces are remembered: twice the skew window.
	NonceTTL = 2 * MaxSkew

	minNonceBytes = 16
	maxNonceBytes = 32
)

var (
	keyIDPattern     = regexp.MustCompile(`^key_[A-Za-z0-9_-]{1,64}$`)
	timestampPattern = regexp.MustCompile(`^[0-9]{1,12}$`)
	b64url           = base64.RawURLEncoding
)

// Request holds the signed parts of an HTTP request.
type Request struct {
	Method string
	// Host is the gateway's host (and port, when not the default), as in the Host header.
	Host string
	// Target is the path and query exactly as sent.
	Target    string
	Timestamp int64
	Nonce     string
	KeyID     string
	Body      []byte
}

// BodyHash is the unpadded base64url SHA-256 of body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return b64url.EncodeToString(sum[:])
}

// String builds the signing string: the fields joined by "\n" with no trailing newline.
func (r Request) String() string {
	return strings.Join([]string{
		Prefix,
		strings.ToUpper(r.Method),
		strings.ToLower(r.Host),
		r.Target,
		strconv.FormatInt(r.Timestamp, 10),
		r.Nonce,
		r.KeyID,
		BodyHash(r.Body),
	}, "\n")
}

// Sign returns the base64url signature of r.
func Sign(key ed25519.PrivateKey, r Request) string {
	return b64url.EncodeToString(ed25519.Sign(key, []byte(r.String())))
}

// Verify reports whether sig is a valid signature of r by key.
func Verify(key ed25519.PublicKey, r Request, sig []byte) bool {
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, []byte(r.String()), sig)
}

// Headers are the parsed signing headers of a request.
type Headers struct {
	KeyID     string
	Timestamp int64
	Nonce     string
	Signature []byte
	// Digest is the SHA-256 from Content-Digest, or nil when the header is absent.
	Digest []byte
}

// ErrMalformed wraps every header parsing failure.
var ErrMalformed = errors.New("malformed signing headers")

// ParseHeaders parses and checks the format of the signing headers. Content-Digest is
// required when the request has a body.
func ParseHeaders(h http.Header, hasBody bool) (Headers, error) {
	var out Headers
	fail := func(format string, args ...any) (Headers, error) {
		return Headers{}, fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, args...)...)
	}

	out.KeyID = h.Get(HeaderKeyID)
	if !keyIDPattern.MatchString(out.KeyID) {
		return fail("%s must be a key ID", HeaderKeyID)
	}
	ts := h.Get(HeaderTimestamp)
	if !timestampPattern.MatchString(ts) {
		return fail("%s must be Unix seconds", HeaderTimestamp)
	}
	out.Timestamp, _ = strconv.ParseInt(ts, 10, 64)

	out.Nonce = h.Get(HeaderNonce)
	nonce, err := b64url.DecodeString(out.Nonce)
	if err != nil || len(nonce) < minNonceBytes || len(nonce) > maxNonceBytes {
		return fail("%s must be %d to %d random bytes, base64url without padding", HeaderNonce, minNonceBytes, maxNonceBytes)
	}

	sig, err := b64url.DecodeString(h.Get(HeaderSignature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fail("%s must be a base64url Ed25519 signature", HeaderSignature)
	}
	out.Signature = sig

	if v := h.Get(HeaderContentDigest); v != "" {
		d, err := ParseContentDigest(v)
		if err != nil {
			return fail("%s: %v", HeaderContentDigest, err)
		}
		out.Digest = d
	} else if hasBody {
		return fail("%s is required when the request has a body", HeaderContentDigest)
	}
	return out, nil
}

// ParseContentDigest extracts the sha-256 member of an RFC 9530 Content-Digest
// dictionary, such as "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".
func ParseContentDigest(v string) ([]byte, error) {
	for member := range strings.SplitSeq(v, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(member), "=")
		if !ok || strings.ToLower(strings.TrimSpace(name)) != "sha-256" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
			return nil, errors.New("sha-256 value must be a byte sequence (:base64:)")
		}
		d, err := base64.StdEncoding.DecodeString(value[1 : len(value)-1])
		if err != nil || len(d) != sha256.Size {
			return nil, errors.New("sha-256 value must be 32 bytes in standard base64")
		}
		return d, nil
	}
	return nil, errors.New("no sha-256 member")
}

// ContentDigest returns the Content-Digest header value for body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// NewNonce returns 16 random bytes, base64url encoded.
func NewNonce() string {
	var b [minNonceBytes]byte
	_, _ = rand.Read(b[:])
	return b64url.EncodeToString(b[:])
}

// SignHTTP signs req and sets the signing headers. body must be the request body (nil for
// none); req.Body is not read. Instances and tests use it to call the gateway.
func SignHTTP(req *http.Request, body []byte, keyID string, key ed25519.PrivateKey, now time.Time) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	r := Request{
		Method:    req.Method,
		Host:      host,
		Target:    req.URL.RequestURI(),
		Timestamp: now.Unix(),
		Nonce:     NewNonce(),
		KeyID:     keyID,
		Body:      body,
	}
	req.Header.Set(HeaderKeyID, keyID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(r.Timestamp, 10))
	req.Header.Set(HeaderNonce, r.Nonce)
	if len(body) > 0 {
		req.Header.Set(HeaderContentDigest, ContentDigest(body))
	}
	req.Header.Set(HeaderSignature, Sign(key, r))
}
