package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test vector from docs/protocol.md, Appendix A.
func TestAppendixAVector(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	assert.Equal(t, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", base64.RawURLEncoding.EncodeToString(seed))
	key := ed25519.NewKeyFromSeed(seed)
	assert.Equal(t, "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
		base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))

	body := []byte(`{"subscription_id":"sub_example","mode":"id_only","notification_id":"n_1"}`)
	assert.Equal(t, "SAUX3kZI6oRsw2ZIemu0vm_ENHcqIi_nr3Mtwf_zBvo", BodyHash(body))

	r := Request{
		Method: "POST", Host: "push.example", Target: "/v1/push", Timestamp: 1760719200,
		Nonce: "AAECAwQFBgcICQoLDA0ODw", KeyID: "key_example", Body: body,
	}
	assert.Equal(t, strings.Join([]string{
		"GOTALK-SIG-V1", "POST", "push.example", "/v1/push", "1760719200",
		"AAECAwQFBgcICQoLDA0ODw", "key_example", "SAUX3kZI6oRsw2ZIemu0vm_ENHcqIi_nr3Mtwf_zBvo",
	}, "\n"), r.String())

	const want = "3-vRa4hvPv4thLZdk2BO6zN_MPuYP8x9sYVISDDvaA7eyStJU6eE_R3-lJsYlZ2Y8IpNzlOPgwEJ8kAPpba2Aw"
	assert.Equal(t, want, Sign(key, r))
	sig, _ := base64.RawURLEncoding.DecodeString(want)
	assert.True(t, Verify(key.Public().(ed25519.PublicKey), r, sig))

	for name, mutate := range map[string]func(*Request){
		"method": func(r *Request) { r.Method = "PUT" },
		"host":   func(r *Request) { r.Host = "other.example" },
		"target": func(r *Request) { r.Target = "/v1/push?x=1" },
		"time":   func(r *Request) { r.Timestamp++ },
		"nonce":  func(r *Request) { r.Nonce = "AAECAwQFBgcICQoLDA0ODx" },
		"key":    func(r *Request) { r.KeyID = "key_other" },
		"body":   func(r *Request) { r.Body = append([]byte{}, body[1:]...) },
	} {
		m := r
		mutate(&m)
		assert.False(t, Verify(key.Public().(ed25519.PublicKey), m, sig), name)
	}
}

func TestHostAndMethodAreCaseInsensitive(t *testing.T) {
	a := Request{Method: "post", Host: "Push.Example", Target: "/v1/x"}
	b := Request{Method: "POST", Host: "push.example", Target: "/v1/x"}
	assert.Equal(t, a.String(), b.String())
}

func TestParseHeaders(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	req := httptest.NewRequest("POST", "https://push.example/v1/instances/inst_1/keys?x=1", nil)
	body := []byte(`{"a":1}`)
	SignHTTP(req, body, "key_abcdefgh", key, time.Unix(1760719200, 0))

	h, err := ParseHeaders(req.Header, true)
	require.NoError(t, err)
	assert.Equal(t, "key_abcdefgh", h.KeyID)
	assert.Equal(t, int64(1760719200), h.Timestamp)
	assert.Len(t, h.Signature, 64)
	assert.Len(t, h.Digest, 32)
	r := Request{Method: "POST", Host: "push.example", Target: "/v1/instances/inst_1/keys?x=1",
		Timestamp: h.Timestamp, Nonce: h.Nonce, KeyID: h.KeyID, Body: body}
	assert.True(t, Verify(key.Public().(ed25519.PublicKey), r, h.Signature))

	cases := map[string]func(http.Header){
		"missing key id":    func(h http.Header) { h.Del(HeaderKeyID) },
		"bad key id":        func(h http.Header) { h.Set(HeaderKeyID, "inst_x") },
		"timestamp":         func(h http.Header) { h.Set(HeaderTimestamp, "-5") },
		"short nonce":       func(h http.Header) { h.Set(HeaderNonce, "AAAA") },
		"long nonce":        func(h http.Header) { h.Set(HeaderNonce, strings.Repeat("A", 60)) },
		"padded nonce":      func(h http.Header) { h.Set(HeaderNonce, "AAECAwQFBgcICQoLDA0ODw==") },
		"signature":         func(h http.Header) { h.Set(HeaderSignature, "abc") },
		"digest missing":    func(h http.Header) { h.Del(HeaderContentDigest) },
		"digest wrong algo": func(h http.Header) { h.Set(HeaderContentDigest, "sha-512=:AAAA:") },
		"digest bad value":  func(h http.Header) { h.Set(HeaderContentDigest, "sha-256=abc") },
	}
	for name, mutate := range cases {
		hdr := req.Header.Clone()
		mutate(hdr)
		_, err := ParseHeaders(hdr, true)
		assert.ErrorIs(t, err, ErrMalformed, name)
	}

	hdr := req.Header.Clone()
	hdr.Del(HeaderContentDigest)
	_, err = ParseHeaders(hdr, false)
	assert.NoError(t, err, "digest is optional without a body")
}

func TestParseContentDigestDictionary(t *testing.T) {
	want := ContentDigest([]byte("hello"))
	d, err := ParseContentDigest("sha-512=:AAAA:, " + want)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSuffix(strings.TrimPrefix(want, "sha-256=:"), ":"), base64.StdEncoding.EncodeToString(d))
}
