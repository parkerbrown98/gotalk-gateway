package providertest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RFC 8291 (Message Encryption for Web Push) with the aes128gcm content coding of RFC 8188.
// The gateway never encrypts or decrypts; these helpers play the instance (Encrypt) and the
// browser (Decrypt) in tests.

const (
	recordSize = 4096
	// keyIDLength is the length of the key ID: the sender's uncompressed P-256 public key.
	keyIDLength = 65
	headerSize  = 16 + 4 + 1 + keyIDLength
)

// Subscription is a browser's push subscription: its endpoint and the keys an instance
// encrypts to. Private stays in the browser.
type Subscription struct {
	Endpoint string
	Token    string
	P256dh   []byte
	Auth     []byte
	Private  *ecdh.PrivateKey
}

// NewBrowserKeys returns a P-256 key pair and a 16-byte auth secret, as pushManager.subscribe
// creates them.
func NewBrowserKeys() (*ecdh.PrivateKey, []byte) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	return k, auth
}

// keys derives the content-encryption key and nonce (RFC 8291 §3.4, RFC 8188 §2.2).
func keys(shared, auth, uaPublic, asPublic, salt []byte) (cek, nonce []byte, err error) {
	prkKey, err := hkdf.Extract(sha256.New, shared, auth)
	if err != nil {
		return nil, nil, err
	}
	info := append(append([]byte("WebPush: info\x00"), uaPublic...), asPublic...)
	ikm, err := hkdf.Expand(sha256.New, prkKey, string(info), 32)
	if err != nil {
		return nil, nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, nil, err
	}
	if cek, err = hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16); err != nil {
		return nil, nil, err
	}
	nonce, err = hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	return cek, nonce, err
}

// Encrypt builds the RFC 8291 body an instance sends: one record, padded with padTo zero
// bytes after the delimiter.
func Encrypt(p256dh, auth, plaintext []byte, padTo int) ([]byte, error) {
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return EncryptWith(as, salt, p256dh, auth, plaintext, padTo)
}

// EncryptWith is Encrypt with a given sender key and salt (test vectors).
func EncryptWith(as *ecdh.PrivateKey, salt, p256dh, auth, plaintext []byte, padding int) ([]byte, error) {
	ua, err := ecdh.P256().NewPublicKey(p256dh)
	if err != nil {
		return nil, fmt.Errorf("p256dh: %w", err)
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()
	cek, nonce, err := keys(shared, auth, p256dh, asPublic, salt)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	record := append(append(bytes.Clone(plaintext), 0x02), make([]byte, padding)...)
	if len(record)+gcm.Overhead() > recordSize {
		return nil, errors.New("plaintext does not fit one record")
	}
	header := make([]byte, 0, headerSize)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, recordSize)
	header = append(header, keyIDLength)
	header = append(header, asPublic...)
	return gcm.Seal(header, nonce, record, nil), nil
}

// Decrypt opens an RFC 8291 body with the browser's key and auth secret.
func Decrypt(ua *ecdh.PrivateKey, auth, body []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, errors.New("body is shorter than the header")
	}
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if len(body) < 21+idlen {
		return nil, errors.New("body is shorter than the key ID")
	}
	asPublic, ciphertext := body[21:21+idlen], body[21+idlen:]
	if rs < 18 || len(ciphertext) > int(rs) {
		return nil, errors.New("body has more than one record")
	}
	as, err := ecdh.P256().NewPublicKey(asPublic)
	if err != nil {
		return nil, fmt.Errorf("key ID is not a P-256 public key: %w", err)
	}
	shared, err := ua.ECDH(as)
	if err != nil {
		return nil, err
	}
	cek, nonce, err := keys(shared, auth, ua.PublicKey().Bytes(), asPublic, salt)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	record, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	record = bytes.TrimRight(record, "\x00")
	if len(record) == 0 || record[len(record)-1] != 0x02 {
		return nil, errors.New("the last record has no 0x02 delimiter")
	}
	return record[:len(record)-1], nil
}

// NewVAPIDKey returns a fresh VAPID key pair as web-push tools print it: the private scalar
// and the uncompressed public key, both base64url without padding.
func NewVAPIDKey() (private, public string) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// WebPush is a fake browser push service (RFC 8030) that also plays the browsers subscribed
// to it: it verifies the VAPID token (RFC 8292), checks the headers, and decrypts each push
// with the subscription's keys. Pushes are recorded under the endpoint's last path segment.
type WebPush struct {
	recorder
	// PublicKey, when set, is the only VAPID key accepted (base64url, as in discovery).
	PublicKey string
	// Now is the clock the token expiry is checked against.
	Now func() time.Time

	mu   sync.Mutex
	subs map[string]Subscription
}

func NewWebPush() *WebPush {
	return &WebPush{recorder: newRecorder(), subs: map[string]Subscription{}, Now: time.Now}
}

// Subscribe creates a browser subscription whose endpoint is base + "/" + a random token,
// like pushManager.subscribe.
func (f *WebPush) Subscribe(base string) Subscription {
	priv, auth := NewBrowserKeys()
	tok := make([]byte, 24)
	_, _ = rand.Read(tok)
	token := base64.RawURLEncoding.EncodeToString(tok)
	s := Subscription{Endpoint: strings.TrimRight(base, "/") + "/" + token, Token: token,
		P256dh: priv.PublicKey().Bytes(), Auth: auth, Private: priv}
	f.mu.Lock()
	f.subs[token] = s
	f.mu.Unlock()
	return s
}

func (f *WebPush) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, reason string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"reason": reason})
	}
	if r.Method != http.MethodPost {
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if err := f.checkVAPID(r.Header.Get("Authorization"), scheme+"://"+r.Host); err != nil {
		fail(http.StatusUnauthorized, "BadJwtToken")
		return
	}
	if r.Header.Get("Content-Encoding") != "aes128gcm" {
		fail(http.StatusBadRequest, "BadContentEncoding")
		return
	}
	if _, err := strconv.Atoi(r.Header.Get("TTL")); err != nil {
		fail(http.StatusBadRequest, "BadExpirationDate")
		return
	}
	switch r.Header.Get("Urgency") {
	case "very-low", "low", "normal", "high":
	default:
		fail(http.StatusBadRequest, "BadUrgency")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	if err != nil {
		fail(http.StatusBadRequest, "BadBody")
		return
	}
	if len(body) > 4096 {
		fail(http.StatusRequestEntityTooLarge, "PayloadTooLarge")
		return
	}
	token := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	req := Request{Token: token, Header: r.Header.Clone(), Raw: body, Proto: r.ProtoMajor, At: time.Now()}
	f.mu.Lock()
	sub, ok := f.subs[token]
	f.mu.Unlock()
	if ok {
		req.Plaintext, req.DecryptErr = Decrypt(sub.Private, sub.Auth, body)
	}
	f.record(req)
	resp := f.next(token)
	if resp.Hook != nil {
		resp.Hook()
	}
	if resp.Status == 0 || resp.Status == http.StatusCreated {
		w.Header().Set("Location", "/message/"+token)
		w.WriteHeader(http.StatusCreated)
		return
	}
	if resp.RetryAfter != "" {
		w.Header().Set("Retry-After", resp.RetryAfter)
	}
	fail(resp.Status, resp.Reason)
}

// checkVAPID verifies "vapid t=<JWT>, k=<key>" for the push service's own origin.
func (f *WebPush) checkVAPID(header, origin string) error {
	params, ok := strings.CutPrefix(header, "vapid ")
	if !ok {
		return errors.New("not a vapid authorization")
	}
	var t, k string
	for p := range strings.SplitSeq(params, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch name {
		case "t":
			t = value
		case "k":
			k = value
		}
	}
	if f.PublicKey != "" && k != f.PublicKey {
		return errors.New("unexpected VAPID key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(k)
	if err != nil {
		return err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return err
	}
	now := f.Now()
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(t, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(origin), jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return err
	}
	exp, _ := claims.GetExpirationTime()
	if exp.After(now.Add(24 * time.Hour)) {
		return errors.New("exp is more than 24 hours ahead")
	}
	if sub, _ := claims["sub"].(string); !strings.HasPrefix(sub, "mailto:") && !strings.HasPrefix(sub, "https:") {
		return errors.New("sub must be a mailto: or https: URL")
	}
	return nil
}

// ServeTLS runs h over TLS with HTTP/2 and returns a client that sends every request to it,
// whatever the URL's host, so tests can use real push service endpoints such as
// https://fcm.googleapis.com/fcm/send/….
func ServeTLS(h http.Handler) (*http.Client, func()) {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	client := srv.Client()
	t := client.Transport.(*http.Transport)
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}} //nolint:gosec // test server with a throwaway certificate
	addr := srv.Listener.Addr().String()
	var d net.Dialer
	t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, srv.Close
}
