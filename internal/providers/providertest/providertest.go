// Package providertest has fake APNs, FCM and Web Push servers for tests and the end-to-end
// suite. The fakes record every push, verify the gateway's credentials, and answer with
// scripted responses so retry, backoff and dead-token handling can be exercised.
package providertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Response is a scripted provider answer. The zero value is a success.
type Response struct {
	Status int
	// Reason is the APNs reason or the FCM errorCode.
	Reason string
	// RetryAfter is sent as the Retry-After header when set.
	RetryAfter string
	// BadTokenField adds an FCM fieldViolation on message.token.
	BadTokenField bool
	// Hook runs before the fake answers, to change state while a push is in flight.
	Hook func()
}

// Request is a push the fake received.
type Request struct {
	Token  string
	Header http.Header
	// Body is the decoded JSON body (APNs and FCM).
	Body map[string]any
	// Raw is the request body (Web Push), and Plaintext what the subscribed browser
	// decrypted from it, or DecryptErr.
	Raw        []byte
	Plaintext  []byte
	DecryptErr error
	Proto      int
	At         time.Time
}

type recorder struct {
	mu       sync.Mutex
	requests []Request
	script   map[string][]Response
	notify   chan struct{}
}

func newRecorder() recorder {
	return recorder{script: map[string][]Response{}, notify: make(chan struct{}, 1)}
}

// Reset forgets recorded pushes and scripted responses.
func (r *recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests, r.script = nil, map[string][]Response{}
}

// Respond queues responses for a token, used in order. Once they run out the fake succeeds.
func (r *recorder) Respond(token string, rs ...Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.script[token] = append(r.script[token], rs...)
}

func (r *recorder) next(token string) Response {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.script[token]
	if len(q) == 0 {
		return Response{}
	}
	r.script[token] = q[1:]
	return q[0]
}

func (r *recorder) record(req Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Requests returns the pushes received so far, optionally only those for one token.
func (r *recorder) Requests(token ...string) []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Request
	for _, req := range r.requests {
		if len(token) == 0 || req.Token == token[0] {
			out = append(out, req)
		}
	}
	return out
}

// Wait blocks until n pushes for token arrived, or the timeout passes.
func (r *recorder) Wait(token string, n int, timeout time.Duration) ([]Request, error) {
	deadline := time.After(timeout)
	for {
		if got := r.Requests(token); len(got) >= n {
			return got, nil
		}
		select {
		case <-r.notify:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			return r.Requests(token), fmt.Errorf("got %d of %d pushes for the token within %s", len(r.Requests(token)), n, timeout)
		}
	}
}

func readJSON(r *http.Request) (map[string]any, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// APNs is a fake of api.push.apple.com. It speaks HTTP/2 (use ServeH2C or an HTTP/2 TLS
// server) and, when Key is set, verifies the ES256 provider token.
type APNs struct {
	recorder
	Key    *ecdsa.PublicKey
	TeamID string
	KeyID  string
	Topic  string
}

func NewAPNs() *APNs { return &APNs{recorder: newRecorder()} }

func (f *APNs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, reason string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"reason": reason})
	}
	token, ok := strings.CutPrefix(r.URL.Path, "/3/device/")
	if r.Method != http.MethodPost || !ok {
		fail(http.StatusNotFound, "BadPath")
		return
	}
	if err := f.checkToken(r.Header.Get("Authorization")); err != nil {
		fail(http.StatusForbidden, "InvalidProviderToken")
		return
	}
	if f.Topic != "" && r.Header.Get("apns-topic") != f.Topic {
		fail(http.StatusBadRequest, "DeviceTokenNotForTopic")
		return
	}
	body, err := readJSON(r)
	if err != nil {
		fail(http.StatusBadRequest, "PayloadEmpty")
		return
	}
	f.record(Request{Token: token, Header: r.Header.Clone(), Body: body, Proto: r.ProtoMajor, At: time.Now()})
	resp := f.next(token)
	if resp.Hook != nil {
		resp.Hook()
	}
	if resp.Status == 0 || resp.Status == http.StatusOK {
		w.Header().Set("apns-id", "00000000-0000-0000-0000-000000000000")
		w.WriteHeader(http.StatusOK)
		return
	}
	if resp.RetryAfter != "" {
		w.Header().Set("Retry-After", resp.RetryAfter)
	}
	fail(resp.Status, resp.Reason)
}

func (f *APNs) checkToken(header string) error {
	raw, ok := strings.CutPrefix(header, "bearer ")
	if !ok {
		return errors.New("missing bearer token")
	}
	if f.Key == nil {
		return nil
	}
	claims := jwt.MapClaims{}
	t, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return f.Key, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuedAt())
	if err != nil {
		return err
	}
	if (f.KeyID != "" && t.Header["kid"] != f.KeyID) || (f.TeamID != "" && claims["iss"] != f.TeamID) {
		return errors.New("wrong key or team")
	}
	return nil
}

// FCM is a fake of the FCM v1 API and of Google's OAuth token endpoint (POST /token). When Key
// is set, it verifies the service account's signed assertion.
type FCM struct {
	recorder
	Key       *rsa.PublicKey
	ProjectID string

	tokenMu sync.Mutex
	issued  int
	revoked map[string]bool
}

func NewFCM(projectID string) *FCM {
	return &FCM{recorder: newRecorder(), ProjectID: projectID, revoked: map[string]bool{}}
}

// TokensIssued is how many access tokens the fake handed out.
func (f *FCM) TokensIssued() int {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	return f.issued
}

// RevokeTokens makes every access token issued so far invalid.
func (f *FCM) RevokeTokens() {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	for i := 1; i <= f.issued; i++ {
		f.revoked["fake-access-"+strconv.Itoa(i)] = true
	}
}

func (f *FCM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/token" {
		f.serveToken(w, r)
		return
	}
	fail := func(status int, grpcStatus, code string, badToken bool) {
		details := []map[string]any{}
		if code != "" {
			details = append(details, map[string]any{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code})
		}
		if badToken {
			details = append(details, map[string]any{"@type": "type.googleapis.com/google.rpc.BadRequest",
				"fieldViolations": []map[string]any{{"field": "message.token", "description": "Invalid registration token"}}})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code": status, "message": "fake error", "status": grpcStatus, "details": details,
		}})
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/"+f.ProjectID+"/messages:send" {
		fail(http.StatusNotFound, "NOT_FOUND", "", false)
		return
	}
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.tokenMu.Lock()
	valid := strings.HasPrefix(tok, "fake-access-") && !f.revoked[tok]
	f.tokenMu.Unlock()
	if !valid {
		fail(http.StatusUnauthorized, "UNAUTHENTICATED", "", false)
		return
	}
	body, err := readJSON(r)
	if err != nil {
		fail(http.StatusBadRequest, "INVALID_ARGUMENT", "INVALID_ARGUMENT", false)
		return
	}
	msg, _ := body["message"].(map[string]any)
	token, _ := msg["token"].(string)
	f.record(Request{Token: token, Header: r.Header.Clone(), Body: body, Proto: r.ProtoMajor, At: time.Now()})
	resp := f.next(token)
	if resp.Hook != nil {
		resp.Hook()
	}
	if resp.Status == 0 || resp.Status == http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "projects/" + f.ProjectID + "/messages/0:1"})
		return
	}
	if resp.RetryAfter != "" {
		w.Header().Set("Retry-After", resp.RetryAfter)
	}
	fail(resp.Status, http.StatusText(resp.Status), resp.Reason, resp.BadTokenField)
}

func (f *FCM) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		return
	}
	if f.Key != nil {
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(r.PostForm.Get("assertion"), claims, func(*jwt.Token) (any, error) { return f.Key, nil },
			jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !strings.Contains(fmt.Sprint(claims["scope"]), "firebase.messaging") {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
	}
	f.tokenMu.Lock()
	f.issued++
	n := f.issued
	f.tokenMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access-" + strconv.Itoa(n), "token_type": "Bearer", "expires_in": 3600})
}

// NewAPNsKey returns a fresh .p8-style PEM key and its public key.
func NewAPNsKey() ([]byte, *ecdsa.PublicKey) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), &k.PublicKey
}

// NewServiceAccount returns a service account key whose token_uri is tokenURL, and its
// public key.
func NewServiceAccount(projectID, tokenURL string) ([]byte, *rsa.PublicKey) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	sa, _ := json.MarshalIndent(map[string]string{
		"type": "service_account", "project_id": projectID, "private_key_id": "test",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "gateway@" + projectID + ".iam.gserviceaccount.com", "client_id": "1",
		"token_uri": tokenURL,
	}, "", "  ")
	return sa, &k.PublicKey
}

// Serve runs h on addr ("127.0.0.1:0" for any port) with HTTP/1.1 and unencrypted HTTP/2, and
// returns its base URL and a function that stops it.
func Serve(addr string, h http.Handler) (string, func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: h, Protocols: p, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return "http://" + ln.Addr().String(), func() { _ = srv.Close() }, nil
}
