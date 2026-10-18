// Package config loads layered configuration: built-in defaults, then an optional YAML
// file, then environment variables, then command-line overrides.
//
// Environment variables use the GOTALK_GATEWAY_ prefix, and the first underscore after the
// prefix separates the section from the key, e.g. GOTALK_GATEWAY_DATABASE_URL ->
// database.url, GOTALK_GATEWAY_SERVER_PUBLIC_URL -> server.public_url. Appending _FILE to
// any variable reads the value from that file path instead (Docker/Kubernetes secrets
// convention). The common platform variables DATABASE_URL, REDIS_URL and PORT are honored
// as fallbacks that only override the built-in defaults. Empty environment variables are
// ignored, so Compose files can pass optional ones through. Apps can only be declared in
// the config file.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
)

const (
	EnvPrefix = "GOTALK_GATEWAY_"
	// EnvConfigFile names the config file when --config is not given.
	EnvConfigFile = EnvPrefix + "CONFIG"
)

type Config struct {
	Server    Server     `koanf:"server"`
	Database  Database   `koanf:"database"`
	Redis     Redis      `koanf:"redis"`
	Log       Log        `koanf:"log"`
	Metrics   Metrics    `koanf:"metrics"`
	Gateway   Gateway    `koanf:"gateway"`
	Instances Instances  `koanf:"instances"`
	Devices   Devices    `koanf:"devices"`
	Delivery  Delivery   `koanf:"delivery"`
	RateLimit RateLimit  `koanf:"ratelimit"`
	Apps      []apps.App `koanf:"apps"`
}

type Server struct {
	Addr string `koanf:"addr"`
	// PublicURL is the externally reachable base URL (e.g. https://push.example.com), used
	// for api_base_url in discovery. When empty it is derived from each request.
	PublicURL string `koanf:"public_url"`
	// TrustProxy honors X-Forwarded-For / X-Forwarded-Proto / X-Forwarded-Host, but only on
	// requests whose direct peer is within TrustedProxies.
	TrustProxy     bool     `koanf:"trust_proxy"`
	TrustedProxies []string `koanf:"trusted_proxies"`
	// DrainDelay is how long the gateway keeps serving after a shutdown signal while
	// /readyz reports "draining", so load balancers stop routing to it first.
	DrainDelay time.Duration `koanf:"drain_delay"`
	// ShutdownTimeout bounds how long in-flight requests get to finish.
	ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
}

// TrustedProxyPrefixes parses TrustedProxies. Validate guarantees it succeeds.
func (s Server) TrustedProxyPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s.TrustedProxies))
	for _, cidr := range s.TrustedProxies {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			out = append(out, p)
		}
	}
	return out
}

type Database struct {
	URL         string `koanf:"url"`
	MaxConns    int32  `koanf:"max_conns"`
	AutoMigrate bool   `koanf:"auto_migrate"`
	// ConnectTimeout bounds how long startup waits for PostgreSQL to become reachable.
	ConnectTimeout time.Duration `koanf:"connect_timeout"`
}

type Redis struct {
	// URL is optional. Without it the gateway runs in single-node mode and keeps nonces and
	// rate limits in memory.
	URL string `koanf:"url"`
}

type Log struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type Metrics struct {
	Enabled bool `koanf:"enabled"`
	// Addr serves /metrics on a separate listener (e.g. ":9090") so it is not exposed with
	// the public API. When empty, /metrics is served on server.addr.
	Addr string `koanf:"addr"`
}

// Gateway describes this gateway in the discovery document.
type Gateway struct {
	Name       string `koanf:"name"`
	TermsURL   string `koanf:"terms_url"`
	PrivacyURL string `koanf:"privacy_url"`
	// SubscriptionExpiryDays is how long a device subscription lives without a refresh.
	SubscriptionExpiryDays int `koanf:"subscription_expiry_days"`
}

// Instances controls instance registration and domain verification.
type Instances struct {
	// AllowHTTP accepts http:// origins. Development only: the origin's well-known document
	// is the root of trust, and plain HTTP lets anyone on the path forge it.
	AllowHTTP bool `koanf:"allow_http"`
	// AllowPrivateNetworks lets verification fetch loopback, private and link-local
	// addresses. Development only: otherwise registration can probe the internal network.
	AllowPrivateNetworks bool `koanf:"allow_private_networks"`
	// AllowedPorts lists origin ports allowed besides the scheme's default (443 or 80).
	AllowedPorts []int `koanf:"allowed_ports"`
}

// Devices controls device subscriptions.
type Devices struct {
	// WebPushHosts restricts Web Push endpoints to these push services and their
	// subdomains. An empty list allows any public host.
	WebPushHosts []string `koanf:"web_push_hosts"`
}

// Delivery controls the push queue and the provider clients.
type Delivery struct {
	// Workers is how many pushes this replica delivers concurrently. 0 makes it accept and
	// queue pushes without delivering any (for API-only replicas).
	Workers int `koanf:"workers"`
	// ProviderTimeout bounds each request to APNs or FCM.
	ProviderTimeout time.Duration `koanf:"provider_timeout"`
	// DeadLetterRetention is how long a push whose retries ran out stays in the queue, with
	// its errors, for inspection.
	DeadLetterRetention time.Duration `koanf:"dead_letter_retention"`
}

// RateLimit rates use the "<limit>-<period>" format, where period is S, M, H or D.
type RateLimit struct {
	Enabled bool `koanf:"enabled"`
	// Registration limits POST /v1/instances per client IP.
	Registration string `koanf:"registration"`
	// Signed limits signed requests per instance.
	Signed string `koanf:"signed"`
	// Verification limits on-demand domain verification fetches per signing key.
	Verification string `koanf:"verification"`
	// DeviceRegistration limits POST /v1/devices per client IP.
	DeviceRegistration string `koanf:"device_registration"`
	// DeviceToken limits registering (or switching to) one platform token.
	DeviceToken string `koanf:"device_token"`
	// DeviceUpdate limits refreshes per subscription.
	DeviceUpdate string `koanf:"device_update"`
}

// Rules maps rule names to rates; empty when rate limiting is disabled.
func (r RateLimit) Rules() map[string]string {
	if !r.Enabled {
		return map[string]string{}
	}
	return map[string]string{
		"registration": r.Registration, "signed": r.Signed, "verification": r.Verification,
		"device_registration": r.DeviceRegistration, "device_token": r.DeviceToken, "device_update": r.DeviceUpdate,
	}
}

func defaults() map[string]any {
	localDB := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("gotalk", "gotalk"),
		Host:     "localhost:5432",
		Path:     "/gotalk_gateway",
		RawQuery: "sslmode=disable",
	}
	return map[string]any{
		"server.addr": ":8090",
		"server.trusted_proxies": []string{
			"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
		},
		"server.drain_delay":               "0s",
		"server.shutdown_timeout":          "20s",
		"database.url":                     localDB.String(),
		"database.max_conns":               20,
		"database.auto_migrate":            true,
		"database.connect_timeout":         "30s",
		"log.level":                        "info",
		"log.format":                       "json",
		"metrics.enabled":                  true,
		"gateway.name":                     "Gotalk Push Gateway",
		"gateway.subscription_expiry_days": 60,
		"instances.allow_http":             false,
		"instances.allow_private_networks": false,
		"instances.allowed_ports":          []int{},
		"ratelimit.enabled":                true,
		"ratelimit.registration":           "5-H",
		"ratelimit.signed":                 "1200-M",
		"ratelimit.verification":           "12-H",
		"ratelimit.device_registration":    "60-H",
		"ratelimit.device_token":           "10-H",
		"ratelimit.device_update":          "60-H",
		"devices.web_push_hosts":           slices.Clone(devices.DefaultWebPushHosts),
		"delivery.workers":                 50,
		"delivery.provider_timeout":        "10s",
		"delivery.dead_letter_retention":   "24h",
	}
}

// listKeys are split on commas when supplied through the environment or overrides.
var listKeys = map[string]bool{"server.trusted_proxies": true, "instances.allowed_ports": true, "devices.web_push_hosts": true}

// Load builds the configuration. configFile may be empty. overrides maps dotted keys (such
// as "server.addr") to values and takes precedence over every other layer.
func Load(configFile string, overrides map[string]string) (*Config, error) {
	return load(configFile, overrides, os.Environ)
}

func load(configFile string, overrides map[string]string, environ func() []string) (*Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults(), "."), nil); err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	// Platform variables are fallbacks: they only beat the built-in defaults, so a stray
	// DATABASE_URL in a shell cannot override an explicit config file.
	platform := map[string]any{}
	for _, kv := range environ() {
		name, value, _ := strings.Cut(kv, "=")
		if value == "" {
			continue
		}
		switch name {
		case "DATABASE_URL":
			platform["database.url"] = value
		case "REDIS_URL":
			platform["redis.url"] = value
		case "PORT":
			platform["server.addr"] = ":" + value
		}
	}
	if err := k.Load(confmap.Provider(platform, "."), nil); err != nil {
		return nil, fmt.Errorf("loading platform environment: %w", err)
	}

	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file %q: %w", configFile, err)
		}
	}

	var fileErr error
	envProvider := env.Provider(".", env.Opt{
		Prefix:      EnvPrefix,
		EnvironFunc: environ,
		TransformFunc: func(name, value string) (string, any) {
			if name == EnvConfigFile {
				return "", nil
			}
			key := strings.ToLower(strings.TrimPrefix(name, EnvPrefix))
			if strings.HasSuffix(key, "_file") {
				if value == "" {
					return "", nil
				}
				// Reading an operator-supplied path is the point of the _FILE convention.
				data, err := os.ReadFile(value) //nolint:gosec // path comes from trusted deployment config
				if err != nil {
					fileErr = errors.Join(fileErr, fmt.Errorf("reading %s: %w", name, err))
					return "", nil
				}
				key = strings.TrimSuffix(key, "_file")
				value = strings.TrimRight(string(data), "\r\n")
			}
			if value == "" {
				return "", nil
			}
			section, rest, ok := strings.Cut(key, "_")
			if !ok {
				return "", nil
			}
			return typed(section+"."+rest, value)
		},
	})
	if err := k.Load(envProvider, nil); err != nil {
		return nil, fmt.Errorf("loading environment: %w", err)
	}
	if fileErr != nil {
		return nil, fileErr
	}

	flagLayer := map[string]any{}
	for key, value := range overrides {
		key, v := typed(key, value)
		flagLayer[key] = v
	}
	if err := k.Load(confmap.Provider(flagLayer, "."), nil); err != nil {
		return nil, fmt.Errorf("loading overrides: %w", err)
	}

	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func typed(key, value string) (string, any) {
	if listKeys[key] {
		return key, splitList(value)
	}
	return key, value
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate reports every invalid setting at once so operators can fix them in one pass.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if _, _, err := net.SplitHostPort(c.Server.Addr); err != nil {
		add("server.addr must be host:port (e.g. :8090), got %q", c.Server.Addr)
	}
	for _, cidr := range c.Server.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			add("server.trusted_proxies contains an invalid CIDR %q", cidr)
		}
	}
	if c.Server.PublicURL != "" {
		u, err := url.Parse(c.Server.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			add("server.public_url must be an absolute http(s) URL without query or fragment, got %q", c.Server.PublicURL)
		}
		c.Server.PublicURL = strings.TrimRight(c.Server.PublicURL, "/")
	}
	if c.Server.DrainDelay < 0 {
		add("server.drain_delay must not be negative")
	}
	if c.Server.ShutdownTimeout <= 0 {
		add("server.shutdown_timeout must be positive")
	}
	if c.Database.URL == "" {
		add("database.url must not be empty (set GOTALK_GATEWAY_DATABASE_URL)")
	}
	if c.Database.MaxConns < 1 {
		add("database.max_conns must be at least 1")
	}
	if c.Database.ConnectTimeout < 0 {
		add("database.connect_timeout must not be negative")
	}
	if c.Redis.URL != "" {
		if _, err := redis.ParseURL(c.Redis.URL); err != nil {
			add("redis.url is invalid: %v", err)
		}
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.Log.Level)); err != nil {
		add("log.level must be debug, info, warn or error, got %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		add("log.format must be json or text, got %q", c.Log.Format)
	}
	if c.Metrics.Addr != "" {
		if _, _, err := net.SplitHostPort(c.Metrics.Addr); err != nil {
			add("metrics.addr must be host:port (e.g. :9090), got %q", c.Metrics.Addr)
		} else if c.Metrics.Addr == c.Server.Addr {
			add("metrics.addr must differ from server.addr; leave it empty to serve /metrics on server.addr")
		}
	}
	if strings.TrimSpace(c.Gateway.Name) == "" {
		add("gateway.name must not be empty")
	}
	for _, f := range []struct{ key, v string }{{"gateway.terms_url", c.Gateway.TermsURL}, {"gateway.privacy_url", c.Gateway.PrivacyURL}} {
		if f.v == "" {
			continue
		}
		if u, err := url.Parse(f.v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("%s must be an absolute http(s) URL, got %q", f.key, f.v)
		}
	}
	if d := c.Gateway.SubscriptionExpiryDays; d < 14 || d > 365 {
		add("gateway.subscription_expiry_days must be between 14 and 365, got %d", d)
	}
	for _, p := range c.Instances.AllowedPorts {
		if p < 1 || p > 65535 {
			add("instances.allowed_ports contains an invalid port %d", p)
		}
	}
	for _, f := range []struct{ key, v string }{
		{"ratelimit.registration", c.RateLimit.Registration},
		{"ratelimit.signed", c.RateLimit.Signed},
		{"ratelimit.verification", c.RateLimit.Verification},
		{"ratelimit.device_registration", c.RateLimit.DeviceRegistration},
		{"ratelimit.device_token", c.RateLimit.DeviceToken},
		{"ratelimit.device_update", c.RateLimit.DeviceUpdate},
	} {
		if _, err := limiter.NewRateFromFormatted(f.v); err != nil {
			add("%s must be <limit>-<period> with period S, M, H or D (e.g. 5-H), got %q", f.key, f.v)
		}
	}
	for i, h := range c.Devices.WebPushHosts {
		h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "."))
		if h == "" || strings.ContainsAny(h, "/:@ *") {
			add("devices.web_push_hosts contains an invalid host name %q (use a name like fcm.googleapis.com)", c.Devices.WebPushHosts[i])
		}
		c.Devices.WebPushHosts[i] = h
	}
	if w := c.Delivery.Workers; w < 0 || w > 10000 {
		add("delivery.workers must be between 0 and 10000, got %d", w)
	}
	if d := c.Delivery.ProviderTimeout; d < time.Second || d > time.Minute {
		add("delivery.provider_timeout must be between 1s and 1m, got %s", d)
	}
	if d := c.Delivery.DeadLetterRetention; d < time.Minute || d > 30*24*time.Hour {
		add("delivery.dead_letter_retention must be between 1m and 720h, got %s", d)
	}
	errs = append(errs, apps.Validate(c.Apps)...)

	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return errors.New("invalid configuration:\n  " + strings.Join(msgs, "\n  "))
}

// NewLogger builds the structured logger described by c.
func NewLogger(c Log, w io.Writer) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.Level)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
