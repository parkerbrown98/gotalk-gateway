package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVAPIDKey = "BExMJ__m8K0lZhFzYG_SNZhoRmRL6BbVOMd25fGlwCN2uGyylC_WegHE-InIhLxpzs3kl6KqUfAS6lMIoFdne2Y"

func environ(vars ...string) func() []string {
	return func() []string { return vars }
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestDefaults(t *testing.T) {
	cfg, err := load("", nil, environ())
	require.NoError(t, err)
	assert.Equal(t, ":8090", cfg.Server.Addr)
	assert.Equal(t, 20*time.Second, cfg.Server.ShutdownTimeout)
	assert.Equal(t, "json", cfg.Log.Format)
	assert.True(t, cfg.Database.AutoMigrate)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, "Gotalk Push Gateway", cfg.Gateway.Name)
	assert.Equal(t, 60, cfg.Gateway.SubscriptionExpiryDays)
	assert.Empty(t, cfg.Apps)
	assert.NotEmpty(t, cfg.Server.TrustedProxyPrefixes())
}

func TestLayerPrecedence(t *testing.T) {
	path := writeFile(t, `
server:
  addr: ":7000"
  public_url: https://file.example/
log:
  level: debug
  format: text
gateway:
  name: File Gateway
`)
	cfg, err := load(path, map[string]string{"log.level": "error"}, environ(
		"GOTALK_GATEWAY_SERVER_ADDR=:7001",
		"GOTALK_GATEWAY_LOG_LEVEL=warn",
		"GOTALK_GATEWAY_SERVER_TRUSTED_PROXIES=10.0.0.0/8, 192.168.1.0/24",
		"GOTALK_GATEWAY_GATEWAY_NAME=", // empty values are ignored
	))
	require.NoError(t, err)
	assert.Equal(t, ":7001", cfg.Server.Addr, "env overrides file")
	assert.Equal(t, "https://file.example", cfg.Server.PublicURL, "file overrides defaults; trailing slash trimmed")
	assert.Equal(t, "error", cfg.Log.Level, "overrides beat env")
	assert.Equal(t, "text", cfg.Log.Format)
	assert.Equal(t, "File Gateway", cfg.Gateway.Name)
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.1.0/24"}, cfg.Server.TrustedProxies)
}

func TestPlatformFallbacksAndFileSecrets(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "db-url")
	require.NoError(t, os.WriteFile(secret, []byte("postgres://from-file/db\n"), 0o600))

	cfg, err := load("", nil, environ("PORT=9999", "REDIS_URL=redis://cache:6379/1", "DATABASE_URL=postgres://platform/db"))
	require.NoError(t, err)
	assert.Equal(t, ":9999", cfg.Server.Addr)
	assert.Equal(t, "redis://cache:6379/1", cfg.Redis.URL)
	assert.Equal(t, "postgres://platform/db", cfg.Database.URL)

	cfg, err = load("", nil, environ("DATABASE_URL=postgres://platform/db", "GOTALK_GATEWAY_DATABASE_URL_FILE="+secret))
	require.NoError(t, err)
	assert.Equal(t, "postgres://from-file/db", cfg.Database.URL, "prefixed variable wins over platform fallback")

	_, err = load("", nil, environ("GOTALK_GATEWAY_DATABASE_URL_FILE=/does/not/exist"))
	require.ErrorContains(t, err, "GOTALK_GATEWAY_DATABASE_URL_FILE")

	path := writeFile(t, "database:\n  url: postgres://from-config/db\nserver:\n  addr: \":7000\"\n")
	cfg, err = load(path, nil, environ("DATABASE_URL=postgres://stray/other", "PORT=9999"))
	require.NoError(t, err)
	assert.Equal(t, "postgres://from-config/db", cfg.Database.URL, "platform fallbacks never beat the config file")
	assert.Equal(t, ":7000", cfg.Server.Addr)
}

func TestConfigFileVariableIsNotAKey(t *testing.T) {
	_, err := load("", nil, environ("GOTALK_GATEWAY_CONFIG=/etc/gotalk-gateway/config.yaml"))
	require.NoError(t, err)
}

// The example config documents the defaults, so it must load and match them.
func TestExampleConfig(t *testing.T) {
	example, err := load(filepath.Join("..", "..", "config.example.yaml"), nil, environ())
	require.NoError(t, err)
	defaults, err := load("", nil, environ())
	require.NoError(t, err)
	assert.Len(t, example.Apps, 1)
	example.Apps = nil
	assert.Equal(t, defaults, example)
}

func TestApps(t *testing.T) {
	path := writeFile(t, `
apps:
  - id: gotalk
    name: Gotalk
    ios:
      bundle_id: app.example.gotalk
    android:
      package_name: app.example.gotalk
    web:
      vapid_public_key: `+testVAPIDKey+`
  - id: white-label
    name: White Label
    android:
      package_name: com.example.chat
`)
	cfg, err := load(path, nil, environ())
	require.NoError(t, err)
	require.Len(t, cfg.Apps, 2)
	assert.Equal(t, []string{"ios", "android", "web"}, cfg.Apps[0].Platforms())
	assert.Equal(t, "app.example.gotalk", cfg.Apps[0].IOS.BundleID)
	assert.Equal(t, testVAPIDKey, cfg.Apps[0].Web.VAPIDPublicKey)
	assert.Equal(t, []string{"android"}, cfg.Apps[1].Platforms())
	assert.Nil(t, cfg.Apps[1].IOS)
}

func TestValidationReportsEveryProblem(t *testing.T) {
	path := writeFile(t, `
server:
  addr: nope
  public_url: ftp://x
  trusted_proxies: [not-a-cidr]
metrics:
  addr: ":8090"
gateway:
  name: " "
  terms_url: /relative
  subscription_expiry_days: 3
log:
  level: loud
  format: xml
redis:
  url: "http://not-redis"
apps:
  - id: Bad_ID
    name: ""
  - id: dup
    name: A
    ios:
      bundle_id: "no dots"
  - id: dup
    name: B
    web:
      vapid_public_key: "AAAA"
`)
	_, err := load(path, nil, environ())
	require.Error(t, err)
	for _, want := range []string{
		"server.addr", "server.public_url", "server.trusted_proxies", "gateway.name", "gateway.terms_url",
		"gateway.subscription_expiry_days", "log.level", "log.format", "redis.url",
		`apps[0]: id "Bad_ID"`, "apps[0]: name must not be empty", "apps[0]: configure at least one",
		"apps[1]: ios.bundle_id", `apps[2]: duplicate id "dup"`, "apps[2]: web.vapid_public_key",
	} {
		assert.Contains(t, err.Error(), want)
	}
}

func TestInstancesAndRateLimit(t *testing.T) {
	cfg, err := load("", nil, environ())
	require.NoError(t, err)
	assert.False(t, cfg.Instances.AllowHTTP)
	assert.Empty(t, cfg.Instances.AllowedPorts)
	assert.Equal(t, map[string]string{
		"registration": "5-H", "signed": "1200-M", "verification": "12-H",
		"device_registration": "60-H", "device_token": "10-H", "device_update": "60-H",
	}, cfg.RateLimit.Rules())
	assert.Contains(t, cfg.Devices.WebPushHosts, "fcm.googleapis.com")

	cfg, err = load("", map[string]string{"devices.web_push_hosts": "Push.Example., fcm.googleapis.com"}, environ())
	require.NoError(t, err)
	assert.Equal(t, []string{"push.example", "fcm.googleapis.com"}, cfg.Devices.WebPushHosts)
	_, err = load("", map[string]string{"devices.web_push_hosts": "https://push.example/x"}, environ())
	assert.ErrorContains(t, err, "devices.web_push_hosts")

	cfg, err = load("", map[string]string{"ratelimit.enabled": "false"}, environ(
		"GOTALK_GATEWAY_INSTANCES_ALLOWED_PORTS=8443, 9443",
		"GOTALK_GATEWAY_INSTANCES_ALLOW_PRIVATE_NETWORKS=true",
	))
	require.NoError(t, err)
	assert.Equal(t, []int{8443, 9443}, cfg.Instances.AllowedPorts)
	assert.True(t, cfg.Instances.AllowPrivateNetworks)
	assert.Empty(t, cfg.RateLimit.Rules(), "disabled rate limiting has no rules")

	_, err = load("", map[string]string{"ratelimit.signed": "lots", "instances.allowed_ports": "70000"}, environ())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ratelimit.signed")
	assert.Contains(t, err.Error(), "instances.allowed_ports")
}

func TestMetricsAddrMustDifferFromServer(t *testing.T) {
	_, err := load("", map[string]string{"metrics.addr": ":8090"}, environ())
	require.ErrorContains(t, err, "metrics.addr must differ")

	cfg, err := load("", map[string]string{"metrics.addr": ":9090"}, environ())
	require.NoError(t, err)
	assert.Equal(t, ":9090", cfg.Metrics.Addr)
}
