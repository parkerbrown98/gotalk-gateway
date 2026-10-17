// Command gotalk-gateway runs the Gotalk push notification gateway.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.yaml.in/yaml/v3"

	"github.com/parkerbrown98/gotalk-gateway/internal/api"
	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/config"
	"github.com/parkerbrown98/gotalk-gateway/internal/database"
	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/nonce"
	"github.com/parkerbrown98/gotalk-gateway/internal/ratelimit"
	"github.com/parkerbrown98/gotalk-gateway/internal/wellknown"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Gotalk push gateway

Usage:
  gotalk-gateway [command] [flags]

Commands:
  serve           Run the gateway (default)
  migrate         Apply database migrations
  migrate status  Show the schema version
  healthcheck     Exit 0 if the local gateway is healthy (for container HEALTHCHECK)
  openapi         Print the OpenAPI spec of the implemented endpoints
                    --format yaml|json (default yaml)
  version         Print the version

Operator commands (take effect on running gateways within 30 seconds):
  instances list [--status S] [--limit N]   List instances
  instances show ID|ORIGIN                  Show an instance, its keys and usage
  instances block ID|ORIGIN --reason TEXT   Block a verified instance; the reason is shown to its operator
  instances unblock ID|ORIGIN               Unblock and re-verify an instance
  instances delete ID|ORIGIN --yes          Deregister an instance and delete its subscriptions
  blocklist list                            List blocklist entries
  blocklist add KIND VALUE --reason TEXT [--expires DURATION]
                                            Block an origin, a domain (and its subdomains) or
                                            a cidr (client addresses); e.g. --expires 72h
  blocklist remove KIND VALUE               Remove an entry

Flags (all commands):
  --config FILE       YAML config file (default: $GOTALK_GATEWAY_CONFIG)
  --set KEY=VALUE     Override a config key, e.g. --set server.addr=:9000 (repeatable)
  --addr ADDR         Shorthand for --set server.addr=ADDR
  --log-level LEVEL   Shorthand for --set log.level=LEVEL
  --log-format FMT    Shorthand for --set log.format=FMT

Configuration is layered: built-in defaults, then the config file, then GOTALK_GATEWAY_*
environment variables, then flags. See docs/configuration.md for every option.
`

type setFlag map[string]string

func (s setFlag) String() string { return "" }

func (s setFlag) Set(v string) error {
	key, value, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(key) == "" {
		return fmt.Errorf("expected KEY=VALUE, got %q", v)
	}
	s[strings.TrimSpace(key)] = value
	return nil
}

// shorthandFlag sets one config key.
type shorthandFlag struct {
	key       string
	overrides setFlag
}

func (f shorthandFlag) String() string     { return "" }
func (f shorthandFlag) Set(v string) error { f.overrides[f.key] = v; return nil }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type adminFlags struct {
	reason, status string
	expires        time.Duration
	limit          int
	yes            bool
}

// arity is the number of positional arguments each command accepts: [min, max].
var arity = map[string][2]int{
	"serve": {0, 0}, "version": {0, 0}, "help": {0, 0}, "openapi": {0, 0}, "healthcheck": {0, 0},
	"migrate": {0, 1}, "instances": {1, 2}, "blocklist": {1, 3},
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configFile := fs.String("config", os.Getenv(config.EnvConfigFile), "")
	overrides := setFlag{}
	fs.Var(overrides, "set", "")
	fs.Var(shorthandFlag{"server.addr", overrides}, "addr", "")
	fs.Var(shorthandFlag{"log.level", overrides}, "log-level", "")
	fs.Var(shorthandFlag{"log.format", overrides}, "log-format", "")
	format := fs.String("format", "yaml", "")
	var af adminFlags
	fs.StringVar(&af.reason, "reason", "", "")
	fs.StringVar(&af.status, "status", "", "")
	fs.DurationVar(&af.expires, "expires", 0, "")
	fs.IntVar(&af.limit, "limit", 100, "")
	fs.BoolVar(&af.yes, "yes", false, "")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if n, ok := arity[cmd]; ok && (len(positional) < n[0] || len(positional) > n[1]) {
		if len(positional) < n[0] {
			return fmt.Errorf("%s needs a subcommand; see gotalk-gateway help", cmd)
		}
		return fmt.Errorf("unexpected argument %q for %s", strings.Join(positional[n[1]:], " "), cmd)
	}

	switch cmd {
	case "version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	case "openapi":
		return printOpenAPI(stdout, *format)
	}
	if _, ok := arity[cmd]; !ok {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}

	cfg, err := config.Load(*configFile, overrides)
	if err != nil {
		return err
	}
	// Commands other than serve write their own output to stdout, so logs go to stderr.
	log := config.NewLogger(cfg.Log, os.Stderr)

	switch cmd {
	case "serve":
		return serve(ctx, cfg, log)
	case "migrate":
		sub := ""
		if len(positional) > 0 {
			sub = positional[0]
		}
		return migrate(ctx, cfg, log, sub, stdout)
	case "instances":
		return instancesCmd(ctx, cfg, log, positional, af, stdout)
	case "blocklist":
		return blocklistCmd(ctx, cfg, log, positional, af, stdout)
	default: // healthcheck
		return healthcheck(cfg)
	}
}

// parseInterleaved parses flags that may appear before, between or after positional
// arguments, and returns the positional arguments in order.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional, args = append(positional, args[0]), args[1:]
	}
}

func printOpenAPI(w io.Writer, format string) error {
	spec := api.OpenAPI(version)
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(spec)
	case "yaml":
		// Round-trip through JSON so the YAML uses the spec's JSON field names.
		raw, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			return err
		}
		return enc.Close()
	default:
		return fmt.Errorf("--format must be yaml or json, got %q", format)
	}
}

func connectDatabase(ctx context.Context, cfg *config.Config, log *slog.Logger) (*pgxpool.Pool, error) {
	return database.Connect(ctx, cfg.Database.URL, cfg.Database.MaxConns, cfg.Database.ConnectTimeout, log)
}

func connectRedis(ctx context.Context, cfg *config.Config, log *slog.Logger) (*redis.Client, error) {
	if cfg.Redis.URL == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	deadline := time.Now().Add(cfg.Database.ConnectTimeout)
	for {
		err := rdb.Ping(ctx).Err()
		if err == nil {
			return rdb, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			_ = rdb.Close()
			return nil, fmt.Errorf("could not connect to Redis at %s: %w (unset GOTALK_GATEWAY_REDIS_URL for single-node mode)", opts.Addr, err)
		}
		log.Warn("waiting for Redis", "addr", opts.Addr, "error", err.Error())
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	}
}

func serve(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	log.Info("starting gotalk-gateway", "version", version, "addr", cfg.Server.Addr)
	if cfg.Server.PublicURL == "" {
		log.Warn("server.public_url is not set; discovery derives api_base_url from each request. Set it in production.")
	}

	pool, err := connectDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	if cfg.Database.AutoMigrate {
		if err := database.Migrate(ctx, pool, log); err != nil {
			return err
		}
	}

	rdb, err := connectRedis(ctx, cfg, log)
	if err != nil {
		return err
	}
	checks := []api.Check{{Name: "database", Ping: pool.Ping}, {Name: "redis"}}
	if rdb != nil {
		defer func() { _ = rdb.Close() }()
		checks[1].Ping = func(ctx context.Context) error { return rdb.Ping(ctx).Err() }
	} else {
		log.Info("running in single-node mode without Redis; set GOTALK_GATEWAY_REDIS_URL when running more than one replica")
	}

	registry := apps.NewRegistry(pool)
	disabled, err := registry.Sync(ctx, cfg.Apps)
	if err != nil {
		return err
	}
	log.Info("app registry synced", "apps", len(cfg.Apps), "disabled", disabled)
	if len(cfg.Apps) == 0 {
		log.Warn("no apps are configured; devices cannot register until apps are added to the config file")
	}

	bl := blocklist.NewCache(pool, log)
	if err := bl.Refresh(ctx); err != nil {
		return err
	}
	if cfg.Instances.AllowHTTP || cfg.Instances.AllowPrivateNetworks {
		log.Warn("development settings are enabled; never use them in production",
			"instances.allow_http", cfg.Instances.AllowHTTP, "instances.allow_private_networks", cfg.Instances.AllowPrivateNetworks)
	}
	fetcher := wellknown.New(wellknown.Options{
		AllowPrivateNetworks: cfg.Instances.AllowPrivateNetworks,
		AllowedPorts:         cfg.Instances.AllowedPorts,
		UserAgent:            "gotalk-gateway/" + version,
	})
	svc := instances.New(pool, fetcher, bl, instances.Options{AllowHTTP: cfg.Instances.AllowHTTP, Logger: log})
	limiter, err := ratelimit.New(rdb, cfg.RateLimit.Rules())
	if err != nil {
		return err
	}

	bgCtx, stopBackground := context.WithCancel(context.Background())
	var background sync.WaitGroup
	background.Go(func() { bl.Run(bgCtx) })
	background.Go(func() { svc.RunMaintenance(bgCtx) })
	defer func() {
		stopBackground()
		background.Wait()
	}()

	metrics := api.NewMetrics(version)
	handler := api.New(api.Deps{
		Config: cfg, Logger: log, Version: version, Apps: registry, Checks: checks, Metrics: metrics,
		Instances: svc, Nonces: nonce.New(rdb), Limiter: limiter, Blocklist: bl,
	})
	servers := []*http.Server{newHTTPServer(cfg.Server.Addr, handler, log)}
	if cfg.Metrics.Enabled && cfg.Metrics.Addr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler())
		servers = append(servers, newHTTPServer(cfg.Metrics.Addr, mux, log))
	}

	errc := make(chan error, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", srv.Addr, err)
		}
		log.Info("listening", "addr", ln.Addr().String())
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Restore default handling so a second SIGINT/SIGTERM exits immediately instead of
	// waiting out the drain and shutdown timeouts.
	signal.Reset(os.Interrupt, syscall.SIGTERM)

	handler.SetDraining()
	if d := cfg.Server.DrainDelay; d > 0 {
		log.Info("draining before shutdown", "delay", d.String())
		time.Sleep(d)
	}
	log.Info("shutting down", "timeout", cfg.Server.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	var shutdownErr error
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("graceful shutdown of %s: %w", srv.Addr, err))
		}
	}
	if shutdownErr != nil {
		return shutdownErr
	}
	log.Info("shutdown complete")
	return nil
}

func newHTTPServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

func migrate(ctx context.Context, cfg *config.Config, log *slog.Logger, sub string, stdout io.Writer) error {
	pool, err := connectDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	switch sub {
	case "status":
		st, err := database.Status(ctx, pool)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "current version: %d\nlatest version:  %d\n", st.Current, st.Latest); err != nil {
			return err
		}
		if st.Current < st.Latest {
			_, err = fmt.Fprintln(stdout, "pending migrations: run `gotalk-gateway migrate`")
		}
		return err
	case "":
		if err := database.Migrate(ctx, pool, log); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "database is up to date")
		return err
	default:
		return fmt.Errorf("unknown migrate subcommand %q", sub)
	}
}

func healthcheck(cfg *config.Config) error {
	_, port, err := net.SplitHostPort(cfg.Server.Addr)
	if err != nil {
		return fmt.Errorf("parsing server.addr: %w", err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz") //nolint:gosec // fixed loopback probe of our own port
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}
