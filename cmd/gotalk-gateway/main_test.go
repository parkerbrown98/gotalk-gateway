package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/parkerbrown98/gotalk-gateway/internal/testdb"
)

func TestVersionAndHelp(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"version"}, &out))
	assert.Equal(t, "dev\n", out.String())

	out.Reset()
	require.NoError(t, run(context.Background(), []string{"help"}, &out))
	assert.Contains(t, out.String(), "gotalk-gateway [command]")
}

func TestOpenAPICommand(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"openapi", "--format", "json"}, &out))
	var spec map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &spec))
	assert.Contains(t, spec["paths"], "/v1/gateway")

	out.Reset()
	require.NoError(t, run(context.Background(), []string{"openapi"}, &out))
	require.NoError(t, yaml.Unmarshal(out.Bytes(), &spec))
	assert.Equal(t, "3.1.0", spec["openapi"])

	assert.Error(t, run(context.Background(), []string{"openapi", "--format", "xml"}, &out))
}

func TestArgumentErrors(t *testing.T) {
	var out bytes.Buffer
	assert.ErrorContains(t, run(context.Background(), []string{"bogus"}, &out), `unknown command "bogus"`)
	assert.ErrorContains(t, run(context.Background(), []string{"serve", "extra"}, &out), "unexpected argument")
	assert.ErrorContains(t, run(context.Background(), []string{"--set", "novalue"}, &out), "KEY=VALUE")
	assert.ErrorContains(t, run(context.Background(), []string{"healthcheck", "--set", "log.format=xml"}, &out), "log.format")
}

func TestSetFlags(t *testing.T) {
	s := setFlag{}
	require.NoError(t, s.Set("server.addr=:1234"))
	require.NoError(t, shorthandFlag{"log.level", s}.Set("debug"))
	assert.Equal(t, setFlag{"server.addr": ":1234", "log.level": "debug"}, s)
}

func TestMain(m *testing.M) {
	code := m.Run()
	testdb.Terminate()
	os.Exit(code)
}

func TestAdminCommands(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	dbURL := pool.Config().ConnString()
	cli := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := run(ctx, append(args, "--set", "database.url="+dbURL, "--log-level", "error"), &out)
		return out.String(), err
	}

	_, err := pool.Exec(ctx, `INSERT INTO instances (id, origin, status, contact_email, verified_at, next_verification_at)
		VALUES ('inst_active00', 'https://forum.example', 'active', 'ops@forum.example', now(), now() + interval '1 day')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO instance_keys (id, instance_id, public_key, status) VALUES ('key_active00', 'inst_active00', $1, 'active')`, make([]byte, 32))
	require.NoError(t, err)

	out, err := cli("instances", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "inst_active00")
	assert.Contains(t, out, "https://forum.example")

	out, err = cli("instances", "show", "HTTPS://Forum.Example/")
	require.NoError(t, err)
	assert.Contains(t, out, "key_active00")
	assert.Contains(t, out, "0 accepted, 0 failed, 0 active subscriptions")

	_, err = cli("instances", "block", "inst_active00")
	assert.ErrorContains(t, err, "reason is required")
	out, err = cli("instances", "block", "https://forum.example", "--reason", "Spam reported by users.")
	require.NoError(t, err)
	assert.Contains(t, out, "blocked inst_active00")
	out, err = cli("instances", "list", "--status", "blocked")
	require.NoError(t, err)
	assert.Contains(t, out, "inst_active00")
	out, err = cli("instances", "show", "inst_active00")
	require.NoError(t, err)
	assert.Contains(t, out, "Spam reported by users.")
	_, err = cli("instances", "unblock", "inst_active00")
	require.NoError(t, err)

	_, err = cli("instances", "delete", "inst_active00")
	assert.ErrorContains(t, err, "--yes")
	_, err = cli("instances", "delete", "inst_active00", "--yes")
	require.NoError(t, err)
	_, err = cli("instances", "show", "inst_active00")
	assert.ErrorContains(t, err, "no such instance")

	_, err = cli("blocklist", "add", "domain", "Spam.Example")
	assert.ErrorContains(t, err, "--reason")
	out, err = cli("blocklist", "add", "domain", "Spam.Example", "--reason", "Spam.", "--expires", "72h")
	require.NoError(t, err)
	assert.Contains(t, out, "blocked domain spam.example")
	_, err = cli("blocklist", "add", "cidr", "203.0.113.9", "--reason", "Bot.")
	require.NoError(t, err)
	_, err = cli("blocklist", "add", "origin", "https://Bad.Example/", "--reason", "No.")
	require.NoError(t, err)
	out, err = cli("blocklist", "list")
	require.NoError(t, err)
	for _, want := range []string{"spam.example", "203.0.113.9/32", "https://bad.example", "Spam."} {
		assert.Contains(t, out, want)
	}
	_, err = cli("blocklist", "remove", "cidr", "203.0.113.9")
	require.NoError(t, err)
	_, err = cli("blocklist", "remove", "cidr", "203.0.113.9")
	assert.ErrorContains(t, err, "no blocklist entry")
	_, err = cli("blocklist", "add", "ip", "1.2.3.4", "--reason", "x")
	assert.ErrorContains(t, err, "kind must be")

	_, err = cli("instances")
	assert.ErrorContains(t, err, "needs a subcommand")
}
