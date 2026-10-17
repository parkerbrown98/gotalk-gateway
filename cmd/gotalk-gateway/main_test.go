package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
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
