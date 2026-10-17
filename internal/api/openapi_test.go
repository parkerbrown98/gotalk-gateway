package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// TestOpenAPIMatchesContract keeps the implementation from drifting away from the published
// contract in docs/openapi.yaml: every implemented operation must be in the contract with
// the same operationId and response schema, and every schema the two share must have the
// same properties and required fields.
func TestOpenAPIMatchesContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	require.NoError(t, err)
	var contract map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &contract))

	generatedJSON, err := json.Marshal(OpenAPI("test"))
	require.NoError(t, err)
	var generated map[string]any
	require.NoError(t, json.Unmarshal(generatedJSON, &generated))

	contractPaths := obj(contract["paths"])
	implemented := 0
	for path, item := range obj(generated["paths"]) {
		for method, op := range obj(item) {
			implemented++
			want := obj(obj(contractPaths[path])[method])
			if !assert.NotNil(t, want, "%s %s is implemented but not in docs/openapi.yaml", strings.ToUpper(method), path) {
				continue
			}
			assert.Equal(t, want["operationId"], obj(op)["operationId"], "%s %s operationId", method, path)
			assert.Equal(t,
				schemaRefOf(t, contract, obj(want["responses"])),
				schemaRefOf(t, generated, obj(obj(op)["responses"])),
				"%s %s success response schema", method, path)
		}
	}
	assert.Positive(t, implemented)

	contractSchemas := obj(obj(contract["components"])["schemas"])
	shared := 0
	for name, gen := range obj(obj(generated["components"])["schemas"]) {
		want := obj(contractSchemas[name])
		if want == nil {
			continue
		}
		shared++
		assert.Equal(t, keys(obj(want["properties"])), keys(obj(obj(gen)["properties"])), "schema %s properties", name)
		assert.Equal(t, strs(want["required"]), strs(obj(gen)["required"]), "schema %s required", name)
	}
	assert.GreaterOrEqual(t, shared, 4, "Gateway, App, GatewayLimits and Problem are shared")
}

// schemaRefOf returns the schema name of the first 2xx JSON response, following one level
// of components/responses indirection.
func schemaRefOf(t *testing.T, doc map[string]any, responses map[string]any) string {
	t.Helper()
	codes := keys(responses)
	for _, code := range codes {
		if !strings.HasPrefix(code, "2") {
			continue
		}
		resp := obj(responses[code])
		if ref, ok := resp["$ref"].(string); ok {
			resp = obj(obj(obj(doc["components"])["responses"])[strings.TrimPrefix(ref, "#/components/responses/")])
		}
		schema := obj(obj(obj(resp["content"])["application/json"])["schema"])
		ref, _ := schema["$ref"].(string)
		return strings.TrimPrefix(ref, "#/components/schemas/")
	}
	return ""
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.(string))
	}
	slices.Sort(out)
	return out
}
