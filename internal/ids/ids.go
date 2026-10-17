// Package ids generates the opaque, prefixed identifiers used across the protocol
// (inst_…, key_…, sub_…, push_…, req_…).
package ids

import (
	"crypto/rand"
	"encoding/base64"
)

const (
	Instance     = "inst"
	Key          = "key"
	Subscription = "sub"
	Push         = "push"
	Request      = "req"
)

// New returns prefix + "_" + 128 random bits as unpadded base64url (22 characters).
func New(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error.
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b[:])
}
