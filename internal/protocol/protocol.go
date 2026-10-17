// Package protocol holds the fixed values of the gateway protocol (docs/protocol.md and
// docs/payload.md) that callers and the gateway must agree on.
package protocol

// Software is the value of "software" in the discovery document.
const Software = "gotalk-gateway"

// APIVersions lists the major API versions this build serves, oldest first.
var APIVersions = []string{"v1"}

// CurrentAPIVersion is the newest entry of APIVersions.
const CurrentAPIVersion = "v1"

// Platforms the protocol defines, in discovery order.
var Platforms = []string{"ios", "android", "web"}

// Payload and request limits. MaxEncryptedBodyBytes leaves headroom under the 4 KB APNs and
// Web Push limits once provider framing and base64 are added.
const (
	MaxPlaintextBytes     = 2048
	MaxEncryptedBodyBytes = 2200
	MaxBatchSize          = 100
	MaxTTLSeconds         = 28 * 24 * 60 * 60
)

// DiscoveryCacheControl is sent with the discovery document.
const DiscoveryCacheControl = "public, max-age=300"
