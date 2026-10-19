package providertest

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestRFC8291Vector checks the instance-side encryption and browser-side decryption against
// RFC 8291 Appendix A.
func TestRFC8291Vector(t *testing.T) {
	plaintext := []byte("When I grow up, I want to be a watermelon")
	as, err := ecdh.P256().NewPrivateKey(b64(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	require.NoError(t, err)
	ua, err := ecdh.P256().NewPrivateKey(b64(t, "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"))
	require.NoError(t, err)
	assert.Equal(t, "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
		base64.RawURLEncoding.EncodeToString(ua.PublicKey().Bytes()))
	auth := b64(t, "BTBZMqHH6r4Tts7J_aSIgg")
	salt := b64(t, "DGv6ra1nlYgDCS1FRnbzlw")

	body, err := EncryptWith(as, salt, ua.PublicKey().Bytes(), auth, plaintext, 0)
	require.NoError(t, err)
	assert.Equal(t, "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
		base64.RawURLEncoding.EncodeToString(body))

	got, err := Decrypt(ua, auth, body)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptRoundTripWithPadding(t *testing.T) {
	ua, auth := NewBrowserKeys()
	body, err := Encrypt(ua.PublicKey().Bytes(), auth, []byte(`{"v":1}`), 249)
	require.NoError(t, err)
	assert.Len(t, body, 86+7+1+249+16)
	got, err := Decrypt(ua, auth, body)
	require.NoError(t, err)
	assert.Equal(t, `{"v":1}`, string(got))

	other, otherAuth := NewBrowserKeys()
	_, err = Decrypt(other, otherAuth, body)
	assert.Error(t, err, "another browser cannot read it")
	body[len(body)-1] ^= 1
	_, err = Decrypt(ua, auth, body)
	assert.Error(t, err, "tampering is detected")
}
