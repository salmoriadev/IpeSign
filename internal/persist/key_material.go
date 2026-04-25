package persist

import (
	"crypto/ed25519"

	"ipesign/internal/cryptoutil"
)

func encodeEd25519PrivateKeyPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	return cryptoutil.MarshalEd25519PrivateKeyPEM(privateKey)
}

func decodeEd25519PrivateKeyPEM(privateKeyPEM []byte) (ed25519.PrivateKey, error) {
	return cryptoutil.ParseEd25519PrivateKeyPEM(privateKeyPEM)
}
