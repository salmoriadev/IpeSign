package cryptoutil

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

func SHA256Tagged(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SHA256Digest(raw []byte) [32]byte {
	return sha256.Sum256(raw)
}

func HashPublicKey(publicKey any) (string, error) {
	raw, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	return SHA256Tagged(raw), nil
}

func ZeroBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

func MarshalEd25519PrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: raw,
	}), nil
}

func ParseEd25519PrivateKeyPEM(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM private key")
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	key, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ed25519")
	}

	return append(ed25519.PrivateKey(nil), key...), nil
}
