package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const (
	sealedBlobVersion     = 1
	pbkdf2Iterations      = 600000
	pbkdf2DerivedKeyBytes = 32
	sealedBlobSaltBytes   = 16
	maxSealedBlobBytes    = 1 << 20
)

type sealedBlob struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	SaltB64    string `json:"saltB64"`
	NonceB64   string `json:"nonceB64"`
	DataB64    string `json:"dataB64"`
}

func SealWithPassphrase(plaintext []byte, passphrase string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required")
	}

	if passphrase == "" {
		return nil, fmt.Errorf("passphrase is required")
	}

	salt := make([]byte, sealedBlobSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key, err := derivePassphraseKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("derive sealing key: %w", err)
	}
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	blob := sealedBlob{
		Version:    sealedBlobVersion,
		KDF:        "pbkdf2",
		Hash:       "sha256",
		Iterations: pbkdf2Iterations,
		SaltB64:    base64.StdEncoding.EncodeToString(salt),
		NonceB64:   base64.StdEncoding.EncodeToString(nonce),
		DataB64:    base64.StdEncoding.EncodeToString(ciphertext),
	}

	encoded, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("marshal sealed blob: %w", err)
	}

	return encoded, nil
}

func OpenWithPassphrase(raw []byte, passphrase string) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("sealed blob is required")
	}
	if len(raw) > maxSealedBlobBytes {
		return nil, fmt.Errorf("sealed blob is too large")
	}

	if passphrase == "" {
		return nil, fmt.Errorf("passphrase is required")
	}

	var blob sealedBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("decode sealed blob: %w", err)
	}

	if blob.Version != sealedBlobVersion {
		return nil, fmt.Errorf("unsupported sealed blob version %d", blob.Version)
	}

	if blob.KDF != "pbkdf2" || blob.Hash != "sha256" || blob.Iterations != pbkdf2Iterations {
		return nil, fmt.Errorf("unsupported sealed blob parameters")
	}

	salt, err := base64.StdEncoding.DecodeString(blob.SaltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) != sealedBlobSaltBytes {
		return nil, fmt.Errorf("invalid sealed blob salt")
	}

	nonce, err := base64.StdEncoding.DecodeString(blob.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(blob.DataB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key, err := derivePassphraseKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("derive opening key: %w", err)
	}
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() || len(ciphertext) < gcm.Overhead() {
		return nil, fmt.Errorf("invalid sealed blob ciphertext")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt sealed blob: %w", err)
	}

	return plaintext, nil
}

func LooksLikeSealedBlob(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maxSealedBlobBytes {
		return false
	}
	var blob sealedBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return false
	}

	return blob.Version > 0 && blob.KDF != ""
}

func derivePassphraseKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iterations, pbkdf2DerivedKeyBytes)
}
