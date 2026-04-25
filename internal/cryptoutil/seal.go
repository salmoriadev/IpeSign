package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := pbkdf2SHA256([]byte(passphrase), salt, pbkdf2Iterations, pbkdf2DerivedKeyBytes)
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

	if blob.KDF != "pbkdf2" || blob.Hash != "sha256" {
		return nil, fmt.Errorf("unsupported sealed blob parameters")
	}

	salt, err := base64.StdEncoding.DecodeString(blob.SaltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(blob.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(blob.DataB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := pbkdf2SHA256([]byte(passphrase), salt, blob.Iterations, pbkdf2DerivedKeyBytes)
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt sealed blob: %w", err)
	}

	return plaintext, nil
}

func LooksLikeSealedBlob(raw []byte) bool {
	var blob sealedBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return false
	}

	return blob.Version > 0 && blob.KDF != ""
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	if iterations <= 0 {
		iterations = 1
	}

	hLen := 32
	numBlocks := (keyLen + hLen - 1) / hLen
	derived := make([]byte, 0, numBlocks*hLen)

	for blockIndex := 1; blockIndex <= numBlocks; blockIndex++ {
		u := pbkdf2Block(password, salt, blockIndex)
		t := append([]byte(nil), u...)

		for i := 1; i < iterations; i++ {
			u = hmacSHA256(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}

		derived = append(derived, t...)
		ZeroBytes(u)
		ZeroBytes(t)
	}

	return derived[:keyLen]
}

func pbkdf2Block(password, salt []byte, blockIndex int) []byte {
	input := make([]byte, 0, len(salt)+4)
	input = append(input, salt...)
	input = append(input,
		byte(blockIndex>>24),
		byte(blockIndex>>16),
		byte(blockIndex>>8),
		byte(blockIndex),
	)

	return hmacSHA256(password, input)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
