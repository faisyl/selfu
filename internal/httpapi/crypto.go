package httpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// EncryptSecret seals plaintext with AES-256-GCM under key. The key is
// stretched with SHA-256 so any 32-byte session secret works. Output is
// nonce || ciphertext.
func EncryptSecret(key []byte, plaintext string) ([]byte, error) {
	return encryptSecret(key, plaintext)
}

// DecryptSecret opens a sealed blob produced by EncryptSecret.
func DecryptSecret(key []byte, sealed []byte) (string, error) {
	return decryptSecret(key, sealed)
}
func encryptSecret(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(secretKey(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// decryptSecret opens a sealed blob produced by encryptSecret.
func decryptSecret(key []byte, sealed []byte) (string, error) {
	block, err := aes.NewCipher(secretKey(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", errors.New("sealed secret too short")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func secretKey(key []byte) []byte {
	sum := sha256.Sum256(key)
	return sum[:]
}
