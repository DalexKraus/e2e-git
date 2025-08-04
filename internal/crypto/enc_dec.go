package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// Encrypt reads plaintext from stdin, encrypts it using AES-GCM with the provided secret,
// and writes the resulting ciphertext (with prepended nonce) to stdout.
// The nonce is randomly generated and included in the output for use during decryption
// (the nonce is stored at the beginning of the ciphertext)
func Encrypt(secret []byte) error {
	plainText, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return fmt.Errorf("cipher err: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher GCM err: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce err: %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	_, err = os.Stdout.Write(cipherText)
	return err
}

// Decrypt reads ciphertext from stdin, extracts the nonce, and decrypts the data using AES-GCM
// with the provided secret. The resulting plaintext is written to stdout.
// It expects the nonce to be prepended to the ciphertext (as produced by Encrypt).
func Decrypt(secret []byte) error {
	cipherText, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return fmt.Errorf("cipher err: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher GCM err: %w", err)
	}

	if len(cipherText) < gcm.NonceSize() {
		return fmt.Errorf("ciphertext too short")
	}

	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]

	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return fmt.Errorf("decrypt err: %w", err)
	}

	_, err = os.Stdout.Write(plainText)
	return err
}
