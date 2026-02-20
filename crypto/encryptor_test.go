package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/xraph/vault/crypto"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("super-secret-password-123!")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag).
	if len(ct) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	// Ciphertext should NOT contain plaintext.
	if bytes.Contains(ct, plaintext) {
		t.Error("ciphertext contains plaintext")
	}

	// Decrypt.
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey(t))
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestDecryptWrongKey(t *testing.T) {
	enc1, _ := crypto.NewEncryptor(testKey(t))
	enc2, _ := crypto.NewEncryptor(testKey(t))

	ct, err := enc1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc2.Decrypt(ct)
	if err == nil {
		t.Error("expected decryption error with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	enc, _ := crypto.NewEncryptor(testKey(t))

	ct, _ := enc.Encrypt([]byte("secret"))

	// Flip a byte in the ciphertext (after the nonce).
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	_, err := enc.Decrypt(tampered)
	if err == nil {
		t.Error("expected decryption error with tampered ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	enc, _ := crypto.NewEncryptor(testKey(t))

	_, err := enc.Decrypt([]byte("short"))
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestNewEncryptorInvalidKeySize(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"empty", []byte{}},
		{"16 bytes", make([]byte, 16)},
		{"31 bytes", make([]byte, 31)},
		{"33 bytes", make([]byte, 33)},
		{"64 bytes", make([]byte, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.NewEncryptor(tt.key)
			if !errors.Is(err, crypto.ErrInvalidKeySize) {
				t.Errorf("got %v, want ErrInvalidKeySize", err)
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	enc, _ := crypto.NewEncryptor(testKey(t))
	plaintext := []byte("same-data")

	ct1, _ := enc.Encrypt(plaintext)
	ct2, _ := enc.Encrypt(plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("encrypting the same plaintext twice should produce different ciphertexts (random nonce)")
	}
}
