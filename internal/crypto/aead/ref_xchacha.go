package aead

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/moera-sudo/usm-password-manager/internal/crypto"
)

const refXChaChaID = crypto.AEADID(0x01)

func init() {
	crypto.RegisterAEAD(RefXChaCha20Poly1305{})
}

type RefXChaCha20Poly1305 struct{}

func (RefXChaCha20Poly1305) ID() crypto.AEADID { return refXChaChaID }

func (RefXChaCha20Poly1305) Name() string { return "xchacha20poly1305" }

func (RefXChaCha20Poly1305) KeySize() int { return chacha20poly1305.KeySize }

func (RefXChaCha20Poly1305) NonceSize() int { return chacha20poly1305.NonceSizeX }

func (RefXChaCha20Poly1305) Overhead() int { return chacha20poly1305.Overhead }

// SAFETY The caller must supply a nonce that never repeats under this key
func (a RefXChaCha20Poly1305) Seal(dst, key, nonce, plaintext, aad []byte) ([]byte, error) {
	c, err := a.cipher(key, nonce)
	if err != nil {
		return nil, err
	}

	return c.Seal(dst, nonce, plaintext, aad), nil
}

func (a RefXChaCha20Poly1305) Open(dst, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	c, err := a.cipher(key, nonce)
	if err != nil {
		return nil, err
	}

	out, err := c.Open(dst, nonce, ciphertext, aad)
	if err != nil {
		// ! Collapse every failure into one error, a detailed reason is an oracle
		return nil, crypto.ErrAuthFailed
	}

	return out, nil
}

func (a RefXChaCha20Poly1305) cipher(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("%w: got %d, want %d", crypto.ErrKeySize, len(key), a.KeySize())
	}
	if len(nonce) != a.NonceSize() {
		return nil, fmt.Errorf("%w: got %d, want %d", crypto.ErrNonceSize, len(nonce), a.NonceSize())
	}

	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("init xchacha20poly1305: %w", err)
	}

	return c, nil
}
