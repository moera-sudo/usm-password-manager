package aead

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/moera-sudo/usm-password-manager/internal/crypto"
)

const vectorPath = "../../../testdata/vectors/xchacha20poly1305.json"

type vectorCase struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	AAD        string `json:"aad"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type vectorFile struct {
	Algorithm string       `json:"algorithm"`
	Source    string       `json:"source"`
	Cases     []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vf.Cases) == 0 {
		t.Fatal("vector file contains no cases")
	}

	return vf
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}

	return b
}

// TEST Byte exact comparison against draft-irtf-cfrg-xchacha-03 A.3.1
func TestVectorsXChaCha20Poly1305(t *testing.T) {
	var a RefXChaCha20Poly1305
	vf := loadVectors(t)

	for _, c := range vf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			key := mustHex(t, c.Key)
			nonce := mustHex(t, c.Nonce)
			aad := mustHex(t, c.AAD)
			plaintext := mustHex(t, c.Plaintext)
			want := mustHex(t, c.Ciphertext)

			got, err := a.Seal(nil, key, nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("ciphertext mismatch\n got: %x\nwant: %x", got, want)
			}

			back, err := a.Open(nil, key, nonce, want, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(back, plaintext) {
				t.Fatalf("plaintext mismatch\n got: %x\nwant: %x", back, plaintext)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	var a RefXChaCha20Poly1305

	key := bytes.Repeat([]byte{0x2a}, a.KeySize())
	nonce := bytes.Repeat([]byte{0x7f}, a.NonceSize())
	plaintext := []byte("correct horse battery staple")
	aad := []byte("record-id-and-version")

	sealed, err := a.Seal(nil, key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != len(plaintext)+a.Overhead() {
		t.Fatalf("unexpected length: got %d, want %d", len(sealed), len(plaintext)+a.Overhead())
	}

	back, err := a.Open(nil, key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", back, plaintext)
	}
}

// TEST The whole point of an AEAD: any single flipped bit must be rejected
func TestOpenRejectsTampering(t *testing.T) {
	var a RefXChaCha20Poly1305

	key := bytes.Repeat([]byte{0x2a}, a.KeySize())
	nonce := bytes.Repeat([]byte{0x7f}, a.NonceSize())
	plaintext := []byte("bank password")
	aad := []byte("record-id-and-version")

	sealed, err := a.Seal(nil, key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tests := map[string]func() ([]byte, []byte, []byte){
		"first ciphertext byte": func() ([]byte, []byte, []byte) {
			bad := slices.Clone(sealed)
			bad[0] ^= 0x01
			return bad, aad, nonce
		},
		"last tag byte": func() ([]byte, []byte, []byte) {
			bad := slices.Clone(sealed)
			bad[len(bad)-1] ^= 0x01
			return bad, aad, nonce
		},
		"associated data": func() ([]byte, []byte, []byte) {
			bad := slices.Clone(aad)
			bad[0] ^= 0x01
			return sealed, bad, nonce
		},
		"nonce": func() ([]byte, []byte, []byte) {
			bad := slices.Clone(nonce)
			bad[0] ^= 0x01
			return sealed, aad, bad
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ct, ad, nc := mutate()

			out, err := a.Open(nil, key, nc, ct, ad)
			if !errors.Is(err, crypto.ErrAuthFailed) {
				t.Fatalf("expected ErrAuthFailed, got %v", err)
			}
			// ! A failed Open must hand back nothing at all
			if out != nil {
				t.Fatalf("expected nil plaintext, got %x", out)
			}
		})
	}
}

func TestRejectsWrongSizes(t *testing.T) {
	var a RefXChaCha20Poly1305

	key := bytes.Repeat([]byte{0x2a}, a.KeySize())
	nonce := bytes.Repeat([]byte{0x7f}, a.NonceSize())

	if _, err := a.Seal(nil, key[:a.KeySize()-1], nonce, nil, nil); !errors.Is(err, crypto.ErrKeySize) {
		t.Fatalf("expected ErrKeySize, got %v", err)
	}
	if _, err := a.Seal(nil, key, nonce[:a.NonceSize()-1], nil, nil); !errors.Is(err, crypto.ErrNonceSize) {
		t.Fatalf("expected ErrNonceSize, got %v", err)
	}
}

func TestRegisteredInRegistry(t *testing.T) {
	impl, err := crypto.LookupAEAD(refXChaChaID)
	if err != nil {
		t.Fatalf("LookupAEAD: %v", err)
	}
	if impl.Name() != "xchacha20poly1305" {
		t.Fatalf("unexpected name: %s", impl.Name())
	}
	if impl.NonceSize() != 24 {
		t.Fatalf("xchacha must use a 24 byte nonce, got %d", impl.NonceSize())
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("plaintext"), []byte("aad"))
	f.Add([]byte(""), []byte(""))

	var a RefXChaCha20Poly1305
	key := bytes.Repeat([]byte{0x2a}, a.KeySize())
	nonce := bytes.Repeat([]byte{0x7f}, a.NonceSize())

	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		sealed, err := a.Seal(nil, key, nonce, plaintext, aad)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}

		back, err := a.Open(nil, key, nonce, sealed, aad)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("round trip mismatch")
		}
	})
}
