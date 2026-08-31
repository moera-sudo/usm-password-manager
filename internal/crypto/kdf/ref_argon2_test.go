package kdf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/moera-sudo/usm-password-manager/internal/crypto"
)

const vectorPath = "../../../testdata/vectors/argon2id.json"

type argon2VectorFile struct {
	Password string `json:"password"`
	Salt     string `json:"salt"`
	KeyLen   int    `json:"key_len"`
	Cases    []struct {
		Name      string `json:"name"`
		Time      uint32 `json:"time"`
		MemoryKiB uint32 `json:"memory_kib"`
		Threads   uint8  `json:"threads"`
		Key       string `json:"key"`
	} `json:"cases"`
}

func TestVectorsArgon2id(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vf argon2VectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vf.Cases) == 0 {
		t.Fatal("vector file contains no cases")
	}

	var k RefArgon2id
	for _, c := range vf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want, err := hex.DecodeString(c.Key)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}

			got := make([]byte, vf.KeyLen)
			p := crypto.Params{MemoryKiB: c.MemoryKiB, Time: c.Time, Threads: c.Threads}

			if err := k.Derive(got, []byte(vf.Password), []byte(vf.Salt), p); err != nil {
				t.Fatalf("Derive: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("key mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// ! These inputs would panic inside x/crypto if they reached it
func TestDeriveRejectsBadParams(t *testing.T) {
	var k RefArgon2id

	out := make([]byte, 32)
	salt := bytes.Repeat([]byte{0x01}, crypto.SaltSize)
	good := crypto.Params{MemoryKiB: 64, Time: 1, Threads: 1}

	tests := map[string]struct {
		out  []byte
		salt []byte
		p    crypto.Params
	}{
		"zero time":       {out, salt, crypto.Params{MemoryKiB: 64, Time: 0, Threads: 1}},
		"zero threads":    {out, salt, crypto.Params{MemoryKiB: 64, Time: 1, Threads: 0}},
		"memory too low":  {out, salt, crypto.Params{MemoryKiB: 4, Time: 1, Threads: 4}},
		"memory too high": {out, salt, crypto.Params{MemoryKiB: crypto.MaxMemoryKiB + 1, Time: 1, Threads: 1}},
		"short salt":      {out, salt[:crypto.MinSaltSize-1], good},
		"empty output":    {nil, salt, good},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := k.Derive(tc.out, []byte("password"), tc.salt, tc.p); !errors.Is(err, crypto.ErrParams) {
				t.Fatalf("expected ErrParams, got %v", err)
			}
		})
	}
}

func TestDifferentSaltGivesDifferentKey(t *testing.T) {
	var k RefArgon2id
	p := crypto.Params{MemoryKiB: 64, Time: 1, Threads: 1}

	first := make([]byte, 32)
	second := make([]byte, 32)

	if err := k.Derive(first, []byte("password"), bytes.Repeat([]byte{0x01}, crypto.SaltSize), p); err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if err := k.Derive(second, []byte("password"), bytes.Repeat([]byte{0x02}, crypto.SaltSize), p); err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("same key for different salts, precomputation attacks would work")
	}
}

func TestRegisteredInRegistry(t *testing.T) {
	impl, err := crypto.LookupKDF(refArgon2idID)
	if err != nil {
		t.Fatalf("LookupKDF: %v", err)
	}
	if impl.Name() != "argon2id" {
		t.Fatalf("unexpected name: %s", impl.Name())
	}
}
