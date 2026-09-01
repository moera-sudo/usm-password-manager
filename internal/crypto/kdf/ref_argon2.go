package kdf

import (
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/moera-sudo/usm-password-manager/internal/crypto"
)

const refArgon2idID = crypto.KDFID(0x01)

func init() {
	crypto.RegisterKDF(RefArgon2id{})
}

// Reference Argon2id backed by x/crypto, id 0x01
type RefArgon2id struct{}

func (RefArgon2id) ID() crypto.KDFID { return refArgon2idID }

func (RefArgon2id) Name() string { return "argon2id" }

func (RefArgon2id) Derive(out, password, salt []byte, p crypto.Params) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(out) == 0 {
		return fmt.Errorf("%w: output buffer is empty", crypto.ErrParams)
	}
	if len(out) > crypto.MaxDerivedKeyLen {
		return fmt.Errorf("%w: output of %d bytes exceeds the %d byte limit", crypto.ErrParams, len(out), crypto.MaxDerivedKeyLen)
	}

	if len(salt) < crypto.MinSaltSize {
		return fmt.Errorf("%w: salt must be at least %d bytes", crypto.ErrParams, crypto.MinSaltSize)
	}

	// SAFETY len(out) is bounded by MaxDerivedKeyLen above, the conversion cannot overflow
	//nolint:gosec // G115: the length is checked against MaxDerivedKeyLen above
	key := argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(out)))
	copy(out, key)
	crypto.Wipe(key)

	return nil
}
