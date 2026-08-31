package crypto

import (
	"errors"
	"fmt"
)

const (
	// ! Upper bound so a hostile header cannot request terabytes of memory
	MaxMemoryKiB = 4 * 1024 * 1024

	// * Lowest salt length the Argon2 spec allows
	MinSaltSize = 8
)

var ErrParams = errors.New("crypto: invalid kdf parameters")

// PERF RFC 9106 section 4, second recommended option
func DefaultParams() Params {
	return Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 4}
}

// ! x/crypto panics when time or threads drop below one, so check first
func (p Params) Validate() error {
	if p.Time < 1 {
		return fmt.Errorf("%w: time must be at least 1", ErrParams)
	}
	if p.Threads < 1 {
		return fmt.Errorf("%w: threads must be at least 1", ErrParams)
	}

	lowest := 8 * uint32(p.Threads)
	if p.MemoryKiB < lowest {
		return fmt.Errorf("%w: memory must be at least %d KiB for %d threads", ErrParams, lowest, p.Threads)
	}
	if p.MemoryKiB > MaxMemoryKiB {
		return fmt.Errorf("%w: memory %d KiB exceeds the %d KiB limit", ErrParams, p.MemoryKiB, MaxMemoryKiB)
	}

	return nil
}
