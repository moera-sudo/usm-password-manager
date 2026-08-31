package crypto

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
)

// Identifier of an AEAD algorithm as written into the vault header
type AEADID uint8

// Identifier of a KDF algorithm as written into the vault header
type KDFID uint8

const (
	// * Reference implementations backed by x/crypto occupy 0x01..0x7f
	refIDMax = 0x7f
	// * Own implementations written in M10 occupy 0x81..0xff
	ownIDMin = 0x81
)

func (id AEADID) IsOwn() bool { return id >= ownIDMin }

func (id KDFID) IsOwn() bool { return id >= ownIDMin }

var (
	// * The header names an algorithm this build does not know
	ErrUnknownAEAD = errors.New("crypto: unknown aead id")
	ErrUnknownKDF  = errors.New("crypto: unknown kdf id")

	// * Key or nonce length does not match what the algorithm requires
	ErrKeySize   = errors.New("crypto: invalid key size")
	ErrNonceSize = errors.New("crypto: invalid nonce size")

	// ! One single error for every authentication failure. Telling apart
	// ! a wrong key from a corrupted tag would hand out an oracle
	ErrAuthFailed = errors.New("crypto: message authentication failed")
)

// * Authenticated encryption with associated data
// SAFETY The key is passed per call and is never retained by the implementation, so the caller stays in control of wiping it
type AEAD interface {
	// * Algorithm id as written into the vault header
	ID() AEADID
	// * Human readable name for logs and error messages
	Name() string
	// * Required key length in bytes
	KeySize() int
	// * Required nonce length in bytes
	NonceSize() int
	// * Number of bytes Seal appends on top of the plaintext
	Overhead() int
	// * Encrypts plaintext and appends the authentication tag
	// SAFETY The nonce must never repeat under the same key
	Seal(dst, key, nonce, plaintext, aad []byte) ([]byte, error)
	// * Verifies the tag, then decrypts
	// ! On authentication failure return an error and no plaintext at all,
	// ! never a partially decrypted buffer
	Open(dst, key, nonce, ciphertext, aad []byte) ([]byte, error)
}

// * Argon2id cost parameters as stored in the vault header
type Params struct {
	// Memory cost in KiB, the dominant factor in brute-force cost
	MemoryKiB uint32
	// Number of passes over the memory block
	Time uint32
	// Degree of parallelism
	Threads uint8
}

// * Password based key derivation function
type KDF interface {
	// * Algorithm id as written into the vault header
	ID() KDFID
	// * Human readable name for logs and error messages
	Name() string

	Derive(out, password, salt []byte, p Params) error
}

var (
	aeads = make(map[AEADID]AEAD)
	kdfs  = make(map[KDFID]KDF)
)

// * Registers an AEAD implementation
// ! Call from init() only. Registering later races with concurrent lookups
func RegisterAEAD(impl AEAD) {
	if impl == nil {
		panic("crypto: RegisterAEAD called with a nil implementation")
	}

	// ! Two algorithms claiming one header byte make vaults ambiguous.
	// ! Refusing to start beats writing files nobody can read back
	if _, exists := aeads[impl.ID()]; exists {
		panic(fmt.Sprintf("crypto: duplicate aead id %#x", impl.ID()))
	}

	aeads[impl.ID()] = impl
}

// * Registers a KDF implementation
// ! Call from init() only. Registering later races with concurrent lookups
func RegisterKDF(impl KDF) {
	if impl == nil {
		panic("crypto: RegisterKDF called with a nil implementation")
	}

	if _, exists := kdfs[impl.ID()]; exists {
		panic(fmt.Sprintf("crypto: duplicate kdf id %#x", impl.ID()))
	}

	kdfs[impl.ID()] = impl
}

// * Looks up an AEAD by the id read from a vault header
// ! An unknown id is a hard error. Falling back to a default would let
// ! an attacker pick the algorithm by editing one byte of the header
func LookupAEAD(id AEADID) (AEAD, error) {
	impl, ok := aeads[id]
	if !ok {
		slog.Error("unknown aead id in vault header", slog.String("id", fmt.Sprintf("%#x", id)))
		return nil, fmt.Errorf("%w: %#x", ErrUnknownAEAD, id)
	}

	slog.Debug("aead resolved", slog.String("name", impl.Name()), slog.Bool("own", id.IsOwn()))

	return impl, nil
}

// * Looks up a KDF by the id read from a vault header
// ! An unknown id is a hard error, see LookupAEAD
func LookupKDF(id KDFID) (KDF, error) {
	impl, ok := kdfs[id]
	if !ok {
		slog.Error("unknown kdf id in vault header", slog.String("id", fmt.Sprintf("%#x", id)))
		return nil, fmt.Errorf("%w: %#x", ErrUnknownKDF, id)
	}

	slog.Debug("kdf resolved", slog.String("name", impl.Name()), slog.Bool("own", id.IsOwn()))

	return impl, nil
}

// * Sorted ids of every registered AEAD, for diagnostics and tests
func RegisteredAEADs() []AEADID {
	ids := make([]AEADID, 0, len(aeads))
	for id := range aeads {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	return ids
}

// * Sorted ids of every registered KDF, for diagnostics and tests
func RegisteredKDFs() []KDFID {
	ids := make([]KDFID, 0, len(kdfs))
	for id := range kdfs {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	return ids
}
