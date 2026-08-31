package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
)

const ( // WARNING Best effort only. Go gives no guaranteed memory scrub until
	// WARNING memguard arrives in M5
	VaultKeySize  = 32
	MasterKeySize = 32
	WrapKeySize   = 32
	AuthKeySize   = 32
	RecordKeySize = 32
	SaltSize      = 16
)

// IMPORTANT Info strings keep derived keys in separate domains, so a wrap
// IMPORTANT key and a record key can never collide
const (
	infoWrap   = "usm/v1/wrap"
	infoRecord = "usm/v1/record/"
)

type SlotKind uint8

const (
	SlotPassword SlotKind = 0x01
	SlotKeyfile  SlotKind = 0x02
	SlotFIDO2    SlotKind = 0x03
	SlotRecovery SlotKind = 0x04
)

var ErrSlot = errors.New("crypto: malformed key slot")

// * One way of unlocking the vault key
type Slot struct {
	Kind    SlotKind
	Nonce   []byte
	Wrapped []byte
	Aux     []byte
}

func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func RandomBytes(out []byte) error {
	if _, err := rand.Read(out); err != nil {
		return fmt.Errorf("read random bytes: %w", err)
	}

	return nil
}

// * Generates the key that actually protects the records
func NewVaultKey(out []byte) error {
	if len(out) != VaultKeySize {
		return fmt.Errorf("%w: vault key must be %d bytes", ErrKeySize, VaultKeySize)
	}

	return RandomBytes(out)
}

func DeriveMasterKey(out []byte, k KDF, password, saltVault []byte, p Params) error {
	if len(out) != MasterKeySize {
		return fmt.Errorf("%w: master key must be %d bytes", ErrKeySize, MasterKeySize)
	}

	return k.Derive(out, password, saltVault, p)
}

// IMPORTANT A separate Argon2 run with its own salt, never an HKDF branch of
// IMPORTANT the master key, so the server knowing auth_key learns nothing
// IMPORTANT about the wrap key
func DeriveAuthKey(out []byte, k KDF, password, saltAuth []byte, p Params) error {
	if len(out) != AuthKeySize {
		return fmt.Errorf("%w: auth key must be %d bytes", ErrKeySize, AuthKeySize)
	}

	return k.Derive(out, password, saltAuth, p)
}

func DeriveWrapKey(out, masterKey []byte) error {
	if len(out) != WrapKeySize {
		return fmt.Errorf("%w: wrap key must be %d bytes", ErrKeySize, WrapKeySize)
	}
	if len(masterKey) != MasterKeySize {
		return fmt.Errorf("%w: master key must be %d bytes", ErrKeySize, MasterKeySize)
	}

	return expand(out, masterKey, infoWrap)
}

// SAFETY A per record key means a repeated nonce can only ever affect one
// SAFETY record instead of the whole vault
func DeriveRecordKey(out, vaultKey, recordID []byte) error {
	if len(out) != RecordKeySize {
		return fmt.Errorf("%w: record key must be %d bytes", ErrKeySize, RecordKeySize)
	}
	if len(vaultKey) != VaultKeySize {
		return fmt.Errorf("%w: vault key must be %d bytes", ErrKeySize, VaultKeySize)
	}
	if len(recordID) == 0 {
		return fmt.Errorf("%w: record id is empty", ErrSlot)
	}

	return expand(out, vaultKey, infoRecord+string(recordID))
}

// WARNING hkdf.Key allocates its own buffer, so the derived key briefly
// WARNING exists twice. Copy it out and wipe the original
func expand(out, secret []byte, info string) error {
	key, err := hkdf.Key(sha256.New, secret, nil, info, len(out))
	if err != nil {
		return fmt.Errorf("hkdf expand: %w", err)
	}
	copy(out, key)
	Wipe(key)

	return nil
}

// SAFETY Kind and aux go into the tag, so a password slot cannot be
// SAFETY relabelled as a keyfile slot without breaking authentication
func slotAAD(kind SlotKind, aux []byte) []byte {
	aad := make([]byte, 0, 1+len(aux))
	aad = append(aad, byte(kind))

	return append(aad, aux...)
}

func WrapVaultKey(a AEAD, kind SlotKind, wrapKey, vaultKey, aux []byte) (Slot, error) {
	if len(vaultKey) != VaultKeySize {
		return Slot{}, fmt.Errorf("%w: vault key must be %d bytes", ErrKeySize, VaultKeySize)
	}

	nonce := make([]byte, a.NonceSize())
	if err := RandomBytes(nonce); err != nil {
		return Slot{}, err
	}

	wrapped, err := a.Seal(nil, wrapKey, nonce, vaultKey, slotAAD(kind, aux))
	if err != nil {
		return Slot{}, fmt.Errorf("wrap vault key: %w", err)
	}

	slog.Debug("vault key wrapped into slot", slog.Int("kind", int(kind)))

	return Slot{Kind: kind, Nonce: nonce, Wrapped: wrapped, Aux: aux}, nil
}

func UnwrapVaultKey(out []byte, a AEAD, wrapKey []byte, s Slot) error {
	if len(out) != VaultKeySize {
		return fmt.Errorf("%w: vault key must be %d bytes", ErrKeySize, VaultKeySize)
	}
	if len(s.Nonce) != a.NonceSize() {
		return fmt.Errorf("%w: nonce is %d bytes", ErrSlot, len(s.Nonce))
	}
	if len(s.Wrapped) != VaultKeySize+a.Overhead() {
		return fmt.Errorf("%w: wrapped key is %d bytes", ErrSlot, len(s.Wrapped))
	}

	plain, err := a.Open(nil, wrapKey, s.Nonce, s.Wrapped, slotAAD(s.Kind, s.Aux))
	if err != nil {
		return err
	}
	defer Wipe(plain)

	if len(plain) != VaultKeySize {
		return fmt.Errorf("%w: unwrapped key is %d bytes", ErrSlot, len(plain))
	}
	copy(out, plain)

	slog.Debug("vault key unwrapped from slot", slog.Int("kind", int(s.Kind)))

	return nil
}
