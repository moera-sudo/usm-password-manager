package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/moera-sudo/usm-password-manager/internal/crypto"
	"github.com/moera-sudo/usm-password-manager/internal/crypto/aead"
	"github.com/moera-sudo/usm-password-manager/internal/crypto/kdf"
)

// PERF Deliberately cheap, these tests derive keys many times over
var testParams = crypto.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func wrapKeyFor(t *testing.T, password, salt []byte) []byte {
	t.Helper()

	master := make([]byte, crypto.MasterKeySize)
	if err := crypto.DeriveMasterKey(master, kdf.RefArgon2id{}, password, salt, testParams); err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	defer crypto.Wipe(master)

	wrap := make([]byte, crypto.WrapKeySize)
	if err := crypto.DeriveWrapKey(wrap, master); err != nil {
		t.Fatalf("DeriveWrapKey: %v", err)
	}

	return wrap
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	a := aead.RefXChaCha20Poly1305{}

	vaultKey := make([]byte, crypto.VaultKeySize)
	if err := crypto.NewVaultKey(vaultKey); err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}

	wrap := wrapKeyFor(t, []byte("master password"), bytes.Repeat([]byte{0x11}, crypto.SaltSize))

	slot, err := crypto.WrapVaultKey(a, crypto.SlotPassword, wrap, vaultKey, nil)
	if err != nil {
		t.Fatalf("WrapVaultKey: %v", err)
	}
	if len(slot.Wrapped) != crypto.VaultKeySize+a.Overhead() {
		t.Fatalf("wrapped key is %d bytes, want %d", len(slot.Wrapped), crypto.VaultKeySize+a.Overhead())
	}

	got := make([]byte, crypto.VaultKeySize)
	if err := crypto.UnwrapVaultKey(got, a, wrap, slot); err != nil {
		t.Fatalf("UnwrapVaultKey: %v", err)
	}
	if !bytes.Equal(got, vaultKey) {
		t.Fatal("unwrapped key differs from the original")
	}
}

// TEST The M1 acceptance criterion from docs/PLAN.md section 11
func TestChangeMasterPasswordKeepsVaultKey(t *testing.T) {
	a := aead.RefXChaCha20Poly1305{}

	vaultKey := make([]byte, crypto.VaultKeySize)
	if err := crypto.NewVaultKey(vaultKey); err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}

	oldWrap := wrapKeyFor(t, []byte("old password"), bytes.Repeat([]byte{0x11}, crypto.SaltSize))
	oldSlot, err := crypto.WrapVaultKey(a, crypto.SlotPassword, oldWrap, vaultKey, nil)
	if err != nil {
		t.Fatalf("WrapVaultKey: %v", err)
	}

	// * Changing the password means a fresh salt and a fresh slot for the very same vault key
	newWrap := wrapKeyFor(t, []byte("new password"), bytes.Repeat([]byte{0x22}, crypto.SaltSize))
	newSlot, err := crypto.WrapVaultKey(a, crypto.SlotPassword, newWrap, vaultKey, nil)
	if err != nil {
		t.Fatalf("WrapVaultKey: %v", err)
	}

	if bytes.Equal(oldSlot.Wrapped, newSlot.Wrapped) {
		t.Fatal("slot ciphertext did not change after the password change")
	}

	got := make([]byte, crypto.VaultKeySize)
	if err := crypto.UnwrapVaultKey(got, a, newWrap, newSlot); err != nil {
		t.Fatalf("UnwrapVaultKey with the new password: %v", err)
	}
	// ! The whole point: records stay encrypted under an unchanged key
	if !bytes.Equal(got, vaultKey) {
		t.Fatal("vault key changed, every record would need re-encryption")
	}

	if err := crypto.UnwrapVaultKey(got, a, oldWrap, newSlot); !errors.Is(err, crypto.ErrAuthFailed) {
		t.Fatalf("the old password still opens the new slot: %v", err)
	}
}

func TestUnwrapRejectsWrongPassword(t *testing.T) {
	a := aead.RefXChaCha20Poly1305{}
	salt := bytes.Repeat([]byte{0x11}, crypto.SaltSize)

	vaultKey := make([]byte, crypto.VaultKeySize)
	if err := crypto.NewVaultKey(vaultKey); err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}

	slot, err := crypto.WrapVaultKey(a, crypto.SlotPassword, wrapKeyFor(t, []byte("right"), salt), vaultKey, nil)
	if err != nil {
		t.Fatalf("WrapVaultKey: %v", err)
	}

	got := make([]byte, crypto.VaultKeySize)
	err = crypto.UnwrapVaultKey(got, a, wrapKeyFor(t, []byte("wrong"), salt), slot)
	if !errors.Is(err, crypto.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

// SAFETY Relabelling a password slot as a keyfile slot must break the tag
func TestSlotKindIsAuthenticated(t *testing.T) {
	a := aead.RefXChaCha20Poly1305{}

	vaultKey := make([]byte, crypto.VaultKeySize)
	if err := crypto.NewVaultKey(vaultKey); err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}

	wrap := wrapKeyFor(t, []byte("master password"), bytes.Repeat([]byte{0x11}, crypto.SaltSize))
	slot, err := crypto.WrapVaultKey(a, crypto.SlotPassword, wrap, vaultKey, nil)
	if err != nil {
		t.Fatalf("WrapVaultKey: %v", err)
	}

	slot.Kind = crypto.SlotKeyfile

	got := make([]byte, crypto.VaultKeySize)
	if err := crypto.UnwrapVaultKey(got, a, wrap, slot); !errors.Is(err, crypto.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestRecordKeysAreDomainSeparated(t *testing.T) {
	vaultKey := make([]byte, crypto.VaultKeySize)
	if err := crypto.NewVaultKey(vaultKey); err != nil {
		t.Fatalf("NewVaultKey: %v", err)
	}

	first := make([]byte, crypto.RecordKeySize)
	second := make([]byte, crypto.RecordKeySize)

	if err := crypto.DeriveRecordKey(first, vaultKey, []byte("record-one")); err != nil {
		t.Fatalf("DeriveRecordKey: %v", err)
	}
	if err := crypto.DeriveRecordKey(second, vaultKey, []byte("record-two")); err != nil {
		t.Fatalf("DeriveRecordKey: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two records share one key, a repeated nonce would break both")
	}

	again := make([]byte, crypto.RecordKeySize)
	if err := crypto.DeriveRecordKey(again, vaultKey, []byte("record-one")); err != nil {
		t.Fatalf("DeriveRecordKey: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("record key derivation is not deterministic")
	}
}

func TestWipeZeroesBuffer(t *testing.T) {
	buf := bytes.Repeat([]byte{0xff}, 32)
	crypto.Wipe(buf)

	if !bytes.Equal(buf, make([]byte, 32)) {
		t.Fatal("buffer was not zeroed")
	}
}
