package dkimcrypt

import (
	"errors"
)

var (

	// ErrVerifyNoKeyForSignature no key

	ErrVerifyNoKeyForSignature = errors.New("no key for verify")

	// ErrVerifyKeyUnavailable when service (dns) is anavailable

	ErrVerifyKeyUnavailable = errors.New("key unavailable")

	// ErrVerifyTagVMustBeTheFirst if present the v tag must be the firts in the record

	ErrVerifyTagVMustBeTheFirst = errors.New("pub key syntax error: v tag must be the first")

	// ErrVerifyVersionMusBeDkim1 if présent flag v (version) must be DKIM1

	ErrVerifyVersionMusBeDkim1 = errors.New("flag v must be set to DKIM1")

	// ErrVerifyBadKeyType bad type for pub key (only rsa is accepted)

	ErrVerifyBadKeyType = errors.New("bad type for key type")

	// ErrVerifyRevokedKey key(s) for this selector is revoked (p is empty)

	ErrVerifyRevokedKey = errors.New("revoked key")

	// ErrVerifyBadKey when we can't parse pubkey

	ErrVerifyBadKey = errors.New("unable to parse pub key")

	// ErrVerifyNoKey when no key is found on DNS record

	ErrVerifyNoKey = errors.New("no public key found in DNS TXT")
)
