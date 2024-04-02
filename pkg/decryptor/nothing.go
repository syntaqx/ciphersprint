package decryptor

import (
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

// NothingDecryptor does not modify the encrypted path, assuming it needs no decryption.
type NothingDecryptor struct{}

func (d *NothingDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "nothing") || challenge.EncryptionMethod == ""
}

func (d *NothingDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	return challenge.EncryptedPath, nil
}
