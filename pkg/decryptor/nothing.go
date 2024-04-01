package decryptor

import (
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

// NothingDecryptor does not modify the encrypted path, assuming it needs no decryption.
type NothingDecryptor struct{}

// Match checks if the encryption method indicates that no decryption is necessary.
func (d *NothingDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	// You might adjust the condition based on how a 'nothing' type is identified in your application
	return strings.Contains(challenge.EncryptionMethod, "nothing") || challenge.EncryptionMethod == ""
}

// Decrypt simply returns the encrypted path as is.
func (d *NothingDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	return challenge.EncryptedPath, nil
}
