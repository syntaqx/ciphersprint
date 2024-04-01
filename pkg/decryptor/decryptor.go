package decryptor

import "github.com/syntaqx/ciphersprint/pkg/challenge"

// Decryptor defines the interface for decryptors
type Decryptor interface {
	Match(challenge challenge.ChallengeResponse) bool
	Decrypt(challenge challenge.ChallengeResponse) (string, error)
}
