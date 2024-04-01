package decryptor

import "github.com/syntaqx/ciphersprint/pkg/challenge"

const TaskPrefix = "task_"

// Decryptor defines the interface for decryptors
type Decryptor interface {
	Match(challenge challenge.ChallengeResponse) bool
	Decrypt(challenge challenge.ChallengeResponse) (string, error)
}
