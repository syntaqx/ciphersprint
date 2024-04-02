package decryptor

import (
	"fmt"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

const (
	TaskPrefix = "task_"
)

var decryptors = []Decryptor{
	&NothingDecryptor{},
	&Base64Decryptor{},
	&SwappedDecryptor{},
	&RotatedDecryptor{},
	&XorHexDecryptor{},
	&ScrambledDecryptor{},
	&JSONASCIIDecryptor{},
	&ASCIIAddDecryptor{},
	// Add more decryptors as needed...
}

// Decryptor defines the interface for decryptors
type Decryptor interface {
	Match(challenge challenge.ChallengeResponse) bool
	Decrypt(challenge challenge.ChallengeResponse) (string, error)
}

// Decrypt attempts to decrypt the encrypted path using the appropriate decryptor
func Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	for _, d := range decryptors {
		if d.Match(challenge) {
			return d.Decrypt(challenge)
		}
	}
	return "", fmt.Errorf("no decryptor found for method: %s", challenge.EncryptionMethod)
}
