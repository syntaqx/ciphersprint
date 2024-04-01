package decryptor

import (
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

type SwappedDecryptor struct{}

func (d *SwappedDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "swapped every pair of characters")
}

func (d *SwappedDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")
	var swappedPath []rune
	for i := 0; i < len(trimmedPath)-1; i += 2 {
		swappedPath = append(swappedPath, rune(trimmedPath[i+1]), rune(trimmedPath[i]))
	}
	if len(trimmedPath)%2 != 0 {
		swappedPath = append(swappedPath, rune(trimmedPath[len(trimmedPath)-1]))
	}
	return "task_" + string(swappedPath), nil
}
