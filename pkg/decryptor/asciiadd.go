package decryptor

import (
	"fmt"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

type ASCIIAddDecryptor struct{}

func (d *ASCIIAddDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "ASCII value of each character")
}

func (d *ASCIIAddDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	var adjustment int
	_, err := fmt.Sscanf(challenge.EncryptionMethod, "added %d to ASCII value of each character", &adjustment)
	if err != nil {
		return "", fmt.Errorf("failed to extract adjustment value: %v", err)
	}

	encryptedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")
	var decryptedChars []rune
	for _, ch := range encryptedPath {
		decryptedChar := rune(ch) - rune(adjustment)
		decryptedChars = append(decryptedChars, decryptedChar)
	}

	decryptedPath := string(decryptedChars)
	return "task_" + decryptedPath, nil
}
