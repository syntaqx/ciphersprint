package decryptor

import (
	"fmt"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

type RotatedDecryptor struct{}

func (d *RotatedDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "circularly rotated left by")
}

func (d *RotatedDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	var rotationAmount int
	_, err := fmt.Sscanf(challenge.EncryptionMethod, "circularly rotated left by %d", &rotationAmount)
	if err != nil {
		return "", fmt.Errorf("failed to parse rotation amount: %v", err)
	}
	trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, TaskPrefix)
	effectiveRotation := rotationAmount % len(trimmedPath)
	reverseRotation := len(trimmedPath) - effectiveRotation
	rotatedPath := trimmedPath[reverseRotation:] + trimmedPath[:reverseRotation]
	return TaskPrefix + rotatedPath, nil
}
