package decryptor

import (
	"encoding/base64"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

type Base64Decryptor struct{}

func (d *Base64Decryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "encoded as base64")
}

func (d *Base64Decryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, TaskPrefix)
	decoded, err := base64.StdEncoding.DecodeString(trimmedPath)
	if err != nil {
		return "", err
	}
	return TaskPrefix + string(decoded), nil
}
