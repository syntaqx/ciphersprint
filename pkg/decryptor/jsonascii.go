package decryptor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

type JSONASCIIDecryptor struct{}

func (d *JSONASCIIDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "converted to a JSON array of ASCII values")
}

func (d *JSONASCIIDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, TaskPrefix)
	var asciiValues []int
	if err := json.Unmarshal([]byte(trimmedPath), &asciiValues); err != nil {
		return "", fmt.Errorf("JSON unmarshal error: %v", err)
	}

	var decryptedPathChars []byte
	for _, asciiVal := range asciiValues {
		decryptedPathChars = append(decryptedPathChars, byte(asciiVal))
	}

	decryptedPath := string(decryptedPathChars)
	return TaskPrefix + decryptedPath, nil
}
