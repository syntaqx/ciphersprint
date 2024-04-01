package decryptor

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
	"github.com/vmihailenco/msgpack/v5"
)

type ScrambledDecryptor struct{}

func (d *ScrambledDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "scrambled! original positions as base64 encoded messagepack")
}

func (d *ScrambledDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	encodedPositions := strings.Split(challenge.EncryptionMethod, ": ")[1]

	messagePackData, err := base64.StdEncoding.DecodeString(encodedPositions)
	if err != nil {
		return "", fmt.Errorf("base64 decoding failed: %v", err)
	}

	var positions []int
	err = msgpack.Unmarshal(messagePackData, &positions)
	if err != nil {
		return "", fmt.Errorf("messagepack unmarshalling failed: %v", err)
	}

	encryptedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")
	decryptedPath := make([]byte, len(encryptedPath))
	for i, pos := range positions {
		decryptedPath[pos] = encryptedPath[i]
	}

	return "task_" + string(decryptedPath), nil
}
