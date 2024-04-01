package decryptor

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

type XorHexDecryptor struct{}

func (d *XorHexDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "hex decoded, encrypted with XOR, hex encoded again")
}

func (d *XorHexDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	var key string
	pattern := `key: (.+)`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(challenge.EncryptionMethod)

	if len(match) != 2 {
		return "", fmt.Errorf("failed to extract key from encryption method: %s", challenge.EncryptionMethod)
	}
	key = match[1]

	encryptedData, err := hex.DecodeString(strings.TrimPrefix(challenge.EncryptedPath, TaskPrefix))
	if err != nil {
		return "", fmt.Errorf("hex decoding failed: %v", err)
	}

	decryptedBytes := make([]byte, len(encryptedData))
	for i := 0; i < len(encryptedData); i++ {
		decryptedBytes[i] = encryptedData[i] ^ key[i%len(key)]
	}

	decryptedPath := hex.EncodeToString(decryptedBytes)
	return TaskPrefix + decryptedPath, nil
}
