package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestJSONASCIIDecryptorMatchAndDecrypt(t *testing.T) {
	tests := []struct {
		name                  string
		expectedDecryptedPath string
		challengeResponse     challenge.ChallengeResponse
	}{
		{
			name:                  "Test 1",
			expectedDecryptedPath: "task_3fe1861ff9b38cbc50ece9407ecd6454",
			challengeResponse: challenge.ChallengeResponse{
				EncryptionMethod: "converted to a JSON array of ASCII values",
				EncryptedPath:    "task_[51,102,101,49,56,54,49,102,102,57,98,51,56,99,98,99,53,48,101,99,101,57,52,48,55,101,99,100,54,52,53,52]",
			},
		},
	}

	decryptor := JSONASCIIDecryptor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !decryptor.Match(tt.challengeResponse) {
				t.Errorf("Expected match to return true")
			}

			decryptedPath, err := decryptor.Decrypt(tt.challengeResponse)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if decryptedPath != tt.expectedDecryptedPath {
				t.Errorf("Expected decrypted path: %s, got: %s", tt.expectedDecryptedPath, decryptedPath)
			}
		})
	}
}
