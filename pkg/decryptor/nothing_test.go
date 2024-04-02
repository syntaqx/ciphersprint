package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestNothingMatchAndDecrypt(t *testing.T) {
	tests := []struct {
		name                  string
		expectedDecryptedPath string
		challengeResponse     challenge.ChallengeResponse
	}{
		{
			name:                  "Test 1",
			expectedDecryptedPath: "task_12345",
			challengeResponse: challenge.ChallengeResponse{
				EncryptionMethod: "nothing",
				EncryptedPath:    "task_12345",
			},
		},
	}

	decryptor := NothingDecryptor{}

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
