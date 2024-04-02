package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestBase64Decryptor_Decrypt(t *testing.T) {
	decryptor := Base64Decryptor{}

	tests := []struct {
		name                  string
		expectedDecryptedPath string
		challengeResponse     challenge.ChallengeResponse
	}{
		{
			name:                  "Test 1",
			expectedDecryptedPath: "task_6c1d15964717bb297932bd6285e8d350",
			challengeResponse: challenge.ChallengeResponse{
				EncryptionMethod: "base64",
				EncryptedPath:    "task_NmMxZDE1OTY0NzE3YmIyOTc5MzJiZDYyODVlOGQzNTA=",
			},
		},
		// Add more test cases here if needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
