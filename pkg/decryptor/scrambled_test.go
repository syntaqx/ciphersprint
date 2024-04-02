package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestScrambledDecryptor_Decrypt(t *testing.T) {
	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
		expectedError         error
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "scrambled! original positions as base64 encoded messagepack: 3AAfHRYXCRAZHA0AHgwGFBIEAgcTGxEVDhgBDwoDBQsIGg==",
			encryptedPath:         "task_887b32ee60e05742ad1786ec57d73c7",
			expectedDecryptedPath: "task_6c2d470acb73ee65377d5887e271e80",
			expectedError:         nil,
		},
		// Add more test cases as needed
	}

	decryptor := ScrambledDecryptor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challengeResponse := challenge.ChallengeResponse{
				EncryptionMethod: tt.encryptionMethod,
				EncryptedPath:    tt.encryptedPath,
			}

			decryptedPath, err := decryptor.Decrypt(challengeResponse)

			if err != tt.expectedError {
				t.Errorf("Expected error: %v, got: %v", tt.expectedError, err)
			}

			if decryptedPath != tt.expectedDecryptedPath {
				t.Errorf("Expected decrypted path: %s, got: %s", tt.expectedDecryptedPath, decryptedPath)
			}
		})
	}
}
