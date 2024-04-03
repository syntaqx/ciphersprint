package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestSwappedDecryptor_Decrypt(t *testing.T) {
	decryptor := SwappedDecryptor{}

	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
		expectedError         error
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "swapped every pair of characters",
			encryptedPath:         "task_a5925c03ee1357ca4446a40ed4c3e2e9",
			expectedDecryptedPath: "task_5a29c530ee3175ac44644ae04d3c2e9e",
			expectedError:         nil,
		},
		// Add more test cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challengeResponse := challenge.ChallengeResponse{
				EncryptionMethod: tt.encryptionMethod,
				EncryptedPath:    tt.encryptedPath,
			}

			if !decryptor.Match(challengeResponse) {
				t.Errorf("Expected match to return true")
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
