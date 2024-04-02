package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestRotatedDecryptor_Decrypt(t *testing.T) {
	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
		expectedError         error
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "circularly rotated left by 18",
			encryptedPath:         "task_8712dac8201cfe675db147d945dc9b25",
			expectedDecryptedPath: "task_675db147d945dc9b258712dac8201cfe",
			expectedError:         nil,
		},
		// Add more test cases as needed
	}

	decryptor := RotatedDecryptor{}

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
