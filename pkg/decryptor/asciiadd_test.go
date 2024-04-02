package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestASCIIAddDecryptor_Decrypt(t *testing.T) {
	decryptor := ASCIIAddDecryptor{}

	tests := []struct {
		name                  string
		expectedDecryptedPath string
		challengeResponse     challenge.ChallengeResponse
	}{
		{
			name:                  "Test 1",
			expectedDecryptedPath: "task_d57760ba85450e120ef1a0d9c7976",
			challengeResponse: challenge.ChallengeResponse{
				EncryptionMethod: "added -4 to ASCII value of each character",
				EncryptedPath:    "task_`1332,^]4101,a-.,ab-],`5_3532",
			},
		},
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
