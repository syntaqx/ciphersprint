package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestNonHexFilterDecryptor_Decrypt(t *testing.T) {
	decryptor := NonHexFilterDecryptor{}

	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
		expectedError         error
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "inserted some non-hex characters",
			encryptedPath:         "task_i7aaa3d2397le03446481773d24e7abgkh06je",
			expectedDecryptedPath: "task_7aaa3d2397e03446481773d24e7ab06e",
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
