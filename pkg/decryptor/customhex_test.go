package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestCustomHexDecryptor_Decrypt(t *testing.T) {
	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
		expectedError         error
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "encoded it with custom hex character set 157a9f204d3b86ec",
			encryptedPath:         "task_7bbf368d45a6b1315474ce200008018e",
			expectedDecryptedPath: "task_2bb5adc9813db0a01828fe67777c70ce",
			expectedError:         nil,
		},
		// Add more test cases as needed
	}

	decryptor := CustomHexDecryptor{}

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
