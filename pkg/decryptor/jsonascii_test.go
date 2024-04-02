package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestJSONASCIIDecryptorMatchAndDecrypt(t *testing.T) {
	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "converted to a JSON array of ASCII values",
			encryptedPath:         "task_[51,102,101,49,56,54,49,102,102,57,98,51,56,99,98,99,53,48,101,99,101,57,52,48,55,101,99,100,54,52,53,52]",
			expectedDecryptedPath: "task_3fe1861ff9b38cbc50ece9407ecd6454",
		},
	}

	decryptor := JSONASCIIDecryptor{}

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
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if decryptedPath != tt.expectedDecryptedPath {
				t.Errorf("Expected decrypted path: %s, got: %s", tt.expectedDecryptedPath, decryptedPath)
			}
		})
	}
}
