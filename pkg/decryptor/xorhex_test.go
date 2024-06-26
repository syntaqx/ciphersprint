package decryptor

import (
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestXorHexDecryptor_Decrypt(t *testing.T) {
	tests := []struct {
		name                  string
		encryptionMethod      string
		encryptedPath         string
		expectedDecryptedPath string
		expectedError         error
	}{
		{
			name:                  "Test 1",
			encryptionMethod:      "hex decoded, encrypted with XOR, hex encoded again. key: secret",
			encryptedPath:         "task_2480774e9c35486d2825654caa1a8b63",
			expectedDecryptedPath: "task_57e5143cf9413b084b570038d97fe811",
			expectedError:         nil,
		},
		{
			name:                  "Test 2",
			encryptionMethod:      "hex decoded, encrypted with XOR, hex encoded again. key: secret",
			encryptedPath:         "task_27800310543fd34c1aec4285d27c8d6e",
			expectedDecryptedPath: "task_54e56062314ba029799e27f1a119ee1c",
			expectedError:         nil,
		},
		// Add more test cases as needed
	}

	decryptor := XorHexDecryptor{}

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
