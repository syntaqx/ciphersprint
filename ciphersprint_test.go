package ciphersprint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

func TestClient_GetChallenge(t *testing.T) {
	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the response body
		challengeResponse := challenge.ChallengeResponse{
			EncryptionMethod: "hex decoded, encrypted with XOR, hex encoded again. key: secret",
			EncryptedPath:    "task_2480774e9c35486d2825654caa1a8b63",
		}
		json.NewEncoder(w).Encode(challengeResponse)
	}))
	defer ts.Close()

	// Create a client with the test server URL
	baseURL, _ := url.Parse(ts.URL)

	client := &Client{
		BaseURL:    baseURL,
		httpClient: ts.Client(),
	}

	// Call the GetChallenge method
	challengeResponse, err := client.GetChallenge("/challenge")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Verify the challenge response
	expectedChallengeResponse := &challenge.ChallengeResponse{
		EncryptionMethod: "hex decoded, encrypted with XOR, hex encoded again. key: secret",
		EncryptedPath:    "task_2480774e9c35486d2825654caa1a8b63",
	}
	if challengeResponse.EncryptionMethod != expectedChallengeResponse.EncryptionMethod {
		t.Errorf("Expected encryption method: %s, got: %s", expectedChallengeResponse.EncryptionMethod, challengeResponse.EncryptionMethod)
	}
	if challengeResponse.EncryptedPath != expectedChallengeResponse.EncryptedPath {
		t.Errorf("Expected encrypted path: %s, got: %s", expectedChallengeResponse.EncryptedPath, challengeResponse.EncryptedPath)
	}
}
