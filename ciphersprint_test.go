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
		challengeResponse := challenge.ChallengeResponse{
			EncryptionMethod: "hex decoded, encrypted with XOR, hex encoded again. key: secret",
			EncryptedPath:    "task_2480774e9c35486d2825654caa1a8b63",
		}
		_ = json.NewEncoder(w).Encode(challengeResponse)
	}))
	defer ts.Close()

	client := NewClient(ts.Client())

	// Set the baseURL to the client to the test server URL
	baseURL, _ := url.Parse(ts.URL)
	client.BaseURL = baseURL

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

func TestCliest_GetChallengeInvalidUrl(t *testing.T) {
	client := NewClient(nil)
	_, err := client.GetChallenge("!@#$%^&*()")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestClient_GetChallengeInvalidResponse(t *testing.T) {
	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewClient(ts.Client())

	// Set the baseURL to the client to the test server URL
	baseURL, _ := url.Parse(ts.URL)
	client.BaseURL = baseURL

	// Call the GetChallenge method
	_, err := client.GetChallenge("/challenge")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}
