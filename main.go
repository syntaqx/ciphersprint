package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
	"github.com/syntaqx/ciphersprint/pkg/decryptor"
)

var decryptors = []decryptor.Decryptor{
	&decryptor.NothingDecryptor{},
	&decryptor.Base64Decryptor{},
	&decryptor.SwappedDecryptor{},
	&decryptor.RotatedDecryptor{},
	&decryptor.XorHexDecryptor{},
	&decryptor.ScrambledDecryptor{},
	&decryptor.JSONASCIIDecryptor{},
	&decryptor.ASCIIAddDecryptor{},
	// Add more decryptors as needed...
}

func main() {
	baseURL := "https://ciphersprint.pulley.com/"
	email := "syntaqx@gmail.com"

	// Start the challenge process
	err := handleChallenge(fmt.Sprintf("%s%s", baseURL, email), 0)
	if err != nil {
		fmt.Printf("Challenge process ended with error: %v\n", err)
	}
}

func handleChallenge(url string, level int) error {
	challengeResponse, err := getChallenge(url)
	if err != nil {
		return fmt.Errorf("error getting challenge for level %d: %v", level, err)
	}

	fmt.Printf("Challenge level %d: %+v\n", level, challengeResponse)
	if strings.Contains(challengeResponse.EncryptionMethod, "hashed with sha256") {
		fmt.Println("Reached the final level. This challenge is unsolvable as it's hashed with SHA256. Congratulations!")
		return nil // Exit gracefully
	}

	decryptedPath, err := decryptPath(*challengeResponse)
	if err != nil {
		return fmt.Errorf("error decrypting path at level %d: %v", level, err)
	}

	// Prepare for the next challenge
	nextChallengeURL := "https://ciphersprint.pulley.com/" + decryptedPath

	// Recursive call to handle the next challenge
	fmt.Printf("Proceeding to challenge level %d (%s)\n", challengeResponse.Level+1, nextChallengeURL)
	return handleChallenge(nextChallengeURL, challengeResponse.Level+1)
}

func getChallenge(url string) (*challenge.ChallengeResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%+v\n", string(body))

	var challenge challenge.ChallengeResponse
	err = json.Unmarshal(body, &challenge)
	if err != nil {
		return nil, err
	}

	return &challenge, nil
}

func decryptPath(challenge challenge.ChallengeResponse) (string, error) {
	for _, d := range decryptors {
		if d.Match(challenge) {
			return d.Decrypt(challenge)
		}
	}
	return "", fmt.Errorf("no decryptor found for method: %s", challenge.EncryptionMethod)
}
