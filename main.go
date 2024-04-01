package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
)

// ChallengeResponse structure to match the JSON response from the server
type ChallengeResponse struct {
	Challenger       string `json:"challenger"`
	EncryptedPath    string `json:"encrypted_path"`
	EncryptionMethod string `json:"encryption_method"`
	ExpiresIn        string `json:"expires_in"`
	Hint             string `json:"hint"`
	Instructions     string `json:"instructions"`
	Level            int    `json:"level"`
}

// Decryptor function type, note the inclusion of the challenge to allow parsing of dynamic parameters
type Decryptor func(challenge ChallengeResponse) (string, error)

// Decryptors map with dynamic rotation handling
var decryptors = map[string]Decryptor{
	"nothing": func(challenge ChallengeResponse) (string, error) {
		return challenge.EncryptedPath, nil
	},
	"encoded as base64": func(challenge ChallengeResponse) (string, error) {
		trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")
		decoded, err := base64.StdEncoding.DecodeString(trimmedPath)
		if err != nil {
			return "", err
		}
		return "task_" + string(decoded), nil
	},
	// Decryptor for "swapped every pair of characters"
	"swapped every pair of characters": func(challenge ChallengeResponse) (string, error) {
		trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")

		// Swap every pair of characters, leaving the last character in place if the length is odd
		var swappedPath []rune
		for i := 0; i < len(trimmedPath)-1; i += 2 {
			swappedPath = append(swappedPath, rune(trimmedPath[i+1]), rune(trimmedPath[i]))
		}

		// If the string length is odd, append the last character as is
		if len(trimmedPath)%2 != 0 {
			swappedPath = append(swappedPath, rune(trimmedPath[len(trimmedPath)-1]))
		}

		return "task_" + string(swappedPath), nil
	},
	// Dynamic rotation decryptor
	"circularly rotated left by": func(challenge ChallengeResponse) (string, error) {
		// Extract the number of positions to rotate from the encryption method description
		var rotationAmount int
		_, err := fmt.Sscanf(challenge.EncryptionMethod, "circularly rotated left by %d", &rotationAmount)
		if err != nil {
			return "", fmt.Errorf("failed to parse rotation amount: %v", err)
		}

		// Remove "task_" prefix from the path before processing
		trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")

		if rotationAmount < 0 {
			return "", fmt.Errorf("rotation amount cannot be negative")
		}

		// Correcting rotation logic:
		// To reverse a left rotation, we perform a right rotation by the same amount.
		// A right rotation by 'n' is equivalent to a left rotation by 'len(s) - n'.
		// Ensure the rotation amount does not exceed the length of the string.
		effectiveRotation := rotationAmount % len(trimmedPath)
		// Calculate left rotation to reverse it
		reverseRotation := len(trimmedPath) - effectiveRotation

		rotatedPath := trimmedPath[reverseRotation:] + trimmedPath[:reverseRotation]

		// Re-append "task_" prefix after processing
		return "task_" + rotatedPath, nil
	},

	// Decryptor for "hex decoded, encrypted with XOR, hex encoded again. key: secret"
	"hex decoded, encrypted with XOR, hex encoded again. key: secret": func(challenge ChallengeResponse) (string, error) {
		// Extract the dynamic key from the encryption method description
		var key string
		pattern := `key: (.+)`
		re := regexp.MustCompile(pattern)
		match := re.FindStringSubmatch(challenge.EncryptionMethod)

		if len(match) != 2 { // match[0] is the full match, match[1] is the first captured group
			return "", fmt.Errorf("failed to extract key from encryption method: %s", challenge.EncryptionMethod)
		}
		key = match[1]

		// Proceed with decryption
		// Step 1: Hex Decode the encrypted path (excluding "task_" prefix)
		encryptedData, err := hex.DecodeString(strings.TrimPrefix(challenge.EncryptedPath, "task_"))
		if err != nil {
			return "", fmt.Errorf("hex decoding failed: %v", err)
		}

		// Step 2: XOR Decrypt using the extracted key
		decryptedBytes := make([]byte, len(encryptedData))
		for i := 0; i < len(encryptedData); i++ {
			decryptedBytes[i] = encryptedData[i] ^ key[i%len(key)]
		}

		// The decryptedBytes should now hold the original data before encryption
		// Assuming this data needs to be re-encoded or directly used as is
		decryptedPath := hex.EncodeToString(decryptedBytes) // Re-encode if necessary, or adjust based on your needs

		return "task_" + decryptedPath, nil
	},
	"scrambled! original positions as base64 encoded messagepack": func(challenge ChallengeResponse) (string, error) {
		// Extract Base64 encoded MessagePack data from the encryption method
		encodedPositions := strings.Split(challenge.EncryptionMethod, ": ")[1]

		// Decode from Base64
		messagePackData, err := base64.StdEncoding.DecodeString(encodedPositions)
		if err != nil {
			return "", fmt.Errorf("base64 decoding failed: %v", err)
		}

		// Unmarshal MessagePack data into positions slice
		var positions []int
		err = msgpack.Unmarshal(messagePackData, &positions)
		if err != nil {
			return "", fmt.Errorf("messagepack unmarshalling failed: %v", err)
		}

		// Decrypt the EncryptedPath
		encryptedPath := strings.TrimPrefix(challenge.EncryptedPath, "task_")
		decryptedPath := make([]byte, len(encryptedPath))
		for i, pos := range positions {
			decryptedPath[pos] = encryptedPath[i]
		}

		// Assuming the decrypted path does not need 'task_' re-prepended or further processing
		return "task_" + string(decryptedPath), nil
	},
}

func main() {
	baseURL := "https://ciphersprint.pulley.com/"
	email := "gfreefitz@gmail.com"

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

func getChallenge(url string) (*ChallengeResponse, error) {
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

	var challenge ChallengeResponse
	err = json.Unmarshal(body, &challenge)
	if err != nil {
		return nil, err
	}

	return &challenge, nil
}

func decryptPath(challenge ChallengeResponse) (string, error) {
	// Dynamically select the decryptor based on the encryption method
	for key, decryptor := range decryptors {
		if strings.Contains(challenge.EncryptionMethod, key) {
			return decryptor(challenge)
		}
	}
	return "", fmt.Errorf("no decryptor found for method: %s", challenge.EncryptionMethod)
}
