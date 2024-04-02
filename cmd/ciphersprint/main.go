package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/syntaqx/ciphersprint"
	"github.com/syntaqx/ciphersprint/pkg/decryptor"
)

func isValidEmail(email string) bool {
	var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(email)
}

func main() {

	client := ciphersprint.NewClient(nil)

	// challenge
	// write a program that solves the challenge returned by this API
	// the first task will be returned by a GET request to /{your_email}
	challengeUrl := "syntaqx@gmail.com"
	if len(os.Args) > 1 {
		challengeUrl = os.Args[1]
	}

	if !isValidEmail(challengeUrl) {
		fmt.Println("Invalid email address provided, unable to start challenge")
		return
	}

	fmt.Printf("Starting challenge with email address %s\n\n", challengeUrl)

	for {
		fmt.Println("Attempting to solve challenge", challengeUrl)

		challenge, err := client.GetChallenge(challengeUrl)
		if err != nil {
			fmt.Printf("Error getting first challenge: %v\n", err)
			return
		}

		fmt.Printf("Challenge: %+v\n", challenge)

		// This is the final challenge EncryptionMethod, so once we've reached
		// this we can break out of the loop
		if strings.Contains(challenge.EncryptionMethod, "hashed with sha256") {
			fmt.Println("Reached the final level, done!")
			break
		}

		// If we have a decrypter defined, use it to decrypt the challenge
		decryptedPath, err := decryptor.Decrypt(*challenge)
		if err != nil {
			fmt.Printf("Error decrypting path: %v\n", err)
			return
		}

		fmt.Printf("Decrypted path: %s\n", decryptedPath)

		// Set the challengeUrl to the decrypted path for the next iteration
		challengeUrl = decryptedPath

		fmt.Println("")
	}
}
