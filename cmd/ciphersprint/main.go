package main

import (
	"fmt"
	"strings"

	"github.com/syntaqx/ciphersprint"
	"github.com/syntaqx/ciphersprint/pkg/decryptor"
)

func main() {
	client := ciphersprint.NewClient(nil)

	// challenge
	// write a program that solves the challenge returned by this API
	// the first task will be returned by a GET request to /{your_email}
	challengeUrl := "syntaqx@gmail.com"

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
