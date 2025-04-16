package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

// loadOrCreateHostKey ensures a valid ED25519 host key in OpenSSH format exists at the given path.
// If not, it creates one using ssh-keygen. It then loads and returns the ssh.Signer.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	// Check if private key exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Host key not found at %s. Generating new ED25519 key...", path)

		// Run ssh-keygen to generate ED25519 key without passphrase
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", path, "-N", "")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to generate host key using ssh-keygen: %w", err)
		}

		log.Printf("New host key generated: %s", path)
	}

	// Read private key
	privateKeyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key: %w", err)
	}

	// Parse to ssh.Signer
	signer, err := ssh.ParsePrivateKey(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %w", err)
	}

	// Save public key (optional, for reference)
	pubKey := ssh.MarshalAuthorizedKey(signer.PublicKey())
	pubPath := path + ".pub"
	if err := os.WriteFile(pubPath, pubKey, 0644); err != nil {
		log.Printf("Warning: could not write public key to %s: %v", pubPath, err)
	}

	log.Printf("Using host key: %s", path)
	log.Printf("Fingerprint : %s", ssh.FingerprintSHA256(signer.PublicKey()))

	return signer, nil
}

