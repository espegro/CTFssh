package main

import (
	"flag"
	"fmt"
	"log"

	gliderssh "github.com/gliderlabs/ssh"
	sshcrypto "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func startShell(s gliderssh.Session) {
	ctxUser := s.Context().Value("user")
	user, ok := ctxUser.(User)
	if !ok {
		log.Printf("Failed to extract user from session context")
		s.Write([]byte("Internal error\n"))
		return
	}

	if user.Banner != "" {
		s.Write([]byte(user.Banner + "\n"))
	} else {
		s.Write([]byte(fmt.Sprintf("Welcome %s!\n", user.Username)))
	}
	s.Write([]byte("Type 'help' to see available commands.\n\n"))

	prompt := "> "
	if user.Prompt != "" {
		prompt = user.Prompt
	}
	term := terminal.NewTerminal(s, prompt)

	for {
		line, err := term.ReadLine()
		if err != nil {
			break
		}
		DispatchCommand(line, s, user)
	}
}

func main() {
	port := flag.String("port", "2222", "Port to listen on")
	hostKeyPath := flag.String("hostkey", "host_key", "Path to SSH host private key")
	usersFile := flag.String("users", "users.json", "Path to JSON user database")
	banner := flag.String("banner", "SSH-2.0-CTF-server", "SSH server banner/version string")
	flag.Parse()

	if err := LoadUsers(*usersFile); err != nil {
		log.Fatalf("Failed to load users: %v", err)
	}

	signer, err := loadOrCreateHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("Failed to load or create host key: %v", err)
	}
	log.Printf("Using host key: %s", *hostKeyPath)
	log.Printf("Fingerprint : %s", sshcrypto.FingerprintSHA256(signer.PublicKey()))

	server := &gliderssh.Server{
		Addr:    ":" + *port,
		Version: *banner,
		Handler: startShell,

		PasswordHandler: func(ctx gliderssh.Context, password string) bool {
			ip := ctx.RemoteAddr().String()
			username := ctx.User()

			user, ok := AuthenticateUser(username, password)
			if !ok {
				log.Printf("Password auth failed for user: %s from %s", username, ip)
				return false
			}

			log.Printf("Password auth success for user: %s from %s", user.Username, ip)
			ctx.SetValue("user", user)
			return true
		},

		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			ip := ctx.RemoteAddr().String()
			username := ctx.User()
			fingerprint := sshcrypto.FingerprintSHA256(key)

			user, ok := PublicKeyAuth(username, key)
			if !ok {
				log.Printf("Public key auth failed for user: %s from %s (fingerprint: %s)", username, ip, fingerprint)
				return false
			}

			log.Printf("Public key auth success for user: %s from %s (fingerprint: %s)", user.Username, ip, fingerprint)
			ctx.SetValue("user", user)
			return true
		},
	}

	server.AddHostKey(signer)

	log.Printf("Starting SSH server on port %s with banner %q...\n", *port, *banner)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("SSH server failed: %v", err)
	}
}

