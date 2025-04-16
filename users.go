package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
	"github.com/amoghe/go-crypt"
)

type User struct {
	Username  string   `json:"username"`
	Hash      string   `json:"hash"`
	Admin     bool     `json:"admin"`
	Restrict  string   `json:"restrict"`
	Allowed   []string `json:"allowed"`
	PubKeys   []string `json:"pubkeys,omitempty"`

	Prompt    string   `json:"prompt,omitempty"`
	Banner    string   `json:"banner,omitempty"`
	// Prelogin removed
}

var users map[string]User

func LoadUsers(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	var userList []User
	if err := json.Unmarshal(data, &userList); err != nil {
		return errors.New("failed to decode user JSON: " + err.Error())
	}

	tempUsers := make(map[string]User)
	for _, u := range userList {
		tempUsers[u.Username] = u
	}
	users = tempUsers
	log.Printf("Loaded %d user(s) from %s", len(users), path)
	return nil
}

func AuthenticateUser(username, password string) (User, bool) {
	u, ok := users[username]
	if !ok {
		return User{}, false
	}
	generated, err := crypt.Crypt(password, u.Hash)
	if err != nil || generated != u.Hash {
		return User{}, false
	}
	return u, true
}

func PublicKeyAuth(username string, key ssh.PublicKey) (User, bool) {
	u, ok := users[username]
	if !ok || len(u.PubKeys) == 0 {
		return User{}, false
	}
	given := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	for _, k := range u.PubKeys {
		if strings.TrimSpace(k) == given {
			return u, true
		}
	}
	return User{}, false
}

