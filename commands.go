package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
    "fmt"
    "time"
	"path/filepath"
	"strings"

	gliderssh "github.com/gliderlabs/ssh"
)

var textDir string = "./text"
var commandDir string = "./command"
var helpDir string = "./help"

// CommandFunc defines the function signature for shell commands
type CommandFunc func(s gliderssh.Session, user User, args []string)

// RegisteredCommands holds built-in commands
var RegisteredCommands = map[string]CommandFunc{
	"help": cmdHelp,
	"info": cmdInfo,
	"exit": cmdExit,
	"blocked": cmdBlocked,
}

// DispatchCommand determines how to handle a given user command
func DispatchCommand(line string, s gliderssh.Session, user User) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	fields := strings.Fields(line)
	cmd := filepath.Base(fields[0]) // normalize to filename
	args := fields[1:]
	remote := s.RemoteAddr().String()
	log.Printf("Full line: '%q' from '%q'", line,remote)

	// Block attempts to use paths or escape characters
	if strings.Contains(cmd, "/") || strings.Contains(cmd, "\\") || strings.ContainsAny(cmd, "&|;$`") {
		log.Printf("Rejected unsafe command: raw=%q from user '%s' @ %s", cmd, user.Username, remote)
		s.Write([]byte("Invalid or unsafe command\n"))
		return
	}

	// Limit command name length
	if len(cmd) > 64 {
		log.Printf("Rejected overly long command: %q from user '%s' @ %s", cmd, user.Username, remote)
		s.Write([]byte("Command name too long\n"))
		return
	}

	// Built-in command
	if handler, ok := RegisteredCommands[cmd]; ok {
		if !isAllowed(cmd, user) {
			log.Printf("Access denied for user '%s' @ %s: tried built-in command %q", user.Username, remote, cmd)
			s.Write([]byte("Access denied to built-in command: " + cmd + "\n"))
			return
		}
		log.Printf("Executing built-in command for user '%s' @ %s: %q", user.Username, remote, cmd)
		handler(s, user, args)
		return
	}

	// Text-based command
	textPath := filepath.Join(textDir, cmd)
	if fileExists(textPath) && isPathWithin(textDir, textPath) {
		if !isAllowed(cmd, user) {
			log.Printf("Access denied to text command '%s' for user '%s' @ %s", cmd, user.Username, remote)
			s.Write([]byte("Access denied to text command: " + cmd + "\n"))
			return
		}
		log.Printf("Serving text command '%s' to user '%s' @ %s", cmd, user.Username, remote)
		data, err := ioutil.ReadFile(textPath)
		if err != nil {
			s.Write([]byte("Error reading text command\n"))
			return
		}
		s.Write(data)
		return
	}

	// External executable command
	commandPath := filepath.Join(commandDir, cmd)
	if isExecutable(commandPath) && isPathWithin(commandDir, commandPath) {
		if !isAllowed(cmd, user) {
			log.Printf("Access denied to executable command '%s' for user '%s' @ %s", cmd, user.Username, remote)
			s.Write([]byte("Access denied to command: " + cmd + "\n"))
			return
		}
		log.Printf("Executing external command '%s' for user '%s' @ %s", cmd, user.Username, remote)
		runExternalCommand(s, commandPath, args)
		return
	}

	log.Printf("Unknown command from user '%s' @ %s: %q", user.Username, remote, cmd)
	s.Write([]byte("Unknown command: " + cmd + "\n"))
}

// === Command implementations ===

func cmdHelp(s gliderssh.Session, user User, args []string) {
	if len(args) == 1 {
		topic := filepath.Base(args[0])
		helpPath := filepath.Join(helpDir, topic)

		if fileExists(helpPath) && isPathWithin(helpDir, helpPath) {
			data, err := ioutil.ReadFile(helpPath)
			if err != nil {
				s.Write([]byte("Error reading help topic\n"))
			} else {
				s.Write(data)
			}
			return
		}
		s.Write([]byte("No specific help for command: " + topic + "\n\n"))
	}

	s.Write([]byte("Available commands:\n"))
	for _, cmd := range user.Allowed {
		s.Write([]byte("  - " + cmd + "\n"))
	}
}

func cmdInfo(s gliderssh.Session, user User, args []string) {
	s.Write([]byte("You are logged in as: " + user.Username + "\n"))
	if user.Admin {
		s.Write([]byte("You are an admin user.\n"))
	}
	if user.Restrict != "" {
		s.Write([]byte("Restricted to: " + user.Restrict + "\n"))
	}
}

func cmdExit(s gliderssh.Session, user User, args []string) {
	s.Write([]byte("Goodbye!\n"))
	s.Exit(0)
}

// === Utility functions ===

func isAllowed(cmd string, user User) bool {
	for _, allowed := range user.Allowed {
		if allowed == cmd {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	mode := info.Mode()
	return !mode.IsDir() && mode&0111 != 0
}

func isPathWithin(baseDir, target string) bool {
	absBase, err1 := filepath.Abs(baseDir)
	absTarget, err2 := filepath.Abs(target)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.HasPrefix(absTarget, absBase)
}

func runExternalCommand(s gliderssh.Session, prog string, args []string) {
	cmd := exec.Command(prog, args...)
	cmd.Stderr = cmd.Stdout
	cmd.Env = []string{"USER=" + s.User()}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.Write([]byte("Failed to start command\n"))
		return
	}
	err = cmd.Start()
	if err != nil {
		s.Write([]byte("Execution error: " + err.Error() + "\n"))
		return
	}
	ioBytes, _ := ioutil.ReadAll(stdout)
	s.Write(ioBytes)
	cmd.Wait()
}

func cmdBlocked(s gliderssh.Session, user User, args []string) {
	if !user.Admin {
		s.Write([]byte("Access denied: admin only command.\n"))
		return
	}

	now := time.Now()
	found := false

	rateLock.Lock()
	defer rateLock.Unlock()

	s.Write([]byte("Currently blocked IPs:\n"))
	for ip, entry := range ipFailures {
		if entry.Blocked && now.Sub(entry.LastFail) < blockDuration {
			s.Write([]byte(fmt.Sprintf("  IP: %-15s  Failures: %d  Blocked until: %s\n",
				ip, entry.Count, entry.LastFail.Add(blockDuration).Format(time.RFC3339))))
			found = true
		}
	}

	s.Write([]byte("\nBlocked usernames:\n"))
	for name, entry := range userFailures {
		if entry.Blocked && now.Sub(entry.LastFail) < blockDuration {
			s.Write([]byte(fmt.Sprintf("  User: %-10s  Failures: %d  Blocked until: %s\n",
				name, entry.Count, entry.LastFail.Add(blockDuration).Format(time.RFC3339))))
			found = true
		}
	}

	if !found {
		s.Write([]byte("No blocked entries.\n"))
	}
}

