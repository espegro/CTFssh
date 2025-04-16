# Makefile for cust SSH server project

BINARY := cust
SRC := main.go users.go hostkey.go commands.go ratelimit.go
HOSTKEY := host_key
USERS := users.json

.PHONY: all clean run hostkey users

# Default target: build
all: $(BINARY)

# Build the binary
$(BINARY): $(SRC)
	go build -o $(BINARY) $(SRC)

# Run the SSH server
run: $(BINARY)
	./$(BINARY)

# Clean build artifacts
clean:
	rm -f $(BINARY) $(HOSTKEY)

# Generate new host key (ED25519)
hostkey:
	ssh-keygen -t ed25519 -f $(HOSTKEY) -N ''

# Print parsed users (optional helper)
users:
	@echo "Loaded users:"
	@jq -r '.[] | "\(.username)\tadmin=\(.admin)\trestrict=\(.restrict)"' $(USERS)

textfiles:
	mkdir -p text
	echo "README.md\ncust\nusers.json\nhost_key\ntext/" > text/ls
	echo "/home/user" > text/pwd
	echo "user" > text/whoami
	echo "Linux custhost 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux" > text/uname
	echo " 10:42:21 up 12 days,  4:33,  2 users,  load average: 0.00, 0.01, 0.05" > text/uptime
	echo "custhost" > text/hostname
	echo "uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)" > text/id
	echo "Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/sda1       20480000 10480000   9000000  54% /" > text/df
	echo "PID TTY          TIME CMD\n1012 pts/0    00:00:00 bash\n1020 pts/0    00:00:00 top" > text/ps

