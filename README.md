# E2E Git - FIDO2 Encryption Tool

E2E Git provides FIDO2-based file encryption and decryption for Git repositories. The tool uses FIDO2 devices to derive encryption keys, ensuring only users with the physical device and PIN can access encrypted files.

## Overview

The program integrates with Git's filter system to provide transparent encryption and decryption of files. FIDO2 devices derive encryption keys through HMAC operations, eliminating the need for key storage. Pre-commit hooks ensure files are encrypted before commits.

Benefits include hardware-backed encryption, transparent Git integration, on-demand key derivation, and cross-platform compatibility.

## Prerequisites

Required dependencies:
- Go 1.21+
- libfido2 development libraries
- pkg-config
- GCC
- FIDO2 device

Install on Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libfido2-dev pinentry-gtk
```

Build the program:
```bash
chmod +x build.sh
./build.sh
```

The build script checks dependencies, downloads Go modules, builds the `e2e-git` binary, and verifies the build.

## Quick Start

Initialize a repository:
```bash
e2e-git init --pinentry=pinentry-gtk .
```

Configure encryption in `.gitattributes`:
```
secrets/** filter=crypt
*.key filter=crypt
*.pem filter=crypt
```

Add and commit files (automatic encryption):
```bash
git add secrets/api-key.txt
git commit -m "Add encrypted API key"
```

Decrypt files:
```bash
git dec secrets/api-key.txt
# or
e2e-git --mode=dec --pinentry=pinentry-gtk secrets/api-key.txt
```

## Commands

### Initialization
```bash
e2e-git init --pinentry=PROGRAM <repository-path>
```
Sets up Git repository for encryption. Installs pre-commit hook, configures Git filter, creates `git dec` alias, and installs filter wrapper script.

## Command Options

Required options:
- `--mode=MODE`: `enc` or `dec`
- PIN input method (one required):
  - `--pin-environment-variable=VAR`: Use environment variable
  - `--pinentry=PROGRAM`: Use pinentry program

Optional options:
- `--key-only`: Output only derived key
- `--log-level=LEVEL`: `info` or `debug`

Examples:
```bash
# Encrypt with pinentry
e2e-git --mode=enc --pinentry=pinentry-gtk secrets/config.env

# Decrypt with environment variable
export FIDO_PIN="123456"
e2e-git --mode=dec --pin-environment-variable=FIDO_PIN secrets/config.env

# Key-only output
e2e-git --key-only --pinentry=pinentry-gtk

# Debug logging
e2e-git --mode=enc --log-level=debug --pinentry=pinentry-gtk file.txt
```

## PIN Input Methods

Environment variable method:
```bash
export FIDO_PIN="123456"
e2e-git --mode=enc --pin-environment-variable=FIDO_PIN file.txt
```

Pinentry program method:
```bash
e2e-git --mode=enc --pinentry=pinentry-gtk file.txt
```

Use one pinentry program that you have installed. Examples: `pinentry-gtk`, `pinentry-qt`, `pinentry-curses`, `pinentry-tty`.

## Git Integration

The program uses Git's filter system with:
- Clean filter: `.git/hooks/filter-wrapper.sh clean` (files stored encrypted in repository)
- Smudge filter: `.git/hooks/filter-wrapper.sh smudge` (files decrypted in working directory)
- Filter name: `crypt`

The filter wrapper script automatically determines the operation mode and calls the e2e-git binary with the appropriate `--mode=enc` (for clean) or `--mode=dec` (for smudge) parameters. The system includes a persistent cache daemon that reduces FIDO2 device interactions by caching derived secrets via Unix domain sockets.

Configure encryption patterns in `.gitattributes`:
```
# Directory patterns
secrets/** filter=crypt
config/production/** filter=crypt

# File extensions
*.key filter=crypt
*.pem filter=crypt
*.p12 filter=crypt

# Specific files
.env.production filter=crypt
database.conf filter=crypt
```

The `git dec` alias provides convenient decryption:
```bash
git dec secrets/api-key.txt
git dec  # Decrypts all files specified in .gitattributes
```

## Advanced Features

**Key-only Output** for scripting:
```bash
KEY=$(e2e-git --key-only --pinentry=pinentry-gtk)
```

**Debug Logging**:
```bash
e2e-git --mode=enc --log-level=debug --pinentry=pinentry-gtk file.txt
```

**Non-interactive Mode**:
```bash
export FIDO_PIN="123456"
e2e-git --mode=enc --pin-environment-variable=FIDO_PIN file.txt
```

## Example Workflow

Make sure to add `e2e-git` to your PATH.

Create and initialize repository:
```bash
mkdir my-secure-project
cd my-secure-project
git init
e2e-git init --pinentry=pinentry-gtk .
```

Configure encryption:
```bash
cat > .gitattributes << EOF
config/** filter=crypt
*.key filter=crypt
*.env filter=crypt
secrets.json filter=crypt
EOF
```

Create sensitive files:
```bash
mkdir config keys
echo "API_KEY=secret-key" > config/production.env
echo "DATABASE_URL=postgresql://user:pass@localhost/db" > config/database.env
echo "-----BEGIN PRIVATE KEY-----" > keys/server.key
cat > secrets.json << EOF
{
    "secret": "pleasedonttellanyone"
}
EOF
```

Commit files (automatic encryption):
```bash
git add .gitattributes config/ keys/server.key secrets.json
git commit -m "Add encrypted configuration files"
```

Verify encryption:
```bash
# Encrypted in repository
git show HEAD:config/production.env

# Decrypted in working directory
cat config/production.env
```

Work with encrypted files:
```bash
# Edit files normally
echo "NEW_API_KEY=another-secret" >> config/production.env
git add config/production.env
git commit -m "Update API key"

# Manual decryption
git dec config/production.env secrets.json
```

Share repository:
*NOTE: Make sure .gitattributes and the credential file are in the repository!*
```bash
git remote add origin https://github.com/username/my-secure-project.git
git push -u origin main
```

Clone on another machine:
```bash
git clone https://github.com/username/my-secure-project.git
cd my-secure-project
cp /path/to/e2e-git .
e2e-git init --pinentry=pinentry-gtk .

# Decrypt all encrypted files after clone
git dec
```

## Troubleshooting

Permission denied:
```
device validation failed: permission denied
```
Solutions: Check udev rules, add user to plugdev group, log out and back in after group changes.

Build problems:

```
Go version too old
```
Solutions: Update Go to 1.23+.

PIN entry issues:
```
pinentry program not found
```
Solutions: Install pinentry (`sudo apt-get install pinentry-gtk2`), use different pinentry program, or use environment variable method.

**Git integration issues:**
```
Files not being encrypted during commit
```
Solutions: 
- Verify `.gitattributes` syntax and patterns
- Check filter wrapper script: `ls -la .git/hooks/filter-wrapper.sh`
- Re-run initialization: `e2e-git init --pinentry=pinentry-gtk .`
- Verify Git filter configuration: `git config --list | grep filter.crypt`

```
Files remain encrypted after clone
```
Solutions:
- Run `git dec` to decrypt all files specified in .gitattributes after cloning
- Ensure e2e-git is properly initialized (e2e-git init) in the new repository
- Verify FIDO2 device is connected and accessible
