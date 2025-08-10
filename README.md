# E2E: M4 & M5 & M6

This repository implements **end-to-end file encryption in Git** using a FIDO2 security key for encryption key derivation.  
The goal is to store and transfer only **encrypted files**, while allowing you to decrypt them locally when you need to work on them.

---

## Quick Start

First, configure the repository with the required Git filters, hooks, and alias by running:

```bash
./e2e-init
```
## How It Works

### 1. Pre-Commit Hook - Encryption
Before each commit, the **pre-commit hook**:
- Detects staged files with the `filter=crypt` attribute (from `.gitattributes`)
- Encrypts their contents using `fido2-derive` and your FIDO2 device
- **Replaces the file in both the index and the working directory** with the encrypted version

This ensures that **no plaintext is left on disk** after committing.

### 2. Smudge Filter - Automatic Decryption
Whenever you:
- Switch branches
- Pull changes
- Check out a file from the repository  

The **smudge filter** automatically decrypts the file into the working directory.

### 3. Manual Decryption - `git dec`
Because files are encrypted in the working directory right after committing,  
a custom Git alias `git dec <file>` is provided to:
- Decrypt a specific file on demand
- Allow editing without switching branches

---

## Workflow

1. **Create or edit a file** in plaintext.
2. **Stage & commit** - the pre-commit hook encrypts it (both index & working dir).
3. **Decrypt the commited file again in the working directory to continue your work/editing**:
   ```bash
   git dec src/a.txt

