# FIDO2 HMAC Deriver

A command-line application that demonstrates how to use FIDO2 devices to derive HMAC secrets using the HMAC secret extension. 

## Requirements
### System Dependencies

- **Linux** (Ubuntu/Debian recommended)
- **Go 1.21+** - [Download from golang.org](https://golang.org/dl/)
- **libfido2** development libraries
- **pkg-config** for library detection
- **GCC** compiler and build tools

### FIDO2 Device Requirements

- FIDO2 compatible device (YubiKey 5 series, SoloKey, etc.)
- Device connected via USB
- Device PIN configured
- HMAC secret extension support

## Installation

### 1. Install System Dependencies

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libfido2-dev libudev-dev
```

### 2. Install Go

Download and install Go from [golang.org](https://golang.org/dl/) or use your package manager.

### 3. Clone and Build

```bash
git clone https://github.com/DalexKraus/fido2-hmac-deriver.git
cd fido2-hmac-deriver
./build.sh
```

The build script will:
- Check all dependencies
- Download Go modules
- Build the application
- Verify the build

## Usage

### Basic Usage

Run the application interactively:
```bash
./fido2-hmac-deriver
```

The application will:
1. Search for connected FIDO2 devices
2. Display available devices for selection
3. Prompt for your device PIN
4. Guide you through the HMAC derivation process
5. Display the derived secret in multiple formats

### Scripting Mode

For integration with other tools, use the `--key-only` flag:
```bash
./fido2-hmac-deriver --key-only
```

This outputs only the derived key to stdout, making it suitable for piping to other commands:
```bash
./fido2-hmac-deriver --key-only
```

### Command Line Options

- `--key-only`: Output only the derived key to stdout (useful for scripting)
- `--help`: Display help information

## Device Setup

### YubiKey Setup

1. **Insert your YubiKey** into a USB port
2. **Set a PIN** if not already configured:
   ```bash
   ykman fido access change-pin
   ```
3. **Verify HMAC support**:
   ```bash
   ykman fido info
   ```

## Architecture

The application is separated into multiple smaller modules:

- **`main.go`**: Application entry point
- **`internal/device/`**: FIDO2 device discovery and management
- **`internal/crypto/`**: HMAC secret derivation and cryptographic operations
- **`internal/ui/`**: User interface and display formatting
- **`internal/types/`**: Type definitions and interfaces

### Dependencies

- **[go-libfido2](https://github.com/keys-pub/go-libfido2)**: Go bindings for libfido2
- **[color](https://github.com/fatih/color)**: Colored terminal output
- **[term](https://golang.org/x/term)**: Terminal utilities for secure input
