package util

import (
	"fmt"
)

// InitConfig holds configuration for the init command
type InitConfig struct {
	TargetPath     string
	DeviceID       string
	PinentryMethod string
	BinaryPath     string
}

// InitCommand handles the initialization of a git repository with FIDO2 encryption
type InitCommand struct {
	Config *InitConfig
}

// NewInitCommand creates a new init command instance
func NewInitCommand(config *InitConfig) *InitCommand {
	return &InitCommand{Config: config}
}

// Execute runs the init command
func (ic *InitCommand) Execute() error {
	// Validate target directory is a git repository
	gitRepo := NewGitRepository(ic.Config.TargetPath)
	isGit, err := gitRepo.IsGitRepository()
	if err != nil {
		return fmt.Errorf("failed to check if directory is a git repository: %w", err)
	}
	if !isGit {
		return fmt.Errorf("target directory is not a git repository: %s", ic.Config.TargetPath)
	}

	// Detect binary path if not provided
	if ic.Config.BinaryPath == "" {
		binaryPath, err := DetectBinaryPath()
		if err != nil {
			return fmt.Errorf("failed to detect binary path: %w", err)
		}
		ic.Config.BinaryPath = binaryPath
	}

	// Create filter wrapper script content (without device ID)
	filterContent := fmt.Sprintf(`#!/bin/bash
# Git filter wrapper for FIDO2 encryption/decryption
# Handles both clean (encrypt) and smudge (decrypt) operations

# Configuration
BINARY_PATH="%s"
PINENTRY_METHOD="%s"

# Determine operation mode from script name or first argument
OPERATION=""
if [[ "$0" == *"clean"* ]] || [[ "$1" == "clean" ]] || [[ "$1" == "encrypt" ]]; then
    OPERATION="enc"
elif [[ "$0" == *"smudge"* ]] || [[ "$1" == "smudge" ]] || [[ "$1" == "decrypt" ]]; then
    OPERATION="dec"
else
    # Default to decrypt for backward compatibility
    OPERATION="dec"
fi

# Read input from stdin and save to temporary file
TEMP_FILE=$(mktemp)
trap "rm -f '$TEMP_FILE'" EXIT

cat > "$TEMP_FILE"

# Process the file with FIDO2 encryption/decryption
if "$BINARY_PATH" --mode="$OPERATION" --pinentry="$PINENTRY_METHOD" "$TEMP_FILE"; then
    # Output the processed file content
    cat "$TEMP_FILE"
else
    # On error, output original content unchanged
    cat "$TEMP_FILE"
    exit 1
fi
`, ic.Config.BinaryPath, ic.Config.PinentryMethod)

	// Install filter wrapper script in hooks directory
	if err := gitRepo.InstallFilterScript("filter-wrapper.sh", filterContent); err != nil {
		return fmt.Errorf("failed to install filter script: %w", err)
	}

	// Configure git filter to use script from hooks directory
	filterScriptPath := ".git/hooks/filter-wrapper.sh"
	if err := gitRepo.ConfigureFilter("crypt", filterScriptPath+" clean", filterScriptPath+" smudge"); err != nil {
		return fmt.Errorf("failed to configure git filter: %w", err)
	}

	// Add git dec alias
	decAlias := "!f(){ " +
		"files=$(git ls-files '*.sec'); " +
		"if [ -n \"$files\" ]; then " +
		"for file in $files; do " +
		"if [ -f \"$file\" ]; then " +
		".git/hooks/filter-wrapper.sh smudge < \"$file\" > \"$file.tmp\" && mv \"$file.tmp\" \"$file\"; " +
		"fi; " +
		"done; " +
		"fi; " +
		"}; f"
	if err := gitRepo.SetAlias("dec", decAlias); err != nil {
		return fmt.Errorf("failed to set git dec alias: %w", err)
	}

	return nil
}

// ValidateConfig validates the init configuration
func (ic *InitCommand) ValidateConfig() error {
	if ic.Config.TargetPath == "" {
		return fmt.Errorf("target path is required")
	}

	if ic.Config.PinentryMethod == "" {
		return fmt.Errorf("pinentry method is required")
	}

	return nil
}
