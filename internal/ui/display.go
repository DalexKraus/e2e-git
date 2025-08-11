// Package ui handles user interface and display formatting.
// This package provides colored output and user interaction
// for the FIDO2 HMAC secret derivation application.
package ui

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"e2e-git/internal/pinentry"
	"e2e-git/internal/types"

	"github.com/fatih/color"
	"golang.org/x/term"
)

// Display implements the UIProvider interface with colored output.
// It provides progress indicators, colored text, and well-formatted output.
type Display struct {
	// Color functions for different types of output
	header    *color.Color
	success   *color.Color
	error     *color.Color
	warning   *color.Color
	info      *color.Color
	highlight *color.Color
	subtle    *color.Color
	logLevel  string // "info" or "debug"
}

// NewDisplay creates a new display provider with predefined color scheme.
// The color scheme is designed to be readable and professional.
func NewDisplay() *Display {
	return &Display{
		header:    color.New(color.FgCyan, color.Bold),
		success:   color.New(color.FgGreen, color.Bold),
		error:     color.New(color.FgRed, color.Bold),
		warning:   color.New(color.FgYellow, color.Bold),
		info:      color.New(color.FgBlue),
		highlight: color.New(color.FgMagenta, color.Bold),
		subtle:    color.New(color.FgHiBlack),
		logLevel:  "info", // Default to info for cleaner output
	}
}

// SetLogLevel sets the log level for the display provider.
func (d *Display) SetLogLevel(level string) {
	d.logLevel = level
}

// GetLogLevel returns the current log level.
func (d *Display) GetLogLevel() string {
	return d.logLevel
}

// DisplayWelcome shows the application header and welcome message.
// Simple and professional without fancy ASCII art.
func (d *Display) DisplayWelcome() {
	if d.logLevel == "debug" {
		d.header.Fprintln(os.Stderr, "FIDO2 HMAC Secret Deriver")
		d.header.Fprintln(os.Stderr, "=========================")
		d.info.Fprintln(os.Stderr, "Deriving cryptographic secrets using FIDO2/CTAP devices.")
		d.subtle.Fprintln(os.Stderr, "Ensure your FIDO2 device is connected via USB.")
	}
}

// DisplayDevices shows a formatted list of available FIDO2 devices.
// Each device is displayed with an index, name, manufacturer, and path.
func (d *Display) DisplayDevices(devices []*types.DeviceInfo) {
	d.header.Fprintln(os.Stderr, "Available FIDO2 Devices:")
	d.header.Fprintln(os.Stderr, "========================")
	fmt.Fprintln(os.Stderr)

	for _, device := range devices {
		// Create a formatted device entry
		d.highlight.Printf("[%d] ", device.Index)
		d.success.Printf("%s", device.Name)

		if device.Manufacturer != "" && device.Manufacturer != device.Name {
			d.info.Printf(" by %s", device.Manufacturer)
		}

		fmt.Println()
		d.subtle.Printf("    Path: %s", device.Path)
		fmt.Println()
		fmt.Println()
	}
}

// GetUserSelection prompts the user to select a device from the list.
// It validates the input and returns the user's choice.
func (d *Display) GetUserSelection(maxChoice int) (int, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		d.info.Printf("Please select a device [1-%d]: ", maxChoice)

		input, err := reader.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			d.warning.Println("Please enter a number.")
			continue
		}

		choice, err := strconv.Atoi(input)
		if err != nil {
			d.warning.Printf("'%s' is not a valid number. Please try again.\n", input)
			continue
		}

		if choice < 1 || choice > maxChoice {
			d.warning.Printf("Please enter a number between 1 and %d.\n", maxChoice)
			continue
		}

		return choice, nil
	}
}

// GetPIN prompts the user to enter their FIDO2 device PIN securely.
// The PIN input is hidden from the terminal for security.
func (d *Display) GetPIN(prompt string) string {
	d.info.Print(prompt)
	pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Add newline after hidden input

	if err != nil {
		d.error.Printf("Failed to read PIN: %v\n", err)
		return ""
	}

	return strings.TrimSpace(string(pinBytes))
}

// GetPINFromEnvironment retrieves the PIN from the specified environment variable.
// Returns the PIN value or an error if the environment variable is not set or empty.
func (d *Display) GetPINFromEnvironment(envVarName string) (string, error) {
	if envVarName == "" {
		return "", fmt.Errorf("environment variable name cannot be empty")
	}

	pin := os.Getenv(envVarName)
	if pin == "" {
		return "", fmt.Errorf("environment variable '%s' is not set or is empty\n\nPlease set the environment variable:\n"+
			"  export %s=\"your_pin_here\"\n"+
			"Or run without --pin-environment-variable to enter PIN interactively", envVarName, envVarName)
	}

	pin = strings.TrimSpace(pin)
	if pin == "" {
		return "", fmt.Errorf("environment variable '%s' contains only whitespace", envVarName)
	}

	if d.logLevel == "debug" {
		d.success.Printf("PIN retrieved from environment variable '%s'\n", envVarName)
	}
	return pin, nil
}

// GetPINWithPinentry prompts for a PIN using pinentry if available.
// Returns an error with instructions to use environment variable method if pinentry is not available.
func (d *Display) GetPINWithPinentry(prompt string) (string, error) {
	// Use the pinentry package to get PIN securely
	description := "Enter your FIDO2 device PIN"
	return pinentry.GetPINWithPinentry(prompt, description)
}

// GetPINWithSpecificPinentry prompts for a PIN using a specific pinentry program.
// Takes the pinentry program path as parameter.
func (d *Display) GetPINWithSpecificPinentry(prompt, pinentryProgram string) (string, error) {
	// Use the pinentry package with a specific program
	description := "Enter your FIDO2 device PIN"
	return pinentry.GetPINWithSpecificPinentry(prompt, description, pinentryProgram)
}

// GetPINWithSpecificPinentryForOperation prompts for a PIN using a specific pinentry program
// with operation-specific description text.
func (d *Display) GetPINWithSpecificPinentryForOperation(prompt, pinentryProgram, mode string) (string, error) {
	var description string
	switch mode {
	case "enc":
		description = "Enter your FIDO2 PIN to encrypt your files"
	case "dec":
		description = "Enter your FIDO2 PIN to decrypt your files"
	default:
		description = "Enter your FIDO2 device PIN"
	}
	return pinentry.GetPINWithSpecificPinentry(prompt, description, pinentryProgram)
}

// DisplayDebug shows a progress message during long-running operations.
// This helps users understand what the application is doing.
func (d *Display) DisplayDebug(message string) {
	if d.logLevel == "debug" {
		d.info.Fprintf(os.Stderr, "[~] %s\n", message)
	}
}

// DisplayResults shows the final HMAC derivation results.
// This includes the secret in multiple encodings and all relevant metadata.
func (d *Display) DisplayResults(result *types.HMACResult) {
	if d.logLevel == "debug" {
		fmt.Fprintln(os.Stderr)
		d.header.Fprintln(os.Stderr, "HMAC Secret Derivation Complete!")
		d.header.Fprintln(os.Stderr, "=================================")
		fmt.Fprintln(os.Stderr)

		// Device Information
		d.highlight.Fprintln(os.Stderr, "Device Information:")
		fmt.Fprintf(os.Stderr, "   Name: %s\n", result.Device.Name)
		fmt.Fprintf(os.Stderr, "   Manufacturer: %s\n", result.Device.Manufacturer)
		fmt.Fprintf(os.Stderr, "   Path: %s\n", result.Device.Path)
		fmt.Fprintln(os.Stderr)

		// Operation Details
		d.highlight.Fprintln(os.Stderr, "Operation Details:")
		fmt.Fprintf(os.Stderr, "   Relying Party: %s\n", result.RelyingParty)
		fmt.Fprintf(os.Stderr, "   Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
		fmt.Fprintf(os.Stderr, "   Duration: %s\n", time.Since(result.Timestamp).Truncate(time.Millisecond))
		fmt.Fprintln(os.Stderr)

		// Security Information
		d.highlight.Fprintln(os.Stderr, "Security Information:")
		secretFingerprint := d.calculateFingerprint(result.Secret)
		saltFingerprint := d.calculateFingerprint(result.Salt)
		credFingerprint := d.calculateFingerprint(result.CredentialID)

		fmt.Fprintf(os.Stderr, "   Secret Fingerprint:     %s\n", secretFingerprint)
		fmt.Fprintf(os.Stderr, "   Salt Fingerprint:       %s\n", saltFingerprint)
		fmt.Fprintf(os.Stderr, "   Credential Fingerprint: %s\n", credFingerprint)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr)
	}
}

// DisplayError shows error messages in a user-friendly format.
// It provides helpful suggestions when possible.
func (d *Display) DisplayError(err error) {
	d.error.Printf("[!] %v\n", err)
}

// DisplayInfo shows success messages with appropriate formatting.
func (d *Display) DisplayInfo(message string) {
	d.success.Fprintf(os.Stderr, "[+] %s\n", message)
}

// calculateFingerprint creates a short fingerprint for data identification.
// This is useful for quickly identifying different pieces of data.
func (d *Display) calculateFingerprint(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}

	// Use a simple hash of the first and last few bytes for a fingerprint
	if len(data) >= 8 {
		return hex.EncodeToString(data[:4]) + "..." + hex.EncodeToString(data[len(data)-4:])
	}

	return hex.EncodeToString(data)
}

// DisplaySeparator shows a visual separator for organizing output.
func (d *Display) DisplaySeparator() {
	d.subtle.Println("----------------------------------------------------------------")
}

// DisplayStep shows a numbered step in a process.
// This helps users follow along with multi-step operations.
func (d *Display) DisplayStep(step int, total int, description string) {
	d.highlight.Printf("Step %d/%d: ", step, total)
	d.info.Printf("%s\n", description)
}

// DisplayWarning shows warning messages that need user attention.
func (d *Display) DisplayWarning(message string) {
	d.warning.Printf("[!] %s\n", message)
}

// ConfirmAction asks the user to confirm an action.
// Returns true if the user confirms, false otherwise.
func (d *Display) ConfirmAction(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)

	d.warning.Printf("%s [y/N]: ", prompt)

	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.ToLower(strings.TrimSpace(input))
	return input == "y" || input == "yes"
}

// OutputKeyOnly outputs just the derived key to stderr for scripting purposes.
// This outputs the key in base64 format to stderr, suitable for piping to other tools.
func (d *Display) OutputKeyOnly(result *types.HMACResult) {
	fmt.Fprintln(os.Stderr, "----- BEGIN DERIVED KEY -----")
	fmt.Fprintln(os.Stderr, base64.StdEncoding.EncodeToString(result.Secret))
	fmt.Fprintln(os.Stderr, "----- END DERIVED KEY -----")
}
