// Package ui handles user interface and display formatting.
// This package provides beautiful, colored output and user interaction
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

	"fido2-hmac-deriver/internal/types"

	"github.com/fatih/color"
	"golang.org/x/term"
)

// Display implements the UIProvider interface with beautiful colored output.
// It provides a rich user experience with progress indicators, colored text,
// and well-formatted output.
type Display struct {
	// Color functions for different types of output
	header    *color.Color
	success   *color.Color
	error     *color.Color
	warning   *color.Color
	info      *color.Color
	highlight *color.Color
	subtle    *color.Color
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
	}
}

// DisplayWelcome shows the application header and welcome message.
// Simple and professional without fancy ASCII art.
func (d *Display) DisplayWelcome() {
	d.header.Println("FIDO2 HMAC Secret Deriver")
	d.header.Println("=========================")
	fmt.Println()
	d.info.Println("Deriving cryptographic secrets using FIDO2/CTAP devices.")
	d.subtle.Println("Ensure your FIDO2 device is connected via USB.")
	fmt.Println()
}

// DisplayDevices shows a formatted list of available FIDO2 devices.
// Each device is displayed with an index, name, manufacturer, and path.
func (d *Display) DisplayDevices(devices []*types.DeviceInfo) {
	d.header.Println("Available FIDO2 Devices:")
	d.header.Println("========================")
	fmt.Println()

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

// DisplayProgress shows a progress message during long-running operations.
// This helps users understand what the application is doing.
func (d *Display) DisplayProgress(message string) {
	d.info.Printf("[~] %s\n", message)
}

// DisplayResults shows the final HMAC derivation results in a beautiful format.
// This includes the secret in multiple encodings and all relevant metadata.
func (d *Display) DisplayResults(result *types.HMACResult) {
	fmt.Println()
	d.header.Println("HMAC Secret Derivation Complete!")
	d.header.Println("=================================")
	fmt.Println()

	// Device Information
	d.highlight.Println("Device Information:")
	fmt.Printf("   Name: %s\n", result.Device.Name)
	fmt.Printf("   Manufacturer: %s\n", result.Device.Manufacturer)
	fmt.Printf("   Path: %s\n", result.Device.Path)
	fmt.Println()

	// Operation Details
	d.highlight.Println("Operation Details:")
	fmt.Printf("   Relying Party: %s\n", result.RelyingParty)
	fmt.Printf("   Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Printf("   Duration: %s\n", time.Since(result.Timestamp).Truncate(time.Millisecond))
	fmt.Println()

	// Secret Information
	d.highlight.Println("Derived Secret:")
	d.success.Printf("   Base64: %s\n", base64.StdEncoding.EncodeToString(result.Secret))
	fmt.Printf("   Hex:    %s\n", hex.EncodeToString(result.Secret))
	fmt.Printf("   Length: %d bytes (%d bit)\n", len(result.Secret), len(result.Secret)*8)
	fmt.Println()

	// Salt Information
	d.highlight.Println("Salt Used:")
	fmt.Printf("   Base64: %s\n", base64.StdEncoding.EncodeToString(result.Salt))
	fmt.Printf("   Hex:    %s\n", hex.EncodeToString(result.Salt))
	fmt.Printf("   Length: %d bytes\n", len(result.Salt))
	fmt.Println()

	// Credential Information
	d.highlight.Println("Credential Information:")
	fmt.Printf("   ID (Base64): %s\n", base64.StdEncoding.EncodeToString(result.CredentialID))
	fmt.Printf("   ID (Hex):    %s\n", hex.EncodeToString(result.CredentialID))
	fmt.Printf("   Length:      %d bytes\n", len(result.CredentialID))
	fmt.Println()

	// Security Information
	d.highlight.Println("Security Information:")
	secretFingerprint := d.calculateFingerprint(result.Secret)
	saltFingerprint := d.calculateFingerprint(result.Salt)
	credFingerprint := d.calculateFingerprint(result.CredentialID)

	fmt.Printf("   Secret Fingerprint:     %s\n", secretFingerprint)
	fmt.Printf("   Salt Fingerprint:       %s\n", saltFingerprint)
	fmt.Printf("   Credential Fingerprint: %s\n", credFingerprint)
	fmt.Println()

	// Usage Notes
	d.info.Println("Usage Notes:")
	d.subtle.Println("   - The derived secret is unique to this device and salt combination")
	d.subtle.Println("   - Store the salt securely if you need to reproduce this secret")
	d.subtle.Println("   - The credential is stored on your FIDO2 device")
	d.subtle.Println("   - This secret can be used for encryption, authentication, or key derivation")
	fmt.Println()
}

// DisplayError shows error messages in a user-friendly format.
// It provides helpful suggestions when possible.
func (d *Display) DisplayError(err error) {
	d.error.Printf("[!] %v\n", err)
}

// DisplaySuccess shows success messages with appropriate formatting.
func (d *Display) DisplaySuccess(message string) {
	d.success.Printf("[+] %s\n", message)
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

// DisplayInfo shows informational messages.
func (d *Display) DisplayInfo(message string) {
	d.info.Printf("[~] %s\n", message)
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

// OutputKeyOnly outputs just the derived key to stdout for scripting purposes.
// This outputs the key in base64 format to stdout, suitable for piping to other tools.
func (d *Display) OutputKeyOnly(result *types.HMACResult) {
	fmt.Println("----- BEGIN DERIVED KEY -----")
	fmt.Println(base64.StdEncoding.EncodeToString(result.Secret))
	fmt.Println("----- END DERIVED KEY -----")
}
