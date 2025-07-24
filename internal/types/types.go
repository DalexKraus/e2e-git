// Package types defines all the data structures and interfaces used throughout the application.
// This package provides a clear contract for how different components interact with each other.
package types

import (
	"time"

	"github.com/keys-pub/go-libfido2"
)

// DeviceInfo represents information about a FIDO2 device.
// This structure contains all the details needed to identify and work with a FIDO2 device.
type DeviceInfo struct {
	Name         string // Human-readable name of the device (e.g., "YubiKey 5 NFC")
	Manufacturer string // Device manufacturer (e.g., "Yubico")
	Path         string // System path to the device (e.g., "/dev/hidraw0")
	Index        int    // Position in the device list (for user selection)
}

// HMACResult contains all the information from a successful HMAC secret derivation.
// This includes the derived secret, the salt used, and metadata about the operation.
type HMACResult struct {
	Secret       []byte      // The derived HMAC secret (typically 32 bytes)
	Salt         []byte      // Random salt used for derivation (32 bytes)
	CredentialID []byte      // FIDO2 credential identifier
	Device       *DeviceInfo // Information about the device used
	Timestamp    time.Time   // When the derivation was performed
	RelyingParty string      // The relying party identifier used
}

// Configuration holds application settings and constants.
type Configuration struct {
	RelyingPartyID   string // Identifier for this application (e.g., "e2e-git")
	RelyingPartyName string // Human-readable name for this application
	UserID           []byte // User identifier for FIDO2 operations
	UserName         string // Username for FIDO2 operations
	UserDisplayName  string // Display name for FIDO2 operations
	SaltSize         int    // Size of the salt in bytes (typically 32)
}

// DeviceManager defines the interface for discovering and selecting FIDO2 devices.
// This interface abstracts the device discovery process, making it easy to test
// and potentially support different device backends in the future.
type DeviceManager interface {
	// ListDevices discovers all available FIDO2 devices connected to the system.
	// Returns a slice of DeviceInfo structures or an error if discovery fails.
	ListDevices() ([]*DeviceInfo, error)

	// SelectDevice presents the list of devices to the user and returns their selection.
	// Takes a slice of available devices and returns the selected device or an error.
	SelectDevice(devices []*DeviceInfo) (*DeviceInfo, error)

	// ValidateDevice checks if a device is still accessible and functional.
	// Returns an error if the device is no longer accessible.
	ValidateDevice(device *DeviceInfo) error
}

// CryptoProvider defines the interface for FIDO2 cryptographic operations.
// This interface handles the actual HMAC secret derivation using FIDO2 devices.
type CryptoProvider interface {
	// DeriveHMACSecret performs the complete HMAC secret derivation process.
	// This includes creating a credential, prompting for PIN, and deriving the secret.
	// Returns an HMACResult with all derivation details or an error.
	DeriveHMACSecret(device *DeviceInfo, pin string, config *Configuration) (*HMACResult, error)

	// ValidateConfiguration checks if the provided configuration is valid.
	// Returns an error if the configuration is invalid.
	ValidateConfiguration(config *Configuration) error
}

// UIProvider defines the interface for user interaction and output formatting.
// This interface handles all user input/output, making the application's UI
// easily customizable and testable.
type UIProvider interface {
	// DisplayWelcome shows the application header and welcome message.
	DisplayWelcome()

	// DisplayDevices shows a formatted list of available FIDO2 devices.
	// Takes a slice of DeviceInfo and presents them in a user-friendly format.
	DisplayDevices(devices []*DeviceInfo)

	// GetUserSelection prompts the user to select a device from the list.
	// Takes the maximum valid selection number and returns the user's choice.
	GetUserSelection(maxChoice int) (int, error)

	// GetPIN prompts the user to enter their FIDO2 device PIN securely.
	// The PIN input should be hidden from the terminal for security.
	GetPIN(prompt string) string

	// DisplayProgress shows a progress message during long-running operations.
	DisplayProgress(message string)

	// DisplayResults shows the final HMAC derivation results in a beautiful format.
	// This includes the secret in multiple encodings and all relevant metadata.
	DisplayResults(result *HMACResult)

	// DisplayError shows error messages in a user-friendly format.
	// Should provide helpful suggestions when possible.
	DisplayError(err error)

	// DisplaySuccess shows success messages with appropriate formatting.
	DisplaySuccess(message string)

	// DisplayInfo shows informational messages.
	DisplayInfo(message string)

	// OutputKeyOnly outputs just the derived key to stdout for scripting purposes.
	OutputKeyOnly(result *HMACResult)
}

// DefaultConfiguration returns the default application configuration.
// This function provides sensible defaults for all configuration values.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		RelyingPartyID:   "e2e-git",
		RelyingPartyName: "End-to-End Git Encryption",
		UserID:           []byte("hmac-user"),
		UserName:         "hmac-user",
		UserDisplayName:  "HMAC Secret User",
		SaltSize:         32, // 256 bit
	}
}

// LibFIDO2Device wraps the libfido2.DeviceLocation for easier testing and abstraction.
// This allows us to work with device information without directly depending on
// the libfido2 library throughout the codebase.
type LibFIDO2Device struct {
	*libfido2.DeviceLocation
}

// ToDeviceInfo converts a LibFIDO2Device to our internal DeviceInfo structure.
// This provides a clean separation between external library types and our internal types.
func (d *LibFIDO2Device) ToDeviceInfo(index int) *DeviceInfo {
	return &DeviceInfo{
		Name:         d.Product,
		Manufacturer: d.Manufacturer,
		Path:         d.Path,
		Index:        index,
	}
}
