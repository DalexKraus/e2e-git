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
	Mode             string // enc or dec
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

	// SelectDeviceByPath finds and returns a device with the specified path.
	// This allows bypassing interactive device selection when the path is known.
	SelectDeviceByPath(devices []*DeviceInfo, path string) (*DeviceInfo, error)

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

	// GetPINFromEnvironment retrieves the PIN from the specified environment variable.
	// Returns the PIN value or an error if the environment variable is not set or empty.
	GetPINFromEnvironment(envVarName string) (string, error)

	// GetPINWithPinentry prompts for a PIN using pinentry if available.
	// Returns an error with instructions to use environment variable method if pinentry is not available.
	GetPINWithPinentry(prompt string) (string, error)

	// GetPINWithSpecificPinentry prompts for a PIN using a specific pinentry program.
	// Takes the pinentry program path as parameter.
	GetPINWithSpecificPinentry(prompt, pinentryProgram string) (string, error)

	// DisplayDebug shows a progress message during long-running operations.
	DisplayDebug(message string)

	// DisplayResults shows the final HMAC derivation results.
	DisplayResults(result *HMACResult)

	// DisplayError shows error messages in a user-friendly format.
	// Should provide helpful suggestions when possible.
	DisplayError(err error)

	// DisplayInfo shows success messages with appropriate formatting.
	DisplayInfo(message string)

	// OutputKeyOnly outputs just the derived key to stdout for scripting purposes.
	OutputKeyOnly(result *HMACResult)
}

// ProcessingStats contains statistics about the file processing operation
type ProcessingStats struct {
	TotalFiles     int
	TotalFolders   int
	ProcessedFiles int
}

// Application represents the main application with all its dependencies.
// This structure follows dependency injection principles for better testability.
type Application struct {
	UI             UIProvider     // User interface provider
	DeviceMgr      DeviceManager  // Device discovery and selection
	CryptoProvider CryptoProvider // HMAC secret derivation
	Config         *Configuration // Application configuration
	KeyOnly        bool           // Output only the key to stdout
	FidoDevice     string         // Specific FIDO device path (optional)
	PinEnvVar      string         // Environment variable name for PIN (optional)
	Pinentry       string         // Pinentry program path (optional)
	FilePaths      []string       // File paths to process
	LogLevel       string         // Log level: info or debug
}

// InitConfig holds configuration for the init command
type InitConfig struct {
	TargetPath     string
	PinentryMethod string
	BinaryPath     string
}

// InitCommand handles the initialization of a git repository with FIDO2 encryption
type InitCommand struct {
	Config *InitConfig
}

// TemplateConfig holds configuration values for template substitution
type TemplateConfig struct {
	BinaryPath     string
	PinentryMethod string
}

// TemplateProcessor handles template file processing and substitution
type TemplateProcessor struct {
	TemplatesDir string
	Config       *TemplateConfig
}

// GitRepository represents a git repository and provides operations for configuration
type GitRepository struct {
	Path string
}

// Manager implements the DeviceManager interface for FIDO2 device operations.
// It uses the libfido2 library to discover and interact with FIDO2 devices.
type Manager struct {
	UI UIProvider // UI provider for user interaction
}

// Provider implements the CryptoProvider interface for FIDO2 HMAC operations.
// It handles the complete process of creating credentials and deriving HMAC secrets.
type Provider struct {
	UI UIProvider // UI provider for user interaction and progress updates
}

// Display implements the UIProvider interface.
// It provides progress indicators, colored text,
// and well-formatted output.
type Display struct {
	// Color functions for different types of output
	Header    interface{} // *color.Color
	Success   interface{} // *color.Color
	Error     interface{} // *color.Color
	Warning   interface{} // *color.Color
	Info      interface{} // *color.Color
	Highlight interface{} // *color.Color
	Subtle    interface{} // *color.Color
	LogLevel  string      // "info" or "debug"
}

// PinentryClient handles communication with the pinentry program.
type PinentryClient struct {
	Cmd    interface{} // *exec.Cmd
	Stdin  interface{} // io.WriteCloser
	Stdout interface{} // io.ReadCloser
	Reader interface{} // *bufio.Reader
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
