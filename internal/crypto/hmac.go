// Package crypto handles FIDO2 cryptographic operations.
// This package provides functionality to derive HMAC secrets using FIDO2 devices
// with proper error handling and user guidance.
package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"fido2-hmac-deriver/internal/types"

	"github.com/keys-pub/go-libfido2"
)

// Provider implements the CryptoProvider interface for FIDO2 HMAC operations.
// It handles the complete process of creating credentials and deriving HMAC secrets.
type Provider struct {
	ui types.UIProvider // UI provider for user interaction and progress updates
}

// NewProvider creates a new crypto provider with the given UI provider.
// The UI provider is used to show progress and interact with the user during operations.
func NewProvider(ui types.UIProvider) *Provider {
	return &Provider{
		ui: ui,
	}
}

// DeriveHMACSecret performs the complete HMAC secret derivation process.
// This is the main function that orchestrates the entire FIDO2 HMAC derivation workflow.
//
// The process involves several steps:
//  1. Connect to the FIDO2 device
//  2. Generate a random salt for HMAC derivation
//  3. Create a new FIDO2 credential with HMAC secret extension
//  4. Use the credential to derive an HMAC secret
//  5. Return all the derivation results
//
// Parameters:
//   - device: Information about the FIDO2 device to use
//   - pin: The device PIN for authentication
//   - config: Application configuration including relying party details
//
// Returns:
//   - HMACResult containing the derived secret and metadata
//   - An error if any step of the process fails
func (p *Provider) DeriveHMACSecret(device *types.DeviceInfo, pin string, config *types.Configuration) (*types.HMACResult, error) {
	// Step 1: Connect to the FIDO2 device
	p.ui.DisplayProgress("Connecting to FIDO2 device...")
	dev, err := libfido2.NewDevice(device.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to device %s: %w\n\nTroubleshooting:\n"+
			"- Ensure the device is still connected\n"+
			"- Check that no other application is using the device\n"+
			"- Try unplugging and reconnecting the device", device.Name, err)
	}

	// Step 2: Generate a deterministic salt for HMAC derivation
	p.ui.DisplayProgress("Generating deterministic salt...")
	salt, err := p.generateDeterministicSalt(config.SaltSize, device, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Step 3: Try to load existing credential or create a new one
	var credentialID []byte
	existingCredentialID, err := p.loadCredentialID(device, config)
	if err != nil {
		// No existing credential found, create a new one
		p.ui.DisplayProgress("Creating FIDO2 credential (please touch your device when it blinks)...")
		attestation, err := p.createCredential(dev, pin, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create FIDO2 credential: %w", err)
		}
		credentialID = attestation.CredentialID

		// Save the credential ID for future use
		err = p.saveCredentialID(credentialID, device, config)
		if err != nil {
			p.ui.DisplayError(fmt.Errorf("failed to save credential ID: %w", err))
		}
	} else {
		// Use existing credential
		credentialID = existingCredentialID
		p.ui.DisplayProgress("Using existing credential...")
	}

	// Step 4: Derive the HMAC secret using the credential
	p.ui.DisplayProgress("Deriving HMAC secret (please touch your device when it blinks)...")
	secret, err := p.deriveSecret(dev, credentialID, salt, pin, config)
	if err != nil {
		return nil, fmt.Errorf("failed to derive HMAC secret: %w", err)
	}

	// Step 5: Create and return the result
	result := &types.HMACResult{
		Secret:       secret,
		Salt:         salt,
		CredentialID: credentialID,
		Device:       device,
		Timestamp:    time.Now(),
		RelyingParty: config.RelyingPartyID,
	}

	p.ui.DisplaySuccess("HMAC secret derived successfully!")
	return result, nil
}

// generateSalt creates a deterministic salt based on device and relying party.
// For deterministic key derivation, the salt must be the same for the same device
// and relying party combination. This ensures repeatable results.
//
// Parameters:
//   - size: The size of the salt in bytes (typically 32 for 256-bit security)
//   - device: Device information to include in salt derivation
//   - config: Configuration containing relying party information
//
// Returns:
//   - A byte slice containing the deterministic salt
//   - An error if salt generation fails
func (p *Provider) generateDeterministicSalt(size int, device *types.DeviceInfo, config *types.Configuration) ([]byte, error) {
	// Create a deterministic salt by hashing device path + relying party ID
	// This ensures the same device + same relying party = same salt = same key
	saltInput := fmt.Sprintf("%s:%s", device.Path, config.RelyingPartyID)

	// Use SHA-256 to create a deterministic hash
	hash := sha256.Sum256([]byte(saltInput))

	// If we need more than 32 bytes, we can extend by hashing again
	if size <= 32 {
		result := make([]byte, size)
		copy(result, hash[:size])
		return result, nil
	}

	// For larger sizes, concatenate multiple hashes
	salt := make([]byte, 0, size)
	counter := 0
	for len(salt) < size {
		counterInput := fmt.Sprintf("%s:%d", saltInput, counter)
		counterHash := sha256.Sum256([]byte(counterInput))
		remaining := size - len(salt)
		if remaining >= 32 {
			salt = append(salt, counterHash[:]...)
		} else {
			salt = append(salt, counterHash[:remaining]...)
		}
		counter++
	}

	return salt, nil
}

// createCredential creates a new FIDO2 credential with HMAC secret extension.
// This credential will be used to derive HMAC secrets. The credential includes
// the HMAC secret extension which is required for our use case.
//
// For deterministic behavior, we use a deterministic client data hash based on
// the relying party ID, ensuring the same credential is created each time.
//
// Parameters:
//   - dev: The FIDO2 device to use
//   - pin: The device PIN for authentication
//   - config: Application configuration
//
// Returns:
//   - The created attestation
//   - An error if credential creation fails
func (p *Provider) createCredential(dev *libfido2.Device, pin string, config *types.Configuration) (*libfido2.Attestation, error) {
	// Generate a deterministic client data hash based on relying party ID
	// This ensures the same credential is created each time for the same RP
	clientDataInput := fmt.Sprintf("fido2-hmac-credential:%s", config.RelyingPartyID)
	clientDataHashArray := sha256.Sum256([]byte(clientDataInput))
	clientDataHash := clientDataHashArray[:]

	// Set up the relying party information
	// This identifies our application to the FIDO2 device
	relyingParty := libfido2.RelyingParty{
		ID:   config.RelyingPartyID,
		Name: config.RelyingPartyName,
	}

	// Set up the user information
	// This represents the user account for which we're creating the credential
	user := libfido2.User{
		ID:          config.UserID,
		Name:        config.UserName,
		DisplayName: config.UserDisplayName,
	}

	// Create the credential with HMAC secret extension
	// The HMAC secret extension is crucial - it enables HMAC secret derivation
	credential, err := dev.MakeCredential(
		clientDataHash,
		relyingParty,
		user,
		libfido2.ES256, // Use ES256 algorithm (ECDSA with SHA-256)
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension}, // Enable HMAC secret extension
			RK:         libfido2.True,                                      // Enable resident key (stores credential on device)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("credential creation failed: %w\n\nPossible causes:\n"+
			"• Incorrect PIN entered\n"+
			"• Device doesn't support HMAC secret extension\n"+
			"• User didn't touch the device when prompted\n"+
			"• Device is in an error state", err)
	}

	return credential, nil
}

// deriveSecret uses an existing credential to derive an HMAC secret.
// This function performs the actual HMAC secret derivation using the FIDO2
// assertion operation with the HMAC secret extension.
//
// Parameters:
//   - dev: The FIDO2 device to use
//   - credentialID: The ID of the credential to use for derivation
//   - salt: The salt to use for HMAC derivation
//   - pin: The device PIN for authentication
//   - config: Application configuration
//
// Returns:
//   - The derived HMAC secret as a byte slice
//   - An error if derivation fails
func (p *Provider) deriveSecret(dev *libfido2.Device, credentialID, salt []byte, pin string, config *types.Configuration) ([]byte, error) {
	// Create a client data hash from the salt
	// This links the salt to the FIDO2 operation
	clientDataHash := sha256.Sum256(salt)

	// Perform the FIDO2 assertion with HMAC secret extension
	// This is where the actual HMAC secret derivation happens
	assertion, err := dev.Assertion(
		config.RelyingPartyID,
		clientDataHash[:],
		[][]byte{credentialID}, // Use the credential we just created
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension}, // Enable HMAC secret extension
			HMACSalt:   salt,                                               // Provide the salt for HMAC derivation
			UP:         libfido2.True,                                      // Require user presence (touch)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("HMAC secret derivation failed: %w\n\nPossible causes:\n"+
			"• Incorrect PIN entered\n"+
			"• User didn't touch the device when prompted\n"+
			"• Credential is not valid or has been removed\n"+
			"• Device communication error", err)
	}

	// Validate that we actually got an HMAC secret
	if len(assertion.HMACSecret) == 0 {
		return nil, fmt.Errorf("device returned empty HMAC secret\n\nThis may indicate:\n" +
			"• The device doesn't properly support HMAC secret extension\n" +
			"• The credential wasn't created with HMAC secret extension\n" +
			"• A device firmware issue")
	}

	return assertion.HMACSecret, nil
}

// ValidateConfiguration checks if the provided configuration is valid.
// This helps catch configuration errors early before attempting operations.
//
// Parameters:
//   - config: The configuration to validate
//
// Returns:
//   - An error if the configuration is invalid
func (p *Provider) ValidateConfiguration(config *types.Configuration) error {
	if config == nil {
		return fmt.Errorf("configuration is nil")
	}

	if config.RelyingPartyID == "" {
		return fmt.Errorf("relying party ID cannot be empty")
	}

	if config.RelyingPartyName == "" {
		return fmt.Errorf("relying party name cannot be empty")
	}

	if len(config.UserID) == 0 {
		return fmt.Errorf("user ID cannot be empty")
	}

	if config.UserName == "" {
		return fmt.Errorf("user name cannot be empty")
	}

	if config.SaltSize <= 0 {
		return fmt.Errorf("salt size must be positive, got %d", config.SaltSize)
	}

	if config.SaltSize < 16 {
		return fmt.Errorf("salt size should be at least 16 bytes for security, got %d", config.SaltSize)
	}

	return nil
}

// getCredentialFilename generates a filename for storing credential ID based on device and config.
// Uses the first 16 characters of the base64-encoded credential ID as requested.
func (p *Provider) getCredentialFilename(credentialID []byte) string {
	base64Cred := base64.StdEncoding.EncodeToString(credentialID)
	if len(base64Cred) > 16 {
		base64Cred = base64Cred[:16]
	}
	// Replace characters that might be problematic in filenames
	filename := strings.ReplaceAll(base64Cred, "/", "_")
	filename = strings.ReplaceAll(filename, "+", "-")
	return filename + ".cred"
}

// saveCredentialID saves a credential ID to a file in the current directory.
func (p *Provider) saveCredentialID(credentialID []byte, device *types.DeviceInfo, config *types.Configuration) error {
	filename := p.getCredentialFilename(credentialID)
	credentialData := base64.StdEncoding.EncodeToString(credentialID)

	err := os.WriteFile(filename, []byte(credentialData), 0644)
	if err != nil {
		return fmt.Errorf("failed to save credential ID to %s: %w", filename, err)
	}

	p.ui.DisplayInfo(fmt.Sprintf("Saved credential ID to %s", filename))
	return nil
}

// loadCredentialID attempts to load an existing credential ID from file.
func (p *Provider) loadCredentialID(device *types.DeviceInfo, config *types.Configuration) ([]byte, error) {
	// We need to find the credential file by trying to match device/config combination
	// For now, we'll look for any .cred files and try to use them
	files, err := os.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read current directory: %w", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".cred") {
			data, err := os.ReadFile(file.Name())
			if err != nil {
				continue
			}

			credentialID, err := base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				continue
			}

			p.ui.DisplayInfo(fmt.Sprintf("Found existing credential in %s", file.Name()))
			return credentialID, nil
		}
	}

	return nil, fmt.Errorf("no existing credential found")
}
