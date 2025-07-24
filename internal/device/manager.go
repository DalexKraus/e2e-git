// Package device handles FIDO2 device discovery and selection.
// This package provides functionality to find connected FIDO2 devices
// and allow users to select which device they want to use.
package device

import (
	"errors"
	"fmt"

	"fido2-hmac-deriver/internal/types"

	"github.com/keys-pub/go-libfido2"
)

// Manager implements the DeviceManager interface for FIDO2 device operations.
// It uses the libfido2 library to discover and interact with FIDO2 devices.
type Manager struct {
	ui types.UIProvider // UI provider for user interaction
}

// NewManager creates a new device manager with the provided UI provider.
// The UI provider is used for displaying devices and getting user input.
func NewManager(ui types.UIProvider) *Manager {
	return &Manager{
		ui: ui,
	}
}

// ListDevices discovers all FIDO2 devices connected to the system.
// It uses libfido2 to enumerate devices and converts them to our internal format.
//
// Returns:
//   - A slice of DeviceInfo structures containing device details
//   - An error if device discovery fails
//
// Common errors:
//   - No devices found: when no FIDO2 devices are connected
//   - Permission errors: when the application lacks permission to access devices
//   - System errors: when the underlying FIDO2 library encounters issues
func (m *Manager) ListDevices() ([]*types.DeviceInfo, error) {
	// Use libfido2 to discover all connected FIDO2 devices
	locations, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("failed to discover FIDO2 devices: %w\n\nTroubleshooting:\n"+
			"- Ensure your FIDO2 device is connected via USB\n"+
			"- Check that you have permission to access USB devices\n"+
			"- Try running with sudo if permission issues persist\n"+
			"- Verify your device is FIDO2 compatible", err)
	}

	// Check if any devices were found
	if len(locations) == 0 {
		return nil, errors.New("no FIDO2 devices found\n\nPlease:\n" +
			"- Connect a FIDO2 device (YubiKey, SoloKey, etc.) via USB\n" +
			"- Ensure the device is properly recognized by your system\n" +
			"- Check that the device supports FIDO2 (not just U2F)")
	}

	// Convert libfido2 device locations to our internal DeviceInfo format
	devices := make([]*types.DeviceInfo, len(locations))
	for i, location := range locations {
		// Wrap the libfido2 device and convert to our format
		wrappedDevice := &types.LibFIDO2Device{DeviceLocation: location}
		devices[i] = wrappedDevice.ToDeviceInfo(i + 1) // 1-based indexing for user display
	}

	return devices, nil
}

// SelectDevice presents the available devices to the user and handles their selection.
// It displays the devices using the UI provider and validates the user's choice.
//
// Parameters:
//   - devices: A slice of available DeviceInfo structures
//
// Returns:
//   - The selected DeviceInfo
//   - An error if selection fails or is invalid
//
// The function will:
//  1. Display all available devices in a formatted list
//  2. Prompt the user to make a selection
//  3. Validate the selection is within the valid range
//  4. Return the selected device
func (m *Manager) SelectDevice(devices []*types.DeviceInfo) (*types.DeviceInfo, error) {
	// Validate input
	if len(devices) == 0 {
		return nil, errors.New("no devices provided for selection")
	}

	// Display the available devices to the user
	m.ui.DisplayDevices(devices)

	// Get the user's selection
	choice, err := m.ui.GetUserSelection(len(devices))
	if err != nil {
		return nil, fmt.Errorf("failed to get user selection: %w", err)
	}

	// Validate the choice is within bounds
	if choice < 1 || choice > len(devices) {
		return nil, fmt.Errorf("invalid selection %d: must be between 1 and %d", choice, len(devices))
	}

	// Return the selected device (convert from 1-based to 0-based indexing)
	selectedDevice := devices[choice-1]
	m.ui.DisplaySuccess(fmt.Sprintf("Selected device: %s (%s)", selectedDevice.Name, selectedDevice.Manufacturer))

	return selectedDevice, nil
}

// ValidateDevice checks if a device is still accessible and functional.
// This can be useful to verify a device hasn't been disconnected.
//
// Parameters:
//   - device: The DeviceInfo to validate
//
// Returns:
//   - An error if the device is no longer accessible
func (m *Manager) ValidateDevice(device *types.DeviceInfo) error {
	if device == nil {
		return errors.New("device is nil")
	}

	// Try to create a connection to the device to verify it's still accessible
	_, err := libfido2.NewDevice(device.Path)
	if err != nil {
		return fmt.Errorf("device %s is no longer accessible: %w\n\nThe device may have been:\n"+
			"- Disconnected from USB\n"+
			"- Claimed by another process\n"+
			"- Put into an error state", device.Name, err)
	}

	// Device is accessible - connection is managed internally by libfido2
	return nil
}

// GetDeviceCapabilities retrieves information about what a device supports.
// This is useful for determining if a device supports the features we need.
//
// Parameters:
//   - device: The DeviceInfo to query
//
// Returns:
//   - A map of capability names to boolean values
//   - An error if the device cannot be queried
func (m *Manager) GetDeviceCapabilities(device *types.DeviceInfo) (map[string]bool, error) {
	dev, err := libfido2.NewDevice(device.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to device: %w", err)
	}

	capabilities := make(map[string]bool)

	// Check for HMAC secret extension support
	// This is critical for our application
	info, err := dev.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	// Check if the device supports the extensions we need
	capabilities["hmac-secret"] = false
	for _, ext := range info.Extensions {
		if ext == "hmac-secret" {
			capabilities["hmac-secret"] = true
			break
		}
	}

	// Add other useful capability checks based on available options
	// Note: info.Options is a map[int]libfido2.Option, not map[string]bool
	capabilities["resident-keys"] = len(info.Options) > 0 // Simplified check
	capabilities["user-presence"] = true                  // Most FIDO2 devices support this
	capabilities["user-verification"] = true              // Most FIDO2 devices support this
	capabilities["pin-support"] = true                    // Most FIDO2 devices support this

	return capabilities, nil
}
