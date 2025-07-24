// FIDO2 HMAC Secret Deriver
//
// This application demonstrates how to use FIDO2 devices to derive HMAC secrets
// using the HMAC secret extension. It provides a complete, modular implementation
// with beautiful CLI interface and comprehensive error handling.
//
// The application follows a clean architecture pattern with separate modules for:
// - Device discovery and management
// - Cryptographic operations
// - User interface and display
// - Type definitions and interfaces
//
// Usage:
//
//	go run main.go
//
// Requirements:
//   - A FIDO2 compatible device (YubiKey, SoloKey, etc.)
//   - Device connected via USB
//   - Device PIN configured
package main

import (
	"flag"
	"fmt"
	"os"

	"fido2-hmac-deriver/internal/crypto"
	"fido2-hmac-deriver/internal/device"
	"fido2-hmac-deriver/internal/types"
	"fido2-hmac-deriver/internal/ui"
)

// Application represents the main application with all its dependencies.
// This structure follows dependency injection principles for better testability.
type Application struct {
	ui             types.UIProvider     // User interface provider
	deviceMgr      types.DeviceManager  // Device discovery and selection
	cryptoProvider types.CryptoProvider // HMAC secret derivation
	config         *types.Configuration // Application configuration
	keyOnly        bool                 // Output only the key to stdout
}

func NewApplication() *Application {
	uiProvider := ui.NewDisplay()
	deviceManager := device.NewManager(uiProvider)
	cryptoProvider := crypto.NewProvider(uiProvider)
	config := types.DefaultConfiguration()

	return &Application{
		ui:             uiProvider,
		deviceMgr:      deviceManager,
		cryptoProvider: cryptoProvider,
		config:         config,
	}
}

// Run executes the main application workflow.
// This is the primary entry point that orchestrates the entire process.
func (app *Application) Run() error {
	app.ui.DisplayWelcome()

	app.ui.DisplayProgress("Searching for FIDO2 devices...")
	devices, err := app.deviceMgr.ListDevices()
	if err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("device discovery failed: %w", err)
	}

	app.ui.DisplaySuccess(fmt.Sprintf("Found %d FIDO2 device(s)", len(devices)))

	selectedDevice, err := app.deviceMgr.SelectDevice(devices)
	if err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("device selection failed: %w", err)
	}

	app.ui.DisplayProgress("Validating device accessibility...")
	if err := app.deviceMgr.ValidateDevice(selectedDevice); err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("device validation failed: %w", err)
	}

	pin := app.ui.GetPIN("Enter your FIDO2 device PIN: ")
	if pin == "" {
		app.ui.DisplayError(fmt.Errorf("PIN is required for FIDO2 operations"))
		return fmt.Errorf("no PIN provided")
	}

	app.ui.DisplayProgress("Validating configuration...")
	if err := app.cryptoProvider.ValidateConfiguration(app.config); err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	app.ui.DisplayInfo("Starting HMAC secret derivation process...")
	app.ui.DisplayInfo("You will need to touch your FIDO2 device when it blinks")

	result, err := app.cryptoProvider.DeriveHMACSecret(selectedDevice, pin, app.config)
	if err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("HMAC secret derivation failed: %w", err)
	}

	if app.keyOnly {
		app.ui.OutputKeyOnly(result)
	} else {
		app.ui.DisplayResults(result)
	}

	return nil
}

func main() {
	// Parse CLI flags
	keyOnly := flag.Bool("key-only", false, "Output only the derived key to stdout (useful for scripting)")
	flag.Parse()

	// Create the application instance
	app := NewApplication()
	app.keyOnly = *keyOnly

	// Run the application and handle any errors
	if err := app.Run(); err != nil {
		app.ui.DisplayError(err)
		os.Exit(1)
	}

	os.Exit(0)
}

func init() {}
