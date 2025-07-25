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
	Pin            string               // get pin from cmd args
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

	if len(devices) == 0 {
		return fmt.Errorf("no FIDO2 devices found")
	}
	selectedDevice := devices[0]
	app.ui.DisplayInfo(fmt.Sprintf("Using device: %s (%s)", selectedDevice.Name, selectedDevice.Path))

	app.ui.DisplayProgress("Validating device accessibility...")
	if err := app.deviceMgr.ValidateDevice(selectedDevice); err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("device validation failed: %w", err)
	}

	app.ui.DisplayProgress("Validating configuration...")
	if err := app.cryptoProvider.ValidateConfiguration(app.config); err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	app.ui.DisplayInfo("Starting HMAC secret derivation process...")
	app.ui.DisplayInfo("You will need to touch your FIDO2 device when it blinks")

	result, err := app.cryptoProvider.DeriveHMACSecret(selectedDevice, app.Pin, app.config)
	if err != nil {
		app.ui.DisplayError(err)
		return fmt.Errorf("HMAC secret derivation failed: %w", err)
	}

	// manual test
	mode := app.config.Mode

	switch mode {
	case "enc":
		app.ui.DisplayInfo(("Encrypting file..."))
		if err := crypto.Encrypt(result.Secret); err != nil {
			app.ui.DisplayError(fmt.Errorf("encryption failed: %w", err))
			return err
		}
		app.ui.DisplaySuccess("Encryption completed!")

	case "dec":
		app.ui.DisplayInfo("Decrypting file...")
		if err := crypto.Decrypt(result.Secret); err != nil {
			app.ui.DisplayError(fmt.Errorf("decryption failed: %w", err))
			return err
		}
		app.ui.DisplaySuccess("Decryption completed!")

	default:
		app.ui.DisplayError(fmt.Errorf("invalid mode: %s (must be 'enc' or 'dec')", mode))
		return fmt.Errorf("invalid mode: %s", mode)
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
	mode := flag.String("mode", "enc", "Operation mode: encryption or decryption (enc|dec)")
	pin := flag.String("pin", "", "FIDO2 device PIN (non-interactive mode)")
	flag.Parse()

	if *pin == "" {
		fmt.Fprintln(os.Stderr, "Error: --pin is required")
		fmt.Fprintln(os.Stderr, "Usage: go run main.go --mode=enc --pin=123456")
		os.Exit(1)
	}

	app := NewApplication()
	app.keyOnly = *keyOnly
	app.config.Mode = *mode
	app.Pin = *pin // Directly assign the pin

	// Run the application and handle any errors
	if err := app.Run(); err != nil {
		app.ui.DisplayError(err)
		os.Exit(1)
	}

	os.Exit(0)
}

func init() {}
