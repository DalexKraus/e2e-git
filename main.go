package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"e2e-git/internal/crypto"
	"e2e-git/internal/device"
	"e2e-git/internal/types"
	"e2e-git/internal/ui"
	"e2e-git/internal/util"
)

func NewApplication() *types.Application {
	uiProvider := ui.NewDisplay()
	deviceManager := device.NewManager(uiProvider)
	cryptoProvider := crypto.NewProvider(uiProvider)
	config := types.DefaultConfiguration()

	return &types.Application{
		UI:             uiProvider,
		DeviceMgr:      deviceManager,
		CryptoProvider: cryptoProvider,
		Config:         config,
	}
}

// runApplication executes the main application workflow.
// This is the primary entry point that orchestrates the entire process.
func runApplication(app *types.Application) error {
	app.UI.DisplayWelcome()

	app.UI.DisplayDebug("Searching for FIDO2 devices...")
	devices, err := app.DeviceMgr.ListDevices()
	if err != nil {
		app.UI.DisplayError(err)
		return fmt.Errorf("device discovery failed: %w", err)
	}

	app.UI.DisplayDebug(fmt.Sprintf("Found %d FIDO2 device(s)", len(devices)))

	// Device selection: use specified device path or interactive selection
	var selectedDevice *types.DeviceInfo
	if app.FidoDevice != "" {
		// Non-interactive mode: select device by path
		selectedDevice, err = app.DeviceMgr.SelectDeviceByPath(devices, app.FidoDevice)
		if err != nil {
			app.UI.DisplayError(err)
			return fmt.Errorf("device selection by path failed: %w", err)
		}
	} else {
		// Interactive mode: let user select device
		selectedDevice, err = app.DeviceMgr.SelectDevice(devices)
		if err != nil {
			app.UI.DisplayError(err)
			return fmt.Errorf("device selection failed: %w", err)
		}
	}

	app.UI.DisplayDebug("Validating device accessibility...")
	if err := app.DeviceMgr.ValidateDevice(selectedDevice); err != nil {
		app.UI.DisplayError(err)
		return fmt.Errorf("device validation failed: %w", err)
	}

	// PIN retrieval: require either environment variable or pinentry
	var pin string
	if app.PinEnvVar != "" {
		// Use PIN from environment variable
		pin, err = app.UI.GetPINFromEnvironment(app.PinEnvVar)
		if err != nil {
			app.UI.DisplayError(err)
			return fmt.Errorf("PIN retrieval from environment failed: %w", err)
		}
		// Show PIN source for info level
		if app.LogLevel == "info" {
			app.UI.DisplayInfo(fmt.Sprintf("Using FIDO2 PIN from environment variable '%s'", app.PinEnvVar))
		}
	} else if app.Pinentry != "" {
		// Use specified pinentry program for secure PIN input with operation-specific text
		if display, ok := app.UI.(*ui.Display); ok {
			pin, err = display.GetPINWithSpecificPinentryForOperation("PIN:", app.Pinentry, app.Config.Mode)
		} else {
			pin, err = app.UI.GetPINWithSpecificPinentry("PIN:", app.Pinentry)
		}
		if err != nil {
			app.UI.DisplayError(err)
			return fmt.Errorf("PIN retrieval with pinentry failed: %w", err)
		}
		if pin == "" {
			app.UI.DisplayError(fmt.Errorf("PIN is required for FIDO2 operations"))
			return fmt.Errorf("no PIN provided")
		}
		// Show PIN source for info level
		if app.LogLevel == "info" {
			app.UI.DisplayInfo(fmt.Sprintf("Using FIDO2 PIN from pinentry program '%s'", app.Pinentry))
		}
	} else {
		// Neither environment variable nor pinentry specified - fail
		err := fmt.Errorf("PIN input method required. Use either:\n" +
			"  --pin-environment-variable=VAR_NAME (to use environment variable)\n" +
			"  --pinentry=PROGRAM (to use pinentry program, e.g., pinentry-gtk)")
		app.UI.DisplayError(err)
		return err
	}

	app.UI.DisplayDebug("Validating configuration...")
	if err := app.CryptoProvider.ValidateConfiguration(app.Config); err != nil {
		app.UI.DisplayError(err)
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	app.UI.DisplayDebug("Starting HMAC secret derivation process...")

	result, err := app.CryptoProvider.DeriveHMACSecret(selectedDevice, pin, app.Config)
	if err != nil {
		app.UI.DisplayError(err)
		return fmt.Errorf("HMAC secret derivation failed: %w", err)
	}

	// If --key-only is specified, output the key and exit early
	if app.KeyOnly {
		app.UI.OutputKeyOnly(result)
		return nil
	}

	// Handles the selected operation mode ("enc" or "dec")
	mode := app.Config.Mode
	operationStartTime := time.Now()

	switch mode {
	case "enc":
		if err := crypto.EncryptFiles(result.Secret, app.FilePaths); err != nil {
			app.UI.DisplayError(fmt.Errorf("encryption failed: %w", err))
			return err
		}
		operationDuration := time.Since(operationStartTime)
		if app.LogLevel == "info" {
			app.UI.DisplayInfo(fmt.Sprintf("Encryption completed in %v", operationDuration.Truncate(time.Millisecond)))
		} else {
			app.UI.DisplayInfo("Encryption completed!")
		}

	case "dec":
		if err := crypto.DecryptFiles(result.Secret, app.FilePaths); err != nil {
			app.UI.DisplayError(fmt.Errorf("decryption failed: %w", err))
			return err
		}
		operationDuration := time.Since(operationStartTime)
		if app.LogLevel == "info" {
			app.UI.DisplayInfo(fmt.Sprintf("Decryption completed in %v", operationDuration.Truncate(time.Millisecond)))
		} else {
			app.UI.DisplayInfo("Decryption completed!")
		}

	default:
		app.UI.DisplayError(fmt.Errorf("invalid mode: %s (must be 'enc' or 'dec')", mode))
		return fmt.Errorf("invalid mode: %s", mode)
	}

	app.UI.DisplayResults(result)

	return nil
}

func main() {
	uiProvider := ui.NewDisplay()

	// Check for init subcommand first
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "init" {
		handleInitCommand(args[1:], uiProvider)
		return
	}

	// Parse CLI flags for normal operation
	keyOnly := flag.Bool("key-only", false, "Output only the derived key to stdout (useful for scripting)")
	mode := flag.String("mode", "", "Operation mode: encryption or decryption (enc|dec)")
	fidoDevice := flag.String("fido-device", "", "Specify FIDO device path (e.g., /dev/hidraw10) to skip device selection")
	pinEnvVar := flag.String("pin-environment-variable", "", "Environment variable name containing the PIN")
	pinentry := flag.String("pinentry", "", "Pinentry program to use for secure PIN input (e.g., pinentry-gtk, /usr/local/bin/pinentry-gtk)")
	logLevel := flag.String("log-level", "info", "Log level: info or debug")
	flag.Parse()

	// Get file paths from remaining arguments
	filePaths := flag.Args()

	// When --key-only is used, file paths and mode are not required
	if !*keyOnly {
		if len(filePaths) == 0 {
			uiProvider.DisplayError(fmt.Errorf("at least one file path is required"))
			uiProvider.DisplayInfo("Usage: e2e-git --mode=enc (--pin-environment-variable=VAR | --pinentry=PROGRAM) [file1] [file2] ...")
			uiProvider.DisplayInfo("       e2e-git --key-only (--pin-environment-variable=VAR | --pinentry=PROGRAM)")
			uiProvider.DisplayInfo("       e2e-git init <repository-path>")
			uiProvider.DisplayInfo("")
			uiProvider.DisplayInfo("PIN Input Methods (one required):")
			uiProvider.DisplayInfo("  --pin-environment-variable=VAR    Use environment variable")
			uiProvider.DisplayInfo("  --pinentry=PROGRAM                Use pinentry program (e.g., pinentry-gtk)")
			os.Exit(1)
		}

		// Validate mode is provided (only when not using --key-only)
		if *mode == "" {
			uiProvider.DisplayError(fmt.Errorf("--mode is required"))
			uiProvider.DisplayInfo("Usage: e2e-git --mode=enc (--pin-environment-variable=VAR | --pinentry=PROGRAM) [file1] [file2] ...")
			uiProvider.DisplayInfo("       e2e-git --key-only (--pin-environment-variable=VAR | --pinentry=PROGRAM)")
			uiProvider.DisplayInfo("       e2e-git init <repository-path>")
			uiProvider.DisplayInfo("")
			uiProvider.DisplayInfo("PIN Input Methods (one required):")
			uiProvider.DisplayInfo("  --pin-environment-variable=VAR    Use environment variable")
			uiProvider.DisplayInfo("  --pinentry=PROGRAM                Use pinentry program (e.g., pinentry-gtk)")
			os.Exit(1)
		}
	}

	// Create the application instance
	app := NewApplication()
	app.KeyOnly = *keyOnly
	app.Config.Mode = *mode
	app.FidoDevice = *fidoDevice
	app.PinEnvVar = *pinEnvVar
	app.Pinentry = *pinentry
	app.FilePaths = filePaths
	app.LogLevel = *logLevel

	// Set log level on UI provider
	if display, ok := app.UI.(*ui.Display); ok {
		display.SetLogLevel(*logLevel)
	}

	// Run the application and handle any errors
	if err := runApplication(app); err != nil {
		app.UI.DisplayError(err)
		os.Exit(1)
	}

	// Success - exit with code 0 (this is implicit, but explicit for clarity)
}

// Handle the "init" subcommand to initialize a git-repository for use with e2e-git.
func handleInitCommand(args []string, uiProvider *ui.Display) {
	// Parse init command flags
	initFlags := flag.NewFlagSet("init", flag.ExitOnError)
	pinentryMethod := initFlags.String("pinentry", "", "Pinentry program to use (required, e.g., pinentry-gtk, pinentry-gtk)")
	initFlags.Parse(args)

	remainingArgs := initFlags.Args()
	if len(remainingArgs) == 0 {
		uiProvider.DisplayError(fmt.Errorf("repository path is required"))
		uiProvider.DisplayInfo("Usage: e2e-git init --pinentry=PROGRAM <repository-path>")
		uiProvider.DisplayInfo("Example: e2e-git init --pinentry=pinentry-gtk .")
		os.Exit(1)
	}

	if *pinentryMethod == "" {
		uiProvider.DisplayError(fmt.Errorf("--pinentry is required"))
		uiProvider.DisplayInfo("Usage: e2e-git init --pinentry=PROGRAM <repository-path>")
		uiProvider.DisplayInfo("Example: e2e-git init --pinentry=pinentry-gtk .")
		os.Exit(1)
	}

	targetPath := remainingArgs[0]

	// Convert to absolute path
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		uiProvider.DisplayError(fmt.Errorf("failed to resolve path '%s': %v", targetPath, err))
		os.Exit(1)
	}

	// Create configuration without device ID
	config := &types.InitConfig{
		TargetPath:     absPath,
		PinentryMethod: *pinentryMethod,
	}

	// Create and execute init command
	initCmd := &types.InitCommand{Config: config}

	// Validate configuration
	if config.TargetPath == "" {
		uiProvider.DisplayError(fmt.Errorf("target path is required"))
		os.Exit(1)
	}

	if config.PinentryMethod == "" {
		uiProvider.DisplayError(fmt.Errorf("pinentry method is required"))
		os.Exit(1)
	}

	// Execute initialization
	uiProvider.DisplayInfo(fmt.Sprintf("Initializing git repository at: %s", absPath))
	if err := executeInitCommand(initCmd); err != nil {
		uiProvider.DisplayError(fmt.Errorf("initialization failed: %v", err))
		os.Exit(1)
	}

	uiProvider.DisplayInfo("Git repository initialized successfully!")
	uiProvider.DisplayInfo("    - Pre-commit hook installed")
	uiProvider.DisplayInfo("    - Git filter 'crypt' configured")
	uiProvider.DisplayInfo("    - Git aliases 'enc' and 'dec' added")
	uiProvider.DisplayInfo("    - Filter wrapper script installed")
	uiProvider.DisplayInfo("")
	uiProvider.DisplayInfo("Mark files for encryption in .gitattributes e.g.:")
	uiProvider.DisplayInfo("secrets/** filter=crypt")
}

// executeInitCommand executes the initialization logic
func executeInitCommand(initCmd *types.InitCommand) error {
	// Use the util package's InitCommand instead
	utilConfig := &util.InitConfig{
		TargetPath:     initCmd.Config.TargetPath,
		PinentryMethod: initCmd.Config.PinentryMethod,
	}

	utilInitCmd := util.NewInitCommand(utilConfig)
	return utilInitCmd.Execute()
}

func init() {}
