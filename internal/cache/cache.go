package cache

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"e2e-git/internal/types"
	"e2e-git/internal/ui"
)

const cacheDuration = 30 * time.Second

// getSocketPath returns the Unix domain socket path for the current user
func getSocketPath() string {
	return "@e2e-git-cache-" + strconv.Itoa(os.Getuid())
}

// startCacheDaemon starts a detached cache daemon process
func startCacheDaemon(secret []byte) error {
	// Get current executable path
	executable, err := os.Executable()
	if err != nil {
		return err
	}

	// Start daemon process with secret as argument
	secretHex := hex.EncodeToString(secret)
	cmd := exec.Command(executable, "--cache-daemon", secretHex)

	// Detach from parent process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	// Start the daemon
	return cmd.Start()
}

// runCacheDaemon runs the cache daemon (called when --cache-daemon flag is used)
func RunCacheDaemon(secretHex string) {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return
	}

	socketPath := getSocketPath()

	// Create Unix domain socket (abstract namespace - no filesystem)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return // Fail silently if we can't create the socket
	}
	defer listener.Close()

	// Set timeout for the entire server
	timeout := time.After(cacheDuration)

	for {
		select {
		case <-timeout:
			return // Exit after timeout
		default:
			// Set a short accept timeout to check for server timeout
			if tcpListener, ok := listener.(*net.UnixListener); ok {
				tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
			}
			if conn, err := listener.Accept(); err == nil {
				// Send the secret to the client
				conn.Write(secret)
				conn.Close()
			}
		}
	}
}

// tryGetCachedSecret attempts to retrieve a cached secret from the cache server
func tryGetCachedSecret() []byte {
	socketPath := getSocketPath()

	// Try to connect to cache server
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil // No cache server running
	}
	defer conn.Close()

	// Read the secret
	secret := make([]byte, 32)
	n, err := conn.Read(secret)
	if err != nil || n != 32 {
		return nil
	}

	return secret
}

// GetSecretWithCache attempts to get a cached secret, or derives a new one
func GetSecretWithCache(app *types.Application, selectedDevice *types.DeviceInfo, pin string) ([]byte, error) {
	// Try to get from cache first
	if secret := tryGetCachedSecret(); secret != nil {
		return secret, nil
	}

	// Cache miss - perform FIDO2 operation
	result, err := app.CryptoProvider.DeriveHMACSecret(selectedDevice, pin, app.Config)
	if err != nil {
		return nil, err
	}

	// Start cache daemon as separate process
	startCacheDaemon(result.Secret)

	// Give the cache daemon a moment to start up
	time.Sleep(200 * time.Millisecond)

	return result.Secret, nil
}

// GetSecretWithFullCache handles the complete authentication flow with caching
func GetSecretWithFullCache(app *types.Application) ([]byte, error) {
	// Try to get from cache first
	if secret := tryGetCachedSecret(); secret != nil {
		return secret, nil
	}

	// Cache miss - need to perform full FIDO2 authentication
	app.UI.DisplayDebug("Searching for FIDO2 devices...")
	devices, err := app.DeviceMgr.ListDevices()
	if err != nil {
		app.UI.DisplayError(err)
		return nil, err
	}

	app.UI.DisplayDebug(fmt.Sprintf("Found %d FIDO2 device(s)", len(devices)))

	// Automatically select the first available device
	selectedDevice, err := app.DeviceMgr.SelectFirstDevice(devices)
	if err != nil {
		app.UI.DisplayError(err)
		return nil, err
	}

	app.UI.DisplayDebug("Validating device accessibility...")
	if err := app.DeviceMgr.ValidateDevice(selectedDevice); err != nil {
		app.UI.DisplayError(err)
		return nil, err
	}

	// PIN retrieval
	var pin string
	if app.PinEnvVar != "" {
		pin, err = app.UI.GetPINFromEnvironment(app.PinEnvVar)
		if err != nil {
			app.UI.DisplayError(err)
			return nil, err
		}
		if app.LogLevel == "info" {
			app.UI.DisplayInfo(fmt.Sprintf("Using FIDO2 PIN from environment variable '%s'", app.PinEnvVar))
		}
	} else if app.Pinentry != "" {
		if display, ok := app.UI.(*ui.Display); ok {
			pin, err = display.GetPINWithSpecificPinentryForOperation("PIN:", app.Pinentry, app.Config.Mode)
		} else {
			pin, err = app.UI.GetPINWithSpecificPinentry("PIN:", app.Pinentry)
		}
		if err != nil {
			app.UI.DisplayError(err)
			return nil, err
		}
		if pin == "" {
			app.UI.DisplayError(fmt.Errorf("PIN is required for FIDO2 operations"))
			return nil, fmt.Errorf("no PIN provided")
		}
		if app.LogLevel == "info" {
			app.UI.DisplayInfo(fmt.Sprintf("Using FIDO2 PIN from pinentry program '%s'", app.Pinentry))
		}
	} else {
		err := fmt.Errorf("PIN input method required")
		app.UI.DisplayError(err)
		return nil, err
	}

	app.UI.DisplayDebug("Starting HMAC secret derivation process...")

	// Perform FIDO2 operation
	result, err := app.CryptoProvider.DeriveHMACSecret(selectedDevice, pin, app.Config)
	if err != nil {
		app.UI.DisplayError(err)
		return nil, err
	}

	// Start cache daemon as separate process
	startCacheDaemon(result.Secret)

	// Give the cache daemon a moment to start up
	time.Sleep(200 * time.Millisecond)

	return result.Secret, nil
}
