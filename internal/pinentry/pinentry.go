// Package pinentry provides secure PIN input using the pinentry program.
// This package handles communication with pinentry for secure password/PIN input
// on macOS and other Unix-like systems.
package pinentry

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// PinentryClient handles communication with the pinentry program.
type PinentryClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	reader *bufio.Reader
}

// IsAvailable checks if pinentry is available on the system.
// It looks for pinentry in common macOS locations.
func IsAvailable() bool {
	// Common pinentry locations on macOS
	locations := []string{
		"/usr/local/bin/pinentry-gtk",
		"/opt/homebrew/bin/pinentry-gtk",
		"/usr/local/bin/pinentry",
		"/opt/homebrew/bin/pinentry",
		"/usr/bin/pinentry",
		"pinentry-gtk", // Check PATH
		"pinentry",     // Check PATH
	}

	for _, location := range locations {
		if _, err := exec.LookPath(location); err == nil {
			return true
		}
	}

	return false
}

// findPinentry finds the best available pinentry program.
func findPinentry() string {
	// Prefer pinentry-gtk on macOS for native GUI
	preferred := []string{
		"/usr/local/bin/pinentry-gtk",
		"/opt/homebrew/bin/pinentry-gtk",
		"pinentry-gtk",
	}

	for _, location := range preferred {
		if path, err := exec.LookPath(location); err == nil {
			return path
		}
	}

	// Fall back to generic pinentry
	fallback := []string{
		"/usr/local/bin/pinentry",
		"/opt/homebrew/bin/pinentry",
		"/usr/bin/pinentry",
		"pinentry",
	}

	for _, location := range fallback {
		if path, err := exec.LookPath(location); err == nil {
			return path
		}
	}

	return ""
}

// NewClient creates a new pinentry client.
func NewClient() (*PinentryClient, error) {
	pinentryPath := findPinentry()
	if pinentryPath == "" {
		return nil, fmt.Errorf("pinentry not found")
	}

	cmd := exec.Command(pinentryPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to start pinentry: %w", err)
	}

	client := &PinentryClient{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		reader: bufio.NewReader(stdout),
	}

	// Read the initial OK response
	if err := client.expectOK(); err != nil {
		client.Close()
		return nil, fmt.Errorf("pinentry initialization failed: %w", err)
	}

	return client, nil
}

// sendCommand sends a command to pinentry and returns the response.
func (c *PinentryClient) sendCommand(command string) error {
	_, err := fmt.Fprintf(c.stdin, "%s\n", command)
	return err
}

// readResponse reads a response line from pinentry.
func (c *PinentryClient) readResponse() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// expectOK reads a response and expects it to be "OK".
func (c *PinentryClient) expectOK() error {
	response, err := c.readResponse()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("expected OK, got: %s", response)
	}
	return nil
}

// GetPIN prompts for a PIN using pinentry and returns it.
func (c *PinentryClient) GetPIN(prompt, description string) (string, error) {
	// Set the description
	if description != "" {
		if err := c.sendCommand(fmt.Sprintf("SETDESC %s", description)); err != nil {
			return "", fmt.Errorf("failed to set description: %w", err)
		}
		if err := c.expectOK(); err != nil {
			return "", fmt.Errorf("failed to set description: %w", err)
		}
	}

	// Set the prompt
	if prompt != "" {
		if err := c.sendCommand(fmt.Sprintf("SETPROMPT %s", prompt)); err != nil {
			return "", fmt.Errorf("failed to set prompt: %w", err)
		}
		if err := c.expectOK(); err != nil {
			return "", fmt.Errorf("failed to set prompt: %w", err)
		}
	}

	// Get the PIN
	if err := c.sendCommand("GETPIN"); err != nil {
		return "", fmt.Errorf("failed to send GETPIN command: %w", err)
	}

	response, err := c.readResponse()
	if err != nil {
		return "", fmt.Errorf("failed to read PIN response: %w", err)
	}

	if strings.HasPrefix(response, "D ") {
		// PIN data follows "D "
		pin := strings.TrimPrefix(response, "D ")
		// Read the OK response
		if err := c.expectOK(); err != nil {
			return "", fmt.Errorf("failed to get OK after PIN: %w", err)
		}
		return pin, nil
	} else if strings.HasPrefix(response, "ERR") {
		if strings.Contains(response, "83886179") { // User cancelled
			return "", fmt.Errorf("PIN entry cancelled by user")
		}
		return "", fmt.Errorf("pinentry error: %s", response)
	}

	return "", fmt.Errorf("unexpected response: %s", response)
}

// Close closes the pinentry client and terminates the process.
func (c *PinentryClient) Close() error {
	var err error

	// Send BYE command to cleanly exit
	if c.stdin != nil {
		c.sendCommand("BYE")
		c.stdin.Close()
	}

	if c.stdout != nil {
		c.stdout.Close()
	}

	if c.cmd != nil && c.cmd.Process != nil {
		if waitErr := c.cmd.Wait(); waitErr != nil {
			err = waitErr
		}
	}

	return err
}

// GetPINWithPinentry is a convenience function that creates a pinentry client,
// gets a PIN, and cleans up automatically.
func GetPINWithPinentry(prompt, description string) (string, error) {
	if !IsAvailable() {
		return "", fmt.Errorf("pinentry is not available on this system.\n\n"+
			"To install pinentry on macOS:\n"+
			"  brew install pinentry-gtk\n\n"+
			"Alternatively, use the environment variable method:\n"+
			"  export FIDO2_PIN=\"your_pin_here\"\n"+
			"  %s --pin-environment-variable=FIDO2_PIN ...", os.Args[0])
	}

	client, err := NewClient()
	if err != nil {
		return "", fmt.Errorf("failed to create pinentry client: %w.\n\n"+
			"Please use the environment variable method instead:\n"+
			"  export FIDO2_PIN=\"your_pin_here\"\n"+
			"  %s --pin-environment-variable=FIDO2_PIN ...", err, os.Args[0])
	}
	defer client.Close()

	pin, err := client.GetPIN(prompt, description)
	if err != nil {
		return "", fmt.Errorf("failed to get PIN from pinentry: %w.\n\n"+
			"Please use the environment variable method instead:\n"+
			"  export FIDO2_PIN=\"your_pin_here\"\n"+
			"  %s --pin-environment-variable=FIDO2_PIN ...", err, os.Args[0])
	}

	return pin, nil
}

// GetPINWithSpecificPinentry is a convenience function that uses a specific pinentry program
// to get a PIN, and cleans up automatically.
func GetPINWithSpecificPinentry(prompt, description, pinentryProgram string) (string, error) {
	// Check if the specified pinentry program exists
	pinentryPath, err := exec.LookPath(pinentryProgram)
	if err != nil {
		return "", fmt.Errorf("specified pinentry program '%s' not found: %w.\n\n"+
			"Please use the environment variable method instead:\n"+
			"  export FIDO2_PIN=\"your_pin_here\"\n"+
			"  %s --pin-environment-variable=FIDO2_PIN ...", pinentryProgram, err, os.Args[0])
	}

	// Create a custom client with the specified pinentry program
	cmd := exec.Command(pinentryPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return "", fmt.Errorf("failed to start pinentry '%s': %w", pinentryProgram, err)
	}

	client := &PinentryClient{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		reader: bufio.NewReader(stdout),
	}
	defer client.Close()

	// Read the initial OK response
	if err := client.expectOK(); err != nil {
		return "", fmt.Errorf("pinentry initialization failed: %w", err)
	}

	pin, err := client.GetPIN(prompt, description)
	if err != nil {
		return "", fmt.Errorf("failed to get PIN from pinentry '%s': %w.\n\n"+
			"Please use the environment variable method instead:\n"+
			"  export FIDO2_PIN=\"your_pin_here\"\n"+
			"  %s --pin-environment-variable=FIDO2_PIN ...", pinentryProgram, err, os.Args[0])
	}

	return pin, nil
}
