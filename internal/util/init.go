package util

import (
	"fmt"
	"path/filepath"
)

// InitConfig holds configuration for the init command
type InitConfig struct {
	TargetPath     string
	DeviceID       string
	PinentryMethod string
	BinaryPath     string
}

// InitCommand handles the initialization of a git repository with FIDO2 encryption
type InitCommand struct {
	Config *InitConfig
}

// NewInitCommand creates a new init command instance
func NewInitCommand(config *InitConfig) *InitCommand {
	return &InitCommand{Config: config}
}

// Execute runs the init command
func (ic *InitCommand) Execute() error {
	// Validate target directory is a git repository
	gitRepo := NewGitRepository(ic.Config.TargetPath)
	isGit, err := gitRepo.IsGitRepository()
	if err != nil {
		return fmt.Errorf("failed to check if directory is a git repository: %w", err)
	}
	if !isGit {
		return fmt.Errorf("target directory is not a git repository: %s", ic.Config.TargetPath)
	}

	// Detect binary path if not provided
	if ic.Config.BinaryPath == "" {
		binaryPath, err := DetectBinaryPath()
		if err != nil {
			return fmt.Errorf("failed to detect binary path: %w", err)
		}
		ic.Config.BinaryPath = binaryPath
	}

	// Get templates directory (relative to binary location)
	templatesDir, err := ic.getTemplatesDir()
	if err != nil {
		return fmt.Errorf("failed to locate templates directory: %w", err)
	}

	// Create template processor
	templateConfig := &TemplateConfig{
		BinaryPath:     ic.Config.BinaryPath,
		DeviceID:       ic.Config.DeviceID,
		PinentryMethod: ic.Config.PinentryMethod,
	}
	processor := NewTemplateProcessor(templatesDir, templateConfig)

	// Validate templates exist
	if err := processor.ValidateTemplates(); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Process and install pre-commit hook
	preCommitContent, err := processor.GetPreCommitHook()
	if err != nil {
		return fmt.Errorf("failed to process pre-commit template: %w", err)
	}

	if err := gitRepo.InstallHook("pre-commit", preCommitContent); err != nil {
		return fmt.Errorf("failed to install pre-commit hook: %w", err)
	}

	// Process and install filter wrapper
	filterContent, err := processor.GetFilterWrapper()
	if err != nil {
		return fmt.Errorf("failed to process filter template: %w", err)
	}

	if err := gitRepo.InstallFilterScript("filter-wrapper.sh", filterContent); err != nil {
		return fmt.Errorf("failed to install filter script: %w", err)
	}

	// Configure git filter
	filterScriptPath := "./filter-wrapper.sh"
	if err := gitRepo.ConfigureFilter("crypt", "cat", filterScriptPath+" decrypt"); err != nil {
		return fmt.Errorf("failed to configure git filter: %w", err)
	}

	// Add git dec alias (from e2e-init)
	decAlias := "!f(){ for f in \"$@\"; do rm -f -- \"$f\"; git checkout -- \"$f\"; done; }; f"
	if err := gitRepo.SetAlias("dec", decAlias); err != nil {
		return fmt.Errorf("failed to set git dec alias: %w", err)
	}

	// Add git enc alias (opposite of dec - stages files for encryption)
	encAlias := "!f(){ git add \"$@\"; }; f"
	if err := gitRepo.SetAlias("enc", encAlias); err != nil {
		return fmt.Errorf("failed to set git enc alias: %w", err)
	}

	return nil
}

// getTemplatesDir returns the path to the templates directory
func (ic *InitCommand) getTemplatesDir() (string, error) {
	// Templates are in hooks/ directory relative to the binary
	binaryDir := filepath.Dir(ic.Config.BinaryPath)
	templatesDir := filepath.Join(binaryDir, "hooks")
	return templatesDir, nil
}

// ValidateConfig validates the init configuration
func (ic *InitCommand) ValidateConfig() error {
	if ic.Config.TargetPath == "" {
		return fmt.Errorf("target path is required")
	}

	if ic.Config.DeviceID == "" {
		return fmt.Errorf("device ID is required")
	}

	if ic.Config.PinentryMethod == "" {
		return fmt.Errorf("pinentry method is required")
	}

	return nil
}
