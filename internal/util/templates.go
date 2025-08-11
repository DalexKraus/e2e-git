package util

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TemplateConfig holds configuration values for template substitution
type TemplateConfig struct {
	BinaryPath     string
	DeviceID       string
	PinentryMethod string
}

// TemplateProcessor handles template file processing and substitution
type TemplateProcessor struct {
	TemplatesDir string
	Config       *TemplateConfig
}

// NewTemplateProcessor creates a new template processor
func NewTemplateProcessor(templatesDir string, config *TemplateConfig) *TemplateProcessor {
	return &TemplateProcessor{
		TemplatesDir: templatesDir,
		Config:       config,
	}
}

// ReadTemplate reads a template file from the templates directory
func (tp *TemplateProcessor) ReadTemplate(templateName string) (string, error) {
	templatePath := filepath.Join(tp.TemplatesDir, templateName)
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template %s: %w", templateName, err)
	}
	return string(content), nil
}

// ProcessTemplate reads a template and substitutes placeholders with config values
func (tp *TemplateProcessor) ProcessTemplate(templateName string) (string, error) {
	content, err := tp.ReadTemplate(templateName)
	if err != nil {
		return "", err
	}

	// Substitute template placeholders
	content = strings.ReplaceAll(content, "{{BINARY_PATH}}", tp.Config.BinaryPath)
	content = strings.ReplaceAll(content, "{{DEVICE_ID}}", tp.Config.DeviceID)
	content = strings.ReplaceAll(content, "{{PINENTRY_METHOD}}", tp.Config.PinentryMethod)

	return content, nil
}

// GetPreCommitHook processes the pre-commit hook template
func (tp *TemplateProcessor) GetPreCommitHook() (string, error) {
	return tp.ProcessTemplate("pre-commit.template")
}

// GetFilterWrapper processes the filter wrapper template
func (tp *TemplateProcessor) GetFilterWrapper() (string, error) {
	return tp.ProcessTemplate("filter-wrapper.template")
}

// ValidateTemplates checks if all required template files exist
func (tp *TemplateProcessor) ValidateTemplates() error {
	requiredTemplates := []string{
		"pre-commit.template",
		"filter-wrapper.template",
	}

	for _, template := range requiredTemplates {
		templatePath := filepath.Join(tp.TemplatesDir, template)
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			return fmt.Errorf("required template file not found: %s", templatePath)
		}
	}

	return nil
}

// DetectBinaryPath attempts to find the e2e-git binary path
func DetectBinaryPath() (string, error) {
	// e2e-git must be in PATH, otherwise tempaltes cannot be created
	if path, err := exec.LookPath("e2e-git"); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("e2e-git binary not found in PATH")
}
