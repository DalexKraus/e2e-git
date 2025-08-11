package util

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitRepository represents a git repository and provides operations for configuration
type GitRepository struct {
	Path string
}

// NewGitRepository creates a new GitRepository instance
func NewGitRepository(path string) *GitRepository {
	return &GitRepository{Path: path}
}

// IsGitRepository checks if the given path is inside a git repository
func (gr *GitRepository) IsGitRepository() (bool, error) {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = gr.Path
	err := cmd.Run()
	return err == nil, nil
}

// GetGitDir returns the .git directory path
func (gr *GitRepository) GetGitDir() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = gr.Path
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get git directory: %w", err)
	}

	gitDir := strings.TrimSpace(string(output))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(gr.Path, gitDir)
	}

	return gitDir, nil
}

// GetHooksDir returns the git hooks directory path
func (gr *GitRepository) GetHooksDir() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-path", "hooks")
	cmd.Dir = gr.Path
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get hooks directory: %w", err)
	}

	hooksDir := strings.TrimSpace(string(output))
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(gr.Path, hooksDir)
	}

	return hooksDir, nil
}

// SetConfig sets a git configuration value
func (gr *GitRepository) SetConfig(key, value string) error {
	cmd := exec.Command("git", "config", key, value)
	cmd.Dir = gr.Path
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set git config %s=%s: %w", key, value, err)
	}
	return nil
}

// ConfigureFilter sets up the git filter configuration
func (gr *GitRepository) ConfigureFilter(filterName, cleanCommand, smudgeCommand string) error {
	configs := map[string]string{
		fmt.Sprintf("filter.%s.clean", filterName):    cleanCommand,
		fmt.Sprintf("filter.%s.smudge", filterName):   smudgeCommand,
		fmt.Sprintf("filter.%s.required", filterName): "true",
	}

	for key, value := range configs {
		if err := gr.SetConfig(key, value); err != nil {
			return err
		}
	}

	return nil
}

// SetAlias creates a git alias
func (gr *GitRepository) SetAlias(aliasName, command string) error {
	return gr.SetConfig(fmt.Sprintf("alias.%s", aliasName), command)
}

// InstallHook copies a hook file to the git hooks directory and makes it executable
func (gr *GitRepository) InstallHook(hookName, sourceContent string) error {
	hooksDir, err := gr.GetHooksDir()
	if err != nil {
		return err
	}

	// Ensure hooks directory exists
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, hookName)

	// Write hook content
	if err := os.WriteFile(hookPath, []byte(sourceContent), 0755); err != nil {
		return fmt.Errorf("failed to write hook file: %w", err)
	}

	return nil
}

// InstallFilterScript installs a filter script in the repository
func (gr *GitRepository) InstallFilterScript(scriptName, content string) error {
	scriptPath := filepath.Join(gr.Path, scriptName)

	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("failed to write filter script: %w", err)
	}

	return nil
}
