package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"e2e-git/internal/types"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// expandPathsWithStats takes a list of paths and expands directories to their constituent files
// Returns the expanded files and statistics about folders and files processed
func expandPathsWithStats(paths []string) ([]string, *types.ProcessingStats, error) {
	var expandedFiles []string
	stats := &types.ProcessingStats{}

	for _, path := range paths {
		if strings.HasSuffix(path, "/") {
			// Directory path - walk recursively
			stats.TotalFolders++
			err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					if filePath != path { // Don't count the root directory again
						stats.TotalFolders++
					}
					return nil
				}

				// Skip .cred files
				if strings.HasSuffix(filePath, ".cred") {
					return nil
				}

				expandedFiles = append(expandedFiles, filePath)
				stats.TotalFiles++
				return nil
			})
			if err != nil {
				return nil, nil, fmt.Errorf("failed to walk directory %s: %w", path, err)
			}
		} else {
			// Check if it's a directory without trailing slash
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				// Directory without trailing slash - walk recursively
				stats.TotalFolders++
				err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						if filePath != path { // Don't count the root directory again
							stats.TotalFolders++
						}
						return nil
					}

					// Skip .cred files
					if strings.HasSuffix(filePath, ".cred") {
						return nil
					}

					expandedFiles = append(expandedFiles, filePath)
					stats.TotalFiles++
					return nil
				})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to walk directory %s: %w", path, err)
				}
			} else {
				// Regular file path
				expandedFiles = append(expandedFiles, path)
				stats.TotalFiles++
			}
		}
	}

	return expandedFiles, stats, nil
}

// printProgressBar displays a progress bar for file processing
func printProgressBar(current, total int, prefix string) {
	if total == 0 {
		return
	}

	barWidth := 40
	progress := float64(current) / float64(total)
	filledWidth := int(progress * float64(barWidth))

	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)
	percentage := int(progress * 100)

	fmt.Printf("\r%s [%s] %d%% (%d/%d)", prefix, bar, percentage, current, total)

	if current == total {
		fmt.Println() // New line when complete
	}
}

// EncryptFiles encrypts multiple files atomically using AES-256-GCM.
// All files are backed up with .bak extension before processing.
// If any operation fails, all files are restored from backups.
func EncryptFiles(secret []byte, filePaths []string) error {
	// Expand directories to individual files and get statistics
	expandedPaths, stats, err := expandPathsWithStats(filePaths)
	if err != nil {
		return fmt.Errorf("failed to expand paths: %w", err)
	}

	// Display initial message with file and folder counts
	if stats.TotalFolders > 0 {
		fmt.Printf("[+] Encrypting %d file(s) from %d folder(s)...\n", stats.TotalFiles, stats.TotalFolders)
	} else {
		fmt.Printf("[+] Encrypting %d file(s)...\n", stats.TotalFiles)
	}

	// Create AES-GCM cipher once for all files (performance optimization)
	if len(secret) != 32 {
		return fmt.Errorf("secret must be 32 bytes for AES-256, got %d bytes", len(secret))
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	backups := make(map[string]string)
	temps := make(map[string]string)

	// Create backups with progress
	for i, filePath := range expandedPaths {
		printProgressBar(i+1, len(expandedPaths), "Creating backups")
		backupPath := filePath + ".bak"
		if err := copyFile(filePath, backupPath); err != nil {
			fmt.Println() // New line after progress bar
			cleanupBackups(backups)
			return fmt.Errorf("failed to create backup for %s: %w", filePath, err)
		}
		backups[filePath] = backupPath
	}

	// Encrypt to temporary files with progress
	for i, filePath := range expandedPaths {
		printProgressBar(i+1, len(expandedPaths), "Encrypting files")
		tempPath := filePath + ".encrypted.tmp"

		// Read file
		plaintext, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("failed to read %s: %w", filePath, err)
		}

		// Generate random nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("failed to generate nonce: %w", err)
		}

		// Encrypt
		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

		// Write encrypted file
		if err := os.WriteFile(tempPath, ciphertext, 0644); err != nil {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("failed to write encrypted %s: %w", tempPath, err)
		}

		temps[filePath] = tempPath
		stats.ProcessedFiles++
	}

	// Atomic replacement (only if all succeeded)
	for original, temp := range temps {
		if err := os.Rename(temp, original); err != nil {
			restoreFromBackups(backups)
			return fmt.Errorf("failed to replace %s: %w", original, err)
		}
	}

	// Cleanup backups on success
	cleanupBackups(backups)
	return nil
}

// DecryptFiles decrypts multiple files atomically using AES-256-GCM.
// All files are backed up with .bak extension before processing.
// If any operation fails, all files are restored from backups.
func DecryptFiles(secret []byte, filePaths []string) error {
	// Expand directories to individual files and get statistics
	expandedPaths, stats, err := expandPathsWithStats(filePaths)
	if err != nil {
		return fmt.Errorf("failed to expand paths: %w", err)
	}

	// Display initial message with file and folder counts
	if stats.TotalFolders > 0 {
		fmt.Printf("[+] Decrypting %d file(s) from %d folder(s)...\n", stats.TotalFiles, stats.TotalFolders)
	} else {
		fmt.Printf("[+] Decrypting %d file(s)...\n", stats.TotalFiles)
	}

	// Create AES-GCM cipher once for all files (performance optimization)
	if len(secret) != 32 {
		return fmt.Errorf("secret must be 32 bytes for AES-256, got %d bytes", len(secret))
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	backups := make(map[string]string)
	temps := make(map[string]string)

	// Create backups with progress
	for i, filePath := range expandedPaths {
		printProgressBar(i+1, len(expandedPaths), "Creating backups")
		backupPath := filePath + ".bak"
		if err := copyFile(filePath, backupPath); err != nil {
			fmt.Println() // New line after progress bar
			cleanupBackups(backups)
			return fmt.Errorf("failed to create backup for %s: %w", filePath, err)
		}
		backups[filePath] = backupPath
	}

	// Decrypt to temporary files with progress
	for i, filePath := range expandedPaths {
		printProgressBar(i+1, len(expandedPaths), "Decrypting files")
		tempPath := filePath + ".decrypted.tmp"

		// Read encrypted file
		ciphertext, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("failed to read %s: %w", filePath, err)
		}

		// Extract nonce and decrypt
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("ciphertext too short in %s", filePath)
		}

		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("failed to decrypt %s: %w", filePath, err)
		}

		// Write decrypted file
		if err := os.WriteFile(tempPath, plaintext, 0644); err != nil {
			fmt.Println() // New line after progress bar
			restoreFromBackups(backups)
			cleanupTemps(temps)
			return fmt.Errorf("failed to write decrypted %s: %w", tempPath, err)
		}

		temps[filePath] = tempPath
		stats.ProcessedFiles++
	}

	// Atomic replacement (only if all succeeded)
	for original, temp := range temps {
		if err := os.Rename(temp, original); err != nil {
			restoreFromBackups(backups)
			return fmt.Errorf("failed to replace %s: %w", original, err)
		}
	}

	// Cleanup backups on success
	cleanupBackups(backups)
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// restoreFromBackups restores all files from their backup copies
func restoreFromBackups(backups map[string]string) {
	for original, backup := range backups {
		if err := os.Rename(backup, original); err != nil {
			// Log error but continue trying to restore other files
			fmt.Fprintf(os.Stderr, "Warning: failed to restore %s from backup: %v\n", original, err)
		}
	}
}

// cleanupBackups removes all backup files
func cleanupBackups(backups map[string]string) {
	for _, backup := range backups {
		if err := os.Remove(backup); err != nil {
			// Log error but continue cleanup
			fmt.Fprintf(os.Stderr, "Warning: failed to cleanup backup %s: %v\n", backup, err)
		}
	}
}

// cleanupTemps removes all temporary files
func cleanupTemps(temps map[string]string) {
	for _, temp := range temps {
		if err := os.Remove(temp); err != nil {
			// Log error but continue cleanup
			fmt.Fprintf(os.Stderr, "Warning: failed to cleanup temp file %s: %v\n", temp, err)
		}
	}
}
