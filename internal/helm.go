package internal

import (
	"fmt"
	"time"

	"github.com/magefile/mage/sh"
)

// ReleaseExists checks if a helm release exists
func ReleaseExists(name string) (bool, error) {
	err := sh.Run("helm", "status", name)
	if err != nil {
		// If helm status fails, the release doesn't exist
		return false, nil
	}
	return true, nil
}

// EnsureHelmRepo adds a helm repository if it doesn't already exist
func EnsureHelmRepo(name, url string) error {
	fmt.Printf("📦 Ensuring helm repository '%s' is available...\n", name)
	return sh.Run("helm", "repo", "add", name, url)
}

// WaitForNamespaceDeleted waits for a namespace to be completely deleted
func WaitForNamespaceDeleted(namespace string) error {
	fmt.Printf("⏳ Waiting for namespace '%s' to be fully deleted...\n", namespace)

	for i := 0; i < 60; i++ { // Wait up to 60 seconds
		err := sh.Run("kubectl", "get", "namespace", namespace)
		if err != nil {
			// If kubectl get namespace fails, the namespace is gone
			fmt.Printf("✅ Namespace '%s' has been deleted\n", namespace)
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for namespace '%s' to be deleted", namespace)
}
