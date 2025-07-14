//go:build mage

package main

import (
	"fmt"
	"os"

	"github.com/konflux-ci/caching/internal"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Kind manages kind cluster operations
type Kind mg.Namespace

// Build manages image building operations
type Build mg.Namespace

// Deploy manages deployment operations
type Deploy mg.Namespace

const clusterName = "caching"

// Default target - shows available targets
func Default() error {
	return sh.Run("mage", "-l")
}

// Kind:Up creates or connects to a kind cluster named 'caching'
func (Kind) Up() error {
	fmt.Println("🚀 Setting up kind cluster...")

	// Check if cluster already exists
	exists, err := internal.ClusterExists(clusterName)
	if err != nil {
		return fmt.Errorf("failed to check cluster existence: %w", err)
	}

	if exists {
		fmt.Printf("✅ Cluster '%s' already exists\n", clusterName)
	} else {
		fmt.Printf("📦 Creating kind cluster '%s'...\n", clusterName)
		err := internal.CreateCluster(clusterName)
		if err != nil {
			return fmt.Errorf("failed to create cluster: %w", err)
		}
		fmt.Printf("✅ Cluster '%s' created successfully\n", clusterName)
	}

	// Export kubeconfig
	fmt.Printf("🔧 Exporting kubeconfig for cluster '%s'...\n", clusterName)
	err = internal.ExportKubeconfig(clusterName)
	if err != nil {
		return fmt.Errorf("failed to export kubeconfig: %w", err)
	}

	fmt.Printf("✅ Kind cluster '%s' is ready!\n", clusterName)
	return nil
}

// Kind:UpClean forces recreation of the kind cluster (deletes existing cluster and creates new one)
func (Kind) UpClean() error {
	fmt.Println("🚀 Setting up kind cluster (clean recreation)...")

	// Check if cluster already exists
	exists, err := internal.ClusterExists(clusterName)
	if err != nil {
		return fmt.Errorf("failed to check cluster existence: %w", err)
	}

	if exists {
		fmt.Printf("🔄 Deleting existing cluster '%s'...\n", clusterName)
		err := internal.DeleteCluster(clusterName)
		if err != nil {
			return fmt.Errorf("failed to delete existing cluster: %w", err)
		}
		fmt.Printf("✅ Cluster '%s' deleted successfully\n", clusterName)
	}

	// Create new cluster
	fmt.Printf("📦 Creating kind cluster '%s'...\n", clusterName)
	err = internal.CreateCluster(clusterName)
	if err != nil {
		return fmt.Errorf("failed to create cluster: %w", err)
	}
	fmt.Printf("✅ Cluster '%s' created successfully\n", clusterName)

	// Export kubeconfig
	fmt.Printf("🔧 Exporting kubeconfig for cluster '%s'...\n", clusterName)
	err = internal.ExportKubeconfig(clusterName)
	if err != nil {
		return fmt.Errorf("failed to export kubeconfig: %w", err)
	}

	fmt.Printf("✅ Kind cluster '%s' is ready!\n", clusterName)
	return nil
}

// Kind:Down tears down the kind cluster
func (Kind) Down() error {
	fmt.Println("🔥 Tearing down kind cluster...")

	// Check if cluster exists first
	exists, err := internal.ClusterExists(clusterName)
	if err != nil {
		return fmt.Errorf("failed to check cluster existence: %w", err)
	}

	if !exists {
		fmt.Printf("ℹ️  Cluster '%s' does not exist\n", clusterName)
		return nil
	}

	// Delete the cluster
	fmt.Printf("🗑️  Deleting kind cluster '%s'...\n", clusterName)
	err = internal.DeleteCluster(clusterName)
	if err != nil {
		return fmt.Errorf("failed to delete cluster: %w", err)
	}

	fmt.Printf("✅ Cluster '%s' deleted successfully\n", clusterName)
	return nil
}

// Kind:Status shows the status of the kind cluster
func (Kind) Status() error {
	fmt.Println("📊 Checking kind cluster status...")

	// Check if cluster exists
	exists, err := internal.ClusterExists(clusterName)
	if err != nil {
		return fmt.Errorf("failed to check cluster existence: %w", err)
	}

	if !exists {
		fmt.Printf("❌ Cluster '%s' does not exist\n", clusterName)
		return nil
	}

	fmt.Printf("✅ Cluster '%s' exists\n", clusterName)

	// Check kubeconfig
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("HOME") + "/.kube/config"
	}

	// Try to get cluster info
	fmt.Printf("🔍 Checking cluster connectivity...\n")
	output, err := internal.GetClusterInfo(clusterName)
	if err != nil {
		fmt.Printf("⚠️  Could not connect to cluster: %v\n", err)
		fmt.Printf("💡 Try running 'mage kind:up' to ensure kubeconfig is exported\n")
		return nil
	}

	fmt.Printf("✅ Cluster is accessible:\n%s\n", output)

	// Get node status
	fmt.Printf("🖥️  Node status:\n")
	err = internal.GetNodeStatus(clusterName)
	if err != nil {
		fmt.Printf("⚠️  Could not get node status: %v\n", err)
	}

	return nil
}

// Build:Squid builds the Squid container image
func (Build) Squid() error {
	fmt.Println("🐳 Building Squid container image...")

	// Build the squid image using podman
	fmt.Printf("📦 Building image with tag 'localhost/konflux-ci/squid:latest'...\n")
	err := sh.Run("podman", "build", "-t", "localhost/konflux-ci/squid:latest", "-f", "Containerfile", ".")
	if err != nil {
		return fmt.Errorf("failed to build squid image: %w", err)
	}

	fmt.Printf("✅ Squid image built successfully\n")

	// Verify the image was built
	fmt.Printf("🔍 Verifying image exists...\n")
	err = sh.Run("podman", "images", "localhost/konflux-ci/squid:latest")
	if err != nil {
		return fmt.Errorf("failed to verify squid image: %w", err)
	}

	fmt.Printf("✅ Squid image 'localhost/konflux-ci/squid:latest' is ready!\n")
	return nil
}

// Build:LoadSquid loads the Squid image into the kind cluster
func (Build) LoadSquid() error {
	fmt.Println("📦 Loading Squid image into kind cluster...")

	// TODO: Implement image loading logic
	// - Load built Squid image into kind cluster
	// - Verify image is available in cluster

	return fmt.Errorf("not implemented yet")
}

// Deploy:Helm deploys the Squid Helm chart to the cluster
func (Deploy) Helm() error {
	fmt.Println("⚓ Deploying Squid Helm chart...")

	// TODO: Implement Helm chart deployment logic
	// - Deploy squid chart with customizations
	// - Wait for deployment to be ready

	return fmt.Errorf("not implemented yet")
}

// Deploy:Status shows the deployment status
func (Deploy) Status() error {
	fmt.Println("📊 Checking deployment status...")

	// TODO: Implement deployment status check
	// - Show pod status
	// - Show service status

	return fmt.Errorf("not implemented yet")
}

// All runs the complete automation workflow
func All() error {
	fmt.Println("🎯 Running complete automation workflow...")

	// TODO: Implement full workflow with proper dependencies
	// This will eventually call the tasks in proper order:
	// 1. Kind:Up
	// 2. Build:Squid
	// 3. Build:LoadSquid
	// 4. Deploy:Helm
	// 5. Deploy:Status

	return fmt.Errorf("not implemented yet")
}

// Clean removes all resources (cluster, images, etc.)
func Clean() error {
	fmt.Println("🧹 Cleaning up all resources...")

	// TODO: Implement cleanup logic
	// - Remove kind cluster
	// - Remove built images
	// - Clean up any temporary files

	return fmt.Errorf("not implemented yet")
}
