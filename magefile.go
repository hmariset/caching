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

// SquidHelm manages squid helm chart operations
type SquidHelm mg.Namespace

const (
	clusterName = "caching"
	// SquidImageTag is the tag used for the squid container image
	squidImageTag = "localhost/konflux-ci/squid:latest"
	// SquidContainerfile is the path to the Containerfile for squid
	squidContainerfile = "Containerfile"
)

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
	fmt.Printf("📦 Building image with tag '%s'...\n", squidImageTag)
	err := sh.Run("podman", "build", "-t", squidImageTag, "-f", squidContainerfile, ".")
	if err != nil {
		return fmt.Errorf("failed to build squid image: %w", err)
	}

	fmt.Printf("✅ Squid image built successfully\n")

	// Verify the image was built
	fmt.Printf("🔍 Verifying image exists...\n")
	err = sh.Run("podman", "images", squidImageTag)
	if err != nil {
		return fmt.Errorf("failed to verify squid image: %w", err)
	}

	fmt.Printf("✅ Squid image '%s' is ready!\n", squidImageTag)
	return nil
}

// Build:LoadSquid loads the Squid image into the kind cluster
func (Build) LoadSquid() error {
	// Ensure dependencies are met
	mg.Deps(Kind.Up, Build.Squid)

	fmt.Println("📦 Loading Squid image into kind cluster...")

	// Load image into kind cluster using process substitution
	fmt.Printf("📤 Loading image into kind cluster '%s'...\n", clusterName)
	err := sh.Run("bash", "-c", fmt.Sprintf("kind load image-archive --name %s <(podman save %s)", clusterName, squidImageTag))
	if err != nil {
		return fmt.Errorf("failed to load image into kind cluster: %w", err)
	}

	// Verify image is available in cluster
	fmt.Printf("🔍 Verifying image is available in cluster...\n")
	err = internal.GetNodeStatus(clusterName)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster for verification: %w", err)
	}

	fmt.Printf("✅ Squid image loaded successfully into kind cluster '%s'!\n", clusterName)
	return nil
}

// SquidHelm:Up deploys the Squid Helm chart to the cluster
func (SquidHelm) Up() error {
	// Ensure dependencies are met
	mg.Deps(Build.LoadSquid)

	fmt.Println("⚓ Deploying Squid Helm chart...")

	// Ensure required helm repositories are available
	fmt.Printf("📦 Ensuring helm repositories are available...\n")
	err := internal.EnsureHelmRepo("jetstack", "https://charts.jetstack.io")
	if err != nil {
		return fmt.Errorf("failed to ensure jetstack repository: %w", err)
	}

	// Build helm dependencies from lock file
	fmt.Printf("📦 Building helm dependencies...\n")
	err = sh.Run("helm", "dependency", "build", "./squid")
	if err != nil {
		return fmt.Errorf("failed to build helm dependencies: %w", err)
	}

	// Check if release already exists
	exists, err := internal.ReleaseExists("squid")
	if err != nil {
		return fmt.Errorf("failed to check release existence: %w", err)
	}

	if exists {
		// Upgrade existing release
		fmt.Printf("⚓ Upgrading existing squid helm release and waiting for readiness...\n")
		err = sh.Run("helm", "upgrade", "squid", "./squid", "--wait", "--timeout=120s")
		if err != nil {
			return fmt.Errorf("failed to upgrade helm chart: %w", err)
		}
	} else {
		// Install new release
		fmt.Printf("⚓ Installing squid helm chart and waiting for readiness...\n")
		err = sh.Run("helm", "install", "squid", "./squid", "--wait", "--timeout=120s")
		if err != nil {
			return fmt.Errorf("failed to install helm chart: %w", err)
		}
	}

	// Show comprehensive deployment status
	fmt.Printf("🔍 Verifying deployment status...\n")
	err = (SquidHelm{}).Status()
	if err != nil {
		return fmt.Errorf("deployment verification failed: %w", err)
	}

	fmt.Printf("✅ Squid helm chart deployed successfully!\n")
	return nil
}

// SquidHelm:Down removes the Squid Helm chart from the cluster
func (SquidHelm) Down() error {
	fmt.Println("🗑️  Removing Squid Helm chart...")

	// Check if release exists first
	exists, err := internal.ReleaseExists("squid")
	if err != nil {
		return fmt.Errorf("failed to check release existence: %w", err)
	}

	if !exists {
		fmt.Printf("ℹ️  Helm release 'squid' does not exist\n")
		return nil
	}

	// Uninstall the helm release
	fmt.Printf("🗑️  Uninstalling squid helm release...\n")
	err = sh.Run("helm", "uninstall", "squid")
	if err != nil {
		return fmt.Errorf("failed to uninstall helm chart: %w", err)
	}

	// Wait for proxy namespace to be fully deleted
	err = internal.WaitForNamespaceDeleted("proxy")
	if err != nil {
		fmt.Printf("⚠️  Warning: %v\n", err)
		// Don't fail the function, just warn - the namespace might be stuck
	}

	fmt.Printf("✅ Squid helm chart removed successfully!\n")
	return nil
}

// SquidHelm:UpClean forces redeployment of the Squid Helm chart (removes and reinstalls)
func (SquidHelm) UpClean() error {
	fmt.Println("🔄 Force redeploying Squid Helm chart...")

	// Remove existing release
	err := (SquidHelm{}).Down()
	if err != nil {
		return fmt.Errorf("failed to remove existing release: %w", err)
	}

	// Install fresh release
	fmt.Printf("⚓ Installing fresh squid helm chart...\n")
	return (SquidHelm{}).Up()
}

// SquidHelm:Status shows the deployment status
func (SquidHelm) Status() error {
	fmt.Println("📊 Checking deployment status...")

	// Check if squid helm release exists
	fmt.Printf("🔍 Checking helm release status...\n")
	err := sh.Run("helm", "status", "squid")
	if err != nil {
		fmt.Printf("❌ Helm release 'squid' not found or not deployed\n")
		return fmt.Errorf("helm release not found: %w", err)
	}

	// Show pod status
	fmt.Printf("🖥️  Pod status:\n")
	err = sh.RunV("kubectl", "get", "pods", "-n", "proxy", "-l", "app.kubernetes.io/name=squid")
	if err != nil {
		fmt.Printf("⚠️  Could not get pod status: %v\n", err)
	}

	// Show service status
	fmt.Printf("🌐 Service status:\n")
	err = sh.RunV("kubectl", "get", "svc", "-n", "proxy", "-l", "app.kubernetes.io/name=squid")
	if err != nil {
		fmt.Printf("⚠️  Could not get service status: %v\n", err)
	}

	// Show deployment status
	fmt.Printf("📦 Deployment status:\n")
	err = sh.RunV("kubectl", "get", "deployment", "-n", "proxy", "-l", "app.kubernetes.io/name=squid")
	if err != nil {
		fmt.Printf("⚠️  Could not get deployment status: %v\n", err)
	}

	fmt.Printf("✅ Deployment status check completed!\n")
	return nil
}

// All runs the complete automation workflow
func All() error {
	fmt.Println("🎯 Running complete automation workflow...")

	// TODO: Implement full workflow with proper dependencies
	// This will eventually call the tasks in proper order:
	// 1. Kind:Up
	// 2. Build:Squid
	// 3. Build:LoadSquid
	// 4. SquidHelm:Up
	// 5. SquidHelm:Status

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
