package testhelpers

import (
	"os"
	"time"
)

// Test configuration constants shared across all test packages
const (
	// General constants
	Timeout  = 60 * time.Second
	Interval = 2 * time.Second

	// Squid constants
	SquidServiceName     = "squid"
	SquidStatefulSetName = "squid"
	SquidContainerName   = "squid"
	SquidComponentLabel  = "squid-caching"

	// Nginx constants
	NginxServiceName     = "nginx"
	NginxStatefulSetName = "nginx"
	NginxPort            = 80
	NginxHTTPSPort       = 443
	NginxComponentLabel  = "nginx-caching"

	// Nginx test backend constants
	NginxTestBackendServiceName = "nginx-test-backend"
	NginxTestBackendPort        = 9090
)

var (
	SquidNamespace     = namespaceFromEnv("SQUID_NAMESPACE", "caching")
	NginxNamespace     = namespaceFromEnv("NGINX_NAMESPACE", "caching")
	TestNamespace      = namespaceFromEnv("TARGET_NAMESPACE", "caching-test")
	SquidTLSSecretName = SquidNamespace + "-tls"
)

func namespaceFromEnv(name, fallback string) string {
	if namespace := os.Getenv(name); namespace != "" {
		return namespace
	}
	return fallback
}
