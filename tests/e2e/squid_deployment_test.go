package e2e_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Squid Helm Chart Deployment", func() {

	Describe("Namespace", func() {
		It("should have the proxy namespace created", func() {
			namespace, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to get proxy namespace")
			Expect(namespace.Name).To(Equal("proxy"))
			Expect(namespace.Status.Phase).To(Equal(corev1.NamespaceActive))
		})
	})

	Describe("Deployment", func() {
		var deployment *appsv1.Deployment

		BeforeEach(func() {
			var err error
			deployment, err = clientset.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to get squid deployment")
		})

		It("should exist and be properly configured", func() {
			Expect(deployment.Name).To(Equal("squid"))
			Expect(deployment.Namespace).To(Equal("proxy"))

			// Check deployment spec
			Expect(deployment.Spec.Replicas).NotTo(BeNil())
			Expect(*deployment.Spec.Replicas).To(BeNumerically(">=", 1))

			// Check selector and labels
			Expect(deployment.Spec.Selector.MatchLabels).To(HaveKeyWithValue("app.kubernetes.io/name", "squid"))
		})

		It("should be ready and available", func() {
			Eventually(func() bool {
				dep, err := clientset.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
				if err != nil {
					return false
				}
				return dep.Status.ReadyReplicas == *dep.Spec.Replicas &&
					dep.Status.AvailableReplicas == *dep.Spec.Replicas
			}, timeout, interval).Should(BeTrue(), "Deployment should be ready and available")
		})

		It("should have the correct container image and configuration", func() {
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := deployment.Spec.Template.Spec.Containers[0]
			Expect(container.Name).To(Equal("squid"))
			Expect(container.Image).To(ContainSubstring("konflux-ci/squid"))

			// Check port configuration
			Expect(container.Ports).To(HaveLen(1))
			Expect(container.Ports[0].ContainerPort).To(Equal(int32(3128)))
			Expect(container.Ports[0].Name).To(Equal("http"))
		})
	})

	Describe("Service", func() {
		var service *corev1.Service

		BeforeEach(func() {
			var err error
			service, err = clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to get squid service")
		})

		It("should exist and be properly configured", func() {
			Expect(service.Name).To(Equal("squid"))
			Expect(service.Namespace).To(Equal("proxy"))

			// Check service type and selector
			Expect(service.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
			Expect(service.Spec.Selector).To(HaveKeyWithValue("app.kubernetes.io/name", "squid"))
		})

		It("should have the correct port configuration", func() {
			Expect(service.Spec.Ports).To(HaveLen(1))

			port := service.Spec.Ports[0]
			Expect(port.Port).To(Equal(int32(3128)))
			Expect(port.TargetPort.StrVal).To(Equal("http"))
			Expect(port.Protocol).To(Equal(corev1.ProtocolTCP))
		})

		It("should have endpoints ready", func() {
			Eventually(func() bool {
				endpoints, err := clientset.CoreV1().Endpoints(namespace).Get(ctx, serviceName, metav1.GetOptions{})
				if err != nil {
					return false
				}

				for _, subset := range endpoints.Subsets {
					if len(subset.Addresses) > 0 {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue(), "Service should have ready endpoints")
		})
	})

	Describe("Pod", func() {
		var pods *corev1.PodList

		BeforeEach(func() {
			var err error
			// Select only application pods, exclude test pods
			labelSelector := "app.kubernetes.io/name=squid,app.kubernetes.io/component!=test"
			pods, err = clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			Expect(err).NotTo(HaveOccurred(), "Failed to list squid pods")
			Expect(pods.Items).NotTo(BeEmpty(), "No squid pods found")
		})

		It("should be running and ready", func() {
			for _, pod := range pods.Items {
				Eventually(func() corev1.PodPhase {
					currentPod, err := clientset.CoreV1().Pods(namespace).Get(ctx, pod.Name, metav1.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					return currentPod.Status.Phase
				}, timeout, interval).Should(Equal(corev1.PodRunning), fmt.Sprintf("Pod %s should be running", pod.Name))

				// Check readiness
				Eventually(func() bool {
					currentPod, err := clientset.CoreV1().Pods(namespace).Get(ctx, pod.Name, metav1.GetOptions{})
					if err != nil {
						return false
					}

					for _, condition := range currentPod.Status.Conditions {
						if condition.Type == corev1.PodReady {
							return condition.Status == corev1.ConditionTrue
						}
					}
					return false
				}, timeout, interval).Should(BeTrue(), fmt.Sprintf("Pod %s should be ready", pod.Name))
			}
		})

		It("should have correct resource configuration", func() {
			for _, pod := range pods.Items {
				Expect(pod.Spec.Containers).To(HaveLen(1))

				container := pod.Spec.Containers[0]
				Expect(container.Name).To(Equal("squid"))

				// Check security context (should run as non-root)
				if container.SecurityContext != nil {
					Expect(container.SecurityContext.RunAsNonRoot).NotTo(BeNil())
					if container.SecurityContext.RunAsNonRoot != nil {
						Expect(*container.SecurityContext.RunAsNonRoot).To(BeTrue())
					}
				}
			}
		})

		It("should have the squid configuration mounted", func() {
			for _, pod := range pods.Items {
				container := pod.Spec.Containers[0]

				// Check for volume mounts
				var foundConfigMount bool
				for _, mount := range container.VolumeMounts {
					if mount.Name == "squid-config" || mount.MountPath == "/etc/squid/squid.conf" {
						foundConfigMount = true
						break
					}
				}
				Expect(foundConfigMount).To(BeTrue(), "Pod should have squid configuration mounted")
			}
		})
	})

	Describe("ConfigMap", func() {
		It("should exist and contain squid configuration", func() {
			configMap, err := clientset.CoreV1().ConfigMaps(namespace).Get(ctx, "squid-config", metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to get squid-config ConfigMap")

			Expect(configMap.Data).To(HaveKey("squid.conf"))
			squidConf := configMap.Data["squid.conf"]

			// Basic configuration checks
			Expect(squidConf).To(ContainSubstring("http_port 3128"))
			Expect(squidConf).To(ContainSubstring("acl localnet src"))
		})
	})

	Describe("HTTP Caching Functionality", func() {
		var (
			testServer    *httptest.Server
			testServerURL string
			requestCount  int32
			proxyURL      *url.URL
			client        *http.Client
		)

		BeforeEach(func() {
			// Reset request counter
			atomic.StoreInt32(&requestCount, 0)

			// Create test HTTP server that tracks requests
			// Use unstarted server so we can configure the listener
			testServer = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := atomic.AddInt32(&requestCount, 1)

				// Add cache headers to make content cacheable
				w.Header().Set("Cache-Control", "public, max-age=300")
				w.Header().Set("Content-Type", "application/json")

				// Return JSON response with request count
				response := map[string]interface{}{
					"message":     "Hello from test server",
					"request_id":  count,
					"timestamp":   time.Now().Unix(),
					"server_hits": count,
				}

				jsonResponse, _ := json.Marshal(response)
				w.Write(jsonResponse)
			}))

			// Configure server to listen on all interfaces and start it
			testServer.Listener, _ = net.Listen("tcp", "0.0.0.0:0")
			testServer.Start()

			// Get the pod's IP address to construct accessible URL
			podIP, err := getPodIP()
			Expect(err).NotTo(HaveOccurred(), "Failed to get pod IP")

			// Construct test server URL using pod IP instead of localhost
			_, port, _ := net.SplitHostPort(testServer.Listener.Addr().String())
			testServerURL = fmt.Sprintf("http://%s:%s", podIP, port)

			// Set up proxy URL to squid service
			proxyURL, err = url.Parse(fmt.Sprintf("http://%s.%s.svc.cluster.local:3128", serviceName, namespace))
			Expect(err).NotTo(HaveOccurred(), "Failed to parse proxy URL")

			// Create HTTP client with proxy configuration
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				// Disable keep-alive to ensure fresh connections
				DisableKeepAlives: true,
			}
			client = &http.Client{
				Transport: transport,
				Timeout:   30 * time.Second,
			}
		})

		AfterEach(func() {
			if testServer != nil {
				testServer.Close()
			}
		})

		It("should cache HTTP responses and serve subsequent requests from cache", func() {
			By("Making the first HTTP request through Squid proxy")
			resp1, err := client.Get(testServerURL)
			Expect(err).NotTo(HaveOccurred(), "First request should succeed")
			defer resp1.Body.Close()

			body1, err := io.ReadAll(resp1.Body)
			Expect(err).NotTo(HaveOccurred(), "Should read first response body")

			// Debug: print the actual response for troubleshooting
			fmt.Printf("DEBUG: Response status: %s\n", resp1.Status)
			fmt.Printf("DEBUG: Response body: %s\n", string(body1))
			fmt.Printf("DEBUG: Test server URL: %s\n", testServerURL)

			var response1 map[string]interface{}
			err = json.Unmarshal(body1, &response1)
			Expect(err).NotTo(HaveOccurred(), "Should parse first response JSON")

			// Verify first request reached the server
			Expect(response1["request_id"]).To(Equal(float64(1)), "First request should hit server")
			Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(1)), "Server should have received 1 request")

			By("Making the second HTTP request for the same URL")
			// Wait a moment to ensure any timing-related caching issues are avoided
			time.Sleep(100 * time.Millisecond)

			resp2, err := client.Get(testServerURL)
			Expect(err).NotTo(HaveOccurred(), "Second request should succeed")
			defer resp2.Body.Close()

			body2, err := io.ReadAll(resp2.Body)
			Expect(err).NotTo(HaveOccurred(), "Should read second response body")

			var response2 map[string]interface{}
			err = json.Unmarshal(body2, &response2)
			Expect(err).NotTo(HaveOccurred(), "Should parse second response JSON")

			By("Verifying the second request was served from cache")
			// The second response should be identical to the first (from cache)
			Expect(response2["request_id"]).To(Equal(float64(1)), "Second request should be served from cache with same request_id")
			Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(1)), "Server should still have received only 1 request")

			// Response bodies should be identical (served from cache)
			Expect(string(body2)).To(Equal(string(body1)), "Cached response should be identical to original")

			By("Verifying cache headers are present")
			// Check that appropriate cache-related headers are present
			Expect(resp1.Header.Get("Cache-Control")).To(ContainSubstring("max-age=300"))
			Expect(resp2.Header.Get("Cache-Control")).To(ContainSubstring("max-age=300"))
		})

		It("should handle different URLs independently", func() {
			By("Making requests to different endpoints")

			// First URL
			resp1, err := client.Get(testServerURL + "/endpoint1")
			Expect(err).NotTo(HaveOccurred())
			defer resp1.Body.Close()

			initialCount := atomic.LoadInt32(&requestCount)

			// Second URL (different from first)
			resp2, err := client.Get(testServerURL + "/endpoint2")
			Expect(err).NotTo(HaveOccurred())
			defer resp2.Body.Close()

			// Both requests should hit the server (different URLs)
			Expect(atomic.LoadInt32(&requestCount)).To(Equal(initialCount+1), "Different URLs should not be cached together")
		})
	})
})
