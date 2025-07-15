package e2e_test

import (
	"fmt"

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
			labelSelector := "app.kubernetes.io/name=squid"
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
})
