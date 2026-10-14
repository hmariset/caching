package helm_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/konflux-ci/caching/tests/testhelpers"
)

var _ = Describe("Helm test namespace isolation", func() {
	It("places test infrastructure and proxy discovery in independent namespaces", func() {
		output, err := testhelpers.RenderHelmTemplate(chartPath, testhelpers.SquidHelmValues{
			Squid: &testhelpers.SquidValues{Namespace: "squid-proxy"},
			Nginx: &testhelpers.NginxValues{Enabled: true, Namespace: "nginx-proxy"},
			Test:  &testhelpers.TestValues{Namespace: "test-infra"},
		})
		Expect(err).NotTo(HaveOccurred())

		testPod := extractSection(output, "# Source: caching/templates/test-pod.yaml")
		Expect(testPod).To(ContainSubstring("namespace: test-infra"))
		Expect(testPod).To(ContainSubstring("name: SQUID_NAMESPACE\n      value: \"squid-proxy\""))
		Expect(testPod).To(ContainSubstring("name: NGINX_NAMESPACE\n      value: \"nginx-proxy\""))

		rbac := extractSection(output, "# Source: caching/templates/test-rbac.yaml")
		Expect(rbac).To(ContainSubstring("namespace: test-infra"))
		testServer := extractSection(output, "# Source: caching/templates/https-test-server.yaml")
		Expect(testServer).To(ContainSubstring("namespace: test-infra"))
	})

	It("renders Nginx tests with Squid disabled", func() {
		output, err := testhelpers.RenderHelmTemplate(chartPath, testhelpers.SquidHelmValues{
			Squid: &testhelpers.SquidValues{Enabled: testhelpers.BoolPtr(false)},
			Nginx: &testhelpers.NginxValues{Enabled: true, Namespace: "nginx-only"},
			Test:  &testhelpers.TestValues{Namespace: "test-infra"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(extractSquidDeploymentSection(output)).To(BeEmpty())
		Expect(extractNginxStatefulSetSection(output)).To(ContainSubstring("namespace: nginx-only"))
		testPod := extractSection(output, "# Source: caching/templates/test-pod.yaml")
		Expect(testPod).To(ContainSubstring("name: SQUID_ENABLED\n      value: \"false\""))
		Expect(testPod).To(ContainSubstring("name: NGINX_ENABLED\n      value: \"true\""))
	})
})
