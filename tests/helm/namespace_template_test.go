package helm_test

import (
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/konflux-ci/caching/tests/testhelpers"
)

var _ = Describe("Component namespaces", func() {
	render := func(settings ...string) (string, error) {
		root, err := testhelpers.FindChartDirectory()
		Expect(err).NotTo(HaveOccurred())
		args := []string{"template", "caching", chartPath, "--set", "installCertManagerComponents=false"}
		for _, setting := range settings {
			args = append(args, "--set", setting)
		}
		cmd := exec.Command("helm", args...)
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		return string(output), err
	}

	It("creates separate namespaces with the component defaults", func() {
		output, err := render("nginx.enabled=true")
		Expect(err).NotTo(HaveOccurred(), output)
		for _, component := range []string{"squid", "nginx"} {
			ns := extractSection(output, "# Source: caching/templates/"+component+"-namespace.yaml")
			Expect(ns).To(ContainSubstring("name: " + component + "-proxy"))
		}
		Expect(output).NotTo(ContainSubstring("# Source: caching/templates/namespace.yaml"))
	})

	It("applies component annotations only to their own namespace", func() {
		output, err := render("nginx.enabled=true", "squid.namespace=forward-proxy", "nginx.namespace=reverse-proxy", "squid.namespaceAnnotations.owner=forward", "nginx.namespaceAnnotations=null")
		Expect(err).NotTo(HaveOccurred(), output)
		squid := extractSection(output, "# Source: caching/templates/squid-namespace.yaml")
		nginx := extractSection(output, "# Source: caching/templates/nginx-namespace.yaml")
		Expect(squid).To(ContainSubstring("owner: forward"))
		Expect(nginx).NotTo(ContainSubstring("annotations:"))
		Expect(extractSquidDeploymentSection(output)).To(ContainSubstring("namespace: forward-proxy"))
		Expect(extractNginxStatefulSetSection(output)).To(ContainSubstring("namespace: reverse-proxy"))
	})

	It("omits disabled component namespaces when no test resources need them", func() {
		output, err := render("squid.enabled=false", "nginx.enabled=true", "test.enabled=false", "mirrord.enabled=false")
		Expect(err).NotTo(HaveOccurred(), output)
		Expect(extractSection(output, "# Source: caching/templates/squid-namespace.yaml")).To(BeEmpty())
		Expect(extractSection(output, "# Source: caching/templates/nginx-namespace.yaml")).NotTo(BeEmpty())
	})

	It("creates the namespace needed by tests when Squid is disabled", func() {
		output, err := render("squid.enabled=false", "test.enabled=true")
		Expect(err).NotTo(HaveOccurred(), output)
		Expect(extractSection(output, "# Source: caching/templates/squid-namespace.yaml")).To(ContainSubstring("name: squid-proxy"))
	})

	DescribeTable("rejects empty component namespaces", func(component string) {
		output, err := render(component + ".namespace=")
		Expect(err).To(HaveOccurred())
		Expect(output).To(ContainSubstring(component))
		Expect(output).To(ContainSubstring("namespace"))
	}, Entry("Squid", "squid"), Entry("Nginx", "nginx"))
})
