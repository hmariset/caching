FROM registry.access.redhat.com/ubi10/ubi-minimal@sha256:4cfec88c16451cc9ce4ba0a8c6109df13d67313a33ff8eb2277d0901b4d81020

# Install required packages for Go and testing (version-locked)
# Note: curl-minimal is already present in ubi10-minimal
RUN microdnf install -y \
    tar-2:1.35-7.el10 \
    gzip-1.13-3.el10 \
    which-2.21-43.el10 \
    procps-ng-4.0.4-7.el10 \
    gcc-14.2.1-7.el10 && \
    microdnf clean all

# Install Go (version-locked)
ARG GO_VERSION=1.24.4
ARG GO_SHA256=77e5da33bb72aeaef1ba4418b6fe511bc4d041873cbf82e5aa6318740df98717
RUN curl -fsSL "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz && \
    echo "${GO_SHA256}  go.tar.gz" | sha256sum -c - && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# Set Go environment
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"
ENV GOPATH="/root/go"
ENV GOCACHE="/tmp/go-cache"

# Install Ginkgo CLI (version-locked)
RUN go install github.com/onsi/ginkgo/v2/ginkgo@v2.23.4

# Create working directory
WORKDIR /app

# Copy module files first
COPY go.mod go.sum ./

# Copy test source files maintaining directory structure
COPY tests/ ./tests/

# Set up Go module and compile tests at build time
RUN go mod download && \
    go mod tidy && \
    cd tests && \
    ginkgo build ./e2e

# Create a non-root user for running tests
RUN adduser --uid 1001 --gid 0 --shell /bin/bash --create-home testuser
USER 1001

# Default command runs the compiled test binary
CMD ["./tests/e2e/e2e.test", "-ginkgo.v"] 
