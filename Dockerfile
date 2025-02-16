FROM --platform=$BUILDPLATFORM golang:1.23 AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    bpftool \
    linux-headers-generic \
    libelf-dev \
    libpcap-dev \
    libbfd-dev \
    binutils-dev \
    build-essential \
    make \
    bpfcc-tools \
    libbpfcc-dev \
    libbpf-dev

WORKDIR /build

# Copy source code
COPY . .

# Generate vmlinux.h from BTF or use pre-generated one
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
    else \
        echo "Warning: /sys/kernel/btf/vmlinux not found. Using pre-generated vmlinux.h"; \
        # Assuming vmlinux.h exists in the repo, otherwise this will fail \
        cp vmlinux.h vmlinux.h || exit 1; \
    fi

# Generate eBPF code
RUN go generate ./...

# Build the binary
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o tc-pkt-counter

# Final stage
FROM debian:bookworm-slim

# Install networking tools and debug utilities
RUN apt-get update && apt-get install -y \
    iproute2 \
    procps \
    net-tools \
    tcpdump \
    iptables \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/tc-pkt-counter /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/tc-pkt-counter"]